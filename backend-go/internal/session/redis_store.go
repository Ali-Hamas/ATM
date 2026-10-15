package session

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
)

// Lua script for atomic session approval.
// Checks:
//  1. Session exists.
//  2. Status is strictly 'pending'.
//  3. Current time <= expiresAt.
// If valid, transitions status to 'approved', sets approvedAt/device/customer, preserves key TTL.
const approveLuaScript = `
local val = redis.call('GET', KEYS[1])
if not val then
    return redis.error_reply("ERR_SESSION_NOT_FOUND")
end

local sess = cjson.decode(val)
if sess['status'] ~= 'pending' then
    return redis.error_reply("ERR_CONFLICT_" .. string.upper(sess['status']))
end

local now = tonumber(ARGV[3])
if now > tonumber(sess['expiresAt']) then
    sess['status'] = 'expired'
    redis.call('SET', KEYS[1], cjson.encode(sess), 'KEEPTTL')
    return redis.error_reply("ERR_SESSION_EXPIRED")
end

sess['status'] = 'approved'
sess['approvedAt'] = now
sess['approvedByDeviceId'] = ARGV[1]
sess['approvedByCustomerRef'] = ARGV[2]

redis.call('SET', KEYS[1], cjson.encode(sess), 'KEEPTTL')
return cjson.encode(sess)
`

// Lua script for atomic session consumption.
// Checks:
//  1. Session exists.
//  2. Status is strictly 'approved'.
// If valid, transitions status to 'consumed', sets consumedAt, preserves key TTL.
const consumeLuaScript = `
local val = redis.call('GET', KEYS[1])
if not val then
    return redis.error_reply("ERR_SESSION_NOT_FOUND")
end

local sess = cjson.decode(val)
if sess['status'] ~= 'approved' then
    return redis.error_reply("ERR_CONFLICT_" .. string.upper(sess['status']))
end

sess['status'] = 'consumed'
sess['consumedAt'] = tonumber(ARGV[1])

redis.call('SET', KEYS[1], cjson.encode(sess), 'KEEPTTL')
return cjson.encode(sess)
`

type RedisStore struct {
	client     *redis.Client
	ttl        time.Duration
	approveSHA string
	consumeSHA string

	auditMu sync.RWMutex
	audit   []AuditEntry
}

func NewRedisStore(client *redis.Client, ttlSeconds int) (*RedisStore, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	if err := client.Ping(ctx).Err(); err != nil {
		return nil, fmt.Errorf("redis ping failed: %w", err)
	}

	approveSHA, err := client.ScriptLoad(ctx, approveLuaScript).Result()
	if err != nil {
		return nil, fmt.Errorf("failed to load approve Lua script into Redis: %w", err)
	}

	consumeSHA, err := client.ScriptLoad(ctx, consumeLuaScript).Result()
	if err != nil {
		return nil, fmt.Errorf("failed to load consume Lua script into Redis: %w", err)
	}

	return &RedisStore{
		client:     client,
		ttl:        time.Duration(ttlSeconds) * time.Second,
		approveSHA: approveSHA,
		consumeSHA: consumeSHA,
	}, nil
}

func (r *RedisStore) Put(sess *Session) error {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	b, err := json.Marshal(sess)
	if err != nil {
		return err
	}

	key := r.sessionKey(sess.ID)
	return r.client.Set(ctx, key, b, r.ttl).Err()
}

func (r *RedisStore) Get(id string) (*Session, bool) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	val, err := r.client.Get(ctx, r.sessionKey(id)).Result()
	if errors.Is(err, redis.Nil) || err != nil {
		return nil, false
	}

	var sess Session
	if err := json.Unmarshal([]byte(val), &sess); err != nil {
		return nil, false
	}

	// Lazy expiration check
	now := time.Now().UnixMilli()
	if sess.Status == StatusPending && now > sess.ExpiresAt {
		sess.Status = StatusExpired
		b, _ := json.Marshal(sess)
		_ = r.client.Set(ctx, r.sessionKey(id), b, redis.KeepTTL).Err()
	}

	return &sess, true
}

func (r *RedisStore) TransitionToApproved(id string, deviceID, customerRef string) (*Session, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	now := time.Now().UnixMilli()
	res, err := r.client.EvalSha(ctx, r.approveSHA, []string{r.sessionKey(id)}, deviceID, customerRef, now).Result()
	if err != nil {
		// Fallback to Eval if ScriptLoad was flushed on Redis server
		res, err = r.client.Eval(ctx, approveLuaScript, []string{r.sessionKey(id)}, deviceID, customerRef, now).Result()
		if err != nil {
			return nil, err
		}
	}

	jsonStr, ok := res.(string)
	if !ok {
		return nil, errors.New("unexpected return type from Redis Lua script")
	}

	var sess Session
	if err := json.Unmarshal([]byte(jsonStr), &sess); err != nil {
		return nil, err
	}
	return &sess, nil
}

func (r *RedisStore) TransitionToConsumed(id string) (*Session, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	now := time.Now().UnixMilli()
	res, err := r.client.EvalSha(ctx, r.consumeSHA, []string{r.sessionKey(id)}, now).Result()
	if err != nil {
		res, err = r.client.Eval(ctx, consumeLuaScript, []string{r.sessionKey(id)}, now).Result()
		if err != nil {
			return nil, err
		}
	}

	jsonStr, ok := res.(string)
	if !ok {
		return nil, errors.New("unexpected return type from Redis Lua script")
	}

	var sess Session
	if err := json.Unmarshal([]byte(jsonStr), &sess); err != nil {
		return nil, err
	}
	return &sess, nil
}

func (r *RedisStore) Log(entry AuditEntry) {
	r.auditMu.Lock()
	defer r.auditMu.Unlock()
	r.audit = append(r.audit, entry)
}

func (r *RedisStore) Audit() []AuditEntry {
	r.auditMu.RLock()
	defer r.auditMu.RUnlock()
	out := make([]AuditEntry, len(r.audit))
	copy(out, r.audit)
	return out
}

// RunSweeper is a no-op for Redis because native Redis key TTL handles
// automatic session cleanup without needing a background goroutine sweeper.
func (r *RedisStore) RunSweeper(ctx context.Context) {
	<-ctx.Done()
}

func (r *RedisStore) sessionKey(id string) string {
	return "atm:session:" + id
}

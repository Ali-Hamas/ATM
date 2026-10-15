#!/usr/bin/env bash
# ============================================================================
# Bank mTLS Certificate Authority & Key Generation Utility (Linux/macOS)
# ============================================================================
set -euo pipefail

TARGET_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/certs"
mkdir -p "$TARGET_DIR"
cd "$TARGET_DIR"

echo "=== Generating Bank Private Root CA (4096-bit RSA) ==="
openssl genrsa -out bank_ca.key 4096
openssl req -x509 -new -nodes -key bank_ca.key -sha256 -days 1825 \
    -subj "/C=GB/O=DemoBank International/OU=Security Operations/CN=DemoBank-Root-CA" \
    -out bank_ca.crt

echo "=== Generating Nginx Server Certificate ==="
openssl genrsa -out server.key 2048
openssl req -new -key server.key \
    -subj "/C=GB/O=DemoBank International/OU=ATM Switch/CN=atm.internal.bank.net" \
    -out server.csr

cat <<EOF > san.cnf
[v3_req]
subjectAltName = @alt_names
[alt_names]
DNS.1 = atm.internal.bank.net
DNS.2 = mobile.bank.net
DNS.3 = localhost
IP.1 = 127.0.0.1
EOF

openssl x509 -req -in server.csr -CA bank_ca.crt -CAkey bank_ca.key -CAcreateserial \
    -out server.crt -days 730 -sha256 -extfile san.cnf -extensions v3_req
rm -f san.cnf server.csr

echo "=== Generating ATM Client Certificate (ATM-001) ==="
openssl genrsa -out atm-001.key 2048
openssl req -new -key atm-001.key \
    -subj "/C=GB/O=DemoBank International/OU=ATM Hardware Fleet/CN=ATM-HARDWARE-LONDON-001" \
    -out atm-001.csr
openssl x509 -req -in atm-001.csr -CA bank_ca.crt -CAkey bank_ca.key -CAcreateserial \
    -out atm-001.crt -days 365 -sha256
rm -f atm-001.csr

echo "=== Generating Untrusted Rogue Certificate (Pen-Test Check) ==="
openssl req -x509 -newkey rsa:2048 -nodes -keyout rogue.key -out rogue.crt -days 365 \
    -subj "/C=XX/O=Attacker Organization/CN=Rogue-Device"

echo "Certificates generated in $TARGET_DIR"
ls -la "$TARGET_DIR"

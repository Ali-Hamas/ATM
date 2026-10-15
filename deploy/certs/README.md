# Mutual TLS (mTLS) Certificates

This directory holds the X.509 certificates and RSA private keys used for ATM terminal and Nginx reverse proxy mutual authentication.

## Generation
To generate a local development/testing PKI hierarchy, run:
```powershell
.\deploy\generate-mtls-certs.ps1
```
Or on Linux/macOS:
```bash
./deploy/generate-mtls-certs.sh
```

Private keys and certificates (`*.key`, `*.crt`, `*.srl`) are ignored by git for security.

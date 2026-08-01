# sc5beacon — SquidC5 native implant v2

**Authorized red team / lab use only.**

## Build

```bash
cd agents/sc5beacon
go mod tidy
go build -ldflags="-s -w" -o sc5beacon .

# Windows
GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" -o sc5beacon.exe .

# Linux arm64
GOOS=linux GOARCH=arm64 go build -ldflags="-s -w" -o sc5beacon-arm64 .
```

## Configure

| Env | Required | Meaning |
|-----|----------|---------|
| `SC5_URL` | yes | `https://C2:8443/api/v1/implant/beacon` |
| `SC5_PSK` | yes | Contents of server `data/implant_psk.txt` |
| `SC5_SLEEP` | no | Base sleep seconds (default 5) |
| `SC5_JITTER` | no | Jitter percent 0–100 (default 20) |
| `SC5_KILL_DATE` | no | Unix epoch; agent exits after |
| `SC5_MAX_MISS` | no | Exit after N failed check-ins |
| `SC5_WORK_START` / `SC5_WORK_END` | no | Working hours (local), 0–23 |
| `SC5_SLEEP_MASK` | no | `jitter` (default) \| `timer` \| `ekko` (timer stand-in) |
| `SC5_ALLOW_INJECT` | no | Must be `1` to accept `inject:*` lab stubs |
| `SC5_ALLOW_BOF` | no | Must be `1` to accept `bof:run` lab stubs |

TLS always verifies the system trust store. For lab CAs, install the CA or set `SSL_CERT_FILE`. There is **no** skip-verify flag.

## Features

- ChaCha20-Poly1305 sealed check-in (matches server `implants/crypto.py`)
- Sleep mask + jitter + kill date + max miss + working hours
- Shell commands + `file:list|read|write|delete` + `sysinfo`
- SOCKS reverse-dial (`socks:start` / `socks:connect`)
- Lab-gated inject / BOF stubs (no real injection unless research build + env gates)
- Cross-compile Linux/Windows/macOS via Go

## Server factory

```bash
sc5 implants build --os linux --arch amd64 --host C2 --port 8443
# or API POST /api/v1/implants/build
```

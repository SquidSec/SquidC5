# sc5beacon - SquidC5 native implant v3

**Authorized red team / lab use only.**

## Build

```bash
cd agents/sc5beacon
go mod tidy
go test ./...
go build -ldflags="-s -w" -o sc5beacon .

GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" -o sc5beacon.exe .
GOOS=linux GOARCH=arm64 go build -ldflags="-s -w" -o sc5beacon-arm64 .
```

## Configure

Priority: `SC5_CONFIG_B64` JSON blob -> individual env vars -> link-time `bakedConfigJSON`.

| Env | Required | Meaning |
|-----|----------|---------|
| `SC5_CONFIG_B64` | recommended | Base64 JSON config blob (factory emits this) |
| `SC5_URL` | yes* | `https://C2:8443/api/v1/implant/beacon` |
| `SC5_PSK` | yes* | Contents of server `data/implant_psk.txt` |
| `SC5_CHANNEL` | no | `http` (default) or `ws` |
| `SC5_WS_URL` | if ws | `wss://C2:8443/ws/v1/beacon` |
| `SC5_SLEEP` / `SC5_JITTER` | no | Sleep seconds / jitter % |
| `SC5_KILL_DATE` | no | Unix epoch exit |
| `SC5_MAX_MISS` | no | Exit after N failed check-ins |
| `SC5_WORK_START` / `SC5_WORK_END` | no | Working hours 0-23 |
| `SC5_SLEEP_MASK` | no | `jitter` \| `timer` \| `ekko` |
| `SC5_ALLOW_INJECT` | no | `1` enables lab inject stubs |
| `SC5_ALLOW_BOF` | no | `1` enables BOF host / catalog simulate |

TLS always verifies system roots. **No** skip-verify flag.

## Features (I1-I5)

- Config blob + factory stagers (bash / PowerShell stage0)
- Jobs: `job:start`, `job:list`, `job:get`, `job:kill`, `async` args
- `pwd` / `cd` / `ps` / `kill` / `sysinfo` / files / shell
- HTTP + **WebSocket** AEAD channels
- COFF parse + catalog BOF simulate (`whoami`,`env`,`dir`,`net`,`screenshot`)
- Sleep mask + buffer wipe OPSEC helpers
- SOCKS reverse-dial; lab-gated inject stubs

## Task cheatsheet

```text
sysinfo | pwd | cd /tmp | ps | kill <pid>
job:start {"command":"sleep 30"} | job:list | job:get | job:kill
file:list | file:read | file:write | file:delete
bof:run  (SC5_ALLOW_BOF=1)
inject:create_remote_thread  (SC5_ALLOW_INJECT=1, lab stub)
```

## Server factory

```bash
sc5 implants build --os linux --arch amd64 --host C2 --port 8443
# or API POST /api/v1/implants/build
```

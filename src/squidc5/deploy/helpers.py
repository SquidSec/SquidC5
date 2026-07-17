"""OpSec deploy helpers: redirector configs and cert rotation plans (no secrets)."""

from __future__ import annotations

from typing import Any


def nginx_redirector_config(
    *,
    listen_port: int = 443,
    upstream_host: str = "127.0.0.1",
    upstream_port: int = 8443,
    server_name: str = "cdn.example.invalid",
    beacon_uris: list[str] | None = None,
) -> str:
    """Generate a lab nginx reverse-proxy snippet for authorized redirector tier."""
    uris = beacon_uris or ["/api/v1/implant/beacon"]
    locations = []
    for u in uris:
        path = u if u.startswith("/") else f"/{u}"
        locations.append(
            f"""
    location {path} {{
        proxy_pass http://{upstream_host}:{upstream_port};
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_http_version 1.1;
    }}""".rstrip()
        )
    locs = "\n".join(locations)
    return f"""# SquidC5 redirector snippet — authorized lab only
# Place under /etc/nginx/sites-available/ and enable TLS with your certs.
server {{
    listen {listen_port} ssl http2;
    server_name {server_name};

    # ssl_certificate     /etc/ssl/certs/fullchain.pem;
    # ssl_certificate_key /etc/ssl/private/privkey.pem;

    location / {{
        return 404;
    }}
{locs}
}}
"""


def cert_rotation_plan(domains: list[str], days: int = 60) -> dict[str, Any]:
    """Deterministic checklist for certificate / domain rotation."""
    return {
        "interval_days": days,
        "domains": list(domains),
        "steps": [
            "Issue new cert (ACME or internal CA) for next domain",
            "Stage redirector with new server_name + cert paths",
            "Update SQUIDC5_PUBLIC_HOST / profile URIs",
            "Regenerate implants against new host",
            "Retire old domain after drain window",
            "Audit listeners and active profile after cutover",
        ],
        "notes": "Never commit private keys. Store certs outside the git tree.",
    }


def wildcard_cert_plan(domains: list[str], days: int = 60) -> dict[str, Any]:
    """ACME DNS-01 wildcard plan for multi-protocol OAST (*.zone) + apex."""
    names: list[str] = []
    for d in domains:
        d = d.strip().lstrip("*.")
        if not d:
            continue
        names.append(d)
        names.append(f"*.{d}")
    # de-dupe preserve order
    seen: set[str] = set()
    ordered = []
    for n in names:
        if n not in seen:
            seen.add(n)
            ordered.append(n)
    certbot_flags = " ".join(f"-d {n}" for n in ordered)
    return {
        "interval_days": days,
        "domains": ordered,
        "challenge": "dns-01",
        "steps": [
            "Delegate NS for OAST/C2 zone to this host (or provider API for DNS-01)",
            f"Issue wildcard via ACME DNS-01: certbot certonly --manual --preferred-challenges dns {certbot_flags}",
            "Or use DNS provider plugin (cloudflare, route53, etc.) for automation",
            "Install fullchain.pem + privkey.pem on redirector / SQUIDC5_TLS_* paths",
            "Point HTTP OAST + beacon Hostnames at apex; DNS OAST uses *.zone tokens",
            "Correlate hits by oast token across http/dns/smtp in GET /api/v1/oast/interactions",
            "Rotate before expiry; never commit private keys",
        ],
        "correlation": {
            "http": "Host or path /o/{token}",
            "dns": "{token}.zone query (any RR type logged)",
            "smtp": "{token}@zone RCPT",
        },
        "notes": "Wildcard requires DNS-01. Lab script: scripts/acme_lab_renew.sh with -d '*.zone' -d zone.",
    }

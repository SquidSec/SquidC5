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

# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | Yes (current alpha line) |
| < 0.1   | No |

After **1.0.0**, only the latest minor of the current major is supported with security fixes.
See CHANGELOG for OPSEC-relevant release notes.

## Responsible Disclosure

If you discover a security vulnerability in SquidC5:

1. **Do not** open a public GitHub issue
2. Contact the maintainers privately via GitHub Security Advisories on this repository
3. Include steps to reproduce, impact assessment, and suggested remediation if available
4. Allow reasonable time for a fix before public disclosure

## Scope Notes

SquidC5 is a C2 framework for **authorized** testing. Issues related to:

- Authentication/token bypass
- MCP tool allow-list bypass
- Admin AI prompt-injection escapes
- Policy engine bypass
- Audit log tampering

are considered high priority.

## Safe Harbor

We will not pursue legal action against researchers who:

- Act in good faith
- Avoid privacy violations and data destruction
- Do not exploit findings beyond what is needed to demonstrate the issue
- Report promptly and keep findings confidential until fixed

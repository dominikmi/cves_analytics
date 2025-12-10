# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in this project, please report it responsibly:

1. **Do NOT open a public GitHub issue**
2. Use [GitHub Security Advisories](https://github.com/dominikmi/cves_analytics/security/advisories/new) to report privately
3. Or email: [your-email@example.com]

## What to Include

- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

## Response Timeline

- **Acknowledgment:** Within 48 hours
- **Initial assessment:** Within 1 week
- **Fix timeline:** Depends on severity

## Supported Versions

| Version | Supported |
|---------|-----------|
| latest (main branch) | ✅ |

## Security Best Practices

When using this tool:

1. **Never commit `.env` files** - they contain API keys
2. **Keep dependencies updated** - run `uv sync` regularly
3. **Review scan results** - don't share reports containing sensitive CVE data about your infrastructure

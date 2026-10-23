# SelfHost SecCheck

[![CI](https://github.com/chrizzo84/selfhost-seccheck/actions/workflows/ci.yml/badge.svg)](https://github.com/chrizzo84/selfhost-seccheck/actions/workflows/ci.yml)
[![License: AGPL v3](https://img.shields.io/badge/License-AGPL_v3-blue.svg)](LICENSE)

**English** · [Deutsch](README.de.md)

Security checks for self-hosted software. Enter the URL of your instance, pick the application (or let
SecCheck detect it) and get a grade from **A+ to F**. The scanner checks the TLS configuration, certificate,
security headers, exposed files, versions, known vulnerabilities and application-specific weaknesses, such
as a Nextcloud data directory in the web root or a setup wizard that was never completed.

All checks are **read-only** (GET/TRACE requests, TLS handshakes, DNS lookups) and run **without logging in**.
Only scan instances you operate or are explicitly allowed to test.

## Features

- **Report** with recommendations, export as JSON and Markdown
- **Config snippets** for nginx, Apache, Caddy and Traefik that fix the findings of a scan
- **App detection** from the URL
- **Dashboard** of all scanned instances with grade and trend
- **History** per instance with a score chart and a comparison to the previous scan (new / resolved)
- **Scheduled scans** (every 6 hours, daily, weekly) with **notifications** via ntfy, Gotify, Pushover or
  email when new problems appear or the grade drops
- **Accepted risks**: accept a finding per instance; it stays visible but no longer counts towards the grade
- **Known vulnerabilities** for the detected version from GitHub security advisories
- **Full cipher analysis** with sslyze (SSLv2/v3, RC4, 3DES, …)
- **English and German** interface and reports

## Supported applications

| Application | App-specific checks |
|---|---|
| **Nextcloud** | supported release branch (endoflife.date), known vulnerabilities, unfinished installation, data directory in the web root, `config.php`/PHP source readable, Nextcloud headers, CalDAV/CardDAV redirects, open self-registration |
| **Gitea / Forgejo** | version, known vulnerabilities (Gitea), open registration, public user list |
| **Vaultwarden** | version, known vulnerabilities, admin panel reachable from the internet |
| **Jellyfin** | version, known vulnerabilities, unfinished setup wizard, public user list |
| **Home Assistant** | open onboarding, `trusted_networks`; never touches the authenticated API, because Home Assistant bans IPs after unauthenticated requests |
| **Immich** | version, admin account not yet created |
| **Paperless-ngx** | available updates, unfinished first setup, open registration, API without login (auto-login) |
| **Portainer CE** | version (aware of parallel LTS/STS branches), admin account not yet created |
| **Grafana** | version and support status, open sign-up, anonymous access, public metrics |
| **AdGuard Home** | unfinished setup wizard, web UI without login |
| **Uptime Kuma** | unfinished database setup, disabled authentication |
| **Any other web app** | the generic checks below |

Generic checks for every application:

| Category | Checks |
|---|---|
| TLS & certificate | HTTPS available, trusted chain, host name, expiry, key strength, signature algorithm, SSLv2/v3 and TLS 1.0/1.1 disabled, TLS 1.3, no weak ciphers, forward secrecy |
| HTTP & transport | HTTP→HTTPS redirect, HSTS, cookie flags, CORS (origin reflection), TRACE |
| Security headers | CSP, clickjacking protection, nosniff, Referrer-Policy, Permissions-Policy, version disclosure |
| Exposed files | `.git`, `.env`, `.htpasswd`, database dumps, backups, `server-status`, `phpinfo`, directory listing |
| DNS / best practices | CAA record, `security.txt` |

Missing your favourite app? Adding one is a single file, see [CONTRIBUTING.md](CONTRIBUTING.md).

## Quick start

### Docker (recommended)

```bash
git clone https://github.com/chrizzo84/selfhost-seccheck.git
cd selfhost-seccheck
docker compose up -d --build        # http://127.0.0.1:8000, data in ./data
```

The compose file binds to `127.0.0.1` only. See [Running it safely](#running-it-safely) before exposing it.

### Without Docker

Requires Python 3.12 or newer.

```bash
./start.sh                  # creates .venv, installs dependencies, runs in the background
./stop.sh
```

`start.sh` picks the next free port if 8000 is taken and prints the URL. Options: `PORT=9000 ./start.sh`
(fixed port), `HOST=0.0.0.0 ./start.sh` (reachable from your network), `./start.sh -f` (foreground).
The log is in `.run/seccheck.log`.

Or by hand:

```bash
python3 -m venv .venv
.venv/bin/pip install -e '.[full]'         # "full" adds sslyze; drop it if it does not install
.venv/bin/python -m seccheck serve         # http://127.0.0.1:8000
```

### Command line

Useful for cron jobs or CI. The exit code is 1 for grade D or F; CLI scans are not stored in the history.

```bash
seccheck scan nextcloud https://cloud.example.com
seccheck --lang de scan nextcloud https://cloud.example.com --json
seccheck list                              # all applications and checks
```

## Grading

Every check has a severity. A failed check deducts points from 100, a warning half of that:

| Severity | critical | high | medium | low | info |
|---|---|---|---|---|---|
| Deduction | 40 | 20 | 8 | 3 | 0 |

Grades: A+ ≥ 97, A ≥ 90, B ≥ 80, C ≥ 65, D ≥ 50, otherwise F. As with SSL Labs, single serious findings cap the
grade: a failed critical check (expired certificate, readable data directory, …) always means F, a failed
high one at most C. Accepted risks do not count. The logic is in [seccheck/core/scoring.py](seccheck/core/scoring.py).

## Configuration

| Variable | Default | Meaning |
|---|---|---|
| `SECCHECK_LANG` | `en` | Default language (`en`, `de`) when the client does not ask for one; also used by the CLI |
| `SECCHECK_DATA_DIR` | `./data` | Directory of the SQLite database (history, instances, settings) |
| `SECCHECK_SCHEDULER` | `1` | `0` disables scheduled scans |
| `SECCHECK_BLOCK_PRIVATE` | `0` | `1` refuses targets in private networks. **Set it whenever the scanner is reachable by others** (SSRF) |
| `SECCHECK_CA_BUNDLE` | certifi | CA bundle for chain validation, e.g. including your internal CA |
| `SECCHECK_CHECK_TIMEOUT` | `30` | Timeout per check in seconds |
| `SECCHECK_HTTP_TIMEOUT` | `10` | Timeout per HTTP request in seconds |
| `SECCHECK_CONCURRENCY` | `8` | Checks running in parallel |
| `GITHUB_TOKEN` | – | Raises the GitHub rate limit (60/h without a token) for version and advisory lookups |

Notifications are configured in the web interface under **Settings**, including the language of scheduled
scans. Credentials (tokens, user keys, SMTP password) are stored in the SQLite file and never sent back to
the browser. Scheduled scans run inside the web server process, so the server has to keep running.

## Running it safely

- **The web interface has no login.** Anyone who can reach it sees the history and can change settings. Run it
  locally or behind a reverse proxy with authentication (e.g. Authelia, Authentik, basic auth).
- **Do not offer it as a public scanner** without `SECCHECK_BLOCK_PRIVATE=1`, otherwise it can be used to probe
  your internal network. Even then it has no rate limiting and no proof that a user owns the scanned domain.
- Some security tools (e.g. fail2ban rules against `.env`/`.git` probing) may ban the scanner. Allow-list its IP
  if needed; it identifies itself with the user agent `SelfHostSecCheck/<version>`.

## Limitations

- The full cipher analysis needs sslyze (`.[full]`, included in the Docker image). Without it the scanner uses the
  local OpenSSL, which often cannot test RC4, DES or 3DES any more; those classes then show up as "not testable
  locally".
- Known vulnerabilities are only found for projects that publish GitHub security advisories (Nextcloud, Gitea,
  Vaultwarden, Jellyfin). Forgejo, Home Assistant and the newer profiles have no advisory check yet.
- Results are an automated outside-in assessment. They do not replace a penetration test.

## Contributing

Contributions are welcome: new applications, new checks, translations and bug reports. Start with
[CONTRIBUTING.md](CONTRIBUTING.md). Security issues in SecCheck itself: see [SECURITY.md](SECURITY.md).

## License

[GNU Affero General Public License v3.0 or later](LICENSE). If you run a modified version as a network
service, you have to offer its source code to its users.

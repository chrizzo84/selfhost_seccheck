# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses [semantic versioning](https://semver.org/).

## [Unreleased]

### Added

- Vulnerability feed: the latest CVEs for the software you run from OSV, GitHub security advisories and the NVD,
  matched against the versions detected by scans, with CISA KEV and EPSS, a watchlist for software that cannot be
  scanned and alerts for new vulnerabilities and newly exploited ones.
- Docker workflow that builds, smoke-tests and pushes the image to GHCR on every push to `main` (`edge`,
  `sha-<commit>`) and on release tags (`latest`, `x.y.z`, `x.y`), for amd64 and arm64, with SBOM and signed
  build provenance.

## [0.1.0] - 2026-10-23

First public release.

### Added

- Web interface with live scan results, grade A+ to F, category scores, JSON and Markdown export.
- Generic checks: TLS and certificate (incl. full cipher analysis with optional sslyze), HTTP transport,
  security headers, exposed files, DNS (CAA) and `security.txt`.
- Application profiles with app-specific checks: Nextcloud, Gitea/Forgejo, Vaultwarden, Jellyfin,
  Home Assistant, Immich, Paperless-ngx, Portainer CE, Grafana, AdGuard Home, Uptime Kuma.
- Version and support status (GitHub releases, endoflife.date) and known vulnerabilities from GitHub security
  advisories (Nextcloud, Gitea, Vaultwarden, Jellyfin).
- Automatic application detection.
- Config snippets for nginx, Apache, Caddy and Traefik matching the findings of a scan.
- Dashboard, per-instance history with score chart and comparison to the previous scan.
- Scheduled scans with notifications via ntfy, Gotify, Pushover and email.
- Accepted risks per instance.
- English and German interface, reports and notifications.
- Command line interface (`seccheck scan`, `seccheck list`), Docker image, `start.sh`/`stop.sh`.

### Fixed

- The advisory check now reads all GitHub security advisories of a project. GitHub paginates them with cursors, so
  only the newest 100 were checked before (relevant for Nextcloud).

[Unreleased]: https://github.com/chrizzo84/selfhost-seccheck/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/chrizzo84/selfhost-seccheck/releases/tag/v0.1.0

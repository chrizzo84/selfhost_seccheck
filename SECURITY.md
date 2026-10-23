# Security policy

## Reporting a vulnerability in SecCheck

Please **do not open a public issue** for security problems in SecCheck itself.

Report them privately via GitHub: **Security → Report a vulnerability** on
<https://github.com/chrizzo84/selfhost-seccheck/security/advisories/new>.

Please include the affected version or commit, steps to reproduce and the impact you see. You will get an answer
as soon as possible; once a fix is available, the advisory is published and you are credited if you wish.

## Supported versions

Security fixes are made for the latest release. Please update before reporting.

## Scope

In scope are vulnerabilities in SecCheck's own code and default configuration, for example:

- ways to make the scanner send requests it should not send (e.g. bypassing `SECCHECK_BLOCK_PRIVATE` or an app
  profile's `no_probe_paths`)
- checks that change state on, or trigger bans or lockouts at, the scanned target
- injection or XSS in the web interface, leaking stored notification credentials

Out of scope:

- The web interface having no login of its own. This is documented; run it locally or behind an authenticating
  reverse proxy.
- Findings that SecCheck reports about *other* software. Report those to the respective project.

## Responsible use

SecCheck is meant for checking instances you operate or are explicitly authorized to test. Do not use it against
third-party systems without permission.

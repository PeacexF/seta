# Seta

**Posture monitoring as code for your public infrastructure.**

Declare what your domains should look like. Run Seta from your terminal, your CI, or a small server. Get told only when something changes.

[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](./LICENSE)
![Status](https://img.shields.io/badge/status-early%20development-orange)

> [!WARNING]
> Seta is in early development and not usable yet. This README describes the tool as planned for the first releases (v0.1–v0.3)

---

## Why Seta

Public infrastructure breaks quietly:

- Someone adds a new SaaS sender, SPF crosses the 10-lookup limit, and your mail starts landing in spam.
- DMARC sits at `p=none` for years because nobody owns it.
- The certificate on a secondary mail server expires on a Sunday.
- A CNAME still points at a deleted cloud resource, waiting to be taken over.

Tools that detect each of these already exist, but they're one-shot and noisy. Seta is built around a different question: **what changed since last time, and does anyone need to act?**

- **Diff-first.** Seta remembers previous runs and alerts only on new, regressed, and resolved findings.
- **Runs anywhere.** One static binary works as a CLI, a CI gate, or a long-running daemon.
- **Pluggable.** Checks, notifiers, and output formats are extension points. External plugins can be written in any language.
- **Config as code.** One YAML file that lives in your repo next to everything else.
- **Actionable.** Every finding comes with evidence and a concrete fix.
- **Safe by default.** Passive checks only, unless you explicitly enable active ones.

## Quick look

```console
$ seta scan example.com

example.com
  HIGH      email.spf.lookup_limit     SPF requires 13 DNS lookups (limit is 10)
            fix: flatten or remove includes; unused senders: include:mailgun.org
  MEDIUM    email.dmarc.policy_none    DMARC policy is p=none, spoofed mail is not rejected
            fix: move to p=quarantine after reviewing aggregate reports
  LOW       email.tlsrpt.missing       No TLS-RPT record at _smtp._tls.example.com
            fix: add TXT "v=TLSRPTv1; rua=mailto:tlsrpt@example.com"

3 findings (1 high, 1 medium, 1 low) · 21 checks · 1.8s
```

*(Illustrative output; the final format may differ.)*

## Install

> Packages will be published with the first release.

```sh
# Go
go install github.com/PeacexF/seta/cmd/seta@latest

# Homebrew
brew install peacexf/tap/seta

# Docker
docker run --rm ghcr.io/peacexf/seta scan example.com
```

Prebuilt binaries for Linux, macOS, and Windows (amd64/arm64) will be available on the [Releases](https://github.com/PeacexF/seta/releases) page.

## Usage

### One-off scan

```sh
seta scan example.com                  # passive checks only
seta scan example.com --active         # also connect to mail servers (STARTTLS)
seta scan example.com --only 'email.spf.*'
seta scan example.com --format json
seta checks explain email.spf.lookup_limit
```

### Config file

Generate a starter config with `seta init`, or write one:

```yaml
# seta.yaml
version: 1

targets:
  - domain: example.com
    active: true
    hosts: [example.com, www.example.com, "api.example.com:8443"]
    email:
      dkim_selectors: ["google", "s1"]

suppressions:
  - check: email.mtasts.missing
    target: legacy.example.com
    reason: "Legacy domain, receives no mail"
    expires: 2027-01-01

notify:
  - type: telegram
    bot_token: ${SETA_TG_TOKEN}
    chat_id: "-1001234567890"
    on: [new, regressed]
    min_severity: medium
  - type: discord
    webhook: ${SETA_DISCORD_WEBHOOK}
    on: [new, regressed, resolved]

schedule: "0 */6 * * *"
```

```sh
seta config validate
seta run -c seta.yaml
```

Secrets are read from environment variables. An unset variable is a validation error, never a silent empty string.

### In CI

Fail the build only on *new* problems, and show findings in GitHub's Code Scanning tab:

```yaml
# .github/workflows/seta.yml
name: seta
on: [pull_request, schedule]

jobs:
  seta:
    runs-on: ubuntu-latest
    permissions:
      security-events: write
    steps:
      - uses: actions/checkout@v4
      - uses: PeacexF/seta-action@v1
        with:
          config: seta.yaml
          baseline: .seta-baseline.json
          fail-on: high
```

Create the baseline once with `seta baseline -o .seta-baseline.json` and commit it.

| Exit code | Meaning |
|---|---|
| `0` | No findings at or above `--fail-on` |
| `1` | Findings at or above `--fail-on` |
| `2` | Usage or config error |
| `3` | Check errors occurred and `--strict` was set |

> [!NOTE]
> GitHub-hosted runners (and most cloud networks) block outbound port 25, so active STARTTLS checks will report *"port 25 unreachable"* as a check error there. Seta never turns that into a false finding. Run active mail checks from a VPS with daemon mode.

### As a daemon

```sh
seta daemon -c seta.yaml
```

Or with Docker Compose:

```yaml
services:
  seta:
    image: ghcr.io/peacexf/seta:latest
    command: daemon -c /etc/seta/seta.yaml
    volumes:
      - ./seta.yaml:/etc/seta/seta.yaml:ro
      - seta-state:/var/lib/seta
    environment:
      SETA_TG_TOKEN: ${SETA_TG_TOKEN}
    restart: unless-stopped

volumes:
  seta-state:
```

The daemon stores state in SQLite and sends one digest per run, and only when something changed. A finding has to be gone for two consecutive runs before it counts as resolved, so a flaky DNS response won't send you a "fixed" message followed by a "broken" one.

Test your notifiers with `seta notify test`.

## Checks

Run `seta checks list` for the full catalog. Checks marked *(active)* probe your servers and only run when enabled.

| Area | What Seta verifies |
|---|---|
| MX | Records exist, hosts resolve, forward-confirmed reverse DNS, match an expected set |
| SPF | Exactly one valid record, 10-lookup limit (resolved recursively), void lookups, no `+all` |
| DMARC | Record exists and parses, policy stronger than `p=none`, reporting configured and authorized |
| DKIM | Configured selectors publish keys, RSA keys ≥ 2048 bits |
| MTA-STS | TXT record and HTTPS policy present, valid, and matching real MX hosts |
| TLS-RPT | Reporting record present |
| STARTTLS *(active)* | Every MX supports STARTTLS with a valid, non-expiring certificate |
| DNSBL | Mail server IPs not listed on blocklists |
| TLS | Certificates trusted, matching the host name and not about to expire; TLS 1.2+ supported; no TLS 1.0/1.1 or weak ciphers *(active)* |
| HTTP | HTTP redirects to HTTPS, HSTS (and preload readiness), CSP, frame protection, `nosniff`, Referrer-Policy; no exposed `/.git` or `/.env` *(active)* |
| DNS | DNSSEC present and valid, CAA records, dangling CNAMEs and subdomain takeover; no open zone transfers or open resolvers *(active)* |

TLS and HTTP checks look at the domain and `www.` unless a target lists its own `hosts:` (and `urls:`).

Planned modules: **domain** (registration expiry via RDAP), **exposure** (open ports against an allowlist), and **ct** (new certificates in Certificate Transparency logs)

## Output formats

| Format | Use it for |
|---|---|
| `table` | Reading in a terminal (default) |
| `json` | Scripting; versioned, stable schema |
| `sarif` | GitHub / GitLab code scanning |
| `markdown` | PR comments and audit reports |

## Notifications

Telegram, Discord, Slack, email (SMTP), and generic webhooks (with optional HMAC signatures). Messages are split automatically to fit each platform's limits, rate limits are respected, and one failing notifier never blocks the others.

## Plugins

Any executable named `seta-plugin-<name>` on your `PATH` can add checks. It speaks a small JSON protocol over stdin/stdout, so plugins can be written in Go, Python, Bash, or anything else:

```console
$ seta-plugin-example describe
{"protocol": 1, "name": "example", "version": "0.1.0", "checks": [...]}

$ echo '{"protocol":1,"check":"example.foo.bar","target":{...}}' | seta-plugin-example run
{"findings": [...], "error": null}
```

Plugins can also live in a `plugins_dir` set in `seta.yaml`, and get settings from its `plugins:` section. `seta plugins list` shows what Seta found; `--no-plugins` turns them off. A Go SDK is in [`sdk/`](./sdk), with example plugins in Go, Python, and Bash in [`examples/plugins/`](./examples/plugins).

## Responsible use

Seta detects misconfiguration. It never exploits it: no relay tests, no takeover attempts, no automatic expansion of scope. Passive checks use public DNS data and make the requests any visitor makes (one TLS handshake and page load per host). Active checks probe your services (old TLS versions, zone transfers, sensitive paths) only when you enable them per target.

**Only scan infrastructure you own or are authorized to test.**

## Contributing

Seta is at an early stage, and ideas, bug reports, and discussion are very welcome. Contribution guidelines, including a "write your first check" walkthrough, will live in [CONTRIBUTING.md](./CONTRIBUTING.md).

To report a security issue in Seta itself, please see [SECURITY.md](./SECURITY.md)

## License

Seta is licensed under the [Apache License 2.0](./LICENSE).

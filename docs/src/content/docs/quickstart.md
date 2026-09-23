---
title: Quickstart
description: Install Seta and scan a domain in under two minutes.
---

## Install

Download a binary for Linux, macOS or Windows from the [releases page](https://github.com/PeacexF/seta/releases), or:

```sh
# Go 1.26+
go install github.com/PeacexF/seta/cmd/seta@latest

# Docker
docker run --rm ghcr.io/peacexf/seta scan example.com
```

## Scan a domain

```sh
seta scan example.com
```

Seta runs every passive email check and groups findings by domain, most severe first:

```console
example.com
  HIGH      email.dkim.weak_key       DKIM key for selector k1 is 1024-bit RSA (selector:k1)
            bits: 1024
            fix: Generate a 2048-bit key with your mail provider, publish it under a new selector, ...
  LOW       email.mtasts.missing      No MTA-STS policy
            queried: _mta-sts.example.com
            fix: Serve a policy at https://mta-sts.<domain>/.well-known/mta-sts.txt ...

3 active checks not run (e.g. STARTTLS); pass --active to connect to mail servers.

2 findings (1 high, 1 low) · 21 checks · 1.2s
```

Each finding has a check ID, the evidence Seta saw, and a fix. For the full explanation of a check:

```sh
seta checks explain email.dkim.weak_key
seta checks list
```

### Check errors are not findings

When Seta can't reach a verdict (a DNS server fails, a mail server is unreachable), it reports a **check error**, never a finding. A flaky network can't make Seta claim your records are missing.

## Common options

```sh
# Several domains at once
seta scan example.com example.org

# Only some checks (globs; "!" excludes)
seta scan --only 'email.spf.*,email.dmarc.*' example.com
seta scan --only '!email.dnsbl.*' example.com

# Check your real DKIM selectors (the s= tag in your mail's DKIM-Signature header)
seta scan --dkim-selector google,s1 example.com

# Active checks: connect to your MX hosts on port 25 for STARTTLS and certificates
seta scan --active example.com

# Machine-readable output (versioned schema, "schema": 1)
seta scan --format json --output report.json example.com
```

:::note[Port 25]
Most home ISPs, cloud providers and CI runners block outbound port 25, so `--active` checks report *could not reach any MX host on port 25* as a check error there. Run them from a server that allows outbound SMTP.
:::

### DKIM without configured selectors

DKIM selectors can't be discovered from DNS. Without `--dkim-selector`, Seta tries a few common names (`google`, `selector1`, `selector2`, `default`, `k1`, `s1`, `mail`). Finding none there is reported as **info**: it doesn't mean the domain lacks DKIM.

### Spamhaus

Spamhaus refuses queries relayed through public resolvers. Seta uses blocklists that allow free queries by default, and adds Spamhaus ZEN when you set a free [Data Query Service](https://www.spamhaus.com/free-trial/sign-up-for-a-free-data-query-service-account/) key:

```sh
export SETA_SPAMHAUS_DQS_KEY=your-key
```

## Exit codes

| Code | Meaning |
|---|---|
| `0` | The scan completed; by default `scan` exits 0 whether or not there were findings |
| `1` | Findings at or above `--fail-on <severity>` |
| `2` | Usage error, or no trustworthy DNS resolver |
| `3` | Some checks could not complete and `--strict` was set |

---
title: DNS resolvers
description: How Seta checks that its DNS answers can be trusted, and how to use DNS over HTTPS or TLS.
---

Every email check depends on DNS. A resolver that drops records would make Seta report records that exist as missing, so before each scan Seta checks the resolver: it looks up the A, MX and TXT records of a few large mail providers, which have existed for well over a decade.

## When the check fails

Some networks (captive portals, filtering ISPs, some VPNs and security appliances) answer A queries but return empty answers for everything else. Seta reports this and stops:

```console
DNS check failed: the resolver (192.168.1.1:53) is returning incomplete answers:
  - MX lookups for gmail.com, outlook.com and yahoo.com returned no records
  - TXT lookups for gmail.com, outlook.com and yahoo.com returned no records
Something on this network is probably intercepting or filtering DNS. Scanning through it
would report records that exist as missing.
```

In a terminal, Seta offers to continue over encrypted DNS, which on-path devices can't rewrite. It tries DNS over HTTPS first and falls back to DNS over TLS. In CI and other non-interactive runs it never switches on its own: it exits with code 2 so you can choose.

## Choosing a resolver

```sh
seta scan --resolver doh example.com     # DNS over HTTPS via 1.1.1.1 and 9.9.9.9
seta scan --resolver dot example.com     # DNS over TLS via 1.1.1.1 and 9.9.9.9
seta scan --resolver 9.9.9.9 example.com # a specific plain DNS server
seta scan --resolver https://dns.example/dns-query,tls://dns.example example.com
```

The default, `system`, uses the servers in `/etc/resolv.conf` (on Windows, 1.1.1.1 and 9.9.9.9).

With `doh` or `dot`, the domains you scan are sent to Cloudflare and Quad9.

`--skip-dns-check` scans without the check. Use it only for resolvers that can't answer public names, such as an isolated test environment.

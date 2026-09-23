# Zone fixtures

RFC 1035 zone files loaded by `dnsx.LoadFakeDir` for offline tests. Each
file's origin is its name without `.zone`, so `mx-ok.test.zone` holds the
`mx-ok.test` zone.

Use the reserved `.test` TLD (RFC 2606) for fixture domains and the
documentation ranges (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`,
`2001:db8::/32`) for addresses. Add a comment at the top of each file saying
what posture it represents.

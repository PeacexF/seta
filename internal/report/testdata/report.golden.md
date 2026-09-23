## Seta report

4 findings (1 critical, 2 high, 1 low) · 1 suppressed · 1 in baseline · 1 check error · 6 checks on 3 targets · 1.23s

### broken.test

| Severity | Check | Finding |
|---|---|---|
| **CRITICAL** | `email.spf.permissive_all` | SPF record allows any sender |
| **HIGH** | `email.mx.missing` | No MX records |
| LOW | `email.mx.fcrdns` | MX host lacks forward-confirmed reverse DNS (mx2.broken.test) |
| **HIGH** | `email.spf.syntax` | SPF record &lt;b&gt;is&lt;/b&gt; \[invalid\](https://evil.test) |

<details><summary>Evidence and fixes</summary>

**`email.spf.permissive_all`** SPF record allows any sender
- record: `v=spf1 +all`
- **Fix:** Replace +all with -all or ~all.

**`email.mx.missing`** No MX records
- implicit\_mx: `192.0.2.80`
- mx\_records: `none`
- **Fix:** Publish MX records.

**`email.mx.fcrdns`** MX host lacks forward-confirmed reverse DNS (mx2.broken.test)

**`email.spf.syntax`** SPF record &lt;b&gt;is&lt;/b&gt; \[invalid\](https://evil.test)
- record: `` v=spf1 a|b `x` ``

</details>

### clean.test

✅ No new findings (1 suppressed or in baseline).

### flaky.test

No findings, but 1 check could not complete.

### Suppressed

| Target | Check | Reason | Expires |
|---|---|---|---|
| clean.test | `email.mtasts.missing` | Receives no mail \| legacy | 2027-01-01 |

### Check errors

These checks could not reach a verdict; they are not findings.

| Target | Check | Error |
|---|---|---|
| flaky.test | `email.mx.missing` | lookup MX flaky.test: server responded SERVFAIL |

> Active checks were not run.

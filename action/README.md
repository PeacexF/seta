# Seta GitHub Action

Runs `seta run` on your config, shows the report in the job summary, uploads findings to
code scanning, and fails the job on findings at or above `fail-on`.

```yaml
# .github/workflows/seta.yml
name: seta
on:
  pull_request:
  push:
    branches: [main]
  schedule:
    - cron: "0 6 * * *" # DNS changes outside of PRs too

jobs:
  seta:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write # SARIF upload
    steps:
      - uses: actions/checkout@v7
      - uses: PeacexF/seta/action@v0.2.0
        with:
          config: seta.yaml
          baseline: .seta-baseline.json # optional: fail only on new findings
          fail-on: high
```

Create the baseline with `seta baseline` and commit it. Code scanning links each finding to
the line of `seta.yaml` that declares its domain.

GitHub-hosted runners block outbound port 25, so active STARTTLS checks report check
errors there, not findings. Run them from a server instead.

| Input | Default | |
|---|---|---|
| `version` | `latest` | Seta release to install |
| `config` | `seta.yaml` | Config file |
| `baseline` | | Baseline file |
| `fail-on` | `low` | `info`, `low`, `medium`, `high`, `critical` or `none` |
| `args` | | Extra `seta run` arguments |
| `upload-sarif` | `true` | Upload to code scanning |
| `sarif-file` | `seta.sarif` | SARIF output path |
| `category` | `seta` | Code scanning category |
| `job-summary` | `true` | Add the report to the job summary |

Output `exit-code` is the exit code of `seta run`.

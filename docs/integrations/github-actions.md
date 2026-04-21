# GitHub Actions

Runs on every PR + push to the default branch, caches the SQLite
store, uploads SARIF to the Security tab, fails the check on blocking
CVEs.

```yaml
# .github/workflows/packguard.yml

name: packguard

on:
  pull_request:
  push:
    branches: [main]
  # Nightly intel refresh — keeps OSV + GHSA cache fresh without
  # slowing PR runs. Omit if you don't want scheduled runs.
  schedule:
    - cron: "0 6 * * *"

permissions:
  contents: read
  security-events: write   # required for upload-sarif
  pull-requests: read

jobs:
  packguard:
    name: packguard · scan + audit
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: install packguard
        run: |
          curl -fsSL https://raw.githubusercontent.com/nalo/packguard/main/install.sh | sh
          echo "$HOME/.local/bin" >> "$GITHUB_PATH"

      - name: restore cache
        uses: actions/cache@v4
        with:
          # Store + intel both live under ~/.packguard — one cache
          # entry covers both. Hash over lockfiles so we only re-scan
          # when deps actually change.
          path: ~/.packguard
          key: packguard-${{ runner.os }}-${{ hashFiles('**/package-lock.json', '**/pnpm-lock.yaml', '**/yarn.lock', '**/poetry.lock', '**/uv.lock', '**/requirements*.txt') }}
          restore-keys: |
            packguard-${{ runner.os }}-

      - name: scan
        run: packguard scan .

      - name: sync intel (scheduled only)
        if: github.event_name == 'schedule' || github.event_name == 'push'
        run: packguard sync

      - name: report (SARIF + fail-on-violation)
        run: packguard report . --format sarif --fail-on-violation > packguard.sarif

      - name: upload SARIF to Security tab
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: packguard.sarif
          category: packguard
```

## What each piece does

| Block | Why |
|---|---|
| `install.sh` pipe | ~46 MB binary, no Docker, no node. Dropping it in `~/.local/bin` keeps the step cache-agnostic across runners. |
| `actions/cache@v4` | Restores `~/.packguard/` when lockfiles are unchanged. Cold run ~30-90s; warm run ~2s. |
| `packguard sync` on schedule | Nightly intel refresh is enough in 99% of cases — fresh OSV/GHSA every 24h. PR runs reuse yesterday's cache. |
| `--fail-on-violation` | Exit 2 on blocking CVE/malware — the workflow turns red + blocks merges if branch protection requires the check. |
| `upload-sarif` with `if: always()` | Upload even when the audit fails, so the Security tab reflects the actual state, not the passing state. |

## Container-based variant

If you'd rather run inside the published image (same result, slightly
heavier cold start):

```yaml
jobs:
  packguard:
    runs-on: ubuntu-latest
    container:
      image: ghcr.io/nalo/packguard:latest
    steps:
      - uses: actions/checkout@v4
      - run: packguard scan .
      - run: packguard sync
      - run: packguard report . --format sarif --fail-on-violation > packguard.sarif
      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: packguard.sarif
          category: packguard
```

## Matrix over a monorepo

If the repo hosts multiple workspaces, scan them in parallel and
aggregate per-workspace SARIF:

```yaml
strategy:
  fail-fast: false
  matrix:
    workspace: [app-web, app-api, worker-ingest]
steps:
  - uses: actions/checkout@v4
  - run: packguard scan ./${{ matrix.workspace }}
  - run: packguard report ./${{ matrix.workspace }} --format sarif --fail-on-violation > packguard.sarif
  - uses: github/codeql-action/upload-sarif@v3
    with:
      sarif_file: packguard.sarif
      category: packguard/${{ matrix.workspace }}
```

Each `category:` gets its own row in the Security tab, so you can spot
which workspace introduced the regression without sifting through a
merged report.

# CI / IDE integrations

Copy-paste recipes that wire `packguard` into common pipelines. Each
snippet is **generic** — drop it into any repo, adjust the scan path
if you don't run PackGuard from the repo root, commit, done.

| Recipe | File | Gist |
|---|---|---|
| GitLab CI | [`gitlab-ci.md`](gitlab-ci.md) | Cached SQLite store, SARIF export, fail-on-critical CVE |
| GitHub Actions | [`github-actions.md`](github-actions.md) | Same, with `upload-sarif` for the Security tab |
| pre-commit | [`pre-commit.md`](pre-commit.md) | Block commits that introduce a critical CVE |
| VSCode task | [`vscode-task.md`](vscode-task.md) | One-shot audit via the command palette |

## The three cross-cutting moves

Every recipe bakes in the same three decisions — pull the background
out of the individual recipes so they stay short.

### 1. Cache the SQLite store between runs

PackGuard persists every scan in `~/.packguard/store.db`. CI runs throw
that away by default, so every run redoes the full scan + sync ⇒ slow.
Cache it.

- **Cache key**: hash of the lockfiles the scanner reads —
  `package-lock.json`, `pnpm-lock.yaml`, `yarn.lock`, `poetry.lock`,
  `uv.lock`, `requirements*.txt`. When any of those change, the store
  needs a fresh scan; otherwise a cold run can cold-start from cache.
- **Cache path**: `~/.packguard/` (covers the store + the per-source
  intel cache).
- **Restore key fallback**: unhashed, so cold CI runs still get *some*
  cache and a stale scan is still better than a blank one.

GitLab + GitHub snippets below both wire this up.

### 2. Run `scan` before `sync` before `audit`

- `scan <path>` walks the repo's lockfiles and persists dependencies
  into the store. Network: only package registries (resolve + latest).
- `sync` pulls fresh OSV + GHSA + malware feeds. Separate step so the
  intel layer has its own cache key (time-based, usually daily).
- `audit <path> --fail-on critical --fail-on-malware` exits non-zero
  when the policy finds a blocking violation. This is the gate.

### 3. Export machine-readable results

- `report <path> --format sarif` dumps a SARIF v2.1 file. GitHub
  Actions ingests this natively into the Security tab; GitLab's
  SAST.gitlab-ci.yml template swallows it via `artifacts:reports:sast`.
- `report --format json` for anything else (custom dashboards,
  Slack notifiers, ...).

## Feature flags worth knowing in CI

- `--offline` on `scan` skips registry calls (useful when the cache is
  hot and you just want a policy re-evaluation).
- `--no-live-fallback` on `audit` skips OSV's live API — useful for
  air-gapped runners once Phase 3 lands.
- `--project <path>` on `report`/`audit`/`graph` scopes to a single
  workspace in a monorepo (Phase 7 feature — see the main README).

## Minimum-viable policy for any repo

```yaml
# .packguard.yml
defaults:
  # Three-axis offset (v0.2.0+). Non-positive integers;
  # missing keys default to 0.
  offset:
    major: 0         # latest major
    minor: -1        # one minor behind
    patch: 0         # latest patch (security fixes)
  allow_patch: true
  stability: stable
  min_age_days: 7
block:
  cve_severity: [high, critical]   # hard-fail on these
  malware: true
  typosquat: warn
```

Every recipe assumes this policy is committed at the repo root. Run
`packguard init` to generate it.

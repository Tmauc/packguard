# GitLab CI

Drop-in stage that runs on every pipeline + MR, caches the SQLite
store, exports a SARIF report, and fails the pipeline on blocking
CVEs.

```yaml
# .gitlab-ci.yml (excerpt)

stages:
  - security

packguard:
  stage: security
  image: ghcr.io/nalo/packguard:latest
  # Same container serves the scanner + the UI; we only need the CLI.
  cache:
    # The lockfile-hash key means: "re-scan only when deps actually
    # change". `$CI_COMMIT_REF_SLUG` keeps MR branches isolated.
    key:
      files:
        - package-lock.json
        - pnpm-lock.yaml
        - yarn.lock
        - poetry.lock
        - uv.lock
        - requirements.txt
    paths:
      - .packguard-cache/
    fallback_keys:
      - packguard-${CI_COMMIT_REF_SLUG}
      - packguard-main
  variables:
    # Pack everything into the project dir so GitLab's cache can carry
    # it across runs. `packguard` honours $HOME/.packguard/store.db.
    HOME: "$CI_PROJECT_DIR/.packguard-cache"
  before_script:
    - mkdir -p "$HOME/.packguard"
  script:
    - packguard scan .
    - packguard sync                                # refresh OSV + GHSA + malware intel
    - packguard report . --format sarif --fail-on-violation > packguard.sarif
  artifacts:
    when: always
    expire_in: 30 days
    paths:
      - packguard.sarif
    reports:
      # GitLab's SAST panel picks this up automatically.
      sast: packguard.sarif
  # MR-only gating. Remove this line to run on every commit.
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
    - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH
```

## What each piece does

| Block | Why |
|---|---|
| `image: ghcr.io/nalo/packguard:latest` | No runtime install; the image is ~46 MB. Pin to `:vX.Y.Z` for reproducibility once you've picked a version. |
| `cache.key.files` | Re-uses the SQLite store when lockfiles haven't changed. First MR run builds the cache (~30-90s depending on repo), subsequent runs hit it in ~2s. |
| `HOME: "$CI_PROJECT_DIR/.packguard-cache"` | GitLab can't cache paths outside the project dir. Redirecting `$HOME` keeps the cache payload inside what GitLab copies around. |
| `packguard sync` | Separate from `scan` because OSV/GHSA refresh is time-based, not lockfile-based. If you want tighter control, run it in a daily scheduled pipeline and skip it in MR pipelines. |
| `report --fail-on-violation` | Exit code 2 when the policy finds a blocking CVE/malware. GitLab shows a red pipeline. |
| `reports.sast` | Surfaces findings in GitLab's Security tab + MR widget, alongside whatever SAST the repo already runs. |

## Faster MR pipelines

If you want sub-30s MR feedback, split into two jobs:

- `packguard:scan` runs on every MR, uses `--offline` when the cache
  is hot (no registry calls, just re-evaluate the policy).
- `packguard:sync` runs on the default branch nightly, refreshing
  intel + committing nothing — the cache key propagates forward.

```yaml
packguard:sync-nightly:
  stage: security
  image: ghcr.io/nalo/packguard:latest
  rules:
    - if: $CI_PIPELINE_SOURCE == "schedule"
  script:
    - packguard sync
  cache:
    key: packguard-intel-nightly
    paths:
      - .packguard-cache/
    policy: push
```

## Blocking on a specific CVE

Swap `--fail-on` for `--fail-on-cve`:

```yaml
script:
  - packguard audit . --fail-on-cve CVE-2026-4800 --fail-on-malware
```

Useful when a vendor advisory just dropped and you want an explicit
hard gate for that exact CVE across every repo, independent of the
policy's severity rules.

# `content/live/` — Live demo snapshot

This folder holds the single source of truth for the `/live` page:
`snapshot.json`. The page imports it statically at build time — there is
no runtime fetch, no API call, no database. Updating the page means
re-running the scan and committing a new `snapshot.json`.

## How it regenerates

A GitHub Action (`.github/workflows/live-demo-snapshot.yml`) runs
weekly and on manual dispatch. It:

1. checks out `main`,
2. installs `packguard` via the one-liner pipe (same script end users run),
3. `packguard scan docs-site/`,
4. `packguard sync` (refresh OSV + GHSA + typosquat lists),
5. exports three JSON files — `report`, `audit --focus all`, `graph`,
6. runs `node docs-site/scripts/build-snapshot.mjs` to merge them,
7. commits `docs-site/content/live/snapshot.json` if it changed.

If any step fails, the workflow exits non-zero and **nothing is
committed** — the merge script refuses to write a partial snapshot.
Better a stale `/live` than a lying one.

## Running it by hand

From the repo root with `packguard` already on `$PATH`:

```bash
packguard scan docs-site/
packguard sync
packguard report docs-site/ --format json > /tmp/pg-report.json
packguard audit  docs-site/ --focus all --format json > /tmp/pg-audit.json
packguard graph  docs-site/ --format json > /tmp/pg-graph.json
node docs-site/scripts/build-snapshot.mjs \
  --report /tmp/pg-report.json \
  --audit  /tmp/pg-audit.json \
  --graph  /tmp/pg-graph.json \
  --out    docs-site/content/live/snapshot.json
```

Or trigger the CI run without leaving your terminal:

```bash
gh workflow run live-demo-snapshot.yml --repo Tmauc/packguard
```

## Why commit the JSON

- The `/live` page is static. No runtime dependency means the site
  survives an OSV outage, a registry hiccup, or any external failure.
- Git history of `snapshot.json` is itself a log of PackGuard's own
  dependency health over time.
- Regenerating is an explicit, reviewable PR — nobody ships a mystery
  snapshot.

## Shape

See `docs-site/types/snapshot.ts` for the full TypeScript shape of
`snapshot.json`. The build-snapshot script is the authoritative writer
— keep the type file in sync when the CLI's JSON output evolves.

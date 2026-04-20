# PackGuard

> Local, multi-repo, multi-ecosystem package version governance with a native offset
> policy engine. One Rust binary, three modes, no cloud.

PackGuard scans your dependency manifests, queries the package registry (npm, PyPI, …),
classifies how far each dep has drifted from `latest`, checks that drift against a
per-repo policy (`.packguard.yml`), and stores the result in a local SQLite cache so
you can report on it offline.

See [CONTEXT.md](./CONTEXT.md) for the full vision, architecture, and roadmap.

**Phase 1 status (MVP CLI): ✅ delivered.** Includes npm + PyPI, SQLite persistence,
policy engine, `init`, `scan`, and `report` with JSON/SARIF output.

---

## Install (from source)

```bash
cargo install --path crates/packguard-cli
# or, during development:
cargo run --release -p packguard-cli -- <args>
```

The binary is called `packguard`.

---

## Quick start

```bash
# 1. Write a conservative .packguard.yml in the repo.
packguard init

# 2. Scan — fetches registry data, classifies, and writes the store.
packguard scan

# 3. Report — reads the store, evaluates the policy, prints a compliance table.
packguard report

# 4. CI gate — exit 1 when at least one blocking violation is stored.
packguard report --fail-on-violation --format sarif > packguard.sarif
```

By default the store lives at `~/.packguard/store.db`. Override with the global
`--store <path>` flag.

---

## Commands

### `packguard init [path] [--force]`

Detects supported ecosystems under `path` and writes
`<path>/.packguard.yml` with the conservative defaults template (`offset: -1`,
`stability: stable`, `min_age_days: 7`, block `high/critical` CVEs + malware +
deprecated + yanked). Refuses to overwrite unless `--force`.

### `packguard scan [path] [--offline] [--force]`

Walks the Tier 1 ecosystems (npm, PyPI) and, for every project it finds:

1. Computes a SHA-256 fingerprint of the ecosystem id + manifest + lockfiles.
2. Compares it to the fingerprint stored in SQLite. If unchanged, skips (add
   `--force` to re-fetch).
3. Fetches `latest` + latest release date from the registry (concurrency 16,
   10 s timeout, rustls-only TLS).
4. Writes the full schema (§8) — repos, workspaces, packages,
   `package_versions`, dependencies, `scan_history`.
5. Renders a table of `installed vs latest` coloured by semver/PEP 440 delta.

`--offline` skips network entirely. It errors cleanly when the cache was never
populated for that repo/ecosystem and prints the command the user must run
first.

### `packguard report [path] [--format table|json|sarif] [--fail-on-violation]`

Reads **only** the SQLite store. Reloads `.packguard.yml` (or the built-in
conservative defaults when absent) and evaluates every stored dependency against
the resolved policy. Output:

- `table` (default): grouped by ecosystem → workspace → package, with a Policy
  column (`compliant` / `warning` / `violation`) and a summary line.
- `json`: a `{ summary, rows[] }` document suitable for custom tooling.
- `sarif`: SARIF 2.1.0 with one `result` per blocking violation.

`--fail-on-violation` exits `1` when the store holds at least one blocking
violation (used in CI).

---

## Policy format (`.packguard.yml`)

Full reference in CONTEXT.md §6. Short tour:

```yaml
defaults:
  offset: -1              # stay one major behind latest
  allow_patch: true
  allow_security_patch: true
  stability: stable       # exclude prereleases
  min_age_days: 7         # ignore releases younger than a week
  block:                  # evaluated in Phase 2 (vuln intel)
    cve_severity: [high, critical]
    malware: true
    deprecated: true
    yanked: true

overrides:
  - match: "react"          # exact name
    offset: 0
  - match: "lodash"
    pin: "4.17.21"          # hard pin
  - match: "@babel/*"       # glob
    offset: -2

groups:
  - name: security-critical
    match: ["jsonwebtoken", "bcrypt*", "@auth/*"]
    offset: 0
    min_age_days: 0
```

Resolution cascade: `defaults` → every matching `group` → every matching
`override`, later layers strictly overriding per-field.

---

## Supported ecosystems (Phase 1 — Tier 1)

| Ecosystem | Managers          | Lockfile used for `installed`             |
|-----------|-------------------|--------------------------------------------|
| npm       | npm / pnpm / yarn | `package-lock.json` v2 or v3               |
| PyPI      | poetry            | `poetry.lock`                              |
| PyPI      | uv                | `uv.lock`                                  |
| PyPI      | pip               | **Declared-only** (see below)              |

Tier 2 (Cargo, Go modules) lands post-MVP. Everything explicitly out of scope is
listed in CONTEXT.md §4.

### pip declared-only mode

pip doesn't ship a native lockfile format. PackGuard parses `requirements*.txt`
in best-effort PEP 508 and only treats a requirement as **installed** when it
uses an exact pin (`pkg==1.2.3`). Loose ranges like `flake8>=7.0` stay at
`installed = None` and classify as `Unknown`/`Warning`. The upshot: a
`requirements.txt`-only repo will produce a mix of fully-classified rows (for
`==` pins) and warnings (for everything else) — if you need full coverage, move
to `pyproject.toml` + `uv.lock` or add a lockfile-ish workflow (e.g.
`pip-compile --generate-hashes`).

---

## Project layout

```
.
├── CONTEXT.md                  # source of truth for scope & decisions
├── Cargo.toml                  # workspace manifest
├── crates/
│   ├── packguard-core          # Ecosystem trait, npm & pypi impls, model
│   ├── packguard-policy        # YAML parser, rule resolution, evaluator
│   ├── packguard-store         # rusqlite + refinery persistence
│   └── packguard-cli           # binary (init / scan / report)
├── fixtures/                   # npm-basic, pypi-poetry, pypi-uv, pypi-pip
└── rust-toolchain.toml
```

---

## Development

```bash
cargo test          # runs the full workspace test suite
cargo clippy --all-targets -- -D warnings
cargo fmt --all -- --check
```

Live (network-hitting) tests against real registries can be wired behind
`PACKGUARD_LIVE_TESTS=1` when Phase 2 lands. For now everything runs offline
against fixtures or in-memory stores.

---

## Non-goals (v1)

- No SaaS/cloud backend.
- No desktop app (no Tauri, no Electron).
- No IDE extension.
- No OS package managers (`apt`, `brew`, `pip install` behaviour beyond
  declared deps), no Docker/Helm, no Nix.

See CONTEXT.md §4 for the complete hors-scope list and §14 for the Phase 1
criteria and what's explicitly deferred to later phases.

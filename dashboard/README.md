# PackGuard dashboard

Vite + React 19 + TypeScript SPA that consumes the REST API exposed by
`packguard-server`. The same Rust binary that ships the CLI also serves
this UI when invoked as `packguard ui`.

## Dev workflow

Two terminals, two ports:

```bash
# Terminal A — Rust API server on :5174
cargo run -p packguard -- ui --no-open --port 5174

# Terminal B — Vite dev server on :5173 (proxies /api/* to :5174)
cd dashboard
pnpm install     # first time
pnpm dev
```

Open http://localhost:5173. Hot reload on the front, `cargo watch` on the
back if you want it (`cargo watch -x 'run -p packguard -- ui --no-open'`).

## Type sharing

DTOs live in `crates/packguard-server/src/dto.rs` annotated with
`#[derive(TS)]`. Plain `cargo test` runs the drift gate; if you change a
DTO and forget to regenerate, the test fails with a one-line reproducer:

```bash
PACKGUARD_REGEN_TYPES=1 cargo test -p packguard-server --test types_drift
```

The generated `*.ts` files live under `dashboard/src/api/types/` and are
committed.

## Scripts

```bash
pnpm dev         # Vite dev server with /api/* proxy
pnpm build       # type-check + production bundle
pnpm test        # vitest run (component + util tests)
pnpm lint        # eslint --max-warnings 0
pnpm typecheck   # tsc -b --noEmit
```

## Phase 4a vs 4b

- **4a (this commit):** scaffold + Overview page + Packages table page +
  layout + Scan/Sync triggers + read-only Policy view.
- **4b (next):** Package detail tabs (Versions / Vulnerabilities /
  Malware / Policy eval / Changelog), visx version timeline, Policies
  editor with live dry-run, `build.rs` embed for release builds, screenshots
  in the root README.

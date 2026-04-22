# Publishing PackGuard

Everything in Phase 8a ships with the repo. This file covers Phase 8b:
the acts that move bytes to third-party registries and therefore
require credentials the code itself can't carry. Each section is a
self-contained checklist a maintainer can follow without re-reading
the Phase 8 briefing.

> **Never commit secrets** referenced below. Use GitHub organization
> secrets (Settings → Secrets → Actions) or a local `.env` the release
> workflow never reads back.

---

## Prerequisites — secrets to provision once

| Secret | Provider | Used by | Required for |
|---|---|---|---|
| `CRATES_IO_TOKEN` | crates.io (Account → API Tokens) | `cargo publish` | publishing crates |
| `DOCKERHUB_USERNAME` | Docker Hub | `.github/workflows/release.yml` · docker push job | Docker Hub push |
| `DOCKERHUB_TOKEN` | Docker Hub → Account Settings → Security → Access Tokens | same | same |
| `COSIGN_PRIVATE_KEY` | `cosign generate-key-pair` | release workflow · sign step | signed binaries |
| `COSIGN_PASSWORD` | (user-chosen) | same | same |
| `HOMEBREW_TAP_TOKEN` | GitHub PAT with `repo` scope on the tap repo | release workflow · homebrew step | Homebrew tap push |

### Generating the cosign keypair

```bash
cosign generate-key-pair                     # interactive password
gh secret set COSIGN_PRIVATE_KEY < cosign.key
gh secret set COSIGN_PASSWORD                # paste the password
# Commit cosign.pub into the repo root so downstream verifiers can
# fetch it without a release-level lookup.
git add cosign.pub && git commit -m "chore(sign): add cosign public key"
```

After the commit, any consumer can verify a release artifact with:

```bash
cosign verify-blob \
  --key https://raw.githubusercontent.com/Tmauc/packguard/main/cosign.pub \
  --signature packguard-vX.Y.Z-aarch64-apple-darwin.tar.gz.sig \
  packguard-vX.Y.Z-aarch64-apple-darwin.tar.gz
```

---

## Order of operations — first release (v0.1.0)

Execute in this order. Each step is idempotent — if the pipeline fails
halfway through, fix + rerun from the failing step.

1. **Tag the release**

   ```bash
   git tag -a v0.1.0 -m "v0.1.0 — initial public release"
   git push origin v0.1.0
   ```

2. **Watch the release workflow**

   ```bash
   gh run watch
   # or: open https://github.com/Tmauc/packguard/actions
   ```

   Outputs: 5 binaries + SHA256SUMS + (optional) cosign signatures in a
   GitHub Release draft. The workflow is gated on `v*` tags — no push
   to the tag, no release.

3. **Verify release artefacts**

   ```bash
   gh release download v0.1.0 --pattern '*.sha256'
   cat packguard-v0.1.0-*.sha256 > LOCAL_SUMS
   curl -sSL -o SHA256SUMS "https://github.com/Tmauc/packguard/releases/download/v0.1.0/SHA256SUMS"
   diff <(sort LOCAL_SUMS) <(sort SHA256SUMS) && echo "checksums match"
   ```

4. **Publish Docker image**

   The release workflow pushes `ghcr.io/tmauc/packguard:v0.1.0` +
   `:latest` unconditionally. Docker Hub push fires only if
   `DOCKERHUB_USERNAME` is set. Smoke test from a non-priviledged shell:

   ```bash
   docker run --rm ghcr.io/tmauc/packguard:v0.1.0 --version
   ```

5. **Publish crates** (separate step — workflow doesn't auto-publish
   because `cargo publish` is irreversible)

   Order matters — dependent crates must be on crates.io before their
   dependents. Wait ~30s between publishes to let the index catch up.

   ```bash
   export CARGO_REGISTRY_TOKEN="$CRATES_IO_TOKEN"
   # Note: from v0.2.0 the binary crate is `packguard` (no `-cli`).
   # Library crates keep the `packguard-<name>` prefix.
   for crate in packguard-core packguard-store packguard-policy \
                packguard-intel packguard-server packguard; do
     cargo publish -p "$crate"
     sleep 30
   done
   ```

   In CI, the workflow `gh workflow run crates-publish.yml -f dry_run=false`
   does the same thing in the same order.

6. **Update the Homebrew tap**

   Create the tap repo `nalo/homebrew-packguard` once (public, with the
   default branch `main`). Then:

   ```bash
   sha256() { shasum -a 256 "$1" | awk '{print $1}'; }
   VERSION=0.1.0
   formula=packaging/homebrew/packguard.rb
   for pair in \
     "DARWIN_ARM64:aarch64-apple-darwin" \
     "DARWIN_X64:x86_64-apple-darwin"   \
     "LINUX_ARM64:aarch64-unknown-linux-gnu" \
     "LINUX_X64:x86_64-unknown-linux-gnu"
   do
     tag="${pair%%:*}"; target="${pair##*:}"
     url="https://github.com/Tmauc/packguard/releases/download/v${VERSION}/packguard-v${VERSION}-${target}.tar.gz"
     curl -fsSL -o "/tmp/${target}.tar.gz" "$url"
     sed -i.bak "s|RELEASE_SHA256_${tag}_PLACEHOLDER|$(sha256 /tmp/${target}.tar.gz)|" "$formula"
   done
   sed -i.bak "s|RELEASE_VERSION_PLACEHOLDER|${VERSION}|" "$formula"
   # Push the rendered formula into the tap repo.
   cp "$formula" ../homebrew-packguard/Formula/packguard.rb
   (cd ../homebrew-packguard && git add Formula/packguard.rb \
     && git commit -m "packguard v${VERSION}" \
     && git push origin main)
   ```

   After the tap push:

   ```bash
   brew tap Tmauc/packguard
   brew install packguard
   packguard --version
   ```

7. **Announce**

   - Edit the GitHub Release draft → mark as "Latest" → publish.
   - Optional: post to `#supply-chain` / social / README badge bump.

---

## Order of operations — subsequent releases (vX.Y.Z)

Same as first release, minus steps that only run once:

1. Tag + push (step 1).
2. Watch workflow + verify artefacts (steps 2–3).
3. `cargo publish` in dependency order (step 5).
4. Re-render the Homebrew formula + push to the tap (step 6 — automated
   via `packaging/homebrew/render.sh` once the first release is out).
5. Edit + publish the release draft (step 7).

If the workflow added signatures (cosign key is set):

- Verify at least one artifact signature locally before publishing the
  release:

  ```bash
  cosign verify-blob --key cosign.pub \
    --signature packguard-vX.Y.Z-x86_64-unknown-linux-gnu.tar.gz.sig \
    packguard-vX.Y.Z-x86_64-unknown-linux-gnu.tar.gz
  ```

---

## Integrating a real pipeline (Phase 8.6)

Pick a host repo you can admit CI changes to. Add one of the snippets
under `docs/integrations/` to its pipeline, commit, open an MR, and
confirm:

- A regular MR passes in green with the PackGuard step under a minute
  (cache-warm).
- A malicious MR that bumps a dep to a version with a known critical
  CVE (e.g. `lodash@4.17.20` carries CVE-2021-23337) gets blocked —
  the MR widget should surface the SARIF finding via GitLab's Security
  panel / GitHub's Security tab.

Once the bloquing MR is reproducible, that's the Phase 8 exit
criterion met — we know the tool has real operational impact.

---

## Rollback

If a published release turns out to be broken:

- **crates.io**: `cargo yank --version X.Y.Z <crate>` for each
  published crate. Yanking doesn't delete, it just stops fresh
  `cargo install` from picking the version up. Pinning users can
  still install the yanked release with
  `cargo install <crate> --version X.Y.Z --locked`.
- **Docker**: retag `:latest` to the previous working version:

  ```bash
  docker pull ghcr.io/tmauc/packguard:vX.Y.Z-1
  docker tag ghcr.io/tmauc/packguard:vX.Y.Z-1 ghcr.io/tmauc/packguard:latest
  docker push ghcr.io/tmauc/packguard:latest
  ```

- **Homebrew**: revert the formula commit on the tap repo. `brew
  upgrade` on end-user machines will downgrade on next run.
- **GitHub release**: mark as "Pre-release" so it stops showing up in
  `releases/latest` (which the installer resolves). Don't delete —
  leaves dangling links worse than a known-broken release.

---

## v0.2.0 — one-time crate rename (Phase 9c)

**Context.** Pre-0.2.0 the binary crate lived on crates.io under
`packguard-cli`. It produced a binary named `packguard`, which made
`cargo install packguard` a 404 — users had to know to type
`cargo install packguard-cli` instead. From 0.2.0 onward the crate
itself is named `packguard`, so the obvious command works.

The directory `crates/packguard-cli/` is intentionally unchanged —
the dir name is an implementation detail and renaming it would churn
a lot of paths (scripts, docs, historical git archaeology) for no
observable benefit. The cargo manifest is the only file that carries
the published crate name; that's where the change is scoped.

### What to run after the 0.2.0 tag is live

The regular release + crates-publish flow takes care of the new
`packguard` crate automatically. The only new manual step is the
one-time yank of `packguard-cli@0.1.0`:

```bash
# After packguard@0.2.0 is live on crates.io and you've smoke-tested
# it (`cargo install packguard && packguard --version`), yank the
# legacy publish so `cargo install packguard-cli` stops resolving to
# a release that will never get newer versions.
cargo yank --version 0.1.0 packguard-cli
```

**Recommendation: Option A (yank).** The yanked release stays
installable for anyone who pins it explicitly —
`cargo install packguard-cli --version 0.1.0 --locked` continues to
work — but it's hidden from `cargo install packguard-cli` defaults,
so no one accidentally gets the frozen 0.1.0 in a fresh pipeline.

**Option B (don't yank)** is also fine if the caution is worth more
than the cleanliness: you simply stop publishing under
`packguard-cli` and document the rename loudly in the README. The
downside is that `cargo install packguard-cli` keeps quietly working
but pinning users there on a release that will never ship security
intel updates.

### Undoing the yank

If the yank causes a regression (a downstream pin nobody flagged),
reverse it:

```bash
cargo yank --version 0.1.0 --undo packguard-cli
```

### Checklist before tagging 0.2.0

1. `./scripts/bump-version.sh 0.2.0` — bumps `Cargo.toml`, refreshes
   `Cargo.lock`, creates a local annotated tag `v0.2.0`.
2. `git push origin main --follow-tags` — kicks off the release
   workflow (binaries + Docker + Homebrew).
3. Wait for the release workflow to finish (~8 min cold; linux/arm64
   takes the longest because of QEMU).
4. `gh workflow run crates-publish.yml -f dry_run=false` — publishes
   all six crates in the correct order.
5. Verify: `cargo install packguard --features ui-embed` on a clean
   machine, `packguard --version` prints `0.2.0`.
6. Optional (Option A): `cargo yank --version 0.1.0 packguard-cli`.

Document the rollback in a GitHub Release note on the next good tag so
users know what happened.

---

## Security posture checklist (pre-release)

Run through this list before every tag push.

- [ ] `cargo audit` clean (or every advisory is explicitly ignored with
      a linked upstream issue).
- [ ] `cargo deny check` clean (workspace deps respect the license +
      duplicate policy).
- [ ] `trivy image ghcr.io/tmauc/packguard:vX.Y.Z` reports no CRITICAL
      un-fixed CVEs (the release workflow enforces this, but spot-check
      locally if CI is flaky).
- [ ] SHA256 of every artefact in `SHA256SUMS` matches the one under
      `dist/<target>/` on the release page.
- [ ] cosign signature verifies (if the key is set).
- [ ] Dashboard-less smoke:
      `docker run --rm ghcr.io/tmauc/packguard:vX.Y.Z scan /workspace`
      reads a mounted lockfile without the `ui-embed` UI ever firing.

When all boxes tick, publish the release draft.

#!/usr/bin/env bash
# Bump the workspace version and prepare a release tag.
#
# Usage:  ./scripts/bump-version.sh <new-version>
# Example: ./scripts/bump-version.sh 0.2.0
#
# What it does:
#   1. Validates the version is semver-shaped
#   2. Rewrites Cargo.toml workspace.package.version
#   3. Runs `cargo check --workspace` to refresh Cargo.lock
#   4. Commits the bump with a conventional message
#   5. Creates an annotated tag `v<new-version>` (but does NOT push)
#
# What it deliberately does NOT do:
#   - Push anything to origin — you review first, then:
#       git push origin main --follow-tags
#   - Publish to crates.io — use the crates-publish workflow instead
#   - Rebuild Homebrew formula — automated by the release workflow

set -euo pipefail

if [ $# -ne 1 ]; then
  echo "usage: $0 <new-version>" >&2
  exit 1
fi

NEW_VERSION="$1"

# Loosely check semver — major.minor.patch, optional pre/build metadata
if ! [[ "$NEW_VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+([-+][A-Za-z0-9.\-]+)?$ ]]; then
  echo "error: '$NEW_VERSION' is not semver-shaped (expected X.Y.Z[-suffix])" >&2
  exit 1
fi

REPO_ROOT="$(git rev-parse --show-toplevel 2>/dev/null || true)"
if [ -z "$REPO_ROOT" ]; then
  echo "error: not in a git repo" >&2
  exit 1
fi

cd "$REPO_ROOT"

# Block mid-flight work
if ! git diff-index --quiet HEAD --; then
  echo "error: uncommitted changes present — stash or commit first" >&2
  git status --short
  exit 1
fi

CURRENT_VERSION=$(
  grep -E '^version[[:space:]]*=' Cargo.toml | head -1 |
  sed -E 's/^version[[:space:]]*=[[:space:]]*"([^"]+)".*/\1/'
)

if [ "$CURRENT_VERSION" = "$NEW_VERSION" ]; then
  echo "error: workspace already at version $NEW_VERSION" >&2
  exit 1
fi

if git rev-parse --verify --quiet "refs/tags/v${NEW_VERSION}" >/dev/null; then
  echo "error: tag v${NEW_VERSION} already exists locally — delete it first if intentional" >&2
  exit 1
fi

echo "bumping workspace: ${CURRENT_VERSION} -> ${NEW_VERSION}"

# Rewrite workspace.package.version only. Internal path deps reference
# the same workspace version, so they don't need touching — they
# resolve through workspace.package.version.workspace = true.
# BUT internal dep *version* fields (path + version = "X.Y.Z") must
# match the workspace version too; rewrite them in place.
#
# Pattern is ^version = "..." with quoted value, which matches the
# [workspace.package].version line and nothing else (version.workspace
# = true has no quoted value). Portable across GNU and BSD sed.
sed -i.bak -E \
  "s/^version = \"[^\"]+\"$/version = \"${NEW_VERSION}\"/" \
  Cargo.toml
rm -f Cargo.toml.bak

# Update internal path+version deps across every member crate
while IFS= read -r manifest; do
  sed -i.bak -E \
    "s|(packguard-[a-z]+)[[:space:]]*=[[:space:]]*\\{[[:space:]]*path[[:space:]]*=[[:space:]]*\"[^\"]+\"[[:space:]]*,[[:space:]]*version[[:space:]]*=[[:space:]]*\"[^\"]+\"[[:space:]]*\\}|\\1 = { path = \"../\\1\", version = \"${NEW_VERSION}\" }|g" \
    "$manifest"
  rm -f "${manifest}.bak"
done < <(find crates -name Cargo.toml -type f)

# Refresh Cargo.lock
cargo check --workspace --quiet

echo "running cargo fmt to catch any Cargo.toml formatting drift"
cargo fmt --all --quiet

# Commit
git add Cargo.toml Cargo.lock crates/*/Cargo.toml
git commit -m "chore: bump version to ${NEW_VERSION}

Bumps workspace.package.version and every internal path+version dep
in lockstep so cargo publish resolves each crate's internal deps
through the registry instead of the local workspace."

# Annotated tag, no push
git tag -a "v${NEW_VERSION}" -m "v${NEW_VERSION} — release"

cat <<EOF

bump complete.

next steps:
  1. review:   git show HEAD && git show v${NEW_VERSION}
  2. push:     git push origin main --follow-tags
  3. release:  the tag push triggers release.yml (binaries + docker + GH release)
  4. crates:   gh workflow run crates-publish.yml -f dry_run=false
  5. brew:     automated by the release workflow once HOMEBREW_TAP_TOKEN is set

EOF

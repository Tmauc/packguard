# syntax=docker/dockerfile:1.7
#
# PackGuard — multi-stage self-contained image.
#
# Stage 1 (dashboard-build) compiles the Vite SPA once so the Rust
# stage can bake it in via the `ui-embed` feature. Staging here (not
# inside build.rs) keeps the Rust layer cacheable: the SPA only
# re-bundles when dashboard/** changes.
#
# Stage 2 (rust-build) compiles a release binary with `ui-embed` on, so
# `/` serves the dashboard, `/api/*` serves the REST layer, and no node
# runtime is required at runtime. `PACKGUARD_SKIP_UI_BUILD=1` stops
# build.rs from re-invoking pnpm build — we trust the artifact from
# stage 1 instead.
#
# Stage 3 (runtime) is `distroless/cc-debian12`: ships glibc + libgcc
# + CA certs (all we need because we use rustls + bundled rusqlite),
# no shell, no package manager, no curl. Image is ~40-50 MB and ships
# as nonroot so a compromised scan can't walk /etc.

FROM node:20-bookworm-slim AS dashboard-build
WORKDIR /src/dashboard
# Copy manifests first so the pnpm install layer only busts on lock changes.
COPY dashboard/package.json dashboard/pnpm-lock.yaml ./
RUN corepack enable && pnpm install --frozen-lockfile
COPY dashboard/ ./
RUN pnpm build

# rust:1.90 matches what we compile against locally; transitive deps
# (icu_*, time 0.3.47, zip 8.x) have pushed MSRV to 1.88 so we stay a
# couple of minors ahead of them. The workspace MSRV in Cargo.toml
# (1.80) still applies to our own crates — this pin only bounds the
# cargo that *parses* the registry.
FROM rust:1.90-bookworm AS rust-build
WORKDIR /src
# Tell build.rs not to invoke pnpm — stage 1 already produced dist/.
ENV PACKGUARD_SKIP_UI_BUILD=1
# Cache the dependency graph before copying the crates themselves so a
# touched-only-src change reuses the downloaded registry.
COPY Cargo.toml Cargo.lock ./
COPY crates/ ./crates/
COPY --from=dashboard-build /src/dashboard/dist ./dashboard/dist
RUN cargo build --release -p packguard-cli --features ui-embed
# Strip symbols to shrink the final image; they stay in the build cache
# for anyone who wants a debug-symbol copy on the side.
RUN strip /src/target/release/packguard

FROM gcr.io/distroless/cc-debian12:nonroot
LABEL org.opencontainers.image.title="PackGuard"
LABEL org.opencontainers.image.description="Dependency supply-chain scanner: OSV/GHSA + malware/typosquat + policy-driven CI gate."
LABEL org.opencontainers.image.source="https://github.com/Tmauc/packguard"
LABEL org.opencontainers.image.licenses="MIT OR Apache-2.0"
COPY --from=rust-build /src/target/release/packguard /usr/local/bin/packguard
WORKDIR /workspace
# The CLI writes its SQLite store to $HOME/.packguard by default, so the
# `nonroot` user needs a writable HOME. Use /home/nonroot which the
# distroless image already creates with the right ownership.
ENV HOME=/home/nonroot
ENTRYPOINT ["/usr/local/bin/packguard"]
CMD ["--help"]

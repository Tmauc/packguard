//! PackGuard HTTP server. Phase 4a scope:
//!
//! - REST API consumed by the `dashboard/` SPA: overview, packages list,
//!   package detail (basic), policy read, scan/sync triggers, job polling.
//! - Async job runner backed by the `jobs` table from migration V4.
//! - DTO types derive `serde::Serialize` + `ts_rs::TS`; the test harness
//!   exports them to `dashboard/src/api/types/` and the workspace's
//!   `assert_ts_types_match_committed` test fails when committed files
//!   drift. Re-export by running `PACKGUARD_REGEN_TYPES=1 cargo test
//!   -p packguard-server`.
//!
//! No business logic lives here — every handler delegates to
//! `packguard-store` / `-core` / `-policy` / `-intel`. Phase 4b will add
//! the policies write endpoint, the package detail tabs, and the build.rs
//! that embeds the Vite bundle for release.

pub mod app;
pub mod dto;
#[cfg(feature = "ui-embed")]
pub mod embed;
pub mod error;
pub mod jobs;
pub mod services;
pub mod state;

pub use app::{router, ServerConfig};
pub use error::ApiError;
pub use state::AppState;

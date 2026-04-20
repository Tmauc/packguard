//! PackGuard core — ecosystem-agnostic scanning primitives.
//!
//! Phase 0 scope: npm only, direct deps, exact installed versions from lockfiles,
//! `latest` from the registry, basic semver classification. Everything larger
//! (policy engine, SQLite, vulns) lands in later phases.

pub mod classify;
pub mod model;
pub mod npm;
pub mod registry;

pub use classify::{Delta, classify};
pub use model::{DepKind, Dependency, Project};

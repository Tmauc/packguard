//! PackGuard Page Actions engine — Phase 12a.
//!
//! Aggregates the store + policy + intel into a prioritized list of
//! remediation actions (`FixMalware`, `FixCveCritical`, `ClearViolation`,
//! `RefreshSync`, `RescanStale`, …) that the dashboard (12b) and CLI
//! (12c) render as a to-do list.
//!
//! The crate is a *read layer* on top of what was already persisted by
//! `packguard scan` / `packguard sync`; it never reaches the network
//! and runs entirely off the SQLite store.

pub mod generator;
pub mod model;
pub mod pm_detect;

pub use generator::{collect_all, filter_min_severity};
pub use model::{stable_action_id, Action, ActionKind, ActionSeverity, ActionTarget};
pub use pm_detect::{detect_package_manager, suggest_upgrade, PackageManager};

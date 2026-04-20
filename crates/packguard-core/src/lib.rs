//! PackGuard core — ecosystem-agnostic scanning primitives.
//!
//! Phase 1 scope: npm + pypi via the `Ecosystem` trait, semver/PEP 440
//! classification. Persistence lives in `packguard-store`; the policy
//! engine lives in `packguard-policy`.

pub mod classify;
pub mod ecosystem;
pub mod model;
pub mod npm;
pub mod registry;

pub use classify::classify_semver;
pub use ecosystem::Ecosystem;
pub use model::{Delta, DepKind, Dependency, Project, RemotePackage};
pub use npm::Npm;

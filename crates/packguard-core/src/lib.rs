//! PackGuard core — ecosystem-agnostic scanning primitives.
//!
//! Phase 1 scope: npm + pypi via the `Ecosystem` trait, semver/PEP 440
//! classification. Persistence lives in `packguard-store`; the policy
//! engine lives in `packguard-policy`.

pub mod classify;
pub mod ecosystem;
pub mod model;
pub mod npm;
pub mod pypi;
pub mod registry;

pub use classify::classify_semver;
pub use ecosystem::Ecosystem;
pub use model::{
    AffectedEvent, AffectedRange, AffectedRangeKind, AffectedSpec, CompatibilityInfo, Delta,
    DepKind, Dependency, DependencyEdge, MalwareKind, MalwareReport, PeerDepSpec, Project,
    RemotePackage, RemoteVersion, Severity, Vulnerability,
};
pub use npm::Npm;
pub use pypi::{classify_pep440, normalize_name, Pypi};

/// Default set of Tier 1 ecosystems enabled in Phase 1.
pub fn default_ecosystems() -> anyhow::Result<Vec<std::sync::Arc<dyn Ecosystem>>> {
    Ok(vec![
        std::sync::Arc::new(Npm::new()?),
        std::sync::Arc::new(Pypi::new()?),
    ])
}

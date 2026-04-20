//! Registry clients. Phase 0: npm only.

pub mod npm;

pub use npm::{NpmClient, PackageInfo};

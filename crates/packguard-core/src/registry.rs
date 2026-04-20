//! Registry clients. Each ecosystem owns its own HTTP client; this module
//! just groups them and is where shared HTTP plumbing will land later (ETag
//! cache, retries, etc. — see §7).

pub mod npm;
pub mod pypi;

pub use npm::NpmClient;
pub use pypi::PypiClient;

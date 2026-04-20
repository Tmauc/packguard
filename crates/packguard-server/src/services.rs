//! Service layer — DTO ↔ store/policy/intel translation. All handlers in
//! `app.rs` go through here, so business logic stays in the existing crates
//! and these functions stay readable.

pub mod overview;
pub mod packages;
pub mod policies;
pub mod scan;
pub mod sync_intel;

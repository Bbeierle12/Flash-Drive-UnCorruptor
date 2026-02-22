//! File recovery algorithms.
//!
//! Phase 1: Deleted file scanning via filesystem directory entries.
//! Phase 3: File signature carving and orphaned cluster scanning.

pub mod carving;

pub use carving::scan_signatures;

//! Filesystem abstractions and implementations.
//!
//! Each supported filesystem implements the `FileSystemOps` trait,
//! providing a uniform interface for scanning, validation, and recovery.

pub mod detect;
pub mod ext4;
pub mod fat32;
pub mod ntfs;
pub mod traits;

pub use detect::detect_filesystem;
pub use traits::FileSystemOps;

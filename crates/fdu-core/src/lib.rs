//! # fdu-core
//!
//! Core library for Flash Drive UnCorruptor.
//! Provides filesystem abstractions, device access, recovery algorithms,
//! diagnostics, and repair operations.
//!
//! This crate has zero dependencies on CLI or web — it is the shared
//! foundation that both `fdu-cli` and `fdu-web` build upon.

pub mod device;
pub mod diagnostics;
pub mod errors;
pub mod fs;
pub mod models;
pub mod recovery;
pub mod repair;

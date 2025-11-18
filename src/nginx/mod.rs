//! Nginx integration layer for e2e-site-spawner.
//!
//! This module exposes the building blocks used to generate, validate,
//! and apply Nginx configurations for managed sites.

/// Public Nginx configuration primitives (structs, enums, helpers).
pub mod config;

mod utils;

#[allow(unused)]
pub use utils::*;

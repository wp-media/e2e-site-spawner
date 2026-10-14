//! Nginx integration layer for e2e-site-spawner.
//!
//! This module exposes the building blocks used to generate, validate,
//! and apply Nginx configurations for managed sites.

/// Public Nginx configuration primitives (structs, enums, helpers).
pub mod config;

/// Detection and rewriting of the PHP-FPM version in existing site configs.
pub mod php_fpm;

mod utils;

#[allow(unused)]
pub use utils::*;

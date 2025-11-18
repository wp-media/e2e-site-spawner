//! Shared utility layer for the e2e-site-spawner.
//!
//! This module centralizes helpers that are reused across CLI commands,
//! Nginx integration, and provisioning workflows. Each submodule focuses
//! on a specific concern (database, filesystem, SSL, validation), keeping
//! the rest of the codebase lightweight and cohesive.

/// Database helpers for creating/dropping MySQL databases and validating names.
pub mod db;

/// Filesystem helpers for site directories, file creation, and revert logic.
pub mod sites;

/// SSL/TLS helpers for certificate generation and housekeeping.
pub mod ssl;

/// Input validation helpers (site names, paths, etc.).
pub mod validators;

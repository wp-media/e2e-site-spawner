//! Command-line interface (CLI) layer for the e2e-site-spawner.
//!
//! This module glues together argument parsing and command dispatching,
//! exposing the submodules that implement those responsibilities.

/// Argument parsing utilities.
///
/// Provides the structures and helpers for defining CLI arguments,
/// subcommands, and flags.
pub mod args;

/// Command implementations.
///
/// Contains the logic behind each CLI subcommand (spawn, delete, etc.).
pub mod commands;
// pub mod help;

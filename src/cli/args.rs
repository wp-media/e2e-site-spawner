//! Command-line argument parsing and CLI structure definition.
//!
//! This module defines the command-line interface for the e2e-site-spawner
//! using the clap library. It specifies all available commands, their arguments,
//! and provides help text and examples for users.
//!
//! # CLI Structure
//!
//! The CLI follows a subcommand pattern:
//! ```text
//! e2sp <COMMAND> [OPTIONS] [ARGS]
//! ```
//!
//! # Available Commands
//!
//! - `spawn` - Create new sites with optional WordPress and SSL
//! - `delete` - Remove sites and all associated resources
//! - `deactivate` - Temporarily disable site access
//! - `activate` - Re-enable deactivated sites
//! - `update` - Add WordPress and/or SSL to an existing site
//! - `list` - Show every site configured on the server

use clap::builder::styling::{AnsiColor, Effects, Styles};
use clap::{Arg, ArgMatches, ColorChoice, Command};

use crate::constants::DEFAULT_PHP_VERSION;
use crate::utils::php::PhpVersion;

/// Application version string compiled from Cargo metadata.
///
/// Combines the package version and authors from Cargo.toml into a single
/// version string displayed with the `--version` flag.
///
/// # Format
/// ```text
/// {version}
/// {authors}
/// ```
///
/// # Example Output
/// ```text
/// 0.1.0
/// WP Media Team
/// ```
const VERSION: &str = concat!(env!("CARGO_PKG_VERSION"), "\n", env!("CARGO_PKG_AUTHORS"));

// TODO: Add aliases to commands where appropriate

/// Builds the complete CLI application structure with all commands and arguments.
///
/// Constructs the command-line interface using clap, defining all subcommands,
/// their arguments, and visual styling for terminal output.
///
/// # Returns
///
/// A configured `Command` instance ready to parse command-line arguments.
///
/// # CLI Design
///
/// ## Visual Styling
/// - **Headers**: Green and bold for command names
/// - **Usage**: Cyan and bold for usage instructions
/// - **Literals**: Yellow and bold for literal values
/// - **Placeholders**: Magenta for argument placeholders
///
/// ## Command Structure
///
/// ### Root Command
/// - Name: "E2E Site Spawner"
/// - Shows help if no subcommand provided
/// - Auto-detects terminal color support
///
/// ### Subcommands
///
/// #### `spawn`
/// Creates new sites with optional features:
/// - **Required**: Site name (domain)
/// - **Options**:
///   - `--ssl`: Enable Let's Encrypt SSL
///   - `--no-wp`: Skip WordPress installation
///   - `--php <VERSION>`: PHP-FPM version (`X.Y`, default
///     [`crate::constants::DEFAULT_PHP_VERSION`]), parsed into a
///     [`PhpVersion`] by [`PhpVersion::parse_cli`] (invalid values exit 2
///     before any privilege check)
///
/// #### `delete`
/// Completely removes sites:
/// - **Required**: Site name to delete
/// - **Removes**: Files, database, nginx config, SSL certs
///
/// #### `deactivate`
/// Temporarily disables sites:
/// - **Required**: Site name to deactivate
/// - **Preserves**: All data and configuration
///
/// #### `activate`
/// Re-enables deactivated sites:
/// - **Required**: Site name to activate
/// - **Restores**: Full site access
///
/// #### `update`
/// Modifies an existing managed site:
/// - **Required**: Site name to update
/// - **Options**: `--wp` (install WordPress), `--ssl` (add HTTPS)
///
/// #### `list`
/// Shows every configured site with its status, SSL, WordPress and path.
///
/// # Examples
///
/// ## Basic Usage
/// ```bash
/// # Create a WordPress site
/// e2sp spawn example.com
///
/// # Create site with SSL
/// e2sp spawn example.com --ssl
///
/// # Create static HTML site
/// e2sp spawn example.com --no-wp
///
/// # Create a WordPress site served by PHP-FPM 8.3
/// e2sp spawn example.com --php 8.3
///
/// # Delete a site
/// e2sp delete example.com
/// ```
///
/// # Color Support
///
/// The CLI automatically detects terminal capabilities:
/// - Full color on modern terminals
/// - Graceful degradation on limited terminals
/// - No color when output is piped
pub fn build_cli() -> Command {
    // Define custom styles for different elements
    let styles = Styles::styled()
        .header(AnsiColor::Green.on_default() | Effects::BOLD)
        .usage(AnsiColor::Cyan.on_default() | Effects::BOLD)
        .literal(AnsiColor::Yellow.on_default() | Effects::BOLD)
        .placeholder(AnsiColor::Magenta.on_default());

    Command::new("E2E Site Spawner")
        .styles(styles)
        .color(ColorChoice::Auto)
        .version(VERSION)
        .author(env!("CARGO_PKG_AUTHORS"))
        .about("CLI tool for managing Nginx sites on the e2e server")
        .arg_required_else_help(true)
        .subcommand(
            Command::new("spawn")
                .about("Creates a new site with Nginx configuration")
                .long_about("Creates a new site with Nginx configuration. By default, creates a WordPress site with database.")
                .after_help("EXAMPLES:\n    \
                    e2sp spawn example.e2e.rocketlabsqa.ovh               # Create a WordPress site with database\n    \
                    e2sp spawn example.e2e.rocketlabsqa.ovh --ssl         # Create a WordPress site with SSL\n    \
                    e2sp spawn example.e2e.rocketlabsqa.ovh --no-wp       # Create a static site without WordPress\n    \
                    e2sp spawn example.e2e.rocketlabsqa.ovh --no-wp --ssl # Create a static site with SSL\n    \
                    e2sp spawn example.e2e.rocketlabsqa.ovh --php 8.3     # Create a WordPress site using PHP-FPM 8.3")
                .arg(
                    Arg::new("site_name")
                        .help("The name of the site to create (e.g., example.e2e.rocketlabsqa.ovh)")
                        .required(true)
                        .value_name("SITE_NAME")
                        .index(1),
                )
                .arg(
                    Arg::new("ssl")
                        .long("ssl")
                        .help("Enable SSL certificate (Let's Encrypt)")
                        .action(clap::ArgAction::SetTrue),
                )
                .arg(
                    Arg::new("no-wp")
                        .long("no-wp")
                        .help("Create the site without WordPress installation")
                        .action(clap::ArgAction::SetTrue),
                )
                .arg(
                    Arg::new("php")
                        .long("php")
                        .help("PHP-FPM version (X.Y) the site's Nginx config uses; its socket must exist")
                        .value_name("VERSION")
                        .value_parser(PhpVersion::parse_cli)
                        .default_value(DEFAULT_PHP_VERSION),
                ),
        )
        .subcommand(
            Command::new("delete")
                .about("Completely removes a site and all associated resources")
                .long_about("Completely removes a site including: site files, database, Nginx configuration, and SSL certificates (if present)")
                .after_help("EXAMPLES:\n    \
                    e2sp delete example.e2e.rocketlabsqa.ovh  # Delete site and all associated resources")
                .arg(
                    Arg::new("site_name")
                        .help("The name of the site to delete (e.g., example.e2e.rocketlabsqa.ovh)")
                        .required(true)
                        .value_name("SITE_NAME")
                        .index(1),
                ),
        )
        .subcommand(
            Command::new("deactivate")
                .about("Temporarily disables site access without data loss")
                .long_about("Deactivates the site (making it inaccessible) while preserving all data including files, database, SSL certificates, and Nginx configuration")
                .after_help("EXAMPLES:\n    \
                    e2sp deactivate example.e2e.rocketlabsqa.ovh  # Temporarily disable site access")
                .arg(
                    Arg::new("site_name")
                        .help("The name of the site to deactivate (e.g., example.e2e.rocketlabsqa.ovh)")
                        .required(true)
                        .value_name("SITE_NAME")
                        .index(1),
                ),
        )
        .subcommand(
            Command::new("activate")
                .about("Re-enables a previously deactivated site")
                .long_about("Reactivates a previously deactivated site, restoring access while keeping all existing data, configuration, and SSL certificates intact")
                .after_help("EXAMPLES:\n    \
                    e2sp activate example.e2e.rocketlabsqa.ovh  # Re-enable site access")
                .arg(
                    Arg::new("site_name")
                        .help("The name of the site to activate (e.g., example.e2e.rocketlabsqa.ovh)")
                        .required(true)
                        .value_name("SITE_NAME")
                        .index(1),
                ),
        )
        .subcommand(
            Command::new("update")
                .about("Modifies an existing site's configuration")
                .long_about("Updates an existing site by adding WordPress and/or SSL support")
                .after_help("EXAMPLES:\n    \
                    e2sp update example.e2e.rocketlabsqa.ovh --wp       # Add WordPress to a static site\n    \
                    e2sp update example.e2e.rocketlabsqa.ovh --ssl      # Add SSL certificate to HTTP-only site\n    \
                    e2sp update example.e2e.rocketlabsqa.ovh --wp --ssl # Add both WordPress and SSL")
                .arg(
                    Arg::new("site_name")
                        .help("The name of the site to update (e.g., example.e2e.rocketlabsqa.ovh)")
                        .required(true)
                        .value_name("SITE_NAME")
                        .index(1),
                )
                .arg(
                    Arg::new("wp")
                        .long("wp")
                        .help("Install WordPress on an existing non-WP site")
                        .action(clap::ArgAction::SetTrue),
                )
                .arg(
                    Arg::new("ssl")
                        .long("ssl")
                        .help("Add SSL certificate to an HTTP-only site")
                        .action(clap::ArgAction::SetTrue),
                ),
        )
        .subcommand(
            Command::new("list")
                .about("Lists all configured sites on the server")
                .long_about("Displays a comprehensive list of all sites configured on this server, showing their status, \
                            SSL configuration, WordPress installation, and other relevant details")
                .after_help("EXAMPLES:\n    \
                    e2sp list                  # Show all configured sites\n\n\
                    OUTPUT FORMAT:\n    \
                    The list shows each site with:\n    \
                    • Site name (domain)\n    \
                    • Status (active/inactive)\n    \
                    • SSL enabled (yes/no)\n    \
                    • WordPress installed (yes/no)\n    \
                    • Site path\n\n\
                    NOTES:\n    \
                    Sites are detected by scanning Nginx configuration files in /etc/nginx/conf.d/")
        )
}

/// Parses command-line arguments and returns the matches.
///
/// This is a convenience function that builds the CLI structure and immediately
/// parses the arguments provided to the program.
///
/// # Returns
///
/// An `ArgMatches` instance containing the parsed command-line arguments,
/// which can be queried to determine which command was invoked and what
/// arguments were provided.
///
/// # Process Flow
///
/// 1. Builds the CLI structure using [`build_cli()`]
/// 2. Parses arguments from `std::env::args_os()`
/// 3. Returns the parsed matches for command dispatch
///
/// # Exit Behavior
///
/// This function may cause the program to exit in the following cases:
/// - Invalid arguments: Exits with error code 2
/// - `--help` flag: Prints help and exits with code 0
/// - `--version` flag: Prints version and exits with code 0
///
/// # Usage Example
///
/// ```ignore
/// use crate::cli::args::get_matches;
///
/// let matches = get_matches();
///
/// if let Some(spawn_matches) = matches.subcommand_matches("spawn") {
///     let site_name = spawn_matches.get_one::<String>("site_name").unwrap();
///     let use_ssl = spawn_matches.get_flag("ssl");
///     // Process spawn command...
/// }
/// ```
///
/// # Panics
///
/// This function will not panic under normal circumstances. However, clap may
/// terminate the process if argument parsing fails or help/version is requested.
pub fn get_matches() -> ArgMatches {
    build_cli().get_matches()
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::error::ErrorKind;

    /// Parses `args` (without the binary name) through [`build_cli`].
    fn parse(args: &[&str]) -> Result<ArgMatches, clap::Error> {
        build_cli().try_get_matches_from(std::iter::once("e2sp").chain(args.iter().copied()))
    }

    /// Returns the `--php` value of a successfully parsed `spawn` invocation.
    fn spawn_php(args: &[&str]) -> PhpVersion {
        let matches = parse(args).expect("spawn should parse");
        let spawn = matches
            .subcommand_matches("spawn")
            .expect("spawn subcommand");
        *spawn
            .get_one::<PhpVersion>("php")
            .expect("php always has a value")
    }

    #[test]
    fn test_spawn_php_defaults_to_default_version() {
        let php = spawn_php(&["spawn", "x.com"]);
        assert_eq!(php, PhpVersion::default_version());
        assert_eq!(php.to_string(), DEFAULT_PHP_VERSION);
    }

    #[test]
    fn test_spawn_php_accepts_explicit_version() {
        assert_eq!(
            spawn_php(&["spawn", "x.com", "--php", "8.3"]).to_string(),
            "8.3"
        );
    }

    #[test]
    fn test_spawn_php_accepts_equals_syntax_with_other_flags() {
        let php = spawn_php(&["spawn", "x.com", "--ssl", "--no-wp", "--php=7.4"]);
        assert_eq!(php.to_string(), "7.4");
    }

    #[test]
    fn test_spawn_php_rejects_invalid_values() {
        for bad in [
            "abc", "8", "8.5.1", "v8.5", " 8.5", "8.x", "8.5/x", "100.1", "",
        ] {
            let err = parse(&["spawn", "x.com", "--php", bad]).expect_err(bad);
            assert!(
                matches!(
                    err.kind(),
                    ErrorKind::ValueValidation | ErrorKind::InvalidValue
                ),
                "{bad:?} gave {:?}",
                err.kind()
            );
        }
    }

    #[test]
    fn test_spawn_php_requires_a_value() {
        assert!(parse(&["spawn", "x.com", "--php"]).is_err());
    }

    #[test]
    fn test_spawn_php_rejects_repeated_flag() {
        let err =
            parse(&["spawn", "x.com", "--php", "8.3", "--php", "8.4"]).expect_err("repeated flag");
        assert_eq!(err.kind(), ErrorKind::ArgumentConflict);
    }

    #[test]
    fn test_php_flag_is_not_accepted_by_update_yet() {
        // `update --php` arrives in P4; until then the flag is spawn-only.
        let err = parse(&["update", "x.com", "--php", "8.3"]).expect_err("unknown flag");
        assert_eq!(err.kind(), ErrorKind::UnknownArgument);
    }

    #[test]
    fn test_default_php_version_constant_passes_the_cli_parser() {
        assert!(PhpVersion::parse_cli(DEFAULT_PHP_VERSION).is_ok());
    }
}

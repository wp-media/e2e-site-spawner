// This file defines the command-line arguments and options using the clap library.
// It specifies the structure of commands and their respective arguments.

use clap::{Command, Arg, ArgMatches, ColorChoice};
use clap::builder::styling::{AnsiColor, Effects, Styles};

// Create a compile-time constant
const VERSION: &str = concat!(
    env!("CARGO_PKG_VERSION"),
    "\n",
    env!("CARGO_PKG_AUTHORS")
);

/// Builds the CLI application with all commands and arguments
pub fn build_cli() -> Command {
    // Define custom styles for different elements
    let styles = Styles::styled()
        .header(AnsiColor::Green.on_default() | Effects::BOLD)
        .usage(AnsiColor::Cyan.on_default() | Effects::BOLD)
        .literal(AnsiColor::Yellow.on_default() | Effects::BOLD)
        .placeholder(AnsiColor::Magenta.on_default());

    Command::new("E2E Site Spawner")
        .styles(styles)
        .color(ColorChoice::Auto) // Auto-detect terminal color support
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
                    e2sp spawn example.e2e.rocketlabsqa.ovh --no-wp --ssl # Create a static site with SSL")
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
        // .subcommand(
        //     Command::new("deactivate")
        //         .about("Temporarily disables site access without data loss")
        //         .long_about("Deactivates the site (making it inaccessible) while preserving all data including files, database, SSL certificates, and Nginx configuration")
        //         .after_help("EXAMPLES:\n    \
        //             e2sp deactivate example.e2e.rocketlabsqa.ovh  # Temporarily disable site access")
        //         .arg(
        //             Arg::new("site_name")
        //                 .help("The name of the site to deactivate (e.g., example.e2e.rocketlabsqa.ovh)")
        //                 .required(true)
        //                 .value_name("SITE_NAME")
        //                 .index(1),
        //         ),
        // )
        // .subcommand(
        //     Command::new("activate")
        //         .about("Re-enables a previously deactivated site")
        //         .long_about("Reactivates a previously deactivated site, restoring access while keeping all existing data, configuration, and SSL certificates intact")
        //         .after_help("EXAMPLES:\n    \
        //             e2sp activate example.e2e.rocketlabsqa.ovh  # Re-enable site access")
        //         .arg(
        //             Arg::new("site_name")
        //                 .help("The name of the site to activate (e.g., example.e2e.rocketlabsqa.ovh)")
        //                 .required(true)
        //                 .value_name("SITE_NAME")
        //                 .index(1),
        //         ),
        // )
        // .subcommand(
        //     Command::new("update")
        //         .about("Modifies an existing site's configuration")
        //         .long_about("Updates an existing site by adding WordPress and/or SSL support")
        //         .after_help("EXAMPLES:\n    \
        //             e2sp update example.e2e.rocketlabsqa.ovh --wp       # Add WordPress to a static site\n    \
        //             e2sp update example.e2e.rocketlabsqa.ovh --ssl      # Add SSL certificate to HTTP-only site\n    \
        //             e2sp update example.e2e.rocketlabsqa.ovh --wp --ssl # Add both WordPress and SSL")
        //         .arg(
        //             Arg::new("site_name")
        //                 .help("The name of the site to update (e.g., example.e2e.rocketlabsqa.ovh)")
        //                 .required(true)
        //                 .value_name("SITE_NAME")
        //                 .index(1),
        //         )
        //         .arg(
        //             Arg::new("wp")
        //                 .long("wp")
        //                 .help("Install WordPress on an existing non-WP site")
        //                 .action(clap::ArgAction::SetTrue),
        //         )
        //         .arg(
        //             Arg::new("ssl")
        //                 .long("ssl")
        //                 .help("Add SSL certificate to an HTTP-only site")
        //                 .action(clap::ArgAction::SetTrue),
        //         ),
        // )
        // .subcommand(
        //     Command::new("help")
        //         .about("Displays help information")
        //         .long_about("Shows detailed help information for all commands or a specific command"),
        // )
}

/// Helper function to get subcommand matches
pub fn get_matches() -> ArgMatches {
    build_cli().get_matches()
}
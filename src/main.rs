// This is the entry point of the CLI application for e2e-site-spawner.
// It sets up the command-line interface and handles the execution of commands based on user input.

mod cli;
mod nginx;
mod utils;

// use cli::commands::{spawn_site, delete_site, deactivate_site, activate_site, update_site};
use cli::commands::{spawn_site, delete_site};

fn main() {
    let matches = cli::args::get_matches();

    // Placeholder for command execution logic
    if let Some(matches) = matches.subcommand_matches("spawn") {
        let site_name = matches.get_one::<String>("site_name").unwrap();
        let ssl = matches.get_flag("ssl");
        let no_wp = matches.get_flag("no-wp");
        spawn_site(site_name, ssl, no_wp);
    } else if let Some(matches) = matches.subcommand_matches("delete") {
        let site_name = matches.get_one::<String>("site_name").unwrap();
        delete_site(site_name);
    }
    // else if let Some(matches) = matches.subcommand_matches("deactivate") {
    //     let site_name = matches.get_one::<String>("site_name").unwrap();
    //     deactivate_site(site_name);
    // } else if let Some(matches) = matches.subcommand_matches("activate") {
    //     let site_name = matches.get_one::<String>("site_name").unwrap();
    //     activate_site(site_name);
    // } else if let Some(matches) = matches.subcommand_matches("update") {
    //     let site_name = matches.get_one::<String>("site_name").unwrap();
    //     let wp = matches.get_flag("wp");
    //     let ssl = matches.get_flag("ssl");
    //     update_site(site_name, wp, ssl);
    // } 
}
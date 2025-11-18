// This is the entry point of the CLI application for e2e-site-spawner.
// It sets up the command-line interface and handles the execution of commands based on user input.

mod cli;
pub mod constants;
pub mod nginx;
pub mod utils;
use cli::commands::{activate_site, deactivate_site, delete_site, spawn_site};
use colored::*;
use std::process;

fn main() {
    let matches = cli::args::get_matches();

    // Placeholder for command execution logic
    if let Some(matches) = matches.subcommand_matches("spawn") {
        // Check for root/sudo privileges before executing
        require_elevated_privileges();

        let site_name = matches.get_one::<String>("site_name").unwrap();
        let ssl = matches.get_flag("ssl");
        if ssl && !check_if_acme_sh_installed() {
            println!(
                "{} 'acme.sh' is not installed. SSL generation requires 'acme.sh' to be installed.",
                "❌".bright_yellow()
            );
            println!("");
            println!(
                "{}  You can install it manually from https://github.com/acmesh-official/acme.sh",
                "ℹ️".bright_blue()
            );
            process::exit(1);
        }
        let no_wp = matches.get_flag("no-wp");
        spawn_site(site_name, ssl, no_wp);
    } else if let Some(matches) = matches.subcommand_matches("delete") {
        // Check for root/sudo privileges before executing
        require_elevated_privileges();

        let site_name = matches.get_one::<String>("site_name").unwrap();
        delete_site(site_name);
    } else if let Some(matches) = matches.subcommand_matches("deactivate") {
        require_elevated_privileges();

        let site_name = matches.get_one::<String>("site_name").unwrap();
        deactivate_site(site_name);
    } else if let Some(matches) = matches.subcommand_matches("activate") {
        require_elevated_privileges();

        let site_name = matches.get_one::<String>("site_name").unwrap();
        activate_site(site_name);
        // } else if let Some(matches) = matches.subcommand_matches("update") {
        //     let site_name = matches.get_one::<String>("site_name").unwrap();
        //     let wp = matches.get_flag("wp");
        //     let ssl = matches.get_flag("ssl");
        //     update_site(site_name, wp, ssl);
        // }
    }
}

/// Checks if the program is running with elevated privileges (root or sudo).
/// Displays a helpful error message and exits if not running with proper privileges.
fn require_elevated_privileges() {
    if !is_running_as_root() {
        print_privilege_error();
        process::exit(1);
    }
}

/// Checks if the current process is running as root (UID 0).
///
/// # Returns
///
/// Returns `true` if running as root, `false` otherwise.
fn is_running_as_root() -> bool {
    #[cfg(unix)]
    {
        unsafe { libc::geteuid() == 0 }
    }

    #[cfg(not(unix))]
    {
        // For non-Unix systems, you might want to implement a different check
        // or just return false with a warning
        eprintln!("Warning: Cannot check for root privileges on non-Unix systems");
        false
    }
}

/// Prints a beautiful, informative error message about missing privileges.
fn print_privilege_error() {
    use colored::*;

    println!();
    println!(
        "{}",
        "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━".bright_red()
    );
    println!(
        "{}",
        "                    ⚠️  ELEVATED PRIVILEGES REQUIRED  ⚠️"
            .bright_red()
            .bold()
    );
    println!(
        "{}",
        "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━".bright_red()
    );
    println!();
    println!(
        "{}",
        "This command requires administrative privileges to:".bright_yellow()
    );
    println!();
    println!(
        "  {}  Create/modify files in system directories (/etc/nginx, /var/www)",
        "•".bright_cyan()
    );
    println!(
        "  {}  Manage Nginx configuration and reload the service",
        "•".bright_cyan()
    );
    println!(
        "  {}  Create MySQL/MariaDB databases and manage permissions",
        "•".bright_cyan()
    );
    println!(
        "  {}  Set proper file ownership and permissions",
        "•".bright_cyan()
    );
    println!();
    println!(
        "{}",
        "─────────────────────────────────────────────────────────────".bright_black()
    );
    println!();
    println!(
        "{} {}",
        "Please run this command with sudo:".bright_white().bold(),
        ""
    );
    println!();

    // Get the current command line arguments to show the exact command
    let args: Vec<String> = std::env::args().collect();
    let command = args.join(" ");

    println!(
        "  {} {}",
        "$ sudo".bright_green().bold(),
        command.bright_white()
    );
    println!();

    println!(
        "{} {}",
        "Or, if you're using the root user:".italic().bright_black(),
        ""
    );
    println!();
    println!("  {} {}", "$".bright_green().bold(), command.bright_white());
    println!();
    println!(
        "{}",
        "─────────────────────────────────────────────────────────────".bright_black()
    );
    println!();
    println!("{}", "📚 Learn more:".bright_blue().bold());
    println!("   • https://linux.die.net/man/8/sudo");
    println!("   • https://docs.nginx.com/nginx/admin-guide/");
    println!();
}
fn check_if_acme_sh_installed() -> bool {
    use std::process::Command;

    match Command::new("acme.sh").arg("--version").output() {
        Ok(output) => output.status.success(),
        Err(_) => false,
    }
}
#[allow(dead_code)]
fn try_acme_sh_installation() -> Result<(), String> {
    use std::process::Command;

    println!("{} Attempting to install acme.sh...", "🔄".bright_blue());

    let install_output = Command::new("curl")
        .args(&["https://get.acme.sh", "|", "sh"])
        .output()
        .map_err(|e| format!("Failed to execute curl command: {}", e))?;

    if !install_output.status.success() {
        let stderr = String::from_utf8_lossy(&install_output.stderr);
        let stdout = String::from_utf8_lossy(&install_output.stdout);

        return Err(format!(
            "Failed to install acme.sh:\n\
            Error output:\n{}{}",
            stdout, stderr
        ));
    }

    println!("{} acme.sh installed successfully!", "✓".bright_green());
    Ok(())
}

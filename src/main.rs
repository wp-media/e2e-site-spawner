//! Entry point for the e2e-site-spawner CLI application.
//!
//! This module sets up the command-line interface and handles the execution of
//! commands based on user input. It ensures proper privileges are in place before
//! executing system-level operations and provides user-friendly error messages.
//!
//! # Architecture
//!
//! The application follows a modular architecture:
//! - `cli` - Command-line interface and argument parsing
//! - `nginx` - Web server configuration management
//! - `utils` - Shared utilities for database, SSL, and validation
//! - `constants` - Global configuration constants
//!
//! # Security
//!
//! All operations require elevated privileges (root/sudo) to ensure proper
//! system file access and service management capabilities.

mod cli;
pub mod constants;
pub mod nginx;
pub mod utils;
use cli::commands::{activate_site, deactivate_site, delete_site, spawn_site};
use colored::*;
use std::process;

/// Main entry point for the e2e-site-spawner application.
///
/// Parses command-line arguments and dispatches to the appropriate command handler.
/// All commands require elevated privileges and will exit with an error if not
/// running as root or with sudo.
///
/// # Command Flow
///
/// 1. Parse command-line arguments using clap
/// 2. Check for required privileges (root/sudo)
/// 3. Validate prerequisites (e.g., acme.sh for SSL)
/// 4. Execute the requested command
/// 5. Exit with appropriate status code
///
/// # Commands
///
/// - `spawn` - Creates a new WordPress site with Nginx configuration
/// - `delete` - Removes a site and all associated resources
/// - `deactivate` - Disables a site without removing files
/// - `activate` - Re-enables a previously deactivated site
///
/// # Exit Codes
///
/// - `0` - Successful execution
/// - `1` - Error during execution (missing privileges, failed operations, etc.)
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
///
/// This function verifies that the current process has the necessary administrative
/// privileges to perform system-level operations. If not running with proper privileges,
/// it displays a detailed error message explaining what operations require elevation
/// and how to run the command correctly, then exits the program.
///
/// # Behavior
///
/// - If running as root (UID 0): Continues execution normally
/// - If not running as root: Prints error message and exits with code 1
///
/// # Why Privileges Are Required
///
/// The e2e-site-spawner needs elevated privileges to:
/// - Create and modify files in `/etc/nginx/` (nginx configurations)
/// - Create directories in `/var/www/` (web content)
/// - Reload system services (nginx)
/// - Create and manage MySQL databases
/// - Set file ownership and permissions
///
/// # Platform Support
///
/// - **Unix/Linux**: Uses `libc::geteuid()` to check effective user ID
/// - **Other platforms**: Displays a warning and denies access
///
/// # Example
///
/// ```no_run
/// // At the start of any privileged operation
/// require_elevated_privileges();
/// // Code here only runs if user has proper privileges
/// ```
fn require_elevated_privileges() {
    if !is_running_as_root() {
        print_privilege_error();
        process::exit(1);
    }
}

/// Checks if the current process is running as root (UID 0).
///
/// Determines whether the process has root privileges by checking the
/// effective user ID (euid) of the current process.
///
/// # Returns
///
/// * `true` - If the effective user ID is 0 (root)
/// * `false` - If not running as root or on non-Unix systems
///
/// # Platform Behavior
///
/// ## Unix/Linux Systems
/// Uses the POSIX `geteuid()` system call to retrieve the effective user ID.
/// Root is always UID 0 on Unix-like systems.
///
/// ## Non-Unix Systems
/// Returns `false` with a warning message, as privilege checking is
/// platform-specific and not implemented for non-Unix systems.
///
/// # Safety
///
/// Uses `unsafe` to call the C library function `libc::geteuid()`.
/// This is safe because:
/// - `geteuid()` is guaranteed not to fail
/// - It only reads the process's euid, causing no side effects
/// - The function is thread-safe
///
/// # Example
///
/// ```no_run
/// if is_running_as_root() {
///     println!("Running with root privileges");
/// } else {
///     println!("Not running as root");
/// }
/// ```
///
/// # See Also
///
/// - [`libc::geteuid`](https://docs.rs/libc/latest/libc/fn.geteuid.html)
/// - [geteuid(2) man page](https://man7.org/linux/man-pages/man2/geteuid.2.html)
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
///
/// Displays a comprehensive, color-formatted error message that explains:
/// - Why elevated privileges are required
/// - What operations need administrative access
/// - How to run the command with proper privileges
/// - Links to relevant documentation
///
/// # Visual Design
///
/// The message uses:
/// - Color coding for different sections (red for errors, yellow for warnings)
/// - Unicode box-drawing characters for visual structure
/// - Emoji indicators for better visibility
/// - Bold text for important information
///
/// # Message Sections
///
/// 1. **Header**: Eye-catching warning about privilege requirements
/// 2. **Explanation**: List of operations requiring privileges
/// 3. **Solution**: Shows exact command to run with sudo
/// 4. **Alternative**: Instructions for root user
/// 5. **Resources**: Links to documentation
///
/// # Dynamic Content
///
/// The function reconstructs the original command line from `std::env::args()`
/// and displays it with `sudo` prepended, making it easy for users to copy
/// and run the correct command.
///
/// # Example Output
///
/// ```text
/// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
///                ⚠️  ELEVATED PRIVILEGES REQUIRED  ⚠️
/// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
///
/// This command requires administrative privileges to:
///
///   • Create/modify files in system directories (/etc/nginx, /var/www)
///   • Manage Nginx configuration and reload the service
///   • Create MySQL/MariaDB databases and manage permissions
///   • Set proper file ownership and permissions
///
/// Please run this command with sudo:
///
///   $ sudo e2e-site-spawner spawn example.com --ssl
/// ```
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

/// Checks if acme.sh is installed on the system.
///
/// Verifies the presence of acme.sh by attempting to run `acme.sh --version`.
/// This tool is required for SSL certificate generation through Let's Encrypt.
///
/// # Returns
///
/// * `true` - If acme.sh is installed and responds to version query
/// * `false` - If acme.sh is not found or fails to execute
///
/// # How It Works
///
/// Executes `acme.sh --version` as a subprocess and checks if:
/// 1. The command can be found and executed
/// 2. The command exits with success status (0)
///
/// # Use Cases
///
/// Called before SSL certificate generation to ensure the required tooling
/// is available. If not installed, the user is prompted to install it.
///
/// # Example
///
/// ```no_run
/// if check_if_acme_sh_installed() {
///     // Proceed with SSL certificate generation
///     generate_ssl(&config)?;
/// } else {
///     println!("Please install acme.sh first");
///     println!("Visit: https://github.com/acmesh-official/acme.sh");
/// }
/// ```
///
/// # Note
///
/// This function assumes acme.sh is in the system's PATH. If installed
/// in a non-standard location, it may return false even if present.
fn check_if_acme_sh_installed() -> bool {
    use std::process::Command;

    match Command::new("acme.sh").arg("--version").output() {
        Ok(output) => output.status.success(),
        Err(_) => false,
    }
}

/// Attempts to automatically install acme.sh from the official repository.
///
/// Downloads and installs acme.sh using the official installation script
/// from https://get.acme.sh. This provides automated SSL certificate
/// management through Let's Encrypt.
///
/// # Returns
///
/// * `Ok(())` - If acme.sh was successfully installed
/// * `Err(String)` - If installation failed, with error details
///
/// # Installation Process
///
/// 1. Downloads the installation script from https://get.acme.sh
/// 2. Executes the script with shell
/// 3. Installs acme.sh to `~/.acme.sh/`
/// 4. Sets up automatic renewal cron job
///
/// # Prerequisites
///
/// - `curl` must be installed
/// - Internet connection required
/// - Write access to home directory
///
/// # Security Considerations
///
/// ⚠️ **Warning**: This function downloads and executes a script from the internet.
/// Ensure you trust the source (https://get.acme.sh) before running.
///
/// # Example
///
/// ```no_run
/// match try_acme_sh_installation() {
///     Ok(()) => println!("acme.sh installed successfully"),
///     Err(e) => eprintln!("Installation failed: {}", e),
/// }
/// ```
///
/// # Errors
///
/// Returns an error if:
/// - `curl` is not installed
/// - Network connection fails
/// - Installation script fails
/// - Insufficient permissions to install
///
/// # Note
///
/// This function is currently marked as `#[allow(dead_code)]` as it's not
/// actively used in the main flow. Consider enabling it for automated setup
/// or removing if manual installation is preferred.
///
/// # Alternative Installation
///
/// For manual installation, users can run:
/// ```bash
/// curl https://get.acme.sh | sh -s email=my@example.com
/// ```
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

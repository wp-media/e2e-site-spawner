//! SSL/TLS certificate management utilities.
//!
//! This module provides functionality for generating and installing SSL certificates
//! using acme.sh and Let's Encrypt. It handles certificate issuance, installation,
//! and provides user-friendly warnings and confirmations for SSL operations.
//!
//! # Features
//!
//! - Let's Encrypt certificate generation via acme.sh
//! - Automatic certificate installation to nginx directories
//! - Auto-renewal configuration through acme.sh cron
//! - User warnings and confirmations for DNS requirements
//! - Colored terminal output for better user experience
//!
//! # Requirements
//!
//! - acme.sh must be installed on the system
//! - Domain must be pointing to the server
//! - Port 80 must be accessible for domain validation
//! - Proper permissions for certificate directories

use colored::*;
use std::io::{self, Write};
use std::process::Command;

use crate::nginx;

/// Generates SSL certificates for a site using acme.sh.
///
/// This function performs two main operations:
/// 1. Issues a new SSL certificate using Let's Encrypt
/// 2. Installs the certificate in the appropriate nginx directories
///
/// # Arguments
///
/// * `nginx_config` - The nginx configuration containing site details and paths
///
/// # Returns
///
/// * `Ok(())` - If SSL certificates were generated and installed successfully
/// * `Err(String)` - If SSL generation failed at any step
///
/// # Process Flow
///
/// 1. **Validation**: Ensures SSL root directory is configured
/// 2. **Certificate Issuance**: Requests certificate from Let's Encrypt using HTTP-01 challenge
/// 3. **Certificate Installation**: Copies certificates to nginx directories
/// 4. **Nginx Reload**: Triggers nginx reload to apply new certificates
///
/// # Requirements
///
/// - acme.sh must be installed on the system
/// - The domain must be pointing to this server's IP address
/// - The webroot directory must exist and be accessible
/// - SSL root directory must be configured in nginx_config
/// - Port 80 must be open for Let's Encrypt validation
///
/// # Error Handling
///
/// The function provides detailed error messages for common issues:
/// - Domain verification failures with troubleshooting steps
/// - Missing acme.sh installation instructions
/// - Permission issues with directories
/// - Existing certificate detection
///
/// # Auto-Renewal
///
/// Certificates installed through this function are automatically added to
/// acme.sh's renewal cron job, ensuring they are renewed before expiration
/// (typically every 60 days, with certificates valid for 90 days).
///
/// # Example
///
/// ```
/// let config = NginxConfig::new(
///     "example.com".to_string(),
///     "/var/www/html".to_string(),
///     "/etc/nginx/conf.d".to_string(),
///     true  // SSL enabled
/// );
///
/// match generate_ssl(&config) {
///     Ok(()) => println!("SSL certificates installed successfully"),
///     Err(e) => eprintln!("SSL generation failed: {}", e),
/// }
/// ```
///
/// # Certificate Paths
///
/// After successful installation, certificates are located at:
/// - Private Key: `{ssl_root}/privkey.pem`
/// - Full Chain: `{ssl_root}/fullchain.pem`
///
/// # Security Notes
///
/// - Certificates are issued by Let's Encrypt (trusted CA)
/// - Private keys are stored with restricted permissions
/// - Uses ACME protocol for secure certificate issuance
/// - Supports both RSA and ECDSA key types (configured in acme.sh)
pub fn generate_ssl(nginx_config: &nginx::config::NginxConfig) -> Result<(), String> {
    // Validate SSL root is configured
    let ssl_root = nginx_config.ssl_root.as_ref().ok_or_else(|| {
        "SSL root path is not configured. Cannot generate SSL certificates.".to_string()
    })?;

    let site_name = &nginx_config.site_name;
    let webroot = &nginx_config.root;

    println!(
        "\n{} Generating SSL certificate for '{}'",
        "🔐".bright_blue(),
        site_name.bright_white()
    );
    println!("{}", "─".repeat(60).bright_black());

    // Step 1: Issue the SSL certificate
    println!(
        "  {} Requesting certificate from Let's Encrypt...",
        "1.".bright_cyan()
    );

    let issue_output = Command::new("acme.sh")
        .args(&[
            "--issue",
            "-d", site_name,
            "--webroot", &webroot,
            "--server", "letsencrypt"
        ])
        .output()
        .map_err(|e| {
            format!(
                "Failed to execute acme.sh: {}. \
                Please ensure acme.sh is correctly installed: http://github.com/acmesh-official/acme.sh",
                e
            )
        })?;

    if !issue_output.status.success() {
        let stderr = String::from_utf8_lossy(&issue_output.stderr);
        let stdout = String::from_utf8_lossy(&issue_output.stdout);

        // Check for common errors
        if stderr.contains("Verify error") || stdout.contains("Verify error") {
            return Err(format!(
                "Domain verification failed for '{}'.\n\
                Please ensure:\n\
                • The domain is pointing to this server's IP\n\
                • DNS has propagated (can take up to 48 hours)\n\
                • Port 80 is accessible from the internet\n\
                • The webroot path {} exists and is accessible\n\n\
                Error output:\n{}",
                site_name, webroot, stderr
            ));
        } else if stderr.contains("already exists") || stdout.contains("already exists") {
            println!(
                "  {} Certificate already exists, skipping issuance",
                "ℹ️".bright_yellow()
            );
        } else {
            return Err(format!(
                "Failed to issue SSL certificate:\n{}{}",
                stdout, stderr
            ));
        }
    } else {
        println!("  {} Certificate issued successfully", "✓".bright_green());
    }

    // Step 2: Install the certificate
    println!(
        "  {} Installing certificate to nginx directories...",
        "2.".bright_cyan()
    );

    let privkey_path = format!("{}/privkey.pem", ssl_root);
    let fullchain_path = format!("{}/fullchain.pem", ssl_root);

    let install_output = Command::new("acme.sh")
        .args(&[
            "--install-cert",
            "-d",
            site_name,
            "--key-file",
            &privkey_path,
            "--fullchain-file",
            &fullchain_path,
            "--reloadcmd",
            "sudo systemctl reload nginx",
            "--server",
            "letsencrypt",
        ])
        .output()
        .map_err(|e| format!("Failed to execute acme.sh install command: {}", e))?;

    if !install_output.status.success() {
        let stderr = String::from_utf8_lossy(&install_output.stderr);
        let stdout = String::from_utf8_lossy(&install_output.stdout);

        return Err(format!(
            "Failed to install SSL certificate:\n\
            • Check if the SSL directory {} exists\n\
            • Ensure proper permissions to write to {}\n\
            • Verify nginx service is running\n\n\
            Error output:\n{}{}",
            ssl_root, ssl_root, stdout, stderr
        ));
    }

    // println!("  {} Certificate installed successfully", "✓".bright_green());
    // println!("  {} Nginx reloaded with new certificate", "✓".bright_green());

    println!("{}", "─".repeat(60).bright_black());
    println!(
        "{} SSL certificate generated and installed successfully!",
        "🎉".bright_green()
    );
    println!();
    println!("{} Certificate details:", "📋".bright_blue());
    println!("  • Domain: {}", site_name.bright_white());
    println!("  • Private key: {}", privkey_path.bright_white());
    println!("  • Certificate: {}", fullchain_path.bright_white());
    println!(
        "  • Auto-renewal: {}",
        "Enabled via acme.sh cron".bright_green()
    );

    Ok(())
}

/// Prints a warning message about SSL requirements.
///
/// Displays a formatted warning to inform users about the prerequisites
/// for successful SSL certificate generation. This is a non-interactive
/// version that simply displays the information without requesting confirmation.
///
/// # Arguments
///
/// * `site_name` - The domain name for which SSL will be configured
///
/// # Output
///
/// Prints to stdout:
/// - Warning header with emoji indicators
/// - DNS requirements for the domain
/// - Information about fallback behavior if SSL fails
/// - Visual separators for clarity
///
/// # Use Cases
///
/// Call this function before attempting SSL generation to ensure users
/// understand the requirements, particularly useful in automated scripts
/// or when running with `--yes` flag.
///
/// # Example
///
/// ```
/// print_ssl_warning("example.com");
/// // Continues with SSL generation without asking for confirmation
/// ```
///
/// # Visual Design
///
/// Uses Unicode box-drawing characters and emoji for enhanced visibility:
/// - ⚠️ Warning emoji to catch attention
/// - ━ Heavy horizontal lines for separation
/// - • Bullet points for requirement lists
pub fn print_ssl_warning(site_name: &str) {
    println!("");
    println!("⚠️  SSL CONFIGURATION WARNING ⚠️");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("For SSL installation to succeed:");
    println!(
        "• The domain '{}' MUST already be pointing to this server",
        site_name
    );
    println!("• DNS propagation must be complete");
    println!("\nIf SSL generation fails:");
    println!("• The site will still be created with HTTP-only access");
    println!("• You can add SSL later");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
}

/// Asks for user confirmation before proceeding with SSL generation.
///
/// Displays a warning message about SSL requirements and prompts the user
/// to confirm they want to proceed. This interactive function ensures users
/// are aware of DNS requirements before attempting certificate generation.
///
/// # Arguments
///
/// * `site_name` - The domain name for which SSL will be configured
///
/// # Returns
///
/// * `true` - If user responds with "y" or "yes" (case-insensitive)
/// * `false` - For any other response including empty input
///
/// # Interaction Flow
///
/// 1. Displays warning message with requirements
/// 2. Prompts user with "Do you want to continue with SSL? [y/N]: "
/// 3. Reads user input from stdin
/// 4. Interprets response (default is No)
///
/// # Example
///
/// ```
/// if ask_for_ssl_confirmation("example.com") {
///     // User confirmed, proceed with SSL
///     generate_ssl(&nginx_config)?;
/// } else {
///     // User declined, skip SSL generation
///     println!("Skipping SSL generation, creating HTTP-only site");
/// }
/// ```
///
/// # User Input
///
/// Accepts the following responses as confirmation:
/// - "y" or "Y"
/// - "yes" or "YES" or any case variation
///
/// All other inputs (including Enter key alone) are treated as "No".
///
/// # Terminal Behavior
///
/// - Flushes stdout to ensure prompt is visible before reading input
/// - Trims whitespace from user input
/// - Handles EOF gracefully (treats as "No")
///
/// # Design Rationale
///
/// This confirmation step prevents failed SSL attempts due to:
/// - Domains not yet pointing to the server
/// - DNS propagation still in progress
/// - Typos in domain names
/// - Testing domains that don't exist
pub fn ask_for_ssl_confirmation(site_name: &str) -> bool {
    println!("");
    println!("⚠️  SSL CONFIGURATION WARNING ⚠️");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("For SSL installation to succeed:");
    println!(
        "• The domain '{}' MUST already be pointing to this server",
        site_name
    );
    println!("• DNS propagation must be complete");
    println!("\nIf SSL generation fails:");
    println!("• The site will still be created with HTTP-only access");
    println!("• You can add SSL later");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");

    print!("\nDo you want to continue with SSL? [y/N]: ");
    io::stdout().flush().unwrap();

    let mut input = String::new();
    io::stdin().read_line(&mut input).unwrap();
    let response = input.trim().to_lowercase();
    response == "y" || response == "yes"
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Tests that generate_ssl fails when SSL root is not configured
    #[test]
    fn test_generate_ssl_without_ssl_root() {
        let config = nginx::config::NginxConfig::new(
            "test.com".to_string(),
            "/var/www/html".to_string(),
            "/etc/nginx/conf.d".to_string(),
            false, // SSL disabled, so ssl_root will be None
        );

        let result = generate_ssl(&config);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .contains("SSL root path is not configured"));
    }

    /// Tests SSL warning message formatting
    #[test]
    fn test_ssl_warning_contains_domain() {
        // This test would need to capture stdout, which is complex
        // For now, we just ensure the function doesn't panic
        print_ssl_warning("example.com");
        // Function should complete without panicking
    }

    /// Tests that ask_for_ssl_confirmation handles various inputs correctly
    #[test]
    #[ignore] // Ignored because it requires user interaction
    fn test_ssl_confirmation_responses() {
        // This test would require mocking stdin, which is complex
        // In a real implementation, you'd use a testing framework
        // that supports stdin mocking
    }
}

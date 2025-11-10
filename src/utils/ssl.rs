use std::io::{self, Write};
use std::process::Command;
use colored::*;

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
/// # Requirements
///
/// - acme.sh must be installed on the system
/// - The domain must be pointing to this server
/// - The webroot directory must exist and be accessible
/// - SSL root directory must be configured in nginx_config
///
/// # Example
///
/// ```
/// let config = NginxConfig::new(
///     "example.com".to_string(),
///     "/var/www/html".to_string(),
///     "/etc/nginx/conf.d".to_string(),
///     Some("/etc/nginx/ssl".to_string())
/// );
/// 
/// match generate_ssl(&config) {
///     Ok(()) => println!("SSL certificates installed successfully"),
///     Err(e) => eprintln!("SSL generation failed: {}", e),
/// }
/// ```
pub fn generate_ssl(nginx_config: &nginx::config::NginxConfig) -> Result<(), String> {
    // Validate SSL root is configured
    let ssl_root = nginx_config.ssl_root.as_ref()
        .ok_or_else(|| "SSL root path is not configured. Cannot generate SSL certificates.".to_string())?;
    
    let site_name = &nginx_config.site_name;
    let webroot = &nginx_config.root;

    println!("\n{} Generating SSL certificate for '{}'", "🔐".bright_blue(), site_name.bright_white());
    println!("{}", "─".repeat(60).bright_black());
    
    // Step 1: Issue the SSL certificate
    println!("  {} Requesting certificate from Let's Encrypt...", "1.".bright_cyan());
    
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
            println!("  {} Certificate already exists, skipping issuance", "ℹ️".bright_yellow());
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
    println!("  {} Installing certificate to nginx directories...", "2.".bright_cyan());
    
    let privkey_path = format!("{}/privkey.pem", ssl_root);
    let fullchain_path = format!("{}/fullchain.pem", ssl_root);
    
    let install_output = Command::new("acme.sh")
        .args(&[
            "--install-cert",
            "-d", site_name,
            "--key-file", &privkey_path,
            "--fullchain-file", &fullchain_path,
            "--reloadcmd", "sudo systemctl reload nginx",
            "--server", "letsencrypt"
        ])
        .output()
        .map_err(|e| {
            format!("Failed to execute acme.sh install command: {}", e)
        })?;
    
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
    println!("{} SSL certificate generated and installed successfully!", "🎉".bright_green());
    println!();
    println!("{} Certificate details:", "📋".bright_blue());
    println!("  • Domain: {}", site_name.bright_white());
    println!("  • Private key: {}", privkey_path.bright_white());
    println!("  • Certificate: {}", fullchain_path.bright_white());
    println!("  • Auto-renewal: {}", "Enabled via acme.sh cron".bright_green());
    
    Ok(())
}

pub fn print_ssl_warning(site_name: &str) {
    println!("");
    println!("⚠️  SSL CONFIGURATION WARNING ⚠️");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("For SSL installation to succeed:");
    println!("• The domain '{}' MUST already be pointing to this server", site_name);
    println!("• DNS propagation must be complete");
    println!("\nIf SSL generation fails:");
    println!("• The site will still be created with HTTP-only access");
    println!("• You can add SSL later");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
}

pub fn ask_for_ssl_confirmation(site_name: &str) -> bool {
    println!("");
    println!("⚠️  SSL CONFIGURATION WARNING ⚠️");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("For SSL installation to succeed:");
    println!("• The domain '{}' MUST already be pointing to this server", site_name);
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
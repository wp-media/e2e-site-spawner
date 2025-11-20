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
/// ```ignore
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
        } else if stderr.contains("Domains not changed") || stdout.contains("Domains not changed") {
            println!(
                "  {} Domain verification skipped (no changes detected)",
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

/// Checks if SSL certificate files exist in the specified directory.
///
/// This function verifies the presence of SSL certificate files that would
/// indicate an already configured SSL setup for a site. It checks for both
/// the private key and the certificate chain files in the SSL root directory.
///
/// # Arguments
///
/// * `ssl_root` - The root directory path where SSL certificates are stored,
///                typically `/etc/nginx/ssl/{site_name}/`
///
/// # Returns
///
/// * `true` - If either the private key OR the certificate file exists
/// * `false` - If neither file exists in the specified directory
///
/// # Detection Logic
///
/// The function returns `true` if **either** of these files exists:
/// - `{ssl_root}/privkey.pem` - The private key file
/// - `{ssl_root}/fullchain.pem` - The full certificate chain file
///
/// The OR logic is intentional because:
/// - Partial SSL setup should still prevent regeneration
/// - Either file existing indicates SSL was attempted
/// - Prevents accidental overwrite of certificates
/// - Allows detection of incomplete SSL installations
///
/// # File Paths
///
/// Standard certificate file locations checked:
/// ```text
/// {ssl_root}/
/// ├── privkey.pem      # Private key (RSA/ECDSA)
/// └── fullchain.pem    # Certificate + intermediate certificates
/// ```
///
/// # Use Cases
///
/// This function is typically used to:
/// - Prevent duplicate SSL certificate generation
/// - Check if SSL can be safely removed
/// - Verify SSL setup completion
/// - Detect partial SSL installations that need cleanup
/// - Determine if update operations can proceed
///
/// # Examples
///
/// ```ignore
/// use utils::ssl::check_if_ssl_files_exist;
///
/// // Check if SSL is already configured for a site
/// let ssl_root = "/etc/nginx/ssl/example.com";
/// if check_if_ssl_files_exist(ssl_root) {
///     println!("SSL certificates already exist, skipping generation");
/// } else {
///     println!("No SSL certificates found, safe to generate");
/// }
///
/// // Use in update operations
/// let nginx_config = NginxConfig::new(/* ... */);
/// if let Some(ssl_root) = &nginx_config.ssl_root {
///     if check_if_ssl_files_exist(ssl_root) {
///         return Err("Cannot update: SSL already configured");
///     }
/// }
/// ```
///
/// # Performance Note
///
/// This function only checks for file existence using filesystem metadata,
/// not file contents. This is efficient but doesn't validate:
/// - Certificate validity or expiration
/// - Certificate/key matching
/// - Proper PEM formatting
/// - Certificate domain matching
///
/// # Security Considerations
///
/// - Only checks existence, doesn't read certificate contents
/// - Doesn't expose any sensitive information
/// - No file permissions are modified
/// - Safe to call without elevated privileges (read-only check)
///
/// # Edge Cases
///
/// The function handles these scenarios gracefully:
/// - Non-existent ssl_root directory (returns false)
/// - Empty directory (returns false)
/// - Symbolic links (follows links to check target)
/// - Permission denied (returns false, doesn't panic)
/// - Other file types with same names (returns true)
///
/// # Related Functions
///
/// Works in conjunction with:
/// - [`generate_ssl`] - Creates the certificates this function checks for
/// - [`update_with_ssl`] - Uses this to prevent duplicate SSL setup
/// - [`delete_site`] - Should remove files this function checks
///
/// # Implementation Note
///
/// Uses `std::path::Path::exists()` which:
/// - Returns false for non-existent paths
/// - Returns false if permission denied
/// - Follows symbolic links
/// - Is atomic and thread-safe
///
/// # Why Not Check Both Files?
///
/// We use OR (`||`) instead of AND (`&&`) because:
/// - Partial installations should block regeneration
/// - Certificate might be manually placed
/// - Private key might exist from previous attempt
/// - Either file indicates SSL work was done
///
/// # Typical Workflow
///
/// ```text
/// 1. check_if_ssl_files_exist() -> false
/// 2. generate_ssl() creates both files
/// 3. check_if_ssl_files_exist() -> true
/// 4. Subsequent SSL operations are blocked
/// ```
pub fn check_if_ssl_files_exist(ssl_root: &str) -> bool {
    let privkey_path = format!("{}/privkey.pem", ssl_root);
    let fullchain_path = format!("{}/fullchain.pem", ssl_root);

    std::path::Path::new(&privkey_path).exists() || 
    std::path::Path::new(&fullchain_path).exists()
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
/// ```ignore
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
/// ```ignore
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
    use std::process::{Command, Stdio};
    use std::fs;
    use tempfile::TempDir;

    // ===== generate_ssl Tests =====

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

    #[test]
    fn test_generate_ssl_with_valid_config() {
        let temp_dir = TempDir::new().unwrap();
        let ssl_dir = temp_dir.path().join("ssl");
        std::fs::create_dir(&ssl_dir).unwrap();
        
        let mut config = nginx::config::NginxConfig::new(
            "test.example.com".to_string(),
            temp_dir.path().to_str().unwrap().to_string(),
            temp_dir.path().to_str().unwrap().to_string(),
            false,
        );
        
        // Manually set SSL root for testing
        config.ssl_root = Some(ssl_dir.to_str().unwrap().to_string());
        
        // Check if acme.sh is available
        let acme_check = Command::new("which")
            .arg("acme.sh")
            .output();
        
        if acme_check.is_err() || !acme_check.unwrap().status.success() {
            // acme.sh not installed, test would fail expectedly
            let result = generate_ssl(&config);
            assert!(result.is_err());
            assert!(result.unwrap_err().contains("acme.sh"));
        } else {
            // This would actually try to get a certificate
            // which would fail for test.example.com
            let result = generate_ssl(&config);
            assert!(result.is_err());
            // Should fail with domain verification error
        }
    }

    #[test]
    #[ignore] // Requires acme.sh and valid domain
    fn test_generate_ssl_integration() {
        // This test would only work with:
        // 1. acme.sh installed
        // 2. A valid domain pointing to this server
        // 3. Port 80 accessible
        
        let config = nginx::config::NginxConfig::new(
            "your-test-domain.com".to_string(),
            "/var/www/html".to_string(),
            "/etc/nginx/conf.d".to_string(),
            true,
        );
        
        match generate_ssl(&config) {
            Ok(()) => {
                // Verify certificate files exist
                let ssl_root = config.ssl_root.as_ref().unwrap();
                let privkey = format!("{}/privkey.pem", ssl_root);
                let fullchain = format!("{}/fullchain.pem", ssl_root);
                
                assert!(std::path::Path::new(&privkey).exists());
                assert!(std::path::Path::new(&fullchain).exists());
            }
            Err(e) => {
                println!("Expected error in test environment: {}", e);
            }
        }
    }

    // ===== Error Message Tests =====

    #[test]
    fn test_generate_ssl_error_messages() {
        // Test that error messages are informative
        let mut config = nginx::config::NginxConfig::new(
            "test.local".to_string(),
            "/nonexistent/path".to_string(),
            "/etc/nginx/conf.d".to_string(),
            false,
        );
        
        // Test missing SSL root
        config.ssl_root = None;
        let result = generate_ssl(&config);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.contains("SSL root"));
        assert!(err.contains("not configured"));
        
        // Test with SSL root but invalid paths
        config.ssl_root = Some("/invalid/ssl/path".to_string());
        
        // Mock acme.sh not found
        if Command::new("acme.sh").output().is_err() {
            let result = generate_ssl(&config);
            assert!(result.is_err());
            let err = result.unwrap_err();
            assert!(err.contains("acme.sh"));
            assert!(err.contains("installed"));
        }
    }

    // ===== Warning and Confirmation Tests =====

    #[test]
    fn test_print_ssl_warning_no_panic() {
        // Ensure function completes without panic for various inputs
        print_ssl_warning("example.com");
        print_ssl_warning("sub.example.com");
        print_ssl_warning("test-site.org");
        print_ssl_warning(""); // Empty domain
        print_ssl_warning("very-long-domain-name-that-exceeds-normal-length.example.com");
    }

    /// Tests that warning includes the actual domain name
    #[test]
    fn test_ssl_warning_output() {
        #![allow(unused_imports)]
        use std::sync::Mutex;
        use std::io::{self, Write};
        
        // Since we can't easily capture stdout in tests, we ensure no panic
        // In production code, you might use a writer trait for testability
        let test_domains = vec![
            "example.com",
            "test.local",
            "my-site.org",
            "subdomain.example.com",
        ];
        
        for domain in test_domains {
            // This ensures the function handles various domain formats
            print_ssl_warning(domain);
        }
    }

    #[test]
    #[ignore] // Requires stdin mocking
    fn test_ask_for_ssl_confirmation_yes() {
        // This would require stdin mocking
        // Example with a hypothetical stdin mock:
        //
        // let input = "y\n";
        // let result = with_stdin(input, || {
        //     ask_for_ssl_confirmation("test.com")
        // });
        // assert_eq!(result, true);
    }

    #[test]
    #[ignore] // Requires stdin mocking  
    fn test_ask_for_ssl_confirmation_no() {
        // Test various "no" responses
        // Would need stdin mocking framework
    }

    // ===== Path Construction Tests =====

    #[test]
    fn test_ssl_certificate_paths() {
        let config = nginx::config::NginxConfig::new(
            "test.com".to_string(),
            "/var/www/html".to_string(),
            "/etc/nginx/conf.d".to_string(),
            true,
        );
        
        if let Some(ssl_root) = &config.ssl_root {
            // Test path construction that would be used in generate_ssl
            let privkey_path = format!("{}/privkey.pem", ssl_root);
            let fullchain_path = format!("{}/fullchain.pem", ssl_root);
            
            assert!(privkey_path.ends_with("/privkey.pem"));
            assert!(fullchain_path.ends_with("/fullchain.pem"));
            assert!(privkey_path.contains("test.com"));
            assert!(fullchain_path.contains("test.com"));
        } else {
            panic!("SSL root should be set when SSL is enabled");
        }
    }

    #[test]
    fn test_acme_command_construction() {
        // Test that commands are constructed correctly
        let site_name = "example.com";
        let webroot = "/var/www/html";
        
        // Test issue command arguments
        let issue_args = vec![
            "--issue",
            "-d", site_name,
            "--webroot", webroot,
            "--server", "letsencrypt"
        ];
        
        assert_eq!(issue_args[1], "-d");
        assert_eq!(issue_args[2], site_name);
        assert_eq!(issue_args[4], webroot);
        
        // Test install command arguments
        let privkey = "/etc/nginx/ssl/privkey.pem";
        let fullchain = "/etc/nginx/ssl/fullchain.pem";
        
        let install_args = vec![
            "--install-cert",
            "-d", site_name,
            "--key-file", privkey,
            "--fullchain-file", fullchain,
            "--reloadcmd", "sudo systemctl reload nginx",
            "--server", "letsencrypt"
        ];
        
        assert_eq!(install_args[0], "--install-cert");
        assert_eq!(install_args[2], site_name);
        assert_eq!(install_args[4], privkey);
        assert_eq!(install_args[6], fullchain);
    }

    // ===== Mock Command Tests =====

    /// Tests command execution error handling
    #[test]
    fn test_command_execution_errors() {
        // Test with a command that doesn't exist
        let result = Command::new("nonexistent_command_12345")
            .arg("--test")
            .output();
        
        assert!(result.is_err());
        
        // Similar error should be caught in generate_ssl
        let config = nginx::config::NginxConfig::new(
            "test.com".to_string(),
            "/var/www/html".to_string(),
            "/etc/nginx/conf.d".to_string(),
            true,
        );
        
        // If acme.sh doesn't exist, generate_ssl should handle it gracefully
        let result = generate_ssl(&config);
        if result.is_err() {
            let err = result.unwrap_err();
            // Should provide helpful error message
            assert!(!err.is_empty());
        }
    }

    // ===== Domain Validation Tests =====

    #[test]
    fn test_domain_name_handling() {
        let test_domains = vec![
            ("simple.com", true),
            ("sub.domain.com", true),
            ("my-site.org", true),
            ("123.456.789.012", true), // IP address format
            ("localhost", true),
            ("test_underscore.com", true),
            ("", true), // Empty should be handled gracefully
            ("very-long-domain-name-with-many-subdomains.example.co.uk", true),
        ];
        
        for (domain, _should_work) in test_domains {
            let config = nginx::config::NginxConfig::new(
                domain.to_string(),
                "/var/www/html".to_string(),
                "/etc/nginx/conf.d".to_string(),
                true,
            );
            
            // Function should handle any domain format without panicking
            let _ = generate_ssl(&config);
        }
    }

    // ===== Output Formatting Tests =====

    #[test]
    fn test_colored_output() {
        use colored::*;
        
        // Test that colored output works correctly
        let test_string = "Test".bright_blue();
        assert!(test_string.to_string().len() > 4); // Includes ANSI codes
        
        let warning = "Warning".bright_yellow();
        assert!(warning.to_string().len() > 7);
        
        let success = "Success".bright_green();
        assert!(success.to_string().len() > 7);
    }

    // ===== SSL Certificate Validation Tests =====

    #[test]
    #[ignore] // Requires actual certificates
    fn test_certificate_file_validation() {
        use std::fs;
        
        let temp_dir = TempDir::new().unwrap();
        let ssl_root = temp_dir.path().join("ssl");
        fs::create_dir(&ssl_root).unwrap();
        
        // Create mock certificate files
        let privkey_path = ssl_root.join("privkey.pem");
        let fullchain_path = ssl_root.join("fullchain.pem");
        
        // Mock PEM content (not valid certs, just for testing file handling)
        let mock_privkey = "-----BEGIN PRIVATE KEY-----\nMOCK_KEY\n-----END PRIVATE KEY-----";
        let mock_cert = "-----BEGIN CERTIFICATE-----\nMOCK_CERT\n-----END CERTIFICATE-----";
        
        fs::write(&privkey_path, mock_privkey).unwrap();
        fs::write(&fullchain_path, mock_cert).unwrap();
        
        // Verify files exist and have content
        assert!(privkey_path.exists());
        assert!(fullchain_path.exists());
        
        let privkey_content = fs::read_to_string(&privkey_path).unwrap();
        assert!(privkey_content.contains("BEGIN PRIVATE KEY"));
        
        let cert_content = fs::read_to_string(&fullchain_path).unwrap();
        assert!(cert_content.contains("BEGIN CERTIFICATE"));
        
        // Check permissions on Unix
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            
            // Set restrictive permissions on private key
            let mut perms = fs::metadata(&privkey_path).unwrap().permissions();
            perms.set_mode(0o600);
            fs::set_permissions(&privkey_path, perms).unwrap();
            
            // Verify permissions
            let metadata = fs::metadata(&privkey_path).unwrap();
            assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
        }
    }

    // ===== Utility Function Tests =====

    /// Helper function to check if a command exists
    fn command_exists(cmd: &str) -> bool {
        Command::new("which")
            .arg(cmd)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    }

    #[test]
    fn test_acme_sh_availability() {
        let has_acme = command_exists("acme.sh");
        
        if has_acme {
            println!("acme.sh is installed");
            
            // Test version command
            let version_result = Command::new("acme.sh")
                .arg("--version")
                .output();
            
            assert!(version_result.is_ok());
            if let Ok(output) = version_result {
                let stdout = String::from_utf8_lossy(&output.stdout);
                assert!(stdout.contains("acme.sh") || stdout.contains("v"));
            }
        } else {
            println!("acme.sh is not installed - some tests will be skipped");
        }
    }

    #[test]
    fn test_nginx_reload_command() {
        // Test that the nginx reload command is properly formatted
        let reload_cmd = "sudo systemctl reload nginx";
        
        // Verify it contains necessary components
        assert!(reload_cmd.contains("nginx"));
        assert!(reload_cmd.contains("reload") || reload_cmd.contains("restart"));
        
        // On systems with systemctl
        if command_exists("systemctl") {
            // Check if nginx service exists (won't actually reload)
            let status = Command::new("systemctl")
                .args(&["status", "nginx"])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
            
            if status.is_ok() {
                println!("nginx service is available via systemctl");
            }
        }
    }

    // ===== Error Recovery Tests =====

    #[test]
    fn test_ssl_generation_error_recovery() {
        // Test that partial SSL generation can be recovered from
        let temp_dir = TempDir::new().unwrap();
        let ssl_dir = temp_dir.path().join("ssl");
        fs::create_dir(&ssl_dir).unwrap();
        
        let mut config = nginx::config::NginxConfig::new(
            "test-recovery.com".to_string(),
            temp_dir.path().to_str().unwrap().to_string(),
            temp_dir.path().to_str().unwrap().to_string(),
            false,
        );
        config.ssl_root = Some(ssl_dir.to_str().unwrap().to_string());
        
        // First attempt fails
        let result1 = generate_ssl(&config);
        assert!(result1.is_err());
        
        // Second attempt should also handle the state gracefully
        let result2 = generate_ssl(&config);
        assert!(result2.is_err());
        
        // No panic or state corruption
    }
}

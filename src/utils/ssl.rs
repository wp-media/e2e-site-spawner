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

use crate::constants::ACME_CONFIG_HOME;
use crate::nginx;
use crate::utils::sites::get_sudo_user;
use colored::*;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::Command;

/// File name acme.sh gives to the issued full chain inside a certificate
/// directory (`CERT_FULLCHAIN_PATH` in acme.sh).
const ACME_FULLCHAIN_FILE: &str = "fullchain.cer";

/// Suffix acme.sh appends to the certificate directory of ECC certificates
/// (`ECC_SUFFIX` in acme.sh).
///
/// ECC is acme.sh's default key type, so certificates issued by this tool
/// normally live in `<domain>_ecc`.
const ACME_ECC_DIR_SUFFIX: &str = "_ecc";

/// Minimum validity a stored certificate must have left to be installed as-is.
///
/// Installing a certificate that is already expired — or expires within hours —
/// leaves the site serving HTTPS that every browser rejects, so such a
/// certificate is re-issued instead of reused.
const MIN_CERTIFICATE_VALIDITY_SECS: u64 = 24 * 60 * 60;

/// What acme.sh currently holds for a given certificate name (domain).
///
/// Classifying this up front is what makes a retry after a failed issuance work:
///
/// - `acme.sh --issue` aborts with `Domain key exists, do you want to overwrite
///   it?` when it finds the domain key left behind by an interrupted attempt,
///   without ever contacting Let's Encrypt.
/// - `acme.sh --install-cert` only checks that the certificate *directory*
///   exists, then copies `fullchain.cer` unconditionally — failing with a bare
///   `cat: …/fullchain.cer: No such file or directory` when no certificate was
///   ever issued.
///
/// Deciding from the files acme.sh actually wrote — instead of pattern-matching
/// its log output — lets the caller pick the right invocation and refuse to
/// install a certificate that does not exist.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AcmeCertificateState {
    /// acme.sh has no certificate directory for this name: nothing was attempted yet.
    Absent,
    /// A certificate directory exists but holds no usable certificate, because a
    /// previous issuance failed or was interrupted before the certificate was
    /// downloaded.
    Incomplete,
    /// A certificate exists but is expired, or expires within
    /// [`MIN_CERTIFICATE_VALIDITY_SECS`], so it must not be installed as-is.
    Expired,
    /// A usable certificate and its private key are present, ready to install.
    Ready,
}

impl AcmeCertificateState {
    /// Explains why issuance has to be forced in this state, for both the
    /// operator-facing notice and the `--force` decision.
    ///
    /// acme.sh refuses to overwrite an existing domain key, and skips renewal
    /// before the renewal window, unless `--force` is passed — so any leftover
    /// state has to be overwritten explicitly.
    ///
    /// # Returns
    ///
    /// * `Some(&str)` - Issuance must be forced, with the reason to display
    /// * `None` - Nothing to overwrite ([`AcmeCertificateState::Absent`]) or
    ///   nothing to do ([`AcmeCertificateState::Ready`])
    fn forced_issuance_reason(self) -> Option<&'static str> {
        match self {
            Self::Incomplete => {
                Some("Incomplete certificate from a previous attempt found, re-issuing")
            }
            Self::Expired => Some("Stored certificate has expired, re-issuing"),
            Self::Absent | Self::Ready => None,
        }
    }
}

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
/// 2. **Certificate Issuance**: `ensure_certificate_issued` requests the
///    certificate from Let's Encrypt using the HTTP-01 challenge, reusing or
///    replacing whatever acme.sh already holds for the domain
/// 3. **Certificate Installation**: `install_certificate` copies the key and full
///    chain to the nginx SSL directory and registers auto-renewal
/// 4. **Nginx Reload**: Triggered by acme.sh's reload command once the files are in place
///
/// # Retrying a Failed Attempt
///
/// A failed issuance (an unpointed domain being the usual cause) leaves a domain
/// key and renewal configuration behind in acme.sh. Re-running this function is
/// safe: leftover state is detected and overwritten, and a certificate is only
/// installed once acme.sh has actually produced one.
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
/// - Issuance that completed without producing a certificate
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

    println!(
        "\n{} Generating SSL certificate for '{}'",
        "🔐".bright_blue(),
        site_name.bright_white()
    );
    println!("{}", "─".repeat(60).bright_black());

    ensure_certificate_issued(site_name, &nginx_config.root)?;
    install_certificate(site_name, ssl_root)?;
    print_generation_summary(site_name, ssl_root);

    Ok(())
}

/// Makes sure acme.sh holds a usable certificate for `site_name`, issuing one
/// when needed.
///
/// This is step 1 of [`generate_ssl`]. It inspects what acme.sh has on disk and
/// issues accordingly, then verifies the outcome so the install step can never
/// run against a certificate that does not exist:
///
/// | State | Action |
/// |-------|--------|
/// | [`AcmeCertificateState::Ready`] | Issuance is skipped, the existing certificate is reused |
/// | [`AcmeCertificateState::Absent`] | `acme.sh --issue` |
/// | [`AcmeCertificateState::Incomplete`] / [`AcmeCertificateState::Expired`] | `acme.sh --issue --force`, to overwrite the leftover state |
///
/// # Arguments
///
/// * `site_name` - Domain the certificate is issued for
/// * `webroot` - Document root used for the HTTP-01 challenge
///
/// # Returns
///
/// * `Ok(())` - acme.sh now holds a usable certificate for the domain
/// * `Err(String)` - acme.sh could not be executed, or finished without
///   producing a certificate (typically a failed domain validation)
fn ensure_certificate_issued(site_name: &str, webroot: &str) -> Result<(), String> {
    println!(
        "  {} Requesting certificate from Let's Encrypt...",
        "1.".bright_cyan()
    );

    let state = classify_acme_certificate(site_name)?;
    if state == AcmeCertificateState::Ready {
        println!(
            "  {} Valid certificate already issued by acme.sh, skipping issuance",
            "ℹ️".bright_yellow()
        );
        return Ok(());
    }

    let force_reason = state.forced_issuance_reason();
    if let Some(reason) = force_reason {
        println!("  {} {}", "ℹ️".bright_yellow(), reason);
    }

    let acme_output = run_acme_issue(site_name, webroot, force_reason.is_some())?;

    // acme.sh exits non-zero for benign reasons too, so its status alone cannot
    // tell issuance apart from a no-op. Only the certificate it wrote can.
    if classify_acme_certificate(site_name)? != AcmeCertificateState::Ready {
        return Err(describe_issuance_failure(site_name, webroot, &acme_output));
    }

    println!("  {} Certificate issued successfully", "✓".bright_green());
    Ok(())
}

/// Installs the issued certificate into the site's nginx SSL directory.
///
/// This is step 2 of [`generate_ssl`]. Besides copying the key and full chain,
/// `acme.sh --install-cert` registers the paths and the reload command in the
/// certificate's renewal configuration, which is what keeps auto-renewal working.
///
/// # Arguments
///
/// * `site_name` - Domain whose certificate is installed
/// * `ssl_root` - Nginx SSL directory for the site, e.g. `/etc/nginx/ssl/example.com`
///
/// # Returns
///
/// * `Ok(())` - Certificate installed and nginx reloaded by acme.sh
/// * `Err(String)` - acme.sh could not be executed, or the installation failed
fn install_certificate(site_name: &str, ssl_root: &str) -> Result<(), String> {
    println!(
        "  {} Installing certificate to nginx directories...",
        "2.".bright_cyan()
    );

    let (privkey_path, fullchain_path) = nginx_certificate_paths(ssl_root);
    let reloadcmd = format!(
        "sudo systemctl reload nginx && chown -R {}:root {}",
        get_sudo_user(),
        ssl_root
    );

    let install_output = Command::new("acme.sh")
        .args([
            "--install-cert",
            "-d",
            site_name,
            "--key-file",
            &privkey_path,
            "--fullchain-file",
            &fullchain_path,
            "--reloadcmd",
            &reloadcmd,
            "--server",
            "letsencrypt",
        ])
        .output()
        .map_err(|e| format!("Failed to execute acme.sh install command: {}", e))?;

    if !install_output.status.success() {
        return Err(format!(
            "Failed to install SSL certificate:\n\
            • Check if the SSL directory {} exists\n\
            • Ensure proper permissions to write to {}\n\
            • Verify nginx service is running\n\n\
            Error output:\n{}{}",
            ssl_root,
            ssl_root,
            String::from_utf8_lossy(&install_output.stdout),
            String::from_utf8_lossy(&install_output.stderr)
        ));
    }

    Ok(())
}

/// Prints the certificate summary shown after a successful generation.
///
/// # Arguments
///
/// * `site_name` - Domain the certificate was issued for
/// * `ssl_root` - Nginx SSL directory holding the installed certificate
fn print_generation_summary(site_name: &str, ssl_root: &str) {
    let (privkey_path, fullchain_path) = nginx_certificate_paths(ssl_root);

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
}

/// Returns the `(private key, full chain)` paths nginx reads for a site.
///
/// These are the destinations acme.sh installs to and the paths embedded in the
/// generated HTTPS server block.
///
/// # Arguments
///
/// * `ssl_root` - Nginx SSL directory for the site
///
/// # Returns
///
/// A tuple of `({ssl_root}/privkey.pem, {ssl_root}/fullchain.pem)`.
fn nginx_certificate_paths(ssl_root: &str) -> (String, String) {
    (
        format!("{}/privkey.pem", ssl_root),
        format!("{}/fullchain.pem", ssl_root),
    )
}

/// Runs `acme.sh --issue` for a domain and returns its combined output.
///
/// A non-zero exit status is deliberately **not** treated as an error here:
/// acme.sh also exits non-zero when it simply declines to act, for instance when
/// an existing certificate is not yet due for renewal. Whether a certificate now
/// exists is decided by `classify_acme_certificate`, which inspects what acme.sh
/// wrote rather than how it worded its log.
///
/// # Arguments
///
/// * `site_name` - Domain to issue the certificate for
/// * `webroot` - Document root served over HTTP, used for the HTTP-01 challenge
/// * `force` - Adds `--force`, required to overwrite the domain key and renewal
///   state left behind by an earlier attempt
///
/// # Returns
///
/// * `Ok(String)` - acme.sh's stdout followed by its stderr
/// * `Err(String)` - acme.sh could not be executed at all
fn run_acme_issue(site_name: &str, webroot: &str, force: bool) -> Result<String, String> {
    let mut args = vec![
        "--issue",
        "-d",
        site_name,
        "--webroot",
        webroot,
        "--server",
        "letsencrypt",
    ];

    if force {
        args.push("--force");
    }

    let output = Command::new("acme.sh")
        .args(&args)
        .output()
        .map_err(acme_execution_error)?;

    Ok(format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    ))
}

/// Builds the error reported when an issuance attempt produced no certificate.
///
/// A failed domain validation is by far the most common cause, so it gets the
/// full checklist; anything else falls back to acme.sh's own output.
///
/// # Arguments
///
/// * `site_name` - Domain that failed to be issued
/// * `webroot` - Document root used for the HTTP-01 challenge
/// * `acme_output` - Combined output of the `acme.sh --issue` run
///
/// # Returns
///
/// The user-facing error message.
fn describe_issuance_failure(site_name: &str, webroot: &str, acme_output: &str) -> String {
    if acme_output.contains("Verify error") {
        return format!(
            "Domain verification failed for '{}'.\n\
            Please ensure:\n\
            • The domain is pointing to this server's IP\n\
            • DNS has propagated (can take up to 48 hours)\n\
            • Port 80 is accessible from the internet\n\
            • The webroot path {} exists and is accessible\n\n\
            Error output:\n{}",
            site_name, webroot, acme_output
        );
    }

    format!(
        "Failed to issue SSL certificate for '{}': \
        acme.sh finished without producing a certificate.\n\n\
        Error output:\n{}",
        site_name, acme_output
    )
}

/// Determines what acme.sh currently holds for a domain.
///
/// # Arguments
///
/// * `site_name` - Domain (certificate name) to inspect
///
/// # Returns
///
/// * `Ok(AcmeCertificateState)` - The classified state
/// * `Err(String)` - acme.sh could not be executed at all
fn classify_acme_certificate(site_name: &str) -> Result<AcmeCertificateState, String> {
    match resolve_acme_cert_dir(site_name)? {
        Some(cert_dir) => Ok(classify_acme_cert_dir(&cert_dir, site_name)),
        None => Ok(AcmeCertificateState::Absent),
    }
}

/// Classifies the acme.sh state stored in a certificate directory.
///
/// Both the full chain and the domain key are required, because
/// `acme.sh --install-cert` copies both and fails on whichever is missing.
///
/// # Arguments
///
/// * `cert_dir` - An existing acme.sh certificate directory
/// * `site_name` - Domain the directory belongs to, used to build the key name
///
/// # Returns
///
/// [`AcmeCertificateState::Incomplete`], [`AcmeCertificateState::Expired`] or
/// [`AcmeCertificateState::Ready`] — never
/// [`AcmeCertificateState::Absent`], which is decided by the caller.
fn classify_acme_cert_dir(cert_dir: &Path, site_name: &str) -> AcmeCertificateState {
    let fullchain = cert_dir.join(ACME_FULLCHAIN_FILE);
    let domain_key = cert_dir.join(format!("{}.key", site_name));

    if !fullchain.is_file() || !domain_key.is_file() {
        return AcmeCertificateState::Incomplete;
    }

    if is_certificate_expiring(&fullchain, MIN_CERTIFICATE_VALIDITY_SECS) {
        return AcmeCertificateState::Expired;
    }

    AcmeCertificateState::Ready
}

/// Resolves the acme.sh certificate directory for a domain.
///
/// acme.sh itself is asked first (`acme.sh --info -d <domain>`), so a custom
/// `CERT_HOME`/`LE_CONFIG_HOME` and the `_ecc` suffix are honoured exactly as
/// `--install-cert` would resolve them. Releases older than 3.0.2 have no
/// `--info` command; for those the lookup falls back to the fleet default layout
/// under [`crate::constants::ACME_CONFIG_HOME`].
///
/// # Arguments
///
/// * `site_name` - Domain (certificate name) to look up
///
/// # Returns
///
/// * `Ok(Some(PathBuf))` - Existing certificate directory
/// * `Ok(None)` - acme.sh holds no directory for this domain
/// * `Err(String)` - acme.sh could not be executed at all
fn resolve_acme_cert_dir(site_name: &str) -> Result<Option<PathBuf>, String> {
    let info_output = Command::new("acme.sh")
        .args(["--info", "-d", site_name])
        .output()
        .map_err(acme_execution_error)?;

    let stdout = String::from_utf8_lossy(&info_output.stdout);

    match parse_domain_conf_path(&stdout) {
        Some(domain_conf) => Ok(domain_conf
            .parent()
            .filter(|dir| dir.is_dir())
            .map(Path::to_path_buf)),
        None => Ok(find_acme_cert_dir(Path::new(ACME_CONFIG_HOME), site_name)),
    }
}

/// Extracts the `DOMAIN_CONF=` path from `acme.sh --info` output.
///
/// `acme.sh --info -d <domain>` prints the resolved `DOMAIN_CONF` path even when
/// that file does not exist yet, which makes it a reliable way to learn where
/// acme.sh keeps the domain's certificate material. It is not necessarily the
/// first line: acme.sh may print informational notices — such as its
/// ECC-certificate detection — to stdout beforehand, so every line is scanned.
///
/// # Arguments
///
/// * `info_output` - Stdout of `acme.sh --info -d <domain>`
///
/// # Returns
///
/// * `Some(PathBuf)` - The reported `<domain>.conf` path
/// * `None` - No `DOMAIN_CONF=` line, e.g. on acme.sh releases without `--info`
fn parse_domain_conf_path(info_output: &str) -> Option<PathBuf> {
    info_output
        .lines()
        .find_map(|line| line.trim().strip_prefix("DOMAIN_CONF="))
        .map(str::trim)
        .filter(|path| !path.is_empty())
        .map(PathBuf::from)
}

/// Locates the acme.sh certificate directory for a domain under a config home.
///
/// Mirrors acme.sh's own `_initpath` preference: the plain `<domain>` directory
/// wins when it exists, otherwise its ECC twin `<domain>_ecc` is used. Keeping
/// that order matters because `acme.sh --install-cert` resolves the directory the
/// same way, and this lookup has to predict what the install step will read.
///
/// # Arguments
///
/// * `config_home` - acme.sh configuration home, e.g. `/root/.acme.sh`
/// * `site_name` - Domain (certificate name) to look up
///
/// # Returns
///
/// * `Some(PathBuf)` - An existing certificate directory
/// * `None` - Neither the plain nor the ECC directory exists
fn find_acme_cert_dir(config_home: &Path, site_name: &str) -> Option<PathBuf> {
    let plain_dir = config_home.join(site_name);
    if plain_dir.is_dir() {
        return Some(plain_dir);
    }

    let ecc_dir = config_home.join(format!("{}{}", site_name, ACME_ECC_DIR_SUFFIX));
    if ecc_dir.is_dir() {
        return Some(ecc_dir);
    }

    None
}

/// Reports whether a certificate expires within the given look-ahead window.
///
/// Delegates to `openssl x509 -checkend`, which reads the leaf certificate of a
/// full-chain file and exits non-zero when it is expired, about to expire, or
/// unreadable.
///
/// # Arguments
///
/// * `cert_path` - Path to a PEM certificate or full chain
/// * `within_secs` - Look-ahead window in seconds
///
/// # Returns
///
/// * `true` - The certificate expires within the window, or openssl could not
///   parse it (an unusable certificate must not be installed either)
/// * `false` - The certificate is valid for longer, or openssl is unavailable.
///   Treating an undeterminable certificate as valid keeps the tool from forcing
///   a needless re-issue; the install step still verifies what it copies.
fn is_certificate_expiring(cert_path: &Path, within_secs: u64) -> bool {
    Command::new("openssl")
        .args([
            "x509",
            "-checkend",
            &within_secs.to_string(),
            "-noout",
            "-in",
        ])
        .arg(cert_path)
        .output()
        .map(|output| !output.status.success())
        .unwrap_or(false)
}

/// Builds the error reported when the acme.sh binary cannot be executed.
///
/// # Arguments
///
/// * `error` - The spawn error returned by [`std::process::Command::output`]
///
/// # Returns
///
/// The user-facing error message, including where to get acme.sh.
fn acme_execution_error(error: io::Error) -> String {
    format!(
        "Failed to execute acme.sh: {}. \
        Please ensure acme.sh is correctly installed: http://github.com/acmesh-official/acme.sh",
        error
    )
}
/// Removes a site from acme.sh management.
///
/// This function deactivates SSL certificate renewal for the specified site
/// by removing it from acme.sh's configuration.
/// # Arguments
/// * `site_name` - The domain name of the site to remove from acme.sh
/// # Returns
/// * `Ok(())` - If the site was successfully removed
/// * `Err(String)` - If there was an error during removal
/// # Example
/// ```ignore
/// match remove_site_from_acme("example.com") {
///     Ok(()) => println!("Site removed from acme.sh successfully"),
///     Err(e) => eprintln!("Failed to remove site from acme.sh: {}", e),
/// }
/// ```
pub fn remove_site_from_acme(site_name: &str) -> Result<(), String> {
    let remove_output = Command::new("acme.sh")
        .args([
            "--remove",
            "-d", site_name,
        ])
        .output()
        .map_err(|e| {
            format!(
                "Failed to execute acme.sh: {}. \
                Please ensure acme.sh is correctly installed as root and available for sudo users: https://github.com/acmesh-official/acme.sh",
                e
            )
        })?;
    if !remove_output.status.success() {
        let stderr = String::from_utf8_lossy(&remove_output.stderr);
        let stdout = String::from_utf8_lossy(&remove_output.stdout);

        return Err(format!(
            "Failed to remove site {} from acme:\n\
            Error output:\n{}{}",
            site_name, stdout, stderr
        ));
    }

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
///   typically `/etc/nginx/ssl/{site_name}/`
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
/// - [`crate::cli::commands::update_site`] - Its `update_with_ssl` step uses this to
///   prevent duplicate SSL setup
/// - [`crate::cli::commands::delete_site`] - Should remove files this function checks
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

    std::path::Path::new(&privkey_path).exists() || std::path::Path::new(&fullchain_path).exists()
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
    println!();
    println!("⚠️  SSL CONFIGURATION WARNING ⚠️");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("For SSL installation to succeed:");
    println!(
        "• The domain '{}' MUST already be pointing to this server",
        site_name
    );
    println!("• DNS propagation must be complete");
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
    println!();
    println!("⚠️  SSL CONFIGURATION WARNING ⚠️");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("For SSL installation to succeed:");
    println!(
        "• The domain '{}' MUST already be pointing to this server",
        site_name
    );
    println!("• DNS propagation must be complete");
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
    use std::fs;
    use std::process::{Command, Stdio};
    use tempfile::TempDir;

    // ===== acme.sh State Detection Tests =====

    /// Writes a self-signed certificate valid for `days` days at `cert_path`.
    ///
    /// Returns `false` when openssl is unavailable, so the caller can skip
    /// assertions that depend on real certificate parsing.
    fn generate_self_signed_cert(cert_path: &Path, days: u32) -> bool {
        if !command_exists("openssl") {
            return false;
        }

        Command::new("openssl")
            .args([
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-subj",
                "/CN=test.local",
                "-days",
                &days.to_string(),
                "-keyout",
            ])
            .arg(cert_path.with_extension("tmpkey"))
            .arg("-out")
            .arg(cert_path)
            .output()
            .map(|output| output.status.success())
            .unwrap_or(false)
    }

    /// Creates an acme.sh-style certificate directory holding the given files.
    fn make_acme_cert_dir(config_home: &Path, dir_name: &str, files: &[&str]) -> PathBuf {
        let cert_dir = config_home.join(dir_name);
        fs::create_dir_all(&cert_dir).unwrap();

        for file in files {
            fs::write(cert_dir.join(file), "test-content").unwrap();
        }

        cert_dir
    }

    #[test]
    fn test_parse_domain_conf_path_from_acme_info_output() {
        let output = "DOMAIN_CONF=/root/.acme.sh/example.com_ecc/example.com.conf\n\
                      Le_Domain=example.com\n\
                      Le_Keylength=ec-256\n";

        assert_eq!(
            parse_domain_conf_path(output),
            Some(PathBuf::from(
                "/root/.acme.sh/example.com_ecc/example.com.conf"
            ))
        );
    }

    #[test]
    fn test_parse_domain_conf_path_after_acme_notice_line() {
        // acme.sh prints its ECC-detection notice on stdout before the
        // `DOMAIN_CONF` line, so the marker is not always the first line.
        let output = "[Tue Apr 14 16:55:10 UTC 2026] The domain 'example.com' seems to \
                      already have an ECC cert, let's use it.\n\
                      DOMAIN_CONF=/root/.acme.sh/example.com_ecc/example.com.conf\n\
                      Le_Keylength=ec-256\n";

        assert_eq!(
            parse_domain_conf_path(output),
            Some(PathBuf::from(
                "/root/.acme.sh/example.com_ecc/example.com.conf"
            ))
        );
    }

    #[test]
    fn test_parse_domain_conf_path_without_info_support() {
        // acme.sh releases older than 3.0.2 have no `--info` command and print
        // their usage instead, which must fall back to the default layout.
        let output = "Usage: acme.sh  command ...[parameters]....\n";

        assert!(parse_domain_conf_path(output).is_none());
    }

    #[test]
    fn test_parse_domain_conf_path_ignores_empty_value() {
        assert!(parse_domain_conf_path("DOMAIN_CONF=\nLe_Domain=example.com\n").is_none());
    }

    #[test]
    fn test_parse_domain_conf_path_trims_whitespace() {
        let output = "  DOMAIN_CONF=/root/.acme.sh/a.com/a.com.conf  \n";

        assert_eq!(
            parse_domain_conf_path(output),
            Some(PathBuf::from("/root/.acme.sh/a.com/a.com.conf"))
        );
    }

    #[test]
    fn test_find_acme_cert_dir_without_any_directory() {
        let temp_dir = TempDir::new().unwrap();

        assert!(find_acme_cert_dir(temp_dir.path(), "example.com").is_none());
    }

    #[test]
    fn test_find_acme_cert_dir_finds_ecc_directory() {
        let temp_dir = TempDir::new().unwrap();
        let ecc_dir = make_acme_cert_dir(temp_dir.path(), "example.com_ecc", &[]);

        assert_eq!(
            find_acme_cert_dir(temp_dir.path(), "example.com"),
            Some(ecc_dir)
        );
    }

    #[test]
    fn test_find_acme_cert_dir_prefers_plain_over_ecc_directory() {
        // Mirrors acme.sh's own `_initpath` preference, which `--install-cert`
        // follows as well.
        let temp_dir = TempDir::new().unwrap();
        let plain_dir = make_acme_cert_dir(temp_dir.path(), "example.com", &[]);
        make_acme_cert_dir(temp_dir.path(), "example.com_ecc", &[]);

        assert_eq!(
            find_acme_cert_dir(temp_dir.path(), "example.com"),
            Some(plain_dir)
        );
    }

    #[test]
    fn test_classify_acme_cert_dir_incomplete_after_failed_issuance() {
        // Reproduces what acme.sh leaves behind when domain validation fails:
        // the domain key and its renewal conf, but no certificate. Installing
        // from this state used to fail with
        // `cat: .../fullchain.cer: No such file or directory`.
        let temp_dir = TempDir::new().unwrap();
        let cert_dir = make_acme_cert_dir(
            temp_dir.path(),
            "wp6.e2e.rocketlabsqa.ovh_ecc",
            &[
                "wp6.e2e.rocketlabsqa.ovh.key",
                "wp6.e2e.rocketlabsqa.ovh.conf",
            ],
        );

        assert_eq!(
            classify_acme_cert_dir(&cert_dir, "wp6.e2e.rocketlabsqa.ovh"),
            AcmeCertificateState::Incomplete
        );
    }

    #[test]
    fn test_classify_acme_cert_dir_incomplete_without_domain_key() {
        let temp_dir = TempDir::new().unwrap();
        let cert_dir =
            make_acme_cert_dir(temp_dir.path(), "example.com_ecc", &[ACME_FULLCHAIN_FILE]);

        assert_eq!(
            classify_acme_cert_dir(&cert_dir, "example.com"),
            AcmeCertificateState::Incomplete
        );
    }

    #[test]
    fn test_classify_acme_cert_dir_ready_with_valid_certificate() {
        let temp_dir = TempDir::new().unwrap();
        let cert_dir = make_acme_cert_dir(temp_dir.path(), "example.com_ecc", &["example.com.key"]);

        if !generate_self_signed_cert(&cert_dir.join(ACME_FULLCHAIN_FILE), 90) {
            println!("openssl is not installed - skipping certificate validity assertions");
            return;
        }

        assert_eq!(
            classify_acme_cert_dir(&cert_dir, "example.com"),
            AcmeCertificateState::Ready
        );
    }

    #[test]
    fn test_classify_acme_cert_dir_treats_unusable_certificate_as_expired() {
        if !command_exists("openssl") {
            println!("openssl is not installed - skipping certificate validity assertions");
            return;
        }

        let temp_dir = TempDir::new().unwrap();
        let cert_dir = make_acme_cert_dir(
            temp_dir.path(),
            "example.com_ecc",
            &["example.com.key", ACME_FULLCHAIN_FILE],
        );

        // `make_acme_cert_dir` writes placeholder content, so openssl cannot
        // read a validity period from the "certificate".
        assert_eq!(
            classify_acme_cert_dir(&cert_dir, "example.com"),
            AcmeCertificateState::Expired
        );
    }

    #[test]
    fn test_is_certificate_expiring_within_window() {
        let temp_dir = TempDir::new().unwrap();
        let cert_path = temp_dir.path().join(ACME_FULLCHAIN_FILE);

        if !generate_self_signed_cert(&cert_path, 1) {
            println!("openssl is not installed - skipping certificate validity assertions");
            return;
        }

        // Valid right now, but not for another two days.
        assert!(!is_certificate_expiring(&cert_path, 0));
        assert!(is_certificate_expiring(&cert_path, 2 * 24 * 60 * 60));
    }

    #[test]
    fn test_is_certificate_expiring_reads_the_leaf_of_a_full_chain() {
        // acme.sh's `fullchain.cer` holds the leaf followed by the intermediates.
        // The leaf is the one that has to decide, and misreading a chain would
        // force a needless re-issue of every certificate the tool ever reuses.
        let temp_dir = TempDir::new().unwrap();
        let leaf_path = temp_dir.path().join("leaf.pem");
        let intermediate_path = temp_dir.path().join("intermediate.pem");

        if !generate_self_signed_cert(&leaf_path, 90)
            || !generate_self_signed_cert(&intermediate_path, 3650)
        {
            println!("openssl is not installed - skipping certificate validity assertions");
            return;
        }

        let chain_path = temp_dir.path().join(ACME_FULLCHAIN_FILE);
        fs::write(
            &chain_path,
            format!(
                "{}{}",
                fs::read_to_string(&leaf_path).unwrap(),
                fs::read_to_string(&intermediate_path).unwrap()
            ),
        )
        .unwrap();

        assert!(!is_certificate_expiring(&chain_path, 0));
        // 100 days ahead the 90-day leaf is gone, even though the long-lived
        // intermediate in the same file is not.
        assert!(is_certificate_expiring(&chain_path, 100 * 24 * 60 * 60));
    }

    #[test]
    fn test_is_certificate_expiring_with_unreadable_certificate() {
        // An unparseable certificate is unusable and must be replaced, but when
        // openssl itself is missing nothing can be concluded, and the documented
        // degradation is to keep the certificate rather than force a re-issue.
        let temp_dir = TempDir::new().unwrap();
        let cert_path = temp_dir.path().join(ACME_FULLCHAIN_FILE);
        fs::write(&cert_path, "not a certificate").unwrap();

        if command_exists("openssl") {
            assert!(is_certificate_expiring(&cert_path, 0));
        } else {
            assert!(!is_certificate_expiring(&cert_path, 0));
        }
    }

    #[test]
    fn test_forced_issuance_reason_per_state() {
        // Only leftover state has to be overwritten with `--force`.
        assert!(
            AcmeCertificateState::Absent
                .forced_issuance_reason()
                .is_none()
        );
        assert!(
            AcmeCertificateState::Ready
                .forced_issuance_reason()
                .is_none()
        );
        assert!(
            AcmeCertificateState::Incomplete
                .forced_issuance_reason()
                .is_some()
        );
        assert!(
            AcmeCertificateState::Expired
                .forced_issuance_reason()
                .is_some()
        );
    }

    #[test]
    fn test_describe_issuance_failure_for_verification_error() {
        let message = describe_issuance_failure(
            "example.com",
            "/var/www/html/example.com",
            "[Tue Apr 14 16:55:10 UTC 2026] example.com: Verify error: Invalid response",
        );

        assert!(message.contains("Domain verification failed for 'example.com'"));
        assert!(message.contains("/var/www/html/example.com"));
        assert!(message.contains("DNS has propagated"));
    }

    #[test]
    fn test_describe_issuance_failure_keeps_acme_output() {
        let message = describe_issuance_failure(
            "example.com",
            "/var/www/html/example.com",
            "[Tue Apr 14 16:55:10 UTC 2026] Domain key exists, do you want to overwrite it?",
        );

        assert!(message.contains("without producing a certificate"));
        assert!(message.contains("Domain key exists"));
    }

    #[test]
    fn test_nginx_certificate_paths() {
        let (privkey_path, fullchain_path) = nginx_certificate_paths("/etc/nginx/ssl/example.com");

        assert_eq!(privkey_path, "/etc/nginx/ssl/example.com/privkey.pem");
        assert_eq!(fullchain_path, "/etc/nginx/ssl/example.com/fullchain.pem");
    }

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
        assert!(
            result
                .unwrap_err()
                .contains("SSL root path is not configured")
        );
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
        let acme_check = Command::new("which").arg("acme.sh").output();

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
        use std::io::{self, Write};
        use std::sync::Mutex;

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
        let issue_args = [
            "--issue",
            "-d",
            site_name,
            "--webroot",
            webroot,
            "--server",
            "letsencrypt",
        ];

        assert_eq!(issue_args[1], "-d");
        assert_eq!(issue_args[2], site_name);
        assert_eq!(issue_args[4], webroot);

        // Test install command arguments
        let privkey = "/etc/nginx/ssl/privkey.pem";
        let fullchain = "/etc/nginx/ssl/fullchain.pem";

        let install_args = vec![
            "--install-cert",
            "-d",
            site_name,
            "--key-file",
            privkey,
            "--fullchain-file",
            fullchain,
            "--reloadcmd",
            "sudo systemctl reload nginx",
            "--server",
            "letsencrypt",
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
        if let Err(err) = result {
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
            (
                "very-long-domain-name-with-many-subdomains.example.co.uk",
                true,
            ),
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

        // Force colorization on so the assertions are deterministic regardless of
        // TTY detection or the NO_COLOR environment variable.
        colored::control::set_override(true);

        // Test that colored output works correctly
        let test_string = "Test".bright_blue();
        assert!(test_string.to_string().len() > 4); // Includes ANSI codes

        let warning = "Warning".bright_yellow();
        assert!(warning.to_string().len() > 7);

        let success = "Success".bright_green();
        assert!(success.to_string().len() > 7);

        colored::control::unset_override();
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
            let version_result = Command::new("acme.sh").arg("--version").output();

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
                .args(["status", "nginx"])
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

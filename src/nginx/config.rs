//! Nginx configuration module for the e2e-site-spawner.
//!
//! This module provides functionality for managing Nginx configuration files,
//! including creation, validation, and template-based generation of site configurations.
//!
//! # Overview
//!
//! The module handles:
//! - Loading and parsing Nginx configuration files
//! - Validating configuration settings and syntax
//! - Generating new configuration files from templates
//! - Supporting both HTTP and HTTPS protocols
//! - Path validation and security checks
//!
//! # Examples
//!
//! ```ignore
//! use nginx::config::{NginxConfig, NginxProtocol};
//!
//! // Create a new site configuration
//! let config = NginxConfig::new(
//!     "example.com".to_string(),
//!     "/var/www/sites".to_string(),
//!     "/etc/nginx/conf.d".to_string(),
//!     true, // Enable SSL
//! );
//!
//! // Validate the configuration
//! config.validate()?;
//!
//! // Generate HTTP and HTTPS configurations
//! let http_config = config.generate_config(NginxProtocol::Http);
//! let https_config = config.generate_config(NginxProtocol::Https);
//! ```

use crate::constants::{NGINX_HTTP_TEMPLATE, NGINX_HTTPS_TEMPLATE, SITES_SSL_PATH};
use std::path::Path;
use std::process::Command;

/// Represents the protocol type for Nginx configuration.
///
/// This enum determines which configuration template will be used
/// and what port bindings and SSL settings will be applied.
///
/// # Variants
///
/// - `Http` - Standard HTTP protocol on port 80
/// - `Https` - Secure HTTPS protocol on port 443 with SSL/TLS
///
/// # Examples
///
/// ```ignore
/// let protocol = NginxProtocol::Https;
/// match protocol {
///     NginxProtocol::Http => println!("Using port 80"),
///     NginxProtocol::Https => println!("Using port 443 with SSL"),
/// }
/// ```
///
/// # Implementation Details
///
/// The protocol affects:
/// - Which template is used for configuration generation
/// - Port bindings (80 for HTTP, 443 for HTTPS)
/// - SSL certificate configuration
/// - Security headers and redirects
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum NginxProtocol {
    /// HTTP protocol - serves content on port 80 without encryption.
    /// 
    /// # Characteristics
    /// - No encryption
    /// - Port 80
    /// - Faster but insecure
    /// - Suitable for development or internal networks
    Http,
    
    /// HTTPS protocol - serves content on port 443 with SSL/TLS encryption.
    /// 
    /// # Characteristics
    /// - TLS encryption
    /// - Port 443
    /// - Requires SSL certificates
    /// - Recommended for production
    Https,
}

/// Represents the complete configuration for an Nginx site.
///
/// This struct holds all the necessary information to generate
/// and manage Nginx configuration files for a specific site.
///
/// # Fields
///
/// * `site_name` - The domain name of the site (e.g., "example.com")
/// * `root` - The document root directory where site files are stored
/// * `nginx_config_file_path` - Full path to the Nginx configuration file
/// * `ssl_root` - Optional path to SSL certificates directory (only when SSL is enabled)
///
/// # Examples
///
/// ```ignore
/// let config = NginxConfig::new(
///     "blog.example.com".to_string(),
///     "/var/www/sites".to_string(),
///     "/etc/nginx/conf.d".to_string(),
///     true,
/// );
/// 
/// println!("Site: {}", config.site_name);
/// println!("Root: {}", config.root);
/// ```
///
/// # Thread Safety
///
/// This struct does not implement `Send` or `Sync` by default, as it's
/// intended for single-threaded configuration generation.
pub struct NginxConfig {
    /// The domain name of the site.
    /// 
    /// Must be a valid domain name according to RFC 1035.
    /// Examples: "example.com", "blog.example.com", "test.local"
    pub site_name: String,
    
    /// The document root directory for the site.
    /// 
    /// This is where all site files (HTML, PHP, assets) are stored.
    /// Example: "/var/www/html/example.com"
    pub root: String,
    
    /// Full path to the Nginx configuration file.
    /// 
    /// The complete path including filename where the Nginx
    /// configuration will be written.
    /// Example: "/etc/nginx/conf.d/example.com.conf"
    pub nginx_config_file_path: String,
    
    /// Optional SSL certificate directory path.
    /// 
    /// Contains the path to SSL certificates when SSL is enabled.
    /// Structure: `{SITES_SSL_PATH}/{site_name}/{site_name}`
    /// Example: Some("/etc/nginx/ssl/example.com/example.com")
    pub ssl_root: Option<String>,
}

impl NginxConfig {
    /// Creates a new NginxConfig instance with the specified parameters.
    ///
    /// This constructor automatically constructs the appropriate paths
    /// based on the provided base paths and site name. If SSL is enabled,
    /// it also creates the SSL certificate path.
    ///
    /// # Arguments
    ///
    /// * `site_name` - The domain name of the site (e.g., "example.com")
    /// * `sites_path` - The base directory where all sites are located (e.g., "/var/www/sites")
    /// * `nginx_config` - The Nginx configuration directory (e.g., "/etc/nginx/conf.d")
    /// * `use_ssl` - Whether to enable SSL for this site
    ///
    /// # Returns
    ///
    /// A new instance of `NginxConfig` with all paths properly constructed.
    ///
    /// # Path Construction
    ///
    /// - Site root: `{sites_path}/{site_name}`
    /// - Nginx config: `{nginx_config}/{site_name}.conf`
    /// - SSL root (if enabled): `{SITES_SSL_PATH}/{site_name}/{site_name}`
    ///
    /// # Examples
    ///
    /// ```ignore
    /// // Create configuration for a site with SSL
    /// let config = NginxConfig::new(
    ///     "shop.example.com".to_string(),
    ///     "/var/www/html".to_string(),
    ///     "/etc/nginx/sites-enabled".to_string(),
    ///     true,
    /// );
    /// 
    /// assert_eq!(config.root, "/var/www/html/shop.example.com");
    /// assert_eq!(config.nginx_config_file_path, "/etc/nginx/sites-enabled/shop.example.com.conf");
    /// assert!(config.ssl_root.is_some());
    /// ```
    ///
    /// # Design Rationale
    ///
    /// The constructor encapsulates path construction logic to:
    /// - Ensure consistent path formatting
    /// - Prevent manual path construction errors
    /// - Centralize path generation logic
    pub fn new(site_name: String, sites_path: String, nginx_config: String, use_ssl: bool) -> Self {
        let ssl_root = use_ssl.then(|| format!("{}/{}", SITES_SSL_PATH, site_name));
        let nginx_config_file_path = format!("{}/{}.conf", nginx_config, site_name);
        let root = format!("{}/{}", sites_path, site_name);
        NginxConfig {
            site_name: site_name.clone(),
            root,
            nginx_config_file_path,
            ssl_root,
        }
    }

    /// Validates the Nginx configuration settings.
    ///
    /// Performs comprehensive validation including:
    /// - Site name validation (domain name format)
    /// - Path existence and accessibility checks
    /// - Security validation (path traversal prevention)
    ///
    /// # Returns
    ///
    /// * `Ok(())` - If all validation checks pass
    /// * `Err(String)` - If any validation fails, with a descriptive error message
    ///
    /// # Validation Steps
    ///
    /// 1. **Site name validation**: Ensures the domain name is valid per RFC 1035
    /// 2. **Path validation**: Verifies all required directories exist
    /// 3. **Security checks**: Prevents path traversal attacks
    ///
    /// # Errors
    ///
    /// This function will return an error if:
    /// - The site name contains invalid characters or format
    /// - Required directories don't exist or aren't accessible
    /// - The site name contains path traversal attempts (`..` or `/`)
    ///
    /// # Examples
    ///
    /// ```ignore
    /// let config = NginxConfig::new(
    ///     "valid-site.com".to_string(),
    ///     "/var/www/sites".to_string(),
    ///     "/etc/nginx/conf.d".to_string(),
    ///     false,
    /// );
    /// 
    /// match config.validate() {
    ///     Ok(()) => println!("Configuration is valid"),
    ///     Err(e) => eprintln!("Validation failed: {}", e),
    /// }
    /// ```
    ///
    /// # Security Considerations
    ///
    /// This method provides defense against:
    /// - Path traversal attacks using `..` or absolute paths
    /// - Invalid domain names that could cause nginx errors
    /// - Missing parent directories that would cause write failures
    ///
    /// # TODO
    /// 
    /// - Aggregate all validation errors to return at once for better UX
    /// - Add DNS resolution check for the domain
    /// - Validate nginx user has write permissions
    pub fn validate(&self) -> Result<(), String> {
        // TODO: Do all confirmations (if possible) and concatenate errors to return all at once, so, all issues can be fixed at once.
        // 1. Validate site name (domain name validation)
        if !crate::utils::validators::validate_site_name(&self.site_name) {
            return Err(format!("Invalid site name: {}", self.site_name));
        }

        // 2. Validate paths exist and are accessible
        self.validate_paths()?;

        // 3. Check for path traversal attacks
        if self.site_name.contains("..") || self.site_name.contains("/") {
            return Err(
                "Site name contains invalid characters (path traversal attempt)".to_string(),
            );
        }

        Ok(())
    }

    /// Validates that all required paths exist and are accessible.
    ///
    /// This internal method checks the existence and accessibility of:
    /// - Parent directory of the site root
    /// - Nginx configuration directory
    /// - SSL certificate directory (if SSL is enabled)
    ///
    /// # Returns
    ///
    /// * `Ok(())` - If all paths are valid and accessible
    /// * `Err(String)` - If any path is invalid, with details about which path failed
    ///
    /// # Validation Logic
    ///
    /// For each path, the method checks:
    /// 1. The parent directory exists (not the final path itself)
    /// 2. The parent is actually a directory (not a file)
    /// 3. SSL paths are validated only when SSL is enabled
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Sites directory doesn't exist
    /// - Sites path exists but isn't a directory
    /// - Nginx configuration directory doesn't exist
    /// - SSL directory doesn't exist (when SSL is enabled)
    ///
    /// # Note
    ///
    /// This method checks parent directories, not the final paths themselves,
    /// as those will be created during site setup. This allows validation
    /// before the site is actually created.
    ///
    /// # Implementation Details
    ///
    /// Uses `Path::parent()` to get parent directories, which returns `None`
    /// for root paths. The method gracefully handles this case.
    fn validate_paths(&self) -> Result<(), String> {
        // Check if root directory parent exists
        if let Some(parent) = Path::new(&self.root).parent() {
            if !parent.exists() {
                return Err(format!("Sites directory does not exist: {:?}", parent));
            }
            if !parent.is_dir() {
                return Err(format!("Sites path is not a directory: {:?}", parent));
            }
        }

        // Check nginx config directory exists
        if let Some(parent) = Path::new(&self.nginx_config_file_path).parent() {
            if !parent.exists() {
                return Err(format!(
                    "Nginx config directory does not exist: {:?}",
                    parent
                ));
            }
        }

        // Check SSL directory if SSL is enabled
        if let Some(ssl_root) = &self.ssl_root {
            if let Some(parent) = Path::new(ssl_root).parent() {
                if !parent.exists() {
                    return Err(format!("SSL directory does not exist: {:?}", parent));
                }
            }
        }

        Ok(())
    }

    /// Generates the Nginx configuration file content from templates.
    ///
    /// This function takes a template (HTTP or HTTPS) based on the specified protocol
    /// and replaces placeholder values with actual configuration values.
    ///
    /// # Arguments
    ///
    /// * `protocol` - The protocol type (`NginxProtocol::Http` or `NginxProtocol::Https`)
    ///
    /// # Returns
    ///
    /// A `String` containing the complete Nginx configuration with all placeholders replaced.
    ///
    /// # Template Placeholders
    ///
    /// The templates use the following placeholder format: `!{{VALUE_NAME}}!`
    ///
    /// Available placeholders:
    /// - `!{{site_name}}!` - Replaced with the site's domain name
    /// - `!{{site_path}}!` - Replaced with the site's root directory path  
    /// - `!{{ssl_path}}!` - Replaced with the SSL certificate directory path (HTTPS only)
    ///
    /// # Panics
    ///
    /// Panics if `NginxProtocol::Https` is specified but `ssl_root` is `None`.
    /// This is a programming error that should be caught during development.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// let config = NginxConfig::new(
    ///     "api.example.com".to_string(),
    ///     "/var/www/html".to_string(),
    ///     "/etc/nginx/conf.d".to_string(),
    ///     true, // SSL enabled
    /// );
    ///
    /// // Generate HTTP configuration
    /// let http_config = config.generate_config(NginxProtocol::Http);
    /// assert!(http_config.contains("listen 80"));
    /// assert!(http_config.contains("api.example.com"));
    ///
    /// // Generate HTTPS configuration
    /// let https_config = config.generate_config(NginxProtocol::Https);
    /// assert!(https_config.contains("listen 443 ssl"));
    /// assert!(https_config.contains("/var/www/html/api.example.com"));
    /// ```
    ///
    /// # Template Selection
    ///
    /// - `NginxProtocol::Http` uses `NGINX_HTTP_TEMPLATE`
    /// - `NginxProtocol::Https` uses `NGINX_HTTPS_TEMPLATE`
    ///
    /// # Performance
    ///
    /// Template replacement is performed using `String::replace()` which
    /// allocates new strings. For large templates or high-frequency generation,
    /// consider caching generated configurations.
    pub fn generate_config(&self, protocol: NginxProtocol) -> String {
        let mut config = match protocol {
            NginxProtocol::Http => NGINX_HTTP_TEMPLATE.to_string(),
            NginxProtocol::Https => {
                if self.ssl_root.is_none() {
                    panic!("SSL path must be provided for HTTPS configuration");
                }
                NGINX_HTTPS_TEMPLATE.to_string()
            }
        };

        // Replace site_name placeholder
        config = config.replace("!{{site_name}}!", &self.site_name);

        // Replace site_path placeholder with the root path
        config = config.replace("!{{site_path}}!", &self.root);

        // Replace ssl_path placeholder (only present in HTTPS template)
        if protocol == NginxProtocol::Https {
            if let Some(ssl_path) = &self.ssl_root {
                config = config.replace("!{{ssl_path}}!", ssl_path);
            }
        }

        config
    }
}

/// Validates the current system-wide Nginx configuration.
///
/// Executes `nginx -t` to verify that the entire Nginx configuration
/// is syntactically correct and can be loaded successfully.
///
/// # Returns
///
/// * `Ok(())` - If the Nginx configuration is valid
/// * `Err(String)` - If the configuration is invalid, containing the nginx error output
///
/// # Command Execution
///
/// Runs: `nginx -t`
/// 
/// This command:
/// - Tests the configuration file syntax
/// - Tests the configuration file references
/// - Does NOT actually start or reload nginx
///
/// # Errors
///
/// This function will return an error if:
/// - The `nginx` command cannot be executed (nginx not installed or not in PATH)
/// - The Nginx configuration contains syntax errors
/// - Configuration files reference missing includes or upstreams
/// - There are permission issues with configuration files
/// - SSL certificates are missing or invalid
///
/// # Examples
///
/// ```ignore
/// use nginx::config::validate_nginx_configuration;
///
/// match validate_nginx_configuration() {
///     Ok(()) => {
///         println!("✓ Nginx configuration is valid");
///         // Safe to reload nginx
///     }
///     Err(e) => {
///         eprintln!("✗ Configuration error: {}", e);
///         // Do not reload nginx
///     }
/// }
/// ```
///
/// # System Requirements
///
/// - Nginx must be installed on the system
/// - The `nginx` command must be in the system PATH
/// - User must have permission to run `nginx -t`
/// - Typically requires sudo/root privileges in production
///
/// # Best Practices
///
/// Always call this function:
/// - Before reloading nginx after configuration changes
/// - After generating new site configurations
/// - Before removing site configurations
/// - As part of CI/CD deployment pipelines
pub fn validate_nginx_configuration() -> Result<(), String> {
    // Execute nginx -t command
    let output = Command::new("nginx")
        .args(&["-t"])
        .output()
        .map_err(|e| format!("Failed to execute nginx: {}.", e))?;

    if output.status.success() {
        Ok(())
    } else {
        // Get the error output from nginx
        let stderr = String::from_utf8_lossy(&output.stderr);

        // Format a concise error message
        Err(format!(
            "Nginx configuration validation failed:\n{}",
            stderr.trim()
        ))
    }
}

/// Validates a specific Nginx configuration file in isolation.
///
/// Creates a temporary Nginx configuration that includes only the
/// specified file, allowing validation of individual site configurations
/// without affecting the main Nginx configuration.
///
/// # Arguments
///
/// * `config_path` - Path to the specific configuration file to validate
///
/// # Returns
///
/// * `Ok(())` - If the configuration file is valid
/// * `Err(String)` - If invalid, containing nginx error output
///
/// # How It Works
///
/// 1. Creates a temporary main configuration file in `/tmp`
/// 2. Writes minimal nginx config that includes the target file
/// 3. Runs `nginx -t -c {temp_config}` for isolated validation
/// 4. Cleans up the temporary file regardless of outcome
///
/// # Temporary Configuration Structure
///
/// ```nginx
/// events {
///     worker_connections 1024;
/// }
/// http {
///     include /path/to/target/config.conf;
/// }
/// ```
///
/// # Errors
///
/// Returns an error if:
/// - Cannot create the temporary configuration file
/// - The nginx command fails to execute
/// - The configuration file contains syntax errors
/// - The configuration references undefined variables or upstreams
/// - SSL certificates referenced in the config don't exist
///
/// # Examples
///
/// ```ignore
/// use nginx::config::validate_nginx_config_file;
///
/// let config_path = "/etc/nginx/sites-enabled/example.com.conf";
/// 
/// match validate_nginx_config_file(config_path) {
///     Ok(()) => println!("✓ Configuration file is valid"),
///     Err(e) => eprintln!("✗ Invalid configuration: {}", e),
/// }
/// ```
///
/// # Security Considerations
///
/// - Temporary file uses process ID to ensure uniqueness
/// - File is created in `/tmp` with default permissions
/// - Always cleaned up, even on error
/// - No sensitive data is written to the temporary file
///
/// # Limitations
///
/// This validation is isolated and may not catch issues that depend on:
/// - Global nginx settings
/// - Shared upstreams or variables
/// - Include files from the main configuration
/// - System resource limits
pub fn validate_nginx_config_file(config_path: &str) -> Result<(), String> {
    use std::fs;

    // Create a temporary main config that includes the target file
    let temp_config = format!("/tmp/nginx_test_{}.conf", std::process::id());
    let include_content = format!(
        "events {{ worker_connections 1024; }}\nhttp {{ include {}; }}\n",
        config_path
    );

    // Write temporary config
    fs::write(&temp_config, include_content)
        .map_err(|e| format!("Failed to create temp config: {}", e))?;

    // Test with the temporary config
    let output = Command::new("nginx")
        .args(&["-t", "-c", &temp_config])
        .output()
        .map_err(|e| {
            let _ = fs::remove_file(&temp_config);
            format!("Failed to execute nginx: {}", e)
        })?;

    // Clean up
    let _ = fs::remove_file(&temp_config);

    if output.status.success() {
        Ok(())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        Err(format!(
            "Invalid configuration in '{}':\n{}",
            config_path,
            stderr.trim()
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::{NGINX_HTTP_CONFIG_MARKER, NGINX_HTTPS_CONFIG_MARKER};

    /// Tests that HTTP configuration is generated correctly
    #[test]
    fn test_generate_http_config() {
        let config = NginxConfig::new(
            "test.example.com".to_string(),
            "/var/www/html".to_string(),
            "/etc/nginx/conf.d".to_string(),
            false, // No SSL
        );

        let generated = config.generate_config(NginxProtocol::Http);

        // Verify HTTP template is used
        assert!(generated.contains(NGINX_HTTP_CONFIG_MARKER));
        assert!(generated.contains("listen 80"));

        // Verify HTTPS content is NOT included
        assert!(!generated.contains(NGINX_HTTPS_CONFIG_MARKER));
        assert!(!generated.contains("listen 443"));

        // Verify placeholders are replaced
        assert!(!generated.contains("!{{site_name}}!"));
        assert!(!generated.contains("!{{site_path}}!"));

        // Verify actual values are present
        assert!(generated.contains("test.example.com"));
        assert!(generated.contains("/var/www/html/test.example.com"));
    }

    /// Tests that HTTPS configuration is generated correctly with SSL paths
    #[test]
    fn test_generate_https_config() {
        let config = NginxConfig::new(
            "secure.example.com".to_string(),
            "/var/www/html".to_string(),
            "/etc/nginx/conf.d".to_string(),
            true, // SSL enabled
        );

        let generated = config.generate_config(NginxProtocol::Https);

        // Verify HTTPS template is used
        assert!(generated.contains(NGINX_HTTPS_CONFIG_MARKER));
        assert!(generated.contains("listen 443"));

        // Verify HTTP content is NOT included
        assert!(!generated.contains(NGINX_HTTP_CONFIG_MARKER));
        assert!(!generated.contains("listen 80"));

        // Verify all placeholders are replaced
        assert!(!generated.contains("!{{site_name}}!"));
        assert!(!generated.contains("!{{site_path}}!"));
        assert!(!generated.contains("!{{ssl_path}}!"));

        // Verify actual values are present
        assert!(generated.contains("secure.example.com"));
        assert!(generated.contains("/var/www/html/secure.example.com"));
        assert!(generated.contains("/etc/nginx/ssl/secure.example.com"));
    }

    /// Tests that generating HTTPS config without SSL path causes a panic
    #[test]
    #[should_panic(expected = "SSL path must be provided for HTTPS configuration")]
    fn test_https_without_ssl_path_panics() {
        let config = NginxConfig::new(
            "example.com".to_string(),
            "/var/www/html".to_string(),
            "/etc/nginx/conf.d".to_string(),
            false, // No SSL
        );

        // This should panic
        config.generate_config(NginxProtocol::Https);
    }

    /// Tests configuration generation with special characters in domain name
    #[test]
    fn test_generate_config_special_characters_in_name() {
        let config = NginxConfig::new(
            "my-site.sub.example.com".to_string(),
            "/var/www/html".to_string(),
            "/etc/nginx/conf.d".to_string(),
            true, // SSL enabled
        );

        let http_generated = config.generate_config(NginxProtocol::Http);
        let https_generated = config.generate_config(NginxProtocol::Https);

        // Verify domain with hyphens and subdomains is correctly replaced in both
        assert!(http_generated.contains("my-site.sub.example.com"));
        assert!(http_generated.contains("/var/www/html/my-site.sub.example.com"));

        assert!(https_generated.contains("my-site.sub.example.com"));
        assert!(https_generated.contains("/var/www/html/my-site.sub.example.com"));
        assert!(https_generated.contains("/etc/nginx/ssl/my-site.sub.example.com"));
    }

    /// Tests that all template placeholders are properly replaced
    #[test]
    fn test_template_replacement_completeness() {
        let config = NginxConfig::new(
            "complete.test.com".to_string(),
            "/custom/www".to_string(),
            "/etc/nginx/conf.d".to_string(),
            true, // SSL enabled
        );

        let http_generated = config.generate_config(NginxProtocol::Http);
        let https_generated = config.generate_config(NginxProtocol::Https);

        // Ensure no unreplaced placeholders remain in HTTP
        assert!(!http_generated.contains("!{{"));
        assert!(!http_generated.contains("}}!"));
        assert!(http_generated.contains("/custom/www/complete.test.com"));

        // Ensure no unreplaced placeholders remain in HTTPS
        assert!(!https_generated.contains("!{{"));
        assert!(!https_generated.contains("}}!"));
        assert!(https_generated.contains("/custom/www/complete.test.com"));
        assert!(https_generated.contains("/etc/nginx/ssl/complete.test.com"));
    }

    /// Tests NginxProtocol enum equality and inequality
    #[test]
    fn test_protocol_enum_equality() {
        assert_eq!(NginxProtocol::Http, NginxProtocol::Http);
        assert_eq!(NginxProtocol::Https, NginxProtocol::Https);
        assert_ne!(NginxProtocol::Http, NginxProtocol::Https);
    }

    /// Tests that enabling SSL but requesting HTTP protocol works correctly
    #[test]
    fn test_generate_config_with_ssl_but_http_protocol() {
        let config = NginxConfig::new(
            "test.com".to_string(),
            "/var/www/html".to_string(),
            "/etc/nginx/conf.d".to_string(),
            true, // SSL enabled
        );

        let http_config = config.generate_config(NginxProtocol::Http);

        // Should only contain HTTP configuration, not HTTPS
        assert!(http_config.contains("listen 80"));
        assert!(!http_config.contains("listen 443"));
        // SSL path shouldn't be replaced in HTTP template (it doesn't exist there)
        assert!(!http_config.contains("/etc/nginx/ssl"));
    }

    /// Tests NginxConfig::new() constructor path generation
    #[test]
    fn test_nginx_config_new_path_construction() {
        // Test without SSL
        let config_no_ssl = NginxConfig::new(
            "test.com".to_string(),
            "/var/www/html".to_string(),
            "/etc/nginx/conf.d".to_string(),
            false,
        );
        
        assert_eq!(config_no_ssl.site_name, "test.com");
        assert_eq!(config_no_ssl.root, "/var/www/html/test.com");
        assert_eq!(config_no_ssl.nginx_config_file_path, "/etc/nginx/conf.d/test.com.conf");
        assert!(config_no_ssl.ssl_root.is_none());

        // Test with SSL
        let config_with_ssl = NginxConfig::new(
            "test.com".to_string(),
            "/var/www/html".to_string(),
            "/etc/nginx/conf.d".to_string(),
            true,
        );
        
        assert_eq!(config_with_ssl.ssl_root, Some("/etc/nginx/ssl/test.com/test.com".to_string()));
    }

    /// Tests validation with invalid site names
    #[test]
    fn test_validate_invalid_site_names() {
        // Test with path traversal attempt
        let config_path_traversal = NginxConfig {
            site_name: "../etc/passwd".to_string(),
            root: "/var/www/html/../etc/passwd".to_string(),
            nginx_config_file_path: "/etc/nginx/conf.d/../etc/passwd.conf".to_string(),
            ssl_root: None,
        };
        
        let result = config_path_traversal.validate();
        assert!(result.is_err());
        // Domain validation will fail first for "../etc/passwd"
        assert!(result.unwrap_err().contains("Invalid site name"));

        // Test with forward slash in name
        let config_with_slash = NginxConfig {
            site_name: "test/com".to_string(),
            root: "/var/www/html/test/com".to_string(),
            nginx_config_file_path: "/etc/nginx/conf.d/test/com.conf".to_string(),
            ssl_root: None,
        };
        
        let result = config_with_slash.validate();
        assert!(result.is_err());
        // Domain validation will fail first for "test/com"
        assert!(result.unwrap_err().contains("Invalid site name"));

        // Test with invalid domain name (no TLD)
        let config_invalid_domain = NginxConfig {
            site_name: "invalid".to_string(),
            root: "/var/www/html/invalid".to_string(),
            nginx_config_file_path: "/etc/nginx/conf.d/invalid.conf".to_string(),
            ssl_root: None,
        };
        
        let result = config_invalid_domain.validate();
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Invalid site name"));
    }

    /// Tests NginxProtocol Debug and Clone traits
    #[test]
    fn test_nginx_protocol_traits() {
        let http = NginxProtocol::Http;
        let https = NginxProtocol::Https;
        
        // Test Debug trait
        assert_eq!(format!("{:?}", http), "Http");
        assert_eq!(format!("{:?}", https), "Https");
        
        // Test Clone trait
        let http_clone = http.clone();
        let https_clone = https.clone();
        assert_eq!(http, http_clone);
        assert_eq!(https, https_clone);
        
        // Test Copy trait (implicitly via assignment)
        let http_copy = http;
        assert_eq!(http, http_copy);
    }

    /// Tests edge cases in path construction
    #[test]
    fn test_nginx_config_edge_case_paths() {
        // Test with trailing slashes in input paths
        let config = NginxConfig::new(
            "example.com".to_string(),
            "/var/www/html/".to_string(),  // Trailing slash
            "/etc/nginx/conf.d/".to_string(),  // Trailing slash
            false,
        );
        
        // Should handle trailing slashes correctly (may result in double slashes)
        assert_eq!(config.root, "/var/www/html//example.com");
        assert_eq!(config.nginx_config_file_path, "/etc/nginx/conf.d//example.com.conf");
        
        // Test with empty base paths (edge case, shouldn't happen in practice)
        let config_empty = NginxConfig::new(
            "test.com".to_string(),
            "".to_string(),
            "".to_string(),
            false,
        );
        
        assert_eq!(config_empty.root, "/test.com");
        assert_eq!(config_empty.nginx_config_file_path, "/test.com.conf");
    }

    /// Tests that multiple placeholders of the same type are all replaced
    #[test]
    fn test_multiple_placeholder_replacement() {
        // This test ensures that if a template has multiple instances of the same
        // placeholder, all get replaced (String::replace replaces all by default)
        let config = NginxConfig::new(
            "multi.test.com".to_string(),
            "/var/www/sites".to_string(),
            "/etc/nginx/sites-enabled".to_string(),
            false,
        );
        
        // Create a mock template with multiple placeholders
        let mut test_template = String::from("server_name !{{site_name}}!;\n");
        test_template.push_str("root !{{site_path}}!;\n");
        test_template.push_str("access_log /var/log/nginx/!{{site_name}}!.access.log;\n");
        test_template.push_str("error_log /var/log/nginx/!{{site_name}}!.error.log;\n");
        
        // Manually apply replacements as the method would
        let result = test_template
            .replace("!{{site_name}}!", &config.site_name)
            .replace("!{{site_path}}!", &config.root);
        
        // Verify all instances were replaced
        // Note: site_name appears 3 times in placeholders + 1 time in the path replacement
        assert_eq!(result.matches("multi.test.com").count(), 4); // 3 from !{{site_name}}! + 1 from path
        assert_eq!(result.matches("/var/www/sites/multi.test.com").count(), 1);
        assert!(!result.contains("!{{"));
    }
}

#[cfg(test)]
mod validation_tests {
    use super::*;
    use std::fs;
    #[allow(unused_imports)]
    use std::path::Path;

    /// Integration test for system nginx validation (requires nginx installed)
    #[test]
    #[ignore] // Requires nginx to be installed
    fn test_validate_nginx_configuration() {
        // This test requires nginx to be installed on the system
        let result = validate_nginx_configuration();

        // We can't guarantee the outcome, but it should return a Result
        match result {
            Ok(()) => println!("System nginx config is valid"),
            Err(e) => println!("System nginx config error: {}", e),
        }
    }

    /// Tests validate_nginx_config_file with a temporary valid config
    #[test]
    #[ignore] // Requires nginx to be installed
    fn test_validate_nginx_config_file_valid() {
        use std::io::Write;
        
        // Create a temporary valid nginx config
        let temp_dir = std::env::temp_dir();
        let config_path = temp_dir.join("test_valid.conf");
        
        let valid_config = r#"
            server {
                listen 80;
                server_name test.local;
                root /var/www/html;
                
                location / {
                    try_files $uri $uri/ =404;
                }
            }
        "#;
        
        let mut file = fs::File::create(&config_path).expect("Failed to create test file");
        file.write_all(valid_config.as_bytes()).expect("Failed to write test config");
        
        // Test validation
        let result = validate_nginx_config_file(config_path.to_str().unwrap());
        
        // Clean up
        let _ = fs::remove_file(&config_path);
        
        // Should be valid
        assert!(result.is_ok());
    }

    /// Tests validate_nginx_config_file with invalid syntax
    #[test]
    #[ignore] // Requires nginx to be installed
    fn test_validate_nginx_config_file_invalid() {
        use std::io::Write;
        
        // Create a temporary invalid nginx config
        let temp_dir = std::env::temp_dir();
        let config_path = temp_dir.join("test_invalid.conf");
        
        let invalid_config = r#"
            server {
                listen 80
                server_name test.local;  # Missing semicolon on listen line
                root /var/www/html;
            }
        "#;
        
        let mut file = fs::File::create(&config_path).expect("Failed to create test file");
        file.write_all(invalid_config.as_bytes()).expect("Failed to write test config");
        
        // Test validation
        let result = validate_nginx_config_file(config_path.to_str().unwrap());
        
        // Clean up
        let _ = fs::remove_file(&config_path);
        
        // Should be invalid
        assert!(result.is_err());
        if let Err(e) = result {
            assert!(e.contains("Invalid configuration"));
        }
    }

    /// Tests path validation with non-existent directories
    #[test]
    fn test_validate_paths_nonexistent() {
        let config = NginxConfig {
            site_name: "test.com".to_string(),
            root: "/nonexistent/path/test.com".to_string(),
            nginx_config_file_path: "/also/nonexistent/test.com.conf".to_string(),
            ssl_root: Some("/ssl/nonexistent/test.com".to_string()),
        };
        
        let result = config.validate_paths();
        assert!(result.is_err());
        // Should mention the nonexistent directory
        assert!(result.unwrap_err().contains("does not exist"));
    }

    /// Tests path validation with file instead of directory
    #[test]
    fn test_validate_paths_file_not_directory() {
        use std::io::Write;
        
        // Create a temporary file (not a directory)
        let temp_dir = std::env::temp_dir();
        let temp_file = temp_dir.join("test_file_not_dir");
        let mut file = fs::File::create(&temp_file).expect("Failed to create test file");
        file.write_all(b"test").expect("Failed to write");
        
        let config = NginxConfig {
            site_name: "test.com".to_string(),
            root: format!("{}/test.com", temp_file.to_str().unwrap()),
            nginx_config_file_path: "/etc/nginx/conf.d/test.com.conf".to_string(),
            ssl_root: None,
        };
        
        let result = config.validate_paths();
        
        // Clean up
        let _ = fs::remove_file(&temp_file);
        
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("not a directory"));
    }
}

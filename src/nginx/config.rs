use crate::constants::{NGINX_HTTP_TEMPLATE, NGINX_HTTPS_TEMPLATE, SITES_SSL_PATH};
/// This module defines the structure and functions for managing Nginx configuration files.
///
/// The primary responsibilities include:
/// - Loading and parsing Nginx configuration files.
/// - Validating configuration settings.
/// - Generating new configuration files for sites.
///
/// Future implementation will include functions to read, write, and validate Nginx configurations.
use std::path::Path;
use std::process::Command;

/// Represents the protocol type for the Nginx configuration
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum NginxProtocol {
    Http,
    Https,
}

pub struct NginxConfig {
    pub site_name: String,
    pub root: String,
    pub nginx_config_file_path: String,
    pub ssl_root: Option<String>,
}

impl NginxConfig {
    /// Creates a new NginxConfig instance with the specified parameters.
    ///
    /// # Arguments
    ///
    /// * `site_name` - The name of the site (domain).
    /// * `sites_path` - The base path where sites are located.
    /// * `nginx_config` - The path to the Nginx configuration directory.
    /// * `ssl_path` - The path to the SSL certificate directory.
    ///
    /// # Returns
    ///
    /// A new instance of NginxConfig.
    pub fn new(
        site_name: String,
        sites_path: String,
        nginx_config: String,
        use_ssl: bool,
    ) -> Self {
        let ssl_path = use_ssl.then(|| {
            format!("{}/{}", SITES_SSL_PATH, site_name)
        });
        let nginx_config_file_path = format!("{}/{}.conf", nginx_config, site_name);
        let root = format!("{}/{}", sites_path, site_name);
        NginxConfig {
            site_name: site_name.clone(),
            root,
            nginx_config_file_path,
            ssl_root: ssl_path.map(|path| format!("{}/{}", path, site_name)),
        }
    }

    /// Validates the Nginx configuration settings.
    ///
    /// This performs both structural validation (paths, names) and
    /// optionally tests the actual nginx configuration syntax.
    ///
    /// # Returns
    ///
    /// A Result indicating success or failure of validation.
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

    /// Validates that required paths exist and are accessible
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
    /// The placeholders follow the pattern `!{{VALUE_NAME}}!` where VALUE_NAME can be:
    /// - `site_name`: Replaced with the site's domain name
    /// - `site_path`: Replaced with the site's root directory path  
    /// - `ssl_path`: Replaced with the SSL certificate directory path (HTTPS only)
    ///
    /// # Arguments
    ///
    /// * `protocol` - The protocol type (HTTP or HTTPS) that determines which template to use
    ///
    /// # Returns
    ///
    /// A string containing the complete Nginx configuration with all placeholders replaced.
    ///
    /// # Panics
    ///
    /// Panics if HTTPS protocol is specified but `ssl_root` is None.
    ///
    /// # Examples
    ///
    /// ```
    /// let config = NginxConfig::new(
    ///     "example.com".to_string(),
    ///     "/var/www/html".to_string(),
    ///     "/etc/nginx/conf.d".to_string(),
    ///     Some("/etc/nginx/ssl".to_string())
    /// );
    /// 
    /// // Generate HTTP configuration
    /// let http_config = config.generate_config(NginxProtocol::Http);
    /// assert!(http_config.contains("listen 80"));
    /// 
    /// // Generate HTTPS configuration
    /// let https_config = config.generate_config(NginxProtocol::Https);
    /// assert!(https_config.contains("listen 443"));
    /// ```
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

/// Validates the current nginx configuration using `nginx -t`.
///
/// # Returns
///
/// * `Ok(())` - If the nginx configuration is valid
/// * `Err(String)` - If the configuration is invalid, with nginx output
///
/// # Examples
///
/// ```
/// match validate_nginx_configuration() {
///     Ok(()) => println!("✓ Nginx configuration is valid"),
///     Err(e) => eprintln!("{}", e),
/// }
/// ```
pub fn validate_nginx_configuration() -> Result<(), String> {
    // Execute nginx -t command
    let output = Command::new("nginx")
        .args(&["-t"])
        .output()
        .map_err(|e| {
            format!("Failed to execute nginx: {}.", e)
        })?;

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

/// Validates a specific nginx configuration file.
///
/// # Arguments
///
/// * `config_path` - Path to the specific configuration file to validate
///
/// # Returns
///
/// * `Ok(())` - If the configuration file is valid
/// * `Err(String)` - If invalid, with nginx error output
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

    #[test]
    #[should_panic(expected = "SSL path must be provided for HTTPS configuration")]
    fn test_https_without_ssl_path_panics() {
        let config = NginxConfig::new(
            "example.com".to_string(),
            "/var/www/html".to_string(),
            "/etc/nginx/conf.d".to_string(),
            false,  // No SSL
        );

        // This should panic
        config.generate_config(NginxProtocol::Https);
    }

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
        assert!(https_generated.contains("/custom/ssl/complete.test.com"));
    }

    #[test]
    fn test_protocol_enum_equality() {
        assert_eq!(NginxProtocol::Http, NginxProtocol::Http);
        assert_eq!(NginxProtocol::Https, NginxProtocol::Https);
        assert_ne!(NginxProtocol::Http, NginxProtocol::Https);
    }

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
}

#[cfg(test)]
mod validation_tests {
    use super::*;

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
}

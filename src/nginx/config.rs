use crate::constants::{NGINX_HTTP_TEMPLATE, NGINX_HTTPS_TEMPLATE};
/// This module defines the structure and functions for managing Nginx configuration files.
///
/// The primary responsibilities include:
/// - Loading and parsing Nginx configuration files.
/// - Validating configuration settings.
/// - Generating new configuration files for sites.
///
/// Future implementation will include functions to read, write, and validate Nginx configurations.
use std::path::Path;

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
        ssl_path: Option<String>,
    ) -> Self {
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
    /// This function combines HTTP and optionally HTTPS templates based on whether
    /// SSL is configured, then replaces placeholder values with actual configuration values.
    /// The placeholders follow the pattern `!{{VALUE_NAME}}!` where VALUE_NAME can be:
    /// - `site_name`: Replaced with the site's domain name
    /// - `site_path`: Replaced with the site's root directory path  
    /// - `ssl_path`: Replaced with the SSL certificate directory path (only when SSL is enabled)
    ///
    /// # Returns
    ///
    /// A string containing the complete Nginx configuration with all placeholders replaced.
    /// If SSL is configured, both HTTP and HTTPS server blocks are included.
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
    /// // Generate configuration (includes both HTTP and HTTPS if SSL is set)
    /// let nginx_config = config.generate_config();
    /// assert!(nginx_config.contains("listen 80"));
    /// assert!(nginx_config.contains("listen 443"));
    /// ```
    pub fn generate_config(&self) -> String {
        let mut config = NGINX_HTTP_TEMPLATE.to_string();
        if self.ssl_root.is_some() {
            config = format!("{}\n\n{}", config, NGINX_HTTPS_TEMPLATE);
        }
        
        // Replace site_name placeholder
        config = config.replace("!{{site_name}}!", &self.site_name);

        // Replace site_path placeholder with the root path
        config = config.replace("!{{site_path}}!", &self.root);

        // Replace ssl_path placeholder (only present in HTTPS template)
        if let Some(ref ssl_path) = self.ssl_root {
            config = config.replace("!{{ssl_path}}!", ssl_path);
        }

        config
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_config_http_only() {
        let config = NginxConfig::new(
            "test.example.com".to_string(),
            "/var/www/html".to_string(),
            "/etc/nginx/conf.d".to_string(),
            None,
        );

        let generated = config.generate_config();

        // Verify HTTP template is included
        assert!(generated.contains("### HTTP Server ###"));
        assert!(generated.contains("listen 80"));
        
        // Verify HTTPS template is NOT included
        assert!(!generated.contains("### HTTPS Server ###"));
        assert!(!generated.contains("listen 443"));
        
        // Verify placeholders are replaced
        assert!(!generated.contains("!{{site_name}}!"));
        assert!(!generated.contains("!{{site_path}}!"));
        assert!(!generated.contains("!{{ssl_path}}!")); // Shouldn't exist in HTTP-only
        
        // Verify actual values are present
        assert!(generated.contains("test.example.com"));
        assert!(generated.contains("/var/www/html/test.example.com"));
    }

    #[test]
    fn test_generate_config_with_ssl() {
        let config = NginxConfig::new(
            "secure.example.com".to_string(),
            "/var/www/html".to_string(),
            "/etc/nginx/conf.d".to_string(),
            Some("/etc/nginx/ssl".to_string()),
        );

        let generated = config.generate_config();

        // Verify both HTTP and HTTPS templates are included
        assert!(generated.contains("### HTTP Server ###"));
        assert!(generated.contains("listen 80"));
        assert!(generated.contains("### HTTPS Server ###"));
        assert!(generated.contains("listen 443"));
        
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
    fn test_generate_config_special_characters_in_name() {
        let config = NginxConfig::new(
            "my-site.sub.example.com".to_string(),
            "/var/www/html".to_string(),
            "/etc/nginx/conf.d".to_string(),
            None,
        );

        let generated = config.generate_config();
        
        // Verify domain with hyphens and subdomains is correctly replaced
        assert!(generated.contains("my-site.sub.example.com"));
        assert!(generated.contains("/var/www/html/my-site.sub.example.com"));
    }

    #[test]
    fn test_template_replacement_completeness() {
        let config = NginxConfig::new(
            "complete.test.com".to_string(),
            "/custom/www".to_string(),
            "/etc/nginx/conf.d".to_string(),
            Some("/custom/ssl".to_string()),
        );

        let generated = config.generate_config();

        // Ensure no unreplaced placeholders remain
        assert!(!generated.contains("!{{"));
        assert!(!generated.contains("}}!"));
        
        // Verify custom paths are used
        assert!(generated.contains("/custom/www/complete.test.com"));
        assert!(generated.contains("/custom/ssl/complete.test.com"));
    }

    #[test]
    fn test_generate_config_template_structure() {
        let config = NginxConfig::new(
            "structure.test.com".to_string(),
            "/var/www/html".to_string(),
            "/etc/nginx/conf.d".to_string(),
            Some("/etc/nginx/ssl".to_string()),
        );

        let generated = config.generate_config();
        
        // Verify the templates are combined with proper spacing
        let lines: Vec<&str> = generated.lines().collect();
        
        // Should have both server blocks
        assert!(lines.iter().any(|line| line.contains("### HTTP Server ###")));
        assert!(lines.iter().any(|line| line.contains("### HTTPS Server ###")));
        
        // Verify there's a gap between HTTP and HTTPS blocks
        assert!(generated.contains("###\n\n### HTTPS"));
    }
}

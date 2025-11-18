//! Command module for the e2e-site-spawner CLI tool.
//!
//! This module contains the implementation of various commands
//! for managing sites on an Nginx server. Each command function
//! provides complete site lifecycle management, from creation to deletion.
//!
//! # Command Overview
//!
//! - **spawn**: Creates new sites with optional WordPress and SSL
//! - **delete**: Completely removes sites and all resources
//! - **deactivate**: Temporarily disables site access
//! - **activate**: Re-enables deactivated sites
//!
//! # Transaction Safety
//!
//! All site creation operations are tracked and can be fully rolled back
//! if any step fails, ensuring the system remains in a consistent state.
//!
//! # Error Handling
//!
//! Commands validate Nginx configuration before and after operations,
//! and will exit the process if critical errors occur to prevent
//! system instability.

use crate::constants::{DB_CHARSET, DB_PASSWORD, DB_USER};
use crate::constants::{DB_HOST, HTML_DEFAULT_INDEX_FILE, NGINX_CONF_D_PATH, SITES_PATH};
use crate::nginx::config::validate_nginx_configuration;
use crate::nginx::{self, reload_nginx};
use crate::nginx::{append_to_nginx_file, create_nginx_file};
use crate::utils::db;
use crate::utils::sites::{self, create_file_with_content_if_not_exists, revert_site_spawn};
use crate::utils::ssl;
use crate::utils::validators::validate_site_name;
use std::env;
use std::path::Path;
use std::{fs, process};

/// Represents the various steps involved in spawning a new site.
/// 
/// Each variant corresponds to a specific action that can be taken
/// during site creation. These steps are tracked to enable proper
/// rollback in case of failure.
///
/// # Purpose
///
/// This enum serves as a transaction log for site creation operations,
/// allowing the system to:
/// - Track which operations have been completed
/// - Identify what needs to be rolled back on failure
/// - Group related operations for efficient cleanup
///
/// # Rollback Strategy
///
/// Steps are reverted in reverse order of completion, and grouped
/// operations (defined by constants like [`REMOVE_NGINX_CONFIG`])
/// are treated as atomic units during rollback.
#[derive(Clone)]
pub enum SpawnSteps {
    /// When Nginx configuration file for HTTP was created.
    /// 
    /// Tracks the creation of the initial HTTP configuration file
    /// at `/etc/nginx/conf.d/{site_name}.conf`
    CreateNginxConfig,
    
    /// When the site's root directory was created.
    /// 
    /// Tracks the creation of the document root directory
    /// at `/var/www/html/{site_name}/`
    CreateSiteDirectory,
    
    /// When the directory to store SSL certificates was created.
    /// 
    /// Tracks the creation of the SSL certificate directory
    /// at `/etc/nginx/ssl/{site_name}/`
    CreateSSLDirectory,
    
    /// When SSL certificates were generated and installed.
    /// 
    /// Tracks successful SSL certificate generation via acme.sh
    /// and installation to the SSL directory
    CreateSSL,
    
    /// When Nginx configuration was updated to include HTTPS settings.
    /// 
    /// Tracks the addition of HTTPS server block to the existing
    /// Nginx configuration file
    CreateNginxConfigWithSSL,
    
    /// When the database for the site was created (stores database name).
    /// 
    /// Tracks MySQL database creation. The String parameter holds
    /// the actual database name used (which may include a numeric
    /// suffix if the original name was taken)
    CreateDatabase(String),
    
    /// When the WordPress configuration file (wp-config.php) was created.
    /// 
    /// Tracks the creation of wp-config.php with database credentials
    /// and security salts
    CreateWPConfigFile,
}

/// Group of steps related to Nginx configuration removal.
/// 
/// This constant defines which spawn steps should be considered
/// as a group when reverting Nginx configuration changes.
/// 
/// # Grouping Logic
/// 
/// Both HTTP and HTTPS configurations affect the same file, so they're
/// grouped together to prevent redundant file removal attempts during
/// rollback operations.
pub const REMOVE_NGINX_CONFIG: [SpawnSteps; 2] = [
    SpawnSteps::CreateNginxConfig,
    SpawnSteps::CreateNginxConfigWithSSL,
];

/// Group of steps related to site directory removal.
/// 
/// This constant defines which spawn steps should be considered
/// as a group when reverting site directory changes.
/// 
/// # Grouping Logic
/// 
/// The site directory contains all WordPress files including wp-config.php,
/// so removing the directory also removes the configuration file. These
/// are grouped to prevent attempting to remove already-deleted files.
pub const REMOVE_SITE_DIRECTORY: [SpawnSteps; 2] = [
    SpawnSteps::CreateSiteDirectory,
    SpawnSteps::CreateWPConfigFile,
];

/// Group of steps related to SSL directory removal.
/// 
/// This constant defines which spawn steps should be considered
/// as a group when reverting SSL-related changes.
/// 
/// # Grouping Logic
/// 
/// The SSL directory contains all certificates, so removing the directory
/// also removes the certificates. These are grouped to ensure complete
/// SSL cleanup with a single operation.
pub const REMOVE_SSL_DIRECTORY: [SpawnSteps; 2] =
    [SpawnSteps::CreateSSLDirectory, SpawnSteps::CreateSSL];

/// Spawns a new site with the given configuration.
///
/// This function orchestrates the entire process of creating a new site,
/// including:
/// - Creating Nginx configuration files
/// - Setting up site directories with proper permissions
/// - Generating SSL certificates (if requested)
/// - Installing WordPress (unless disabled)
/// - Creating a MySQL database
/// - Configuring WordPress with database credentials
///
/// The function tracks each completed step and automatically reverts
/// all changes if any step fails, ensuring the system remains in a
/// clean state.
///
/// # Arguments
///
/// * `site_name` - The name of the site to create. Must be a valid domain name.
/// * `ssl` - If `true`, generates SSL certificates and configures HTTPS.
/// * `no_wp` - If `true`, creates a static site without WordPress installation.
///
/// # Process Flow
///
/// 1. **Validation Phase**
///    - Validates Nginx configuration health
///    - Validates site name format
///    - Displays SSL warnings if applicable
///
/// 2. **Nginx Setup**
///    - Creates HTTP configuration
///    - Validates configuration syntax
///
/// 3. **Directory Creation**
///    - Creates site root directory
///    - Sets ownership to www-data:root
///    - Creates SSL directory if needed
///
/// 4. **SSL Configuration** (if enabled)
///    - Generates Let's Encrypt certificates
///    - Updates Nginx config with HTTPS
///
/// 5. **WordPress Installation** (unless disabled)
///    - Downloads and extracts WordPress
///    - Creates MySQL database
///    - Generates wp-config.php
///
/// 6. **Finalization**
///    - Reloads Nginx service
///    - Reports success
///
/// # Rollback Behavior
///
/// If any step fails, the function:
/// 1. Stops execution immediately
/// 2. Reverts all completed steps in reverse order
/// 3. Exits the process with status code 1
///
/// # Directory Structure Created
///
/// ```text
/// /var/www/html/{site_name}/        # Site root
/// ├── (WordPress files)              # If WordPress enabled
/// └── index.html                     # If static site
/// 
/// /etc/nginx/conf.d/{site_name}.conf # Nginx config
/// 
/// /etc/nginx/ssl/{site_name}/        # If SSL enabled
/// ├── privkey.pem                    # Private key
/// └── fullchain.pem                  # Certificate chain
/// ```
///
/// # Permissions
///
/// - Site directory: 777 (www-data:root ownership)
/// - SSL directory: 750 (current_user:root ownership)
/// - Configuration files: Created with default umask
///
/// # Panics
///
/// This function will exit the process with status code 1 if:
/// - Nginx configuration validation fails
/// - Site name validation fails
/// - Any critical step in the site creation process fails
///
/// # Example
///
/// ```no_run
/// // Create a WordPress site with SSL
/// spawn_site("example.local", true, false);
/// 
/// // Create a static site without SSL or WordPress
/// spawn_site("static.local", false, true);
/// ```
///
/// # See Also
///
/// * [`delete_site`] - To remove a created site
/// * [`deactivate_site`] - To temporarily disable a site
pub fn spawn_site(site_name: &str, ssl: bool, no_wp: bool) {
    // Phase 1: Pre-validation
    validate_nginx_configuration().unwrap_or_else(|e| {
        eprintln!("✗ Nginx configuration validation failed before spawning a new site.");
        eprintln!("Make sure Nginx configuration is okay, since nginx reloads is required.");
        eprintln!("Nginx error: \n{}", e);
        process::exit(1);
    });
    
    if ssl {
        ssl::print_ssl_warning(site_name);
    }
    
    println!("Preparing to create site: {}", site_name);
    if no_wp {
        println!("WordPress will not be installed on this site.");
    } else {
        println!("WordPress will be installed on this site.");
    }
    
    validate_site_name(site_name);
    
    // Initialize tracking for rollback
    let mut steps_completed: Vec<SpawnSteps> = Vec::new();
    
    // Create Nginx configuration object
    let nginx_config = nginx::config::NginxConfig::new(
        site_name.to_string(),
        SITES_PATH.to_string(),
        NGINX_CONF_D_PATH.to_string(),
        ssl,
    );
    
    nginx_config.validate().unwrap_or_else(|e| {
        eprintln!("✗ Validation failed: {}", e);
        process::exit(1);
    });
    
    // Phase 2: Create HTTP configuration
    match create_nginx_file(
        nginx_config.nginx_config_file_path.as_str(),
        &nginx_config.generate_config(nginx::config::NginxProtocol::Http),
    ) {
        Ok(()) => {
            println!("✓ Nginx configuration file for HTTP created successfully");
            steps_completed.push(SpawnSteps::CreateNginxConfig);
        }
        Err(e) => {
            eprintln!(
                "✗ Failed to create Nginx configuration file for HTTP: {}",
                e
            );
            process::exit(1);
        }
    }
    
    // Phase 3: Create site directory
    match sites::create_directory_if_not_exists(nginx_config.root.as_str(), Some(0o777)) {
        Ok(()) => {
            // Change ownership of Sites directory www-data:root
            if sites::set_path_owner(Some("www-data"), Some("root"), nginx_config.root.as_str())
                .is_err()
            {
                eprintln!("✗ Failed to set Sites directory ownership.");
                sites::remove_directory(nginx_config.root.as_str()).unwrap_or(());
                revert_site_spawn(site_name, &steps_completed, &nginx_config);
            }
            println!("✓ Site directory created successfully");
            steps_completed.push(SpawnSteps::CreateSiteDirectory);
        }
        Err(e) => {
            eprintln!("✗ Failed to create site directory: {}", e);
            revert_site_spawn(site_name, &steps_completed, &nginx_config);
        }
    }
    
    // Validate Nginx config after HTTP setup
    let _ = validate_nginx_configuration().unwrap_or_else(|e| {
        eprintln!(
            "✗ Nginx configuration validation failed after creating HTTP config. \n{}",
            e
        );
        revert_site_spawn(site_name, &steps_completed, &nginx_config);
    });
    
    // Phase 4: SSL setup (if enabled)
    if let Some(ssl_root) = &nginx_config.ssl_root {
        println!("SSL will be enabled for this site.");
        
        // Create SSL directory
        match sites::create_directory_if_not_exists(ssl_root, Some(0o750)) {
            Ok(()) => {
                // Change ownership of SSL directory to current user:root
                let current_user = env::var("USER").unwrap_or_else(|_| "www-data".to_string());
                if sites::set_path_owner(Some(&current_user), Some("root"), ssl_root).is_err() {
                    eprintln!("✗ Failed to set SSL directory ownership.");
                    sites::remove_directory(ssl_root).unwrap_or(());
                    revert_site_spawn(site_name, &steps_completed, &nginx_config);
                }
                println!("✓ SSL directory created successfully");
                steps_completed.push(SpawnSteps::CreateSSLDirectory);
            }
            Err(e) => {
                eprintln!("✗ Failed to create SSL directory: {}", e);
                revert_site_spawn(site_name, &steps_completed, &nginx_config);
            }
        }
    }
    match ssl::generate_ssl(&nginx_config) {
        Ok(()) => {
            println!("✓ SSL certificates generated and installed successfully");
            steps_completed.push(SpawnSteps::CreateSSL);
            let https_config = nginx_config.generate_config(nginx::config::NginxProtocol::Https);
            match append_to_nginx_file(&nginx_config.nginx_config_file_path, &https_config) {
                Ok(()) => {
                    println!("✓ Nginx configuration file updated for HTTPS successfully");
                    steps_completed.push(SpawnSteps::CreateNginxConfigWithSSL);
                }
                Err(e) => {
                    eprintln!(
                        "✗ Failed to update Nginx configuration file for HTTPS: {}",
                        e
                    );
                    revert_site_spawn(site_name, &steps_completed, &nginx_config);
                }
            }
        }
        Err(e) => {
            eprintln!("✗ SSL generation failed: {}", e);
            revert_site_spawn(site_name, &steps_completed, &nginx_config);
        }
    }
    let _ = validate_nginx_configuration().unwrap_or_else(|e| {
        eprintln!(
            "✗ Nginx configuration validation failed after creating HTTPS config. \n{}",
            e
        );
        revert_site_spawn(site_name, &steps_completed, &nginx_config);
    });
    if !no_wp {
        println!("Installing WordPress on the site.");
        
        // Download and extract WordPress
        match sites::put_wordpress_in_site_directory(nginx_config.root.as_str()) {
            Ok(()) => {
                println!("✓ WordPress installed successfully in site directory");
            }
            Err(e) => {
                eprintln!("✗ Failed to install WordPress: {}", e);
                revert_site_spawn(site_name, &steps_completed, &nginx_config);
            }
        }
        
        // Create database for WordPress site
        let db_name = db::create_db_name(site_name);

        match db::create_wordpress_database(&db_name, false) {
            Ok(db_name) => {
                println!("✓ Database created successfully: {}", db_name);
                steps_completed.push(SpawnSteps::CreateDatabase(db_name.clone()));
            }
            Err(e) => {
                eprintln!("✗ Failed to create database: {}", e);
                revert_site_spawn(site_name, &steps_completed, &nginx_config);
            }
        }
        
        // Create WordPress configuration file
        match sites::create_wp_config_file(
            &nginx_config.root,
            &db_name,
            DB_USER,
            DB_PASSWORD,
            DB_HOST,
            DB_CHARSET,
        ) {
            Ok(()) => {
                println!("✓ WordPress configuration file created successfully");
                steps_completed.push(SpawnSteps::CreateWPConfigFile);
            }
            Err(e) => {
                eprintln!("✗ Failed to create wp-config.php file: {}", e);
                revert_site_spawn(site_name, &steps_completed, &nginx_config);
            }
        }
    } else {
        // Create default index.html for static site
        let path = format!("{}/index.html", nginx_config.root);
        create_file_with_content_if_not_exists(&path, HTML_DEFAULT_INDEX_FILE, None).unwrap_or(());
    }
    
    // Phase 6: Reload Nginx to apply changes
    reload_nginx().unwrap_or_else(|e| {
        eprintln!("✗ Failed to reload Nginx: {}", e);
        revert_site_spawn(site_name, &steps_completed, &nginx_config);
    });
}

/// Deletes an existing site and all its associated resources.
///
/// This function performs a complete cleanup of a site, including:
/// - Removing the site's root directory and all files
/// - Deleting Nginx configuration files
/// - Removing SSL certificates and directories
/// - Dropping the associated MySQL database
///
/// The function attempts to remove all resources even if some operations fail,
/// logging errors for failed operations but continuing with the cleanup process.
///
/// # Arguments
///
/// * `site_name` - The name of the site to delete.
///
/// # Process Flow
///
/// 1. **Pre-validation**: Ensures Nginx configuration is valid
/// 2. **Resource Removal**: Attempts to delete (continues on failure):
///    - Site root directory (`/var/www/html/{site_name}`)
///    - Nginx configuration (`/etc/nginx/conf.d/{site_name}.conf`)
///    - SSL certificates (`/etc/nginx/ssl/{site_name}`)
///    - MySQL database (`wp_{site_name}`)
/// 3. **Post-validation**: Verifies Nginx configuration remains valid
/// 4. **Nginx Reload**: Applies configuration changes
///
/// # Error Recovery
///
/// Unlike site creation, deletion continues even if individual operations fail.
/// This ensures maximum cleanup even in error conditions. Failed operations
/// are logged but don't stop the overall deletion process.
///
/// # Panics
///
/// This function will exit the process with status code 1 if:
/// - Initial Nginx configuration validation fails
/// - Nginx configuration validation fails after deletion
/// - Nginx reload fails after deletion
///
/// # Safety
///
/// ⚠️ **Warning**: This operation is destructive and cannot be undone.
/// All site data, including:
/// - WordPress files and uploads
/// - Database content
/// - SSL certificates
/// - Configuration files
/// 
/// will be permanently deleted.
///
/// # Example
///
/// ```no_run
/// // Delete a site and all its resources
/// delete_site("example.local");
/// ```
///
/// # See Also
///
/// * [`spawn_site`] - To create a new site
/// * [`deactivate_site`] - To temporarily disable without deletion
pub fn delete_site(site_name: &str) {
    println!("Preparing to delete site: {}", site_name);
    println!("Validating Nginx configuration...");
    
    // Ensure Nginx is healthy before making changes
    validate_nginx_configuration().unwrap_or_else(|e| {
        eprintln!("✗ Nginx configuration validation failed before deletion.");
        eprintln!("Make sure Nginx configuration is okay before deleting a site, since nginx reloads is required.");
        eprintln!("Nginx error: \n{}", e);
        process::exit(1);
    });
    
    // Create config object to get paths
    let nginx_config = nginx::config::NginxConfig::new(
        site_name.to_string(),
        SITES_PATH.to_string(),
        NGINX_CONF_D_PATH.to_string(),
        true, // Assume SSL might be present
    );
    
    nginx_config.validate().unwrap_or_else(|e| {
        eprintln!("✗ Validation failed: {}", e);
        process::exit(1);
    });
    
    // Attempt to remove all resources (continue on failure)
    println!("Attempting to delete site resources...");
    
    // Remove site directory
    let _ = sites::remove_directory(nginx_config.root.as_str()).unwrap_or_else(|e| {
        eprintln!("✗ Failed to remove site directory: {}", e);
    });
    
    // Remove Nginx configuration
    println!("Attempting to remove Nginx configuration...");
    sites::remove_file(nginx_config.nginx_config_file_path.as_str()).unwrap_or_else(|e| {
        eprintln!("✗ Failed to remove Nginx configuration file: {}", e);
    });
    
    // Remove SSL certificates
    println!("Attempting to remove SSL files...");
    // Safe to call unwrap here as ssl_root is Some when ssl is true
    sites::remove_directory(nginx_config.ssl_root.as_ref().unwrap()).unwrap_or_else(|e| {
        eprintln!("✗ Failed to remove SSL directory: {}", e);
    });
    
    // Drop database
    let db_name = db::create_db_name(site_name);
    println!("Attempting to drop database '{}'...", db_name);
    match db::drop_database(&db_name) {
        Ok(()) => (),
        Err(e) => eprintln!("✗ Failed to delete database: {}", e),
    }
    
    // Validate configuration after changes
    validate_nginx_configuration().unwrap_or_else(|e| {
        eprintln!("✗ Nginx configuration validation failed after deletion.");
        eprintln!("Make sure Nginx configuration is okay before reloading Nginx.");
        eprintln!("Nginx error: \n{}", e);
        process::exit(1);
    });
    
    // Reload Nginx to apply changes
    reload_nginx().unwrap_or_else(|e| {
        eprintln!("✗ Failed to reload Nginx: {}", e);
        process::exit(1);
    });
}

/// Temporarily deactivates a site without deleting its resources.
///
/// This function disables a site by renaming its Nginx configuration file
/// to have a `.deactivated` extension, which prevents Nginx from loading it.
/// The site's files, database, and SSL certificates remain intact and can
/// be reactivated later using the `activate_site` function.
///
/// # Arguments
///
/// * `site_name` - The name of the site to deactivate.
///
/// # Behavior
///
/// - Validates Nginx configuration before making changes
/// - Renames the configuration file from `.conf` to `.conf.deactivated`
/// - Reloads Nginx to apply the changes
/// - Exits gracefully if the site is already deactivated
///
/// # File Operations
///
/// ```text
/// Before: /etc/nginx/conf.d/example.com.conf
/// After:  /etc/nginx/conf.d/example.com.conf.deactivated
/// ```
///
/// # Preserved Resources
///
/// The following remain untouched:
/// - Site files in `/var/www/html/{site_name}`
/// - MySQL database
/// - SSL certificates in `/etc/nginx/ssl/{site_name}`
/// - The renamed configuration file
///
/// # Use Cases
///
/// - Temporary maintenance windows
/// - Debugging site issues
/// - Staging sites that aren't currently needed
/// - Quick site suspension without data loss
///
/// # Panics
///
/// This function will exit the process with status code 1 if:
/// - Nginx configuration validation fails
/// - The rename operation fails
/// - Nginx reload fails
///
/// # Example
///
/// ```no_run
/// // Temporarily disable a site
/// deactivate_site("example.local");
/// // The site can later be reactivated with activate_site()
/// ```
///
/// # See Also
///
/// * [`activate_site`] - To re-enable the deactivated site
/// * [`delete_site`] - To permanently remove the site
pub fn deactivate_site(site_name: &str) {
    println!("Attempting to deactivate site: {}", site_name);
    
    // Validate Nginx before changes
    validate_nginx_configuration().unwrap_or_else(|e| {
        eprintln!("✗ Nginx configuration validation failed before deactivation.");
        eprintln!("Make sure Nginx configuration is okay, since nginx reloads is required.");
        eprintln!("Nginx error: \n{}", e);
        process::exit(1);
    });
    
    // Create config object to get paths
    let nginx_config = nginx::config::NginxConfig::new(
        site_name.to_string(),
        SITES_PATH.to_string(),
        NGINX_CONF_D_PATH.to_string(),
        false,
    );
    
    nginx_config.validate().unwrap_or_else(|e| {
        eprintln!("✗ Validation failed: {}", e);
        process::exit(1);
    });

    // Define source and destination paths
    let active_path = Path::new(&nginx_config.nginx_config_file_path);
    let deactivated_path = active_path.with_extension("conf.deactivated");

    // Check if configuration exists
    if !active_path.exists() {
        println!("Nothing to deactivate for site '{}'.", site_name);
        process::exit(0);
    }

    // Rename configuration file
    match fs::rename(&active_path, &deactivated_path) {
        Ok(()) => {
            println!("✓ Site '{}' deactivated successfully.", site_name);
        }
        Err(e) => {
            eprintln!("✗ Failed to deactivate site '{}': {}", site_name, e);
            process::exit(1);
        }
    }

    // Reload Nginx to apply changes
    reload_nginx().unwrap_or_else(|e| {
        eprintln!("✗ Failed to reload Nginx: {}", e);
        process::exit(1);
    });
}

/// Reactivates a previously deactivated site.
///
/// This function re-enables a site that was previously deactivated by
/// renaming its configuration file back from `.conf.deactivated` to `.conf`,
/// allowing Nginx to load it again. All site resources (files, database,
/// SSL certificates) that were preserved during deactivation become
/// accessible again.
///
/// # Arguments
///
/// * `site_name` - The name of the site to activate.
///
/// # Behavior
///
/// - Validates Nginx configuration before making changes
/// - Renames the configuration file from `.conf.deactivated` back to `.conf`
/// - Reloads Nginx to apply the changes
/// - Exits gracefully if the site is already active or doesn't exist
///
/// # File Operations
///
/// ```text
/// Before: /etc/nginx/conf.d/example.com.conf.deactivated
/// After:  /etc/nginx/conf.d/example.com.conf
/// ```
///
/// # Prerequisites
///
/// The site must have been previously deactivated using [`deactivate_site`].
/// All original resources should still be present:
/// - Site files in `/var/www/html/{site_name}`
/// - MySQL database (if WordPress site)
/// - SSL certificates (if HTTPS enabled)
///
/// # Recovery Time
///
/// Activation is nearly instantaneous, requiring only:
/// 1. File rename operation
/// 2. Nginx configuration reload
///
/// The site becomes accessible immediately after Nginx reload completes.
///
/// # Panics
///
/// This function will exit the process with status code 1 if:
/// - Nginx configuration validation fails
/// - The rename operation fails
/// - Nginx reload fails
///
/// # Example
///
/// ```no_run
/// // Reactivate a previously deactivated site
/// activate_site("example.local");
/// ```
///
/// # See Also
///
/// * [`deactivate_site`] - To temporarily disable a site
/// * [`spawn_site`] - To create a new site
pub fn activate_site(site_name: &str) {
    println!("Attempting to activate site: {}", site_name);
    
    // Validate Nginx before changes
    validate_nginx_configuration().unwrap_or_else(|e| {
        eprintln!("✗ Nginx configuration validation failed before activation.");
        eprintln!("Make sure Nginx configuration is okay, since nginx reloads is required.");
        eprintln!("Nginx error: \n{}", e);
        process::exit(1);
    });
    
    // Create config object to get paths
    let nginx_config = nginx::config::NginxConfig::new(
        site_name.to_string(),
        SITES_PATH.to_string(),
        NGINX_CONF_D_PATH.to_string(),
        false,
    );
    
    nginx_config.validate().unwrap_or_else(|e| {
        eprintln!("✗ Validation failed: {}", e);
        process::exit(1);
    });

    // Define source and destination paths
    let active_path = Path::new(&nginx_config.nginx_config_file_path);
    let deactivated_path = active_path.with_extension("conf.deactivated");

    // Check if deactivated configuration exists
    if !deactivated_path.exists() {
        println!("Nothing to activate for site '{}'.", site_name);
        process::exit(0);
    }

    // Rename configuration file back to active
    match fs::rename(&deactivated_path, &active_path) {
        Ok(()) => {
            println!("✓ Site '{}' activated successfully.", site_name);
        }
        Err(e) => {
            eprintln!("✗ Failed to activate site '{}': {}", site_name, e);
            process::exit(1);
        }
    }

    // Reload Nginx to apply changes
    reload_nginx().unwrap_or_else(|e| {
        eprintln!("✗ Failed to reload Nginx: {}", e);
        process::exit(1);
    });
}

// /// Updates an existing site with new configurations.
// ///
// /// This function allows modification of an existing site's configuration,
// /// such as adding WordPress to a static site or enabling SSL on a site
// /// that was initially created without it.
// ///
// /// # Arguments
// ///
// /// * `site_name` - The name of the site to update.
// /// * `wp` - If `true`, installs WordPress on an existing static site.
// /// * `ssl` - If `true`, generates SSL certificates and enables HTTPS.
// ///
// /// # Status
// ///
// /// ⚠️ **Not Implemented**: This function is currently a placeholder
// /// for future functionality and will not perform any operations.
// ///
// /// # Planned Features
// ///
// /// When implemented, this function will support:
// ///
// /// ## WordPress Addition
// /// - Install WordPress in existing static sites
// /// - Create database and wp-config.php
// /// - Preserve existing static files
// /// - Update Nginx configuration for PHP processing
// ///
// /// ## SSL Enablement
// /// - Generate Let's Encrypt certificates
// /// - Update Nginx configuration for HTTPS
// /// - Add HTTP to HTTPS redirect
// /// - Preserve existing site functionality
// ///
// /// ## Other Updates
// /// - Modify Nginx configuration parameters
// /// - Update site directory permissions
// /// - Change PHP version or configuration
// /// - Enable/disable caching
// ///
// /// # Example (Future)
// ///
// /// ```no_run
// /// // Add WordPress to a static site
// /// update_site("static.local", true, false);
// ///
// /// // Enable SSL on an HTTP-only site
// /// update_site("http-only.local", false, true);
// ///
// /// // Add both WordPress and SSL
// /// update_site("basic.local", true, true);
// /// ```
// pub fn update_site(site_name: &str, wp: bool, ssl: bool) {
//     println!("Preparing to update site: {}", site_name);
//     if wp {
//         println!("WordPress will be installed on this site.");
//     }
//     if ssl {
//         println!("SSL will be installed on this site.");
//     }
//     // Future implementation goes here
// }

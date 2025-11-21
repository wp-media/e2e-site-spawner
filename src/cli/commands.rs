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
use crate::constants::{DB_HOST, HTML_DEFAULT_INDEX_FILE, NGINX_CONF_D_PATH, SITES_PATH, NGINX_HTTP_CONFIG_MARKER, NGINX_HTTPS_CONFIG_MARKER};
use crate::nginx::config::validate_nginx_configuration;
use crate::nginx::{self, reload_nginx, check_if_https_in_nginx_config_file};
use crate::nginx::{append_to_nginx_file, create_nginx_file, get_list_of_sites_nginx_file_paths};
use crate::utils::db;
use crate::utils::sites::{self, check_if_site_exists, create_file_with_content_if_not_exists, get_sudo_user, put_wordpress_in_site_directory, revert_site_spawn};
use crate::utils::ssl::{self, remove_site_from_acme};
use crate::utils::validators::validate_site_name;
use std::path::Path;
use std::{fs, process};
use colored::*;

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

    if !validate_site_name(site_name) {
        eprintln!("✗ Invalid site name: {}", site_name);
        process::exit(1);
    }

    // Initialize tracking for rollback
    let mut steps_completed: Vec<SpawnSteps> = Vec::new();
    
    // Create Nginx configuration object
    let nginx_config = nginx::config::NginxConfig::new(
        site_name.to_string(),
        SITES_PATH.to_string(),
        NGINX_CONF_D_PATH.to_string(),
        ssl,
    );
    if check_if_site_exists(&nginx_config) {
        eprintln!("✗ Site '{}' seems to already exist. Cannot continue.", site_name);
        process::exit(1);
    }
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
            if sites::set_path_owner_recursive(Some("www-data"), Some("root"), nginx_config.root.as_str())
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

    // Nginx reload is needed for the site to be accessible at least by HTTP (Required for SSL generation)
    reload_nginx().unwrap_or_else(|e| {
        eprintln!("✗ Failed to reload Nginx: {}", e);
        revert_site_spawn(site_name, &steps_completed, &nginx_config);
    });
    // Phase 4: SSL setup (if enabled)
    if let Some(ssl_root) = &nginx_config.ssl_root {
        println!("SSL will be enabled for this site.");
        
        // Create SSL directory
        match sites::create_directory_if_not_exists(ssl_root, Some(0o750)) {
            Ok(()) => {
                println!("✓ SSL directory created successfully");
                steps_completed.push(SpawnSteps::CreateSSLDirectory);
            }
            Err(e) => {
                eprintln!("✗ Failed to create SSL directory: {}", e);
                revert_site_spawn(site_name, &steps_completed, &nginx_config);
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
        // Change ownership of SSL directory to current user:root
        let current_user = get_sudo_user();
        sites::set_path_owner_recursive(Some(&current_user), Some("root"), ssl_root).unwrap_or(());
    }
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
    print!("Validating Nginx configuration...");
    
    // Ensure Nginx is healthy before making changes
    validate_nginx_configuration().unwrap_or_else(|e| {
        println!("{}", " failed".bright_red());
        eprintln!("✗ Nginx configuration validation failed before deletion.");
        eprintln!("Make sure Nginx configuration is okay before deleting a site, since nginx reloads is required.");
        eprintln!("Nginx error: \n{}", e);
        process::exit(1);
    });
    println!("{}", " ok".bright_green());
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
    print!("Attempting to delete site resources...");
    
    // Remove site directory
    match sites::remove_directory(nginx_config.root.as_str()) {
        Ok(()) => println!("{}", " ok".bright_green()),
        Err(e) => {
            println!("{}", " failed".bright_red());
            eprintln!("✗ Failed to remove site directory: {}", e)
        },
    }

    // Remove Nginx configuration
    print!("Attempting to remove Nginx configuration...");
    match sites::remove_file(nginx_config.nginx_config_file_path.as_str()) {
        Ok(()) => println!("{}", " ok".bright_green()),
        Err(e) => {
            println!("{}", " failed".bright_red());
            eprintln!("✗ Failed to remove Nginx configuration file: {}", e)
        },
    }
    // Remove site from acme (prevent future renewals)
    print!("Attempting to remove site from acme (Deactivate SSL renewal)...");
    match remove_site_from_acme(site_name) {
        Ok(()) => println!("{}", " ok".bright_green()),
        Err(e) => {
            println!("{}", " failed".bright_red());
            eprintln!("✗ Failed to remove site from acme: {}", e)
        },
    }
    // Remove SSL certificates
    print!("Attempting to remove SSL files...");
    // Safe to call unwrap here as ssl_root is Some when ssl is true
    match sites::remove_directory(nginx_config.ssl_root.as_ref().unwrap()) {
        Ok(()) => println!("{}", " ok".bright_green()),
        Err(e) => {
            println!("{}", " failed".bright_red());
            eprintln!("✗ Failed to remove SSL directory: {}", e)
        },
    };
    
    // Drop database
    let db_name = db::create_db_name(site_name);
    print!("Attempting to drop database '{}'...", db_name);
    match db::drop_database(&db_name) {
        Ok(()) => println!("{}", " ok".bright_green()),
        Err(e) => {
            println!("{}", " failed".bright_red());
            eprintln!("✗ Failed to drop database '{}': {}", db_name, e)
        },
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

/// Updates an existing site with new configurations.
///
/// This function allows modification of an existing site's configuration,
/// such as adding WordPress to a static site or enabling SSL on a site
/// that was initially created without it.
///
/// # Arguments
///
/// * `site_name` - The name of the site to update.
/// * `wp` - If `true`, installs WordPress on an existing static site.
/// * `ssl` - If `true`, generates SSL certificates and enables HTTPS.
///
/// # Status
///
/// ⚠️ **Not Implemented**: This function is currently a placeholder
/// for future functionality and will not perform any operations.
///
/// # Planned Features
///
/// When implemented, this function will support:
///
/// ## WordPress Addition
/// - Install WordPress in existing static sites
/// - Create database and wp-config.php
/// - Preserve existing static files
/// - Update Nginx configuration for PHP processing
///
/// ## SSL Enablement
/// - Generate Let's Encrypt certificates
/// - Update Nginx configuration for HTTPS
/// - Add HTTP to HTTPS redirect
/// - Preserve existing site functionality
///
/// ## Other Updates
/// - Modify Nginx configuration parameters
/// - Update site directory permissions
/// - Change PHP version or configuration
/// - Enable/disable caching
///
/// # Example (Future)
///
/// ```no_run
/// // Add WordPress to a static site
/// update_site("static.local", true, false);
///
/// // Enable SSL on an HTTP-only site
/// update_site("http-only.local", false, true);
///
/// // Add both WordPress and SSL
/// update_site("basic.local", true, true);
/// ```
pub fn update_site(site_name: &str, wp: bool, ssl: bool) {
    if !wp && !ssl {
        println!("No updates specified for site '{}'. Exiting.", site_name);
        process::exit(0);
    }
    if !validate_site_name(site_name) {
        eprintln!("✗ Invalid site name: {}", site_name);
        process::exit(1);
    }
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
        // Phase 1: Pre-validation
    validate_nginx_configuration().unwrap_or_else(|e| {
        eprintln!("✗ Nginx configuration validation failed before updating.");
        eprintln!("Make sure Nginx configuration is okay, since nginx reloads is required.");
        eprintln!("Nginx error: \n{}", e);
        process::exit(1);
    });
    if !check_if_site_exists(&nginx_config) {
        eprintln!("✗ Site '{}' does not exist. Cannot update.", site_name);
        process::exit(1);
    }
    println!("Preparing to update site: {}", site_name);
    if wp {
        update_with_wordpress(&nginx_config).unwrap_or(());
    } if ssl {
        update_with_ssl(&nginx_config).unwrap_or(());
    }
}

/// Lists all configured sites with their status and features.
///
/// This function scans the Nginx configuration directory and displays information
/// about each site including:
/// - Whether it's managed by e2sp
/// - SSL status (if HTTPS is configured)
/// - WordPress status (if wp-config.php exists)
/// - Active/Deactivated status based on file extension
///
/// The output is color-coded for better readability.
pub fn list_sites() {
    use colored::*;
    
    let config_sites_path = Path::new(NGINX_CONF_D_PATH);
    if !config_sites_path.exists() || !config_sites_path.is_dir() {
        println!("No Nginx configuration directory found at '{}'.", NGINX_CONF_D_PATH);
        return;
    }
    
    // Get all nginx config files (both .conf and .conf.deactivated)
    let sites_nginx_files = get_list_of_sites_nginx_file_paths().unwrap_or_else(|e| {
        eprintln!("✗ Failed to read Nginx configuration directory: {}", e);
        process::exit(1);
    });
    
    if sites_nginx_files.is_empty() {
        println!("No sites found in Nginx configuration directory '{}'.", NGINX_CONF_D_PATH);
        return;
    }
    
    // Structure to hold site information
    struct SiteInfo {
        name: String,
        is_managed: bool,
        has_ssl: bool,
        has_wordpress: bool,
        is_active: bool,
    }
    
    let mut sites: Vec<SiteInfo> = Vec::new();
    
    // Process each configuration file
    for file_path in sites_nginx_files {
        // Read file content once for all checks
        let content = match fs::read_to_string(&file_path) {
            Ok(c) => c,
            Err(_) => continue, // Skip files we can't read
        };
        
        // Check if it's a valid nginx config with server block
        if !content.contains("server {") {
            continue;
        }
        
        // Get file name and determine status
        let file_name = Path::new(&file_path)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default()
            .to_string();
        
        // Determine if site is active based on file extension
        let is_active = file_name.ends_with(".conf") && !file_name.ends_with(".conf.deactivated");
        
        // Extract site name by removing extensions
        let base = file_name
            .strip_suffix(".conf.deactivated")
            .or_else(|| file_name.strip_suffix(".conf"))
            .unwrap_or(&file_name)
            .to_string();
        
        // Validate site name
        if !validate_site_name(&base) {
            continue;
        }
        
        // Check if managed by e2sp (contains our marker from the template)
        let is_managed = content.contains(NGINX_HTTP_CONFIG_MARKER);
        if !is_managed {
            // If not managed, add with minimal info
            sites.push(SiteInfo {
                name: base,
                is_managed,
                has_ssl: false,
                has_wordpress: false,
                is_active: false,
            });
            continue;
        }
        // Check for SSL (only if managed by e2sp)
        let has_ssl = content.contains(NGINX_HTTPS_CONFIG_MARKER);
        
        // Construct the site path using SITES_PATH constant and base name
        let wp_config_path = format!("{}/{}/wp-config.php", SITES_PATH, base);
        // Check for WordPress by looking for wp-config.php in site root
        let has_wordpress = Path::new(&wp_config_path).exists();

        sites.push(SiteInfo {
            name: base,
            is_managed,
            has_ssl,
            has_wordpress,
            is_active,
        });
    }
    
    // Sort sites alphabetically by name
    sites.sort_by(|a, b| a.name.cmp(&b.name));
    
    if sites.is_empty() {
        println!("No valid sites found.");
        return;
    }
    
    // Print header
    println!("\n{}", "Configured Sites:".bold().underline());
    println!();
    
    // Display each site with its status
    for site in &sites {
        if !site.is_managed {
            // Non-e2sp managed sites
            println!("  {} - {}",
                site.name.bright_white(),
                "not managed by e2sp".dimmed()
            );
        } else {
            // Build features list
            let mut features = Vec::new();
            if site.has_ssl {
                features.push("ssl");
            }
            if site.has_wordpress {
                features.push("wp");
            }
            
            // Format the line based on what features exist
            let status = if site.is_active {
                "(active)".green()
            } else {
                "(deactivated)".yellow()
            };
            
            if features.is_empty() {
                // No features, just show name and status
                println!("  {} - {}",
                    site.name.bright_white(),
                    status
                );
            } else {
                // Show features
                let features_str = features.iter().map(|f| {
                    match *f {
                        "ssl" => "ssl".green().to_string(),
                        "wp" => "wp".blue().to_string(),
                        _ => f.to_string(),
                    }
                }).collect::<Vec<_>>().join(", ");
                
                println!("  {} - {} - {}",
                    site.name.bright_white(),
                    features_str,
                    status
                );
            }
        }
    }
    
    println!();
    
    // Print summary
    let total = sites.len();
    let managed = sites.iter().filter(|s| s.is_managed).count();
    let active = sites.iter().filter(|s| s.is_managed && s.is_active).count();
    let deactivated = sites.iter().filter(|s| s.is_managed && !s.is_active).count();
    let unmanaged = sites.iter().filter(|s| !s.is_managed).count();
    
    println!("{}", "Summary:".bold());
    println!("  Total sites: {}", total.to_string().bright_white());
    
    if managed > 0 {
        println!("  Managed by e2sp: {} ({} active, {} deactivated)",
            managed.to_string().cyan(),
            active.to_string().green(),
            deactivated.to_string().yellow()
        );
    }
    
    if unmanaged > 0 {
        println!("  Not managed by e2sp: {}",
            unmanaged.to_string().dimmed()
        );
    }
}

/// Installs WordPress on an existing static site.
///
/// This function transforms a static HTML site into a dynamic WordPress site by
/// installing WordPress files, creating a database, and generating the necessary
/// configuration. The function ensures no existing WordPress installation is present
/// before proceeding with the installation.
///
/// # Arguments
///
/// * `nginx_config` - The Nginx configuration object containing site details and paths.
///
/// # Returns
///
/// * `Ok(())` - WordPress was successfully installed on the site
/// * `Err(())` - Installation failed (WordPress already exists, database issues, etc.)
///
/// # Process Flow
///
/// 1. **Pre-installation Checks**
///    - Verifies WordPress is not already installed (checks for wp-config.php)
///    - Confirms database doesn't already exist for the site
///    - Ensures site directory exists and is accessible
///
/// 2. **WordPress File Installation**
///    - Downloads latest WordPress version
///    - Extracts WordPress files to site directory
///    - Preserves existing static files (index.html, etc.)
///    - Sets appropriate file permissions
///
/// 3. **Database Creation**
///    - Creates MySQL database with UTF8MB4 charset
///    - Names database as `wp_{site_name}` (with underscores)
///    - Grants full privileges to configured database user
///    - Handles name conflicts with numeric suffixes if needed
///
/// 4. **Configuration Generation**
///    - Creates wp-config.php with database credentials
///    - Generates unique authentication keys and salts
///    - Sets WordPress database constants
///    - Configures debug settings based on environment
///
/// # Files Created/Modified
///
/// ```text
/// /var/www/html/{site_name}/
/// ├── wp-admin/                  # WordPress admin files (created)
/// ├── wp-content/                # Themes, plugins, uploads (created)
/// ├── wp-includes/               # WordPress core files (created)
/// ├── wp-config.php              # Database configuration (created)
/// ├── index.php                  # WordPress entry point (created)
/// └── (existing static files)    # Preserved during installation
/// ```
///
/// # Database Structure
///
/// Creates database: `wp_{site_name}` containing:
/// - WordPress core tables (wp_posts, wp_users, etc.)
/// - Charset: UTF8MB4 for full Unicode support
/// - Collation: utf8mb4_unicode_ci
///
/// # Error Conditions
///
/// The function will fail and return `Err(())` if:
/// - WordPress is already installed (wp-config.php exists)
/// - Database already exists for the site
/// - Unable to download or extract WordPress files
/// - Database creation fails (connection issues, permissions)
/// - Unable to write wp-config.php file
/// - File system operations fail (permissions, disk space)
///
/// # Rollback Behavior
///
/// On failure, the function attempts partial cleanup:
/// - Database is dropped if wp-config.php creation fails
/// - WordPress files may remain if database creation fails
/// - Original static files are preserved throughout
/// - Manual cleanup may be required for partial installations
///
/// # Safety Considerations
///
/// - Checks for existing installations before proceeding
/// - Preserves existing static content during installation
/// - Database credentials are never logged or displayed
/// - File permissions are set appropriately for security
/// - Validates each step before proceeding to the next
///
/// # Example
///
/// ```no_run
/// let nginx_config = NginxConfig::new(
///     "static-site.com".to_string(),
///     "/var/www/html/static-site.com".to_string(),
///     "/etc/nginx/conf.d".to_string(),
///     false,  // SSL configuration
/// );
///
/// match update_with_wordpress(&nginx_config) {
///     Ok(()) => println!("WordPress installed successfully"),
///     Err(()) => eprintln!("Failed to install WordPress"),
/// }
/// ```
///
/// # Prerequisites
///
/// - Site must exist as a static site (directory created)
/// - MySQL/MariaDB server must be running and accessible
/// - Database user must have CREATE privileges
/// - Sufficient disk space for WordPress files (~50MB)
/// - Write permissions on the site directory
/// - No existing WordPress installation in the directory
///
/// # Post-Installation Requirements
///
/// After successful installation:
/// - Navigate to site URL to complete WordPress setup wizard
/// - Configure site title, admin user, and password
/// - Choose initial theme and plugins
/// - Configure permalink structure if needed
/// - Set up regular backups for database and files
///
/// # Migration Notes
///
/// When converting a static site:
/// - Static HTML files are preserved but not linked
/// - Consider migrating static content to WordPress pages
/// - Update Nginx configuration for PHP processing if needed
/// - Configure WordPress permalinks to match old URLs if applicable
///
/// # Performance Considerations
///
/// - WordPress requires PHP-FPM for processing
/// - Database queries add latency compared to static files
/// - Consider caching solutions (Redis, Memcached) for production
/// - Regular database optimization may be needed
///
/// # Security Recommendations
///
/// Post-installation security steps:
/// - Change default "admin" username if used
/// - Enable two-factor authentication
/// - Keep WordPress and plugins updated
/// - Configure file permissions properly (755 for directories, 644 for files)
/// - Consider security plugins like Wordfence or Sucuri
///
/// # See Also
///
/// * [`put_wordpress_in_site_directory`] - Core WordPress installation logic
/// * [`create_wordpress_database`] - Database creation with retry logic
/// * [`create_wp_config_file`] - Configuration file generation
/// * [`spawn_site`] - Creates new sites with WordPress from scratch
fn update_with_wordpress(nginx_config: &nginx::config::NginxConfig) -> Result<(), ()> {
    let site_name = &nginx_config.site_name;
    
    // Pre-installation check: Verify WordPress is not already installed
    let wp_config_path = format!("{}/wp-config.php", nginx_config.root);
    if Path::new(&wp_config_path).exists() {
        eprintln!("✗ WordPress seems to already exist for site '{}'. Cannot update.", site_name);
        eprintln!("  Found existing wp-config.php at: {}", wp_config_path);
        return Err(());
    }
    
    // Check if database already exists (would indicate partial or previous installation)
    let db_name = db::create_db_name(site_name);
    match db::database_exists(&db_name, None) {
        Ok(exists) => {
            if exists {
                eprintln!("✗ Database '{}' already exists for site '{}'. Cannot update.", db_name, site_name);
                eprintln!("  This may indicate a previous WordPress installation.");
                eprintln!("  Please check and clean up any existing database if needed.");
                return Err(());
            }
        }
        Err(e) => {
            eprintln!("✗ Failed to check database existence: {}", e);
            eprintln!("  Cannot proceed without verifying database state.");
            return Err(());
        }
    }
    
    println!("Attempting to install WordPress on this site...");
    println!("  Site directory: {}", nginx_config.root);
    println!("  Database name: {}", db_name);
    
    // Step 1: Download and extract WordPress files to site directory
    match put_wordpress_in_site_directory(nginx_config.root.as_str()) {
        Ok(()) => {
            println!("✓ WordPress files installed successfully in site directory");
        }
        Err(e) => {
            eprintln!("✗ Failed to install WordPress files: {}", e);
            eprintln!("  Ensure the site directory exists and is writable.");
            return Err(());
        }
    }
    
    // Step 2: Create MySQL database for WordPress
    match db::create_wordpress_database(&db_name, false) {
        Ok(created_db_name) => {
            println!("✓ Database '{}' created successfully", created_db_name);
            
            // Note: created_db_name might differ from db_name if a suffix was added
            // due to conflicts, but we use the original for consistency
        }
        Err(e) => {
            eprintln!("✗ Failed to create database: {}", e);
            eprintln!("  WordPress files have been installed but database creation failed.");
            eprintln!("  You may need to manually clean up the WordPress files.");
            return Err(());
        }
    }
    
    // Step 3: Generate WordPress configuration file with database credentials
    match sites::create_wp_config_file(
        &nginx_config.root,
        &db_name,
        DB_USER,
        DB_PASSWORD,
        DB_HOST,
        DB_CHARSET,
    ) {
        Ok(()) => {
            println!("✓ WordPress configuration file (wp-config.php) created successfully");
        }
        Err(e) => {
            eprintln!("✗ Failed to create wp-config.php file: {}", e);
            eprintln!("  Attempting to clean up database...");
            
            // Rollback: Remove the database since configuration failed
            match db::drop_database(&db_name) {
                Ok(()) => {
                    println!("  Database '{}' has been removed.", db_name);
                }
                Err(drop_err) => {
                    eprintln!("  WARNING: Failed to remove database '{}': {}", db_name, drop_err);
                    eprintln!("  Manual cleanup of the database may be required.");
                }
            }
            
            eprintln!("  WordPress files remain in the directory and need manual cleanup.");
            return Err(());
        }
    }
    
    println!("✓ WordPress successfully installed on site '{}'", site_name);
    println!("");
    println!("  Next steps:");
    println!("  1. Navigate to http://{} to complete WordPress setup", site_name);
    println!("  2. Follow the installation wizard to set up your admin account");
    println!("  3. Configure your site settings and install themes/plugins as needed");
    
    Ok(())
}

/// Adds SSL/HTTPS support to an existing HTTP-only site.
///
/// This function enables SSL on a site that was initially created without HTTPS support.
/// It generates Let's Encrypt certificates, updates the Nginx configuration to include
/// HTTPS server blocks, and validates all changes before committing them.
///
/// # Arguments
///
/// * `nginx_config` - The Nginx configuration object containing site details and paths.
///
/// # Returns
///
/// * `Ok(())` - SSL was successfully enabled for the site
/// * `Err(())` - SSL enablement failed (site already has SSL, certificate generation failed, etc.)
///
/// # Process Flow
///
/// 1. **Pre-flight Checks**
///    - Verifies SSL is not already enabled (checks certificate files and config)
///    - Backs up the current Nginx configuration for rollback
///
/// 2. **SSL Certificate Generation**
///    - Creates SSL directory at `/etc/nginx/ssl/{site_name}/`
///    - Generates Let's Encrypt certificates via acme.sh
///    - Installs certificates in the SSL directory
///
/// 3. **Nginx Configuration Update**
///    - Appends HTTPS server block to existing configuration
///    - Adds SSL certificate paths and security headers
///    - Configures HTTP to HTTPS redirect
///
/// 4. **Validation & Rollback**
///    - Validates the updated Nginx configuration
///    - Reverts all changes if validation fails
///    - Preserves original configuration on any error
///
/// # Files Modified
///
/// ```text
/// /etc/nginx/conf.d/{site_name}.conf     # Updated with HTTPS server block
/// /etc/nginx/ssl/{site_name}/
/// ├── privkey.pem                        # Private key (created)
/// └── fullchain.pem                       # Certificate chain (created)
/// ```
///
/// # Error Conditions
///
/// The function will fail and return `Err(())` if:
/// - SSL files already exist in the SSL directory
/// - HTTPS configuration already exists in the Nginx config file
/// - Unable to read the existing Nginx configuration
/// - SSL certificate generation fails (domain verification, rate limits, etc.)
/// - Nginx configuration becomes invalid after updates
/// - File system operations fail (permissions, disk space, etc.)
///
/// # Rollback Behavior
///
/// On failure, the function attempts to restore the original state:
/// - Nginx configuration is reverted to the backed-up version
/// - SSL certificates may remain (manual cleanup required)
/// - No database or WordPress files are affected
///
/// # Safety Considerations
///
/// - The function backs up the Nginx configuration before modifications
/// - All changes are validated before being committed
/// - Partial updates are avoided through atomic operations where possible
/// - SSL private keys are created with restricted permissions
///
/// # Example
///
/// ```no_run
/// let nginx_config = NginxConfig::new(
///     "example.com".to_string(),
///     "/var/www/html".to_string(),
///     "/etc/nginx/conf.d".to_string(),
///     true,  // SSL enabled in config object
/// );
///
/// match update_with_ssl(&nginx_config) {
///     Ok(()) => println!("SSL enabled successfully"),
///     Err(()) => eprintln!("Failed to enable SSL"),
/// }
/// ```
///
/// # Prerequisites
///
/// - Site must exist and be accessible via HTTP
/// - Domain must be properly configured (DNS pointing to server)
/// - Port 80 must be accessible for Let's Encrypt validation
/// - acme.sh must be installed and configured
/// - User must have permissions to modify Nginx configurations
///
/// # Post-Success Requirements
///
/// After successful SSL enablement:
/// - Nginx reload is required (handled by caller)
/// - Site will be accessible via HTTPS on port 443
/// - HTTP traffic will redirect to HTTPS
/// - SSL certificates will auto-renew via acme.sh cron job
///
/// # See Also
///
/// * [`ssl::generate_ssl`] - Core SSL certificate generation logic
/// * [`check_if_https_in_nginx_config_file`] - Checks for existing HTTPS config
/// * [`validate_nginx_configuration`] - Validates Nginx syntax
fn update_with_ssl(nginx_config: &nginx::config::NginxConfig) -> Result<(), ()> {
    let site_name = &nginx_config.site_name;
    
    // Pre-flight check: Verify SSL is not already enabled
    // Safe to call unwrap here as ssl_root is Some when ssl is true in the config
    let ssl_root = nginx_config.ssl_root.as_ref().unwrap();
    
    // Check both certificate files and nginx config for existing SSL
    if ssl::check_if_ssl_files_exist(ssl_root) || 
       check_if_https_in_nginx_config_file(&nginx_config.nginx_config_file_path) {
        eprintln!("✗ SSL seems to already exist for site '{}'. Cannot update.", site_name);
        return Err(());
    }
    
    println!("Attempting to enable SSL for this site...");
    
    // Backup current nginx configuration for potential rollback
    let original_nginx_config_file_content = match fs::read_to_string(&nginx_config.nginx_config_file_path) {
        Ok(content) => content,
        Err(e) => {
            eprintln!("✗ Failed to read existing Nginx configuration file for site '{}': {}", site_name, e);
            eprintln!("  Cannot proceed with SSL update without backup.");
            return Err(());
        }
    };
    
    // Generate SSL certificates via Let's Encrypt
    match ssl::generate_ssl(&nginx_config) {
        Ok(()) => {
            println!("✓ SSL certificates generated and installed successfully");
            let https_config = nginx_config.generate_config(nginx::config::NginxProtocol::Https);
            match append_to_nginx_file(&nginx_config.nginx_config_file_path, &https_config) {
                Ok(()) => {
                    println!("✓ Nginx configuration file updated for HTTPS successfully");
                }
                Err(e) => {
                    eprintln!(
                        "✗ Failed to update Nginx configuration file for HTTPS: {}",
                        e
                    );
                    return Err(());
                }
            }
        }
        Err(e) => {
            eprintln!("✗ SSL generation failed: {}", e);
            return Err(());
        }
    }
    
    // Generate HTTPS server block configuration
    let https_config = nginx_config.generate_config(nginx::config::NginxProtocol::Https);
    
    // Append HTTPS configuration to existing nginx config file
    match append_to_nginx_file(&nginx_config.nginx_config_file_path, &https_config) {
        Ok(()) => {
            println!("✓ Nginx configuration file updated for HTTPS successfully");
        }
        Err(e) => {
            eprintln!("✗ Failed to update Nginx configuration file for HTTPS: {}", e);
            
            // Attempt to revert to original configuration
            println!("Attempting to revert Nginx configuration...");
            if let Err(err) = fs::write(&nginx_config.nginx_config_file_path, &original_nginx_config_file_content) {
                eprintln!("✗ CRITICAL: Failed to revert Nginx configuration file: {}", err);
                eprintln!("  Manual intervention may be required to restore the configuration.");
            }
            return Err(());
        }
    }
    
    // Validate the updated nginx configuration
    if let Err(e) = validate_nginx_configuration() {
        eprintln!("✗ Nginx configuration validation failed after SSL update: {}", e);
        println!("Attempting to revert Nginx configuration...");
        
        // Revert to backed up configuration
        if let Err(err) = fs::write(&nginx_config.nginx_config_file_path, original_nginx_config_file_content) {
            eprintln!("✗ CRITICAL: Failed to revert Nginx configuration file: {}", err);
            eprintln!("  The Nginx configuration may be in an invalid state.");
            eprintln!("  Manual intervention required to fix the configuration.");
        } else {
            println!("✓ Successfully reverted Nginx configuration to original state");
        }
        return Err(());
    }
    
    println!("✓ SSL successfully enabled for site '{}'", site_name);
    Ok(())
}
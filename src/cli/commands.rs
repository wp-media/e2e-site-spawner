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
//! - **update**: Switches the PHP-FPM version, adds WordPress and/or SSL
//! - **list**: Lists every configured site and its features
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
use crate::constants::{
    DB_HOST, HTML_DEFAULT_INDEX_FILE, NGINX_CONF_D_PATH, NGINX_HTTPS_CONFIG_MARKER, SITES_PATH,
    WEB_SERVER_GROUP, WEB_SERVER_USER,
};
use crate::nginx::config::validate_nginx_configuration;
use crate::nginx::php_fpm::{PhpFpmConfigError, detect_php_version, set_php_version};
use crate::nginx::{
    self, check_if_https_in_nginx_config_file, is_active_site, is_managed_by_this_tool,
    is_websites_config_file, reload_nginx,
};
use crate::nginx::{
    append_to_nginx_file, create_nginx_file, ensure_regular_nginx_file,
    get_list_of_sites_nginx_file_paths, overwrite_nginx_file,
};
use crate::utils::db;
use crate::utils::php::{self, PhpVersion};
use crate::utils::sites::{
    self, check_if_site_exists, create_file_with_content_if_not_exists, get_sudo_user,
    put_wordpress_in_site_directory, revert_site_spawn,
};
use crate::utils::ssl::{self, remove_site_from_acme};
use crate::utils::validators::validate_site_name;
use colored::*;
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
/// * `php` - PHP-FPM version written into `fastcgi_pass`; its socket must exist.
///
/// # Process Flow
///
/// 1. **Validation Phase**
///    - Validates Nginx configuration health
///    - Validates site name format
///    - Preflights the chosen PHP-FPM socket (`php`); if it is missing,
///      exits 1 listing the installed versions, before anything is written
///    - Displays SSL warnings if applicable
///
/// 2. **Nginx Setup**
///    - Creates HTTP configuration
///    - Validates configuration syntax
///
/// 3. **Directory Creation**
///    - Creates site root directory
///    - Sets ownership to www-data:www-data
///    - Creates SSL directory if needed
///
/// 4. **SSL Configuration** (if enabled)
///    - Generates Let's Encrypt certificates
///    - Updates Nginx config with HTTPS
///
/// 5. **WordPress Installation** (unless disabled)
///    - Downloads and extracts WordPress
///    - Creates MySQL database
///    - Generates wp-config.php (debug logging on, `FS_METHOD` direct)
///    - Creates the `wp-content/uploads` directory WordPress does not ship
///
/// 6. **Finalization**
///    - Re-applies web server ownership to every file just written
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
/// │   └── wp-content/uploads/        # Created here, not shipped by WordPress
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
/// - Site directory: 777 (www-data:www-data ownership, applied recursively to
///   every file once the last one is written)
/// - `wp-content/uploads`: 777 (www-data:www-data ownership)
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
/// spawn_site("example.local", true, false, PhpVersion::default_version());
///
/// // Create a static site without SSL or WordPress, served by PHP-FPM 8.3
/// // (static sites still need a live PHP-FPM socket)
/// let php = PhpVersion::parse("8.3").expect("8.3 is a valid PHP version");
/// spawn_site("static.local", false, true, php);
/// ```
///
/// # See Also
///
/// * [`delete_site`] - To remove a created site
/// * [`deactivate_site`] - To temporarily disable a site
pub fn spawn_site(site_name: &str, ssl: bool, no_wp: bool, php: PhpVersion) {
    println!("Preparing to create site: {}", site_name);
    println!();
    // Phase 1: Pre-validation
    validate_nginx_configuration().unwrap_or_else(|e| {
        eprintln!("✗ Nginx configuration validation failed before spawning a new site.");
        eprintln!("Make sure Nginx configuration is okay, since nginx reloads is required.");
        eprintln!("Nginx error: \n{}", e);
        process::exit(1);
    });

    if !validate_site_name(site_name) {
        eprintln!("✗ Invalid site name: {}", site_name);
        process::exit(1);
    }

    // Initialize tracking for rollback
    let mut steps_completed: Vec<SpawnSteps> = Vec::new();

    // Create Nginx configuration object
    let nginx_config = build_spawn_config(site_name, ssl, php);
    if check_if_site_exists(&nginx_config) {
        eprintln!(
            "✗ Site '{}' seems to already exist. Cannot continue.",
            site_name
        );
        process::exit(1);
    }
    nginx_config.validate().unwrap_or_else(|e| {
        eprintln!("✗ Validation failed: {}", e);
        process::exit(1);
    });
    exit_unless_fpm_available(nginx_config.php_version);

    if ssl {
        ssl::print_ssl_warning(site_name);
    }

    if no_wp {
        println!("WordPress will not be installed on this site.");
    } else {
        println!("WordPress will be installed on this site.");
    }

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
            // Hand the directory to the web server up front so a static site is
            // already writable; the tree is re-owned after every file is written.
            if let Err(e) = sites::set_web_server_ownership(nginx_config.root.as_str()) {
                eprintln!("✗ Failed to set Sites directory ownership: {}", e);
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
    validate_nginx_configuration().unwrap_or_else(|e| {
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
                let https_config =
                    nginx_config.generate_config(nginx::config::NginxProtocol::Https);
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
        validate_nginx_configuration().unwrap_or_else(|e| {
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
        println!("Creating database '{}'...", db_name);
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

        // WordPress ships no uploads directory and cannot create one itself while
        // the tree still belongs to root, so create it before handing the site over.
        match sites::create_wp_uploads_directory(&nginx_config.root) {
            Ok(()) => {
                println!("✓ WordPress uploads directory created successfully");
            }
            Err(e) => {
                eprintln!("✗ Failed to create WordPress uploads directory: {}", e);
                revert_site_spawn(site_name, &steps_completed, &nginx_config);
            }
        }
    } else {
        // Create default index.html for static site
        let path = format!("{}/index.html", nginx_config.root);
        create_file_with_content_if_not_exists(&path, HTML_DEFAULT_INDEX_FILE, None).unwrap_or(());
    }

    // Hand the finished tree to the web server. Everything above was written by
    // root, and PHP-FPM must own it to write uploads, plugins, themes, and
    // debug.log.
    if let Err(e) = sites::set_web_server_ownership(&nginx_config.root) {
        eprintln!("✗ Failed to set site directory ownership: {}", e);
        revert_site_spawn(site_name, &steps_completed, &nginx_config);
    }
    println!("✓ Site files ownership set to {}", WEB_SERVER_USER);

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
        }
    }

    // Remove Nginx configuration
    print!("Attempting to remove Nginx configuration...");
    match sites::remove_file(nginx_config.nginx_config_file_path.as_str()) {
        Ok(()) => println!("{}", " ok".bright_green()),
        Err(e) => {
            println!("{}", " failed".bright_red());
            eprintln!("✗ Failed to remove Nginx configuration file: {}", e)
        }
    }
    // Remove site from acme (prevent future renewals)
    print!("Attempting to remove site from acme (Deactivate SSL renewal)...");
    match remove_site_from_acme(site_name) {
        Ok(()) => println!("{}", " ok".bright_green()),
        Err(e) => {
            if e.contains("is not an issued domain") {
                println!("{}", " ok".bright_green());
                println!("✓ Site was not issued by acme, skipping removal.");
            } else {
                println!("{}", " failed".bright_red());
                eprintln!("✗ Failed to remove site from acme: {}", e)
            }
        }
    }
    // Remove SSL certificates
    {
        // Safe to call unwrap here as ssl_root is Some when ssl is true
        let ssl_root = &nginx_config.ssl_root.unwrap();
        let path = Path::new(ssl_root);
        print!("Attempting to remove SSL files...");
        if !path.exists() {
            println!("{}", " ok".bright_green());
            println!("✓ No SSL directory found, skipping removal.");
        } else {
            match sites::remove_directory(ssl_root) {
                Ok(()) => println!("{}", " ok".bright_green()),
                Err(e) => {
                    println!("{}", " failed".bright_red());
                    eprintln!("✗ Failed to remove SSL directory: {}", e)
                }
            };
        }
    }

    // Drop database
    let db_name = db::create_db_name(site_name);
    print!("Attempting to drop database '{}'...", db_name);
    match db::drop_database(&db_name) {
        Ok(()) => println!("{}", " ok".bright_green()),
        Err(e) => {
            println!("{}", " failed".bright_red());
            eprintln!("✗ Failed to drop database '{}': {}", db_name, e)
        }
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
    match fs::rename(active_path, &deactivated_path) {
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
    match fs::rename(&deactivated_path, active_path) {
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
/// Switches the site's PHP-FPM version, adds WordPress to a static site,
/// and/or enables SSL on a site that was created without it.
///
/// # Arguments
///
/// * `site_name` - The name of the site to update.
/// * `wp` - If `true`, installs WordPress on an existing static site.
/// * `ssl` - If `true`, generates SSL certificates and enables HTTPS.
/// * `php` - If `Some`, rewrites every `fastcgi_pass` to that PHP-FPM version.
///
/// # Behavior
///
/// Exits early (status `0`) if nothing is requested. Otherwise it validates the
/// site name and the current Nginx configuration, confirms the site exists and
/// is managed by e2sp and its config is a regular file (not a symlink), backs
/// up its Nginx config, resolves the PHP version the update writes (`php`,
/// else the site's detected version; `ssl` without `php` exits `1` when it
/// cannot be detected) and preflights its socket before any mutation. Then it
/// runs the requested steps in order PHP → WordPress → SSL:
///
/// - `php` → `update_with_php` rewrites the config's socket paths (skipped when
///   the site already uses that version), validates it and reverts on failure.
/// - `wp` → [`update_with_wordpress`] installs WordPress into the existing site
///   (failing safely if WordPress or its database already exist). It does not
///   touch the Nginx config.
/// - `ssl` → [`update_with_ssl`] issues Let's Encrypt certificates and appends
///   the HTTPS server block using the resolved PHP version, so both blocks
///   agree; it reverts the Nginx config on failure. It is skipped (and counts
///   as failed) when the PHP step failed, since its block would then disagree
///   with the HTTP block.
///
/// Otherwise each step reports its own errors and runs even if another failed.
/// Afterwards, if any successful step changed the Nginx config, the combined
/// result is validated (`nginx -t`) and Nginx is reloaded so the change takes
/// effect — even when another step failed. If that final validation fails,
/// or a failed step could not restore its own change, the config is restored
/// to the backup taken before any step ran, and Nginx is not reloaded.
///
/// # Panics
///
/// Never panics; exits the process with status code `1` if the site name is
/// invalid, the Nginx configuration is invalid or unreadable, the site does
/// not exist, it is not managed by e2sp, its config is a symlink, `ssl` needs
/// an undetectable PHP version, the needed PHP-FPM socket is missing,
/// any requested sub-step failed, or the final Nginx validation/reload failed.
/// Exits with `0` only when every requested step succeeded and any needed
/// reload went through.
///
/// # Example
///
/// ```no_run
/// // Add WordPress to a static site
/// update_site("static.example.com", true, false, None);
///
/// // Enable SSL on an HTTP-only site, keeping its PHP version
/// update_site("http-only.example.com", false, true, None);
///
/// // Move a site to PHP-FPM 8.5
/// update_site("legacy.example.com", false, false, PhpVersion::parse("8.5").ok());
/// ```
pub fn update_site(site_name: &str, wp: bool, ssl: bool, php: Option<PhpVersion>) {
    if !wp && !ssl && php.is_none() {
        println!("No updates specified for site '{}'. Exiting.", site_name);
        process::exit(0);
    }
    if !validate_site_name(site_name) {
        eprintln!("✗ Invalid site name: {}", site_name);
        process::exit(1);
    }
    let base_config = build_spawn_config(site_name, ssl, PhpVersion::default_version());
    exit_unless_existing_managed_site(&base_config);
    // Taken before any step runs, so the final gate can undo the combined result
    let pre_update_config =
        read_nginx_config_backup(&base_config).unwrap_or_else(|()| process::exit(1));
    let target = resolve_update_php(php, ssl, &pre_update_config);
    let nginx_config = build_spawn_config(site_name, ssl, target);
    println!("Preparing to update site: {}", site_name);
    // Phase 2: Apply every requested sub-step, then reload and report once
    let outcomes = run_update_steps(&UpdateStep::requested(wp, ssl, php), &nginx_config);
    let summary = UpdateSummary::from_outcomes(&outcomes);
    finish_update(&nginx_config, &pre_update_config, summary);
}

/// Exits with a `✗` error unless `nginx_config` is a valid, existing site
/// managed by e2sp and Nginx's current configuration passes `nginx -t`.
///
/// # Arguments
///
/// * `nginx_config` - The site about to be updated.
///
/// # Panics
///
/// Never panics; exits the process with status `1` on any failed check.
fn exit_unless_existing_managed_site(nginx_config: &nginx::config::NginxConfig) {
    let site_name = &nginx_config.site_name;
    nginx_config.validate().unwrap_or_else(|e| {
        eprintln!("✗ Validation failed: {}", e);
        process::exit(1);
    });
    validate_nginx_configuration().unwrap_or_else(|e| {
        eprintln!("✗ Nginx configuration validation failed before updating.");
        eprintln!("Make sure Nginx configuration is okay, since nginx reloads is required.");
        eprintln!("Nginx error: \n{}", e);
        process::exit(1);
    });
    if !check_if_site_exists(nginx_config) {
        eprintln!("✗ Site '{}' does not exist. Cannot update.", site_name);
        process::exit(1);
    }
    if !is_managed_by_this_tool(&nginx_config.nginx_config_file_path) {
        eprintln!(
            "✗ Site '{}' is not managed by e2sp. Cannot update.",
            site_name
        );
        process::exit(1);
    }
    exit_unless_regular_config_file(nginx_config);
}

/// Exits with a `✗` error unless the site's config is a regular file.
///
/// `--ssl` appends through a symlink while every restore
/// ([`overwrite_nginx_file`]) refuses one, so a failed step could not be
/// rolled back. Rejecting it here, before any mutation or certificate
/// issuance, keeps `update` fully reversible; `spawn` is unaffected.
///
/// # Arguments
///
/// * `nginx_config` - The site about to be updated.
fn exit_unless_regular_config_file(nginx_config: &nginx::config::NginxConfig) {
    if let Err(e) = ensure_regular_nginx_file(&nginx_config.nginx_config_file_path) {
        eprintln!(
            "✗ Cannot update site '{}' safely: {}",
            nginx_config.site_name, e
        );
        eprintln!("  Replace it with a regular file (not a symlink) and retry.");
        process::exit(1);
    }
}

/// Resolves the PHP version an `update` writes and preflights its socket.
///
/// Exits (status `1`) before any mutation or certificate issuance when
/// `--ssl` needs the site's version but it cannot be detected (see
/// [`resolve_php_version`]), or when a version that will be written has no
/// live PHP-FPM socket.
///
/// # Arguments
///
/// * `requested` - The `--php` value, if any.
/// * `ssl` - `--ssl` was passed (its HTTPS block uses the resolved version).
/// * `current_config` - The site's current Nginx config text.
///
/// # Returns
///
/// The resolved version every config change of this update will use.
fn resolve_update_php(
    requested: Option<PhpVersion>,
    ssl: bool,
    current_config: &str,
) -> PhpVersion {
    let detected = detect_php_version(current_config);
    let target = resolve_php_version(requested, &detected, ssl).unwrap_or_else(|e| {
        eprintln!("✗ {}", e);
        process::exit(1);
    });
    if fpm_preflight_needed(requested, &detected, ssl) {
        exit_unless_fpm_available(target);
    }
    target
}

/// Picks the PHP version an `update` writes (pure; no I/O).
///
/// Fails closed: `--ssl` without `--php` on a site whose version cannot be
/// detected is refused instead of guessing a default, because the HTTPS block
/// would be appended to a live config and a real certificate issued.
///
/// # Arguments
///
/// * `requested` - The `--php` value, if any; always wins.
/// * `detected` - The version detected in the site's current config.
/// * `ssl` - `--ssl` was passed, so the version is written into a new block.
///
/// # Returns
///
/// The version to use. Without `--ssl` and `--php` nothing writes it, so an
/// undetectable version resolves to [`PhpVersion::default_version`].
///
/// # Errors
///
/// The user-facing reason (see [`undetectable_php_message`]) when `--ssl`
/// needs the detected version and detection failed.
fn resolve_php_version(
    requested: Option<PhpVersion>,
    detected: &Result<PhpVersion, PhpFpmConfigError>,
    ssl: bool,
) -> Result<PhpVersion, String> {
    match (requested, detected) {
        (Some(version), _) => Ok(version),
        (None, Ok(version)) => Ok(*version),
        (None, Err(_)) if !ssl => Ok(PhpVersion::default_version()),
        (None, Err(e)) => Err(undetectable_php_message(e)),
    }
}

/// Explains why `--ssl` cannot pick the site's PHP version, with a remedy
/// that actually works for that failure (pure).
///
/// `--php X.Y` helps only for [`PhpFpmConfigError::Inconsistent`]:
/// `set_php_version` unifies mixed sockets, but refuses configs with no
/// `fastcgi_pass` or a non-socket one, so those need a manual fix.
///
/// # Arguments
///
/// * `error` - Why detection failed.
///
/// # Returns
///
/// The message, without the leading `✗`.
fn undetectable_php_message(error: &PhpFpmConfigError) -> String {
    let hint = match error {
        PhpFpmConfigError::Inconsistent(_) => "pass --php X.Y to choose one",
        PhpFpmConfigError::NoFastcgiPass | PhpFpmConfigError::Unrecognized(_) => {
            "point every fastcgi_pass at a PHP-FPM socket (unix:/var/run/php/phpX.Y-fpm.sock) by hand first; --php cannot rewrite this config"
        }
    };
    format!("Cannot detect the site's PHP version ({error}); {hint}")
}

/// Whether switching the site to `target` would change its config (pure).
///
/// # Arguments
///
/// * `detected` - The version detected in the site's current config.
/// * `target` - The requested version.
///
/// # Returns
///
/// `false` only when every `fastcgi_pass` already uses `target`.
fn php_switch_needed(detected: &Result<PhpVersion, PhpFpmConfigError>, target: PhpVersion) -> bool {
    !matches!(detected, Ok(current) if *current == target)
}

/// Whether `update` must check the PHP-FPM socket before mutating (pure).
///
/// # Arguments
///
/// * `requested` - The `--php` value, if any.
/// * `detected` - The version detected in the site's current config.
/// * `ssl` - `--ssl` was passed (its HTTPS block always names a socket).
///
/// # Returns
///
/// `true` when a socket path will be written: always for `--ssl`, and for
/// `--php` unless the site already uses that version.
fn fpm_preflight_needed(
    requested: Option<PhpVersion>,
    detected: &Result<PhpVersion, PhpFpmConfigError>,
    ssl: bool,
) -> bool {
    ssl || requested.is_some_and(|target| php_switch_needed(detected, target))
}

/// Builds the [`nginx::config::NginxConfig`] for a site from `spawn`/`update` args.
///
/// Pure (no I/O), so the `--php` wiring is unit-testable: the returned config
/// is both what [`spawn_site`] / [`update_site`] preflight and what they render.
///
/// # Arguments
///
/// * `site_name` - Domain of the site.
/// * `ssl` - Whether the config gets an SSL root.
/// * `php` - PHP-FPM version written into every `fastcgi_pass`.
///
/// # Returns
///
/// A config under [`SITES_PATH`] / [`NGINX_CONF_D_PATH`] targeting `php`.
fn build_spawn_config(site_name: &str, ssl: bool, php: PhpVersion) -> nginx::config::NginxConfig {
    nginx::config::NginxConfig::new(
        site_name.to_string(),
        SITES_PATH.to_string(),
        NGINX_CONF_D_PATH.to_string(),
        ssl,
    )
    .with_php_version(php)
}

/// Exits with a `✗` error unless `version`'s PHP-FPM socket is live.
///
/// Preflight for `spawn` and `update --php` / `--ssl`, called before any
/// mutation so a config is never written for a missing socket (`nginx -t`
/// passes, but PHP returns 502). The message logic lives in
/// [`crate::utils::php::ensure_fpm_available`].
///
/// # Arguments
///
/// * `version` - Version whose socket path will be written.
fn exit_unless_fpm_available(version: PhpVersion) {
    if let Err(e) = php::ensure_fpm_available(version) {
        eprintln!("✗ {}", e);
        process::exit(1);
    }
}

/// Whether a successful `update` sub-step modified the site's Nginx config.
///
/// Lets [`update_site`] decide if Nginx must be validated and reloaded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NginxChange {
    /// The step left the Nginx config untouched (e.g. WordPress install).
    Unchanged,
    /// The step rewrote the Nginx config; a reload is needed to apply it.
    Changed,
}

/// One sub-step `update` can run.
///
/// Adding a step means adding a variant, its [`UpdateStep::nginx_change`] arm,
/// its [`UpdateStep::run`] arm, and its place in [`UpdateStep::requested`]; the
/// compiler flags every match to update.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UpdateStep {
    /// Switch every `fastcgi_pass` to this PHP-FPM version (`--php`).
    Php(PhpVersion),
    /// Install WordPress into a static site (`--wp`).
    WordPress,
    /// Issue a certificate and append the HTTPS block (`--ssl`).
    Ssl,
}

impl UpdateStep {
    /// Lists the steps the user asked for, in execution order.
    ///
    /// # Arguments
    ///
    /// * `wp` - `--wp` was passed.
    /// * `ssl` - `--ssl` was passed.
    /// * `php` - The `--php` value, if any.
    ///
    /// # Returns
    ///
    /// The requested steps: PHP first (so the HTTPS block appended later uses
    /// the new version), then WordPress, then SSL.
    fn requested(wp: bool, ssl: bool, php: Option<PhpVersion>) -> Vec<Self> {
        let rest = [(wp, Self::WordPress), (ssl, Self::Ssl)]
            .into_iter()
            .filter_map(|(wanted, step)| wanted.then_some(step));
        php.map(Self::Php).into_iter().chain(rest).collect()
    }

    /// Whether this step must be skipped because an earlier `--php` step failed.
    ///
    /// The SSL step writes the resolved PHP version into the HTTPS block; if
    /// the HTTP block could not be switched, the two would disagree.
    ///
    /// # Arguments
    ///
    /// * `php_failed` - A preceding [`UpdateStep::Php`] step failed.
    ///
    /// # Returns
    ///
    /// `true` for [`UpdateStep::Ssl`] after a failed PHP switch.
    fn blocked_by_php_failure(self, php_failed: bool) -> bool {
        php_failed && self == Self::Ssl
    }

    /// How a successful run of this step affects the Nginx config.
    ///
    /// # Returns
    ///
    /// [`NginxChange::Changed`] for steps that rewrite the site's config (a
    /// PHP switch to the version already in use is reported as unchanged by
    /// [`UpdateStep::run`]).
    fn nginx_change(self) -> NginxChange {
        match self {
            Self::Php(_) | Self::Ssl => NginxChange::Changed,
            Self::WordPress => NginxChange::Unchanged,
        }
    }

    /// Runs the step against the site.
    ///
    /// # Arguments
    ///
    /// * `nginx_config` - The site being updated (built with SSL for `Ssl`,
    ///   and with the resolved PHP version).
    ///
    /// # Returns
    ///
    /// The step's Nginx impact on success, or how it failed (already reported).
    fn run(self, nginx_config: &nginx::config::NginxConfig) -> UpdateStepOutcome {
        let changed = match self {
            Self::Php(version) => update_with_php(nginx_config, version)?,
            Self::WordPress => update_with_wordpress(nginx_config)
                .map(|()| true)
                .map_err(|()| StepFailure::ConfigIntact)?,
            Self::Ssl => update_with_ssl(nginx_config).map(|()| true)?,
        };
        Ok(if changed {
            self.nginx_change()
        } else {
            NginxChange::Unchanged
        })
    }
}

/// Runs `steps` in order against the site, skipping SSL after a failed PHP
/// switch (see [`fold_step_outcomes`]).
///
/// # Arguments
///
/// * `steps` - The requested steps, from [`UpdateStep::requested`].
/// * `nginx_config` - The site being updated.
///
/// # Returns
///
/// One outcome per step; a skipped step counts as failed.
fn run_update_steps(
    steps: &[UpdateStep],
    nginx_config: &nginx::config::NginxConfig,
) -> Vec<UpdateStepOutcome> {
    fold_step_outcomes(
        steps,
        |step| step.run(nginx_config),
        || {
            eprintln!(
                "✗ Skipping SSL: the PHP version switch failed, so the HTTPS block would not match."
            );
        },
    )
}

/// Sequencing rule of `update`, decoupled from I/O so it is unit-testable.
///
/// Every step runs, even after another failed, except one
/// [`UpdateStep::blocked_by_php_failure`]: it is not run, `on_skip` is called
/// instead, and it counts as [`StepFailure::ConfigIntact`].
///
/// # Arguments
///
/// * `steps` - The requested steps, in execution order.
/// * `run` - Runs one step and returns its outcome.
/// * `on_skip` - Reports a skipped step.
///
/// # Returns
///
/// One outcome per step, in order.
fn fold_step_outcomes(
    steps: &[UpdateStep],
    mut run: impl FnMut(UpdateStep) -> UpdateStepOutcome,
    mut on_skip: impl FnMut(),
) -> Vec<UpdateStepOutcome> {
    let mut php_failed = false;
    let mut outcomes = Vec::with_capacity(steps.len());
    for &step in steps {
        let outcome = if step.blocked_by_php_failure(php_failed) {
            on_skip();
            Err(StepFailure::ConfigIntact)
        } else {
            run(step)
        };
        php_failed |= matches!(step, UpdateStep::Php(_)) && outcome.is_err();
        outcomes.push(outcome);
    }
    outcomes
}

/// Switches every `fastcgi_pass` of the site to `target`, validating with
/// `nginx -t` and restoring the original file on failure.
///
/// The target socket was already preflighted by [`update_site`]. Nginx is not
/// reloaded here; [`update_site`] reloads once after all steps.
///
/// # Arguments
///
/// * `nginx_config` - The site being updated.
/// * `target` - The PHP-FPM version to switch to.
///
/// # Returns
///
/// * `Ok(true)` - The config was rewritten and passes `nginx -t`
/// * `Ok(false)` - The site already uses `target`; nothing changed
/// * `Err(StepFailure::ConfigIntact)` - Reading, rewriting, writing or
///   validating failed (already reported); the config holds its original
///   contents
/// * `Err(StepFailure::ConfigLeftModified)` - `nginx -t` failed and the
///   restore failed too; [`finish_update`] retries it
fn update_with_php(
    nginx_config: &nginx::config::NginxConfig,
    target: PhpVersion,
) -> Result<bool, StepFailure> {
    let site_name = &nginx_config.site_name;
    let original =
        read_nginx_config_backup(nginx_config).map_err(|()| StepFailure::ConfigIntact)?;
    if !php_switch_needed(&detect_php_version(&original), target) {
        println!("✓ Site '{site_name}' already uses PHP {target}; nothing to change");
        return Ok(false);
    }
    let rewritten = set_php_version(&original, target).map_err(|e| {
        eprintln!("✗ Cannot switch site '{site_name}' to PHP {target}: {e}");
        StepFailure::ConfigIntact
    })?;
    write_nginx_config(nginx_config, &rewritten).map_err(|()| StepFailure::ConfigIntact)?;
    if let Err(e) = validate_nginx_configuration() {
        eprintln!("✗ Nginx configuration validation failed after the PHP switch: {e}");
        return Err(StepFailure::after_restore(restore_nginx_config(
            nginx_config,
            &original,
        )));
    }
    println!("✓ Site '{site_name}' switched to PHP {target}");
    Ok(true)
}

/// Atomically replaces the site's Nginx config with `content`.
///
/// # Arguments
///
/// * `nginx_config` - The site whose config file is replaced.
/// * `content` - The new full config text.
///
/// # Returns
///
/// * `Ok(())` - The new content is in place
/// * `Err(())` - The write failed (already reported); the file is unchanged
fn write_nginx_config(nginx_config: &nginx::config::NginxConfig, content: &str) -> Result<(), ()> {
    overwrite_nginx_file(&nginx_config.nginx_config_file_path, content).map_err(|e| {
        eprintln!("✗ Failed to write Nginx configuration file: {e}");
    })
}

/// How a failed `update` sub-step left the site's Nginx config. The failure
/// itself has always been reported already.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StepFailure {
    /// The config holds what it held before the step (never written, or
    /// restored), or the step was skipped.
    ConfigIntact,
    /// The step wrote the config and could not restore it; [`finish_update`]
    /// must retry restoring the pre-update config.
    ConfigLeftModified,
}

impl StepFailure {
    /// Classifies a failed step from the result of its own restore attempt.
    ///
    /// # Arguments
    ///
    /// * `restored` - Result of [`restore_nginx_config`] (or a rollback built
    ///   on it).
    ///
    /// # Returns
    ///
    /// [`StepFailure::ConfigIntact`] if the restore succeeded,
    /// [`StepFailure::ConfigLeftModified`] otherwise.
    fn after_restore(restored: Result<(), ()>) -> Self {
        match restored {
            Ok(()) => Self::ConfigIntact,
            Err(()) => Self::ConfigLeftModified,
        }
    }
}

/// Result of one `update` sub-step: the Nginx impact on success, or how the
/// step failed (already reported).
type UpdateStepOutcome = Result<NginxChange, StepFailure>;

/// What [`finish_update`] does with Nginx once every sub-step ran.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FinalNginxAction {
    /// No step changed the config; leave Nginx alone.
    Nothing,
    /// Validate the combined config and reload (restoring it if invalid).
    ApplyChanges,
    /// A step left a broken config behind; restore the pre-update config and
    /// do not reload (Nginx still runs the pre-update configuration).
    RestorePreUpdate,
}

/// What [`update_site`] must do after all sub-steps ran, derived purely from
/// their outcomes so the decision is unit-testable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct UpdateSummary {
    /// At least one successful step changed the Nginx config.
    needs_reload: bool,
    /// At least one requested step failed.
    any_failed: bool,
    /// A failed step left the config modified and could not restore it.
    restore_needed: bool,
}

impl UpdateSummary {
    /// Summarizes sub-step outcomes.
    ///
    /// # Arguments
    ///
    /// * `outcomes` - One entry per requested sub-step, in execution order.
    ///
    /// # Returns
    ///
    /// The summary; an empty slice means nothing to reload and nothing failed.
    fn from_outcomes(outcomes: &[UpdateStepOutcome]) -> Self {
        Self {
            needs_reload: outcomes.contains(&Ok(NginxChange::Changed)),
            any_failed: outcomes.iter().any(Result::is_err),
            restore_needed: outcomes.contains(&Err(StepFailure::ConfigLeftModified)),
        }
    }

    /// Decides what [`finish_update`] does with Nginx.
    ///
    /// A leftover broken config wins over a pending reload: reloading would
    /// apply a config no step vouched for.
    ///
    /// # Returns
    ///
    /// The [`FinalNginxAction`] to take.
    fn final_action(&self) -> FinalNginxAction {
        if self.restore_needed {
            FinalNginxAction::RestorePreUpdate
        } else if self.needs_reload {
            FinalNginxAction::ApplyChanges
        } else {
            FinalNginxAction::Nothing
        }
    }

    /// Process exit code from the sub-steps alone.
    ///
    /// # Returns
    ///
    /// `1` if any step failed, `0` otherwise.
    fn exit_code(&self) -> i32 {
        i32::from(self.any_failed)
    }

    /// Process exit code once the final validate + reload has run.
    ///
    /// # Arguments
    ///
    /// * `nginx_applied` - Result of the final validate + reload (`Ok` when it
    ///   was not needed).
    ///
    /// # Returns
    ///
    /// `1` if any step or the final Nginx apply failed, `0` otherwise.
    fn final_exit_code(&self, nginx_applied: Result<(), ()>) -> i32 {
        if nginx_applied.is_err() {
            1
        } else {
            self.exit_code()
        }
    }
}

/// Applies pending Nginx changes, prints the final summary, and exits with
/// the update's status.
///
/// Reloads (after `nginx -t`) whenever a successful step changed the config,
/// even if another step failed, so completed work is not left inactive.
///
/// # Arguments
///
/// * `nginx_config` - The updated site.
/// * `pre_update_config` - The site's Nginx config before any step ran.
/// * `summary` - The summarized sub-step outcomes.
///
/// # Panics
///
/// Never panics; always terminates the process: status `1` if validation,
/// reload, or any sub-step failed, `0` otherwise.
fn finish_update(
    nginx_config: &nginx::config::NginxConfig,
    pre_update_config: &str,
    summary: UpdateSummary,
) -> ! {
    let nginx_applied = match summary.final_action() {
        FinalNginxAction::Nothing => Ok(()),
        FinalNginxAction::ApplyChanges => apply_nginx_changes(nginx_config, pre_update_config),
        FinalNginxAction::RestorePreUpdate => {
            retry_pre_update_restore(nginx_config, pre_update_config)
        }
    };
    let exit_code = summary.final_exit_code(nginx_applied);
    if exit_code == 0 {
        println!("✓ Site '{}' updated successfully", nginx_config.site_name);
    } else {
        eprintln!(
            "✗ Update of site '{}' finished with errors.",
            nginx_config.site_name
        );
    }
    process::exit(exit_code);
}

/// Second chance for a step whose own restore failed: writes
/// `pre_update_config` back without reloading.
///
/// This undoes every Nginx change of this update (none was reloaded, so the
/// running Nginx already matches it); files the steps created are kept.
///
/// # Arguments
///
/// * `nginx_config` - The updated site.
/// * `pre_update_config` - The site's Nginx config before any step ran.
///
/// # Returns
///
/// * `Ok(())` - The config is back to its pre-update contents
/// * `Err(())` - The retry failed too (reported as CRITICAL, with recovery
///   steps)
fn retry_pre_update_restore(
    nginx_config: &nginx::config::NginxConfig,
    pre_update_config: &str,
) -> Result<(), ()> {
    eprintln!("✗ A failed step left the Nginx config modified; restoring its pre-update state.");
    if restore_nginx_config(nginx_config, pre_update_config).is_err() {
        eprintln!("  Nginx was not reloaded and still runs the pre-update configuration.");
        eprintln!("  Do not reload Nginx until `sudo nginx -t` passes again.");
        return Err(());
    }
    eprintln!("  Nginx was not reloaded; all Nginx changes of this update were undone.");
    eprintln!("  Files created by the update steps (certificates, WordPress) were kept.");
    Ok(())
}

/// Validates the combined Nginx configuration and reloads Nginx.
///
/// On validation failure the site's config is restored to
/// `pre_update_config` and Nginx is not reloaded; files the steps created
/// (certificates, WordPress files) are kept.
///
/// # Arguments
///
/// * `nginx_config` - The updated site.
/// * `pre_update_config` - The site's Nginx config before any step ran.
///
/// # Returns
///
/// * `Ok(())` - The configuration is valid and Nginx was reloaded
/// * `Err(())` - Validation or reload failed (already reported)
fn apply_nginx_changes(
    nginx_config: &nginx::config::NginxConfig,
    pre_update_config: &str,
) -> Result<(), ()> {
    // Each step validates its own edit; this gates the combined result of all steps
    if let Err(e) = validate_nginx_configuration() {
        eprintln!("✗ Nginx configuration validation failed after updating; not reloading.");
        eprintln!("Nginx error: \n{}", e);
        // Already reported either way; the update fails regardless
        let _ = restore_nginx_config(nginx_config, pre_update_config);
        eprintln!("  Files created by the update steps (certificates, WordPress) were kept.");
        return Err(());
    }
    if let Err(e) = reload_nginx() {
        eprintln!("✗ Failed to reload Nginx: {}", e);
        eprintln!("  The config is updated and valid; apply it with:");
        eprintln!("    sudo nginx -t && sudo systemctl reload nginx");
        return Err(());
    }
    println!("✓ Nginx reloaded successfully");
    Ok(())
}

/// Labels shown for a site feature in `list` output.
///
/// Kept separate from colouring so the formatting is unit-testable.
#[derive(Debug, Clone, PartialEq, Eq)]
enum SiteFeature {
    /// HTTPS is configured.
    Ssl,
    /// WordPress is installed (`wp-config.php` exists).
    WordPress,
    /// The PHP-FPM version the config passes to, or `None` when it could not
    /// be detected (no, unrecognized or inconsistent `fastcgi_pass` lines).
    Php(Option<PhpVersion>),
}

impl SiteFeature {
    /// Returns the plain-text label, e.g. `ssl`, `wp`, `php 8.5` or `php ?`.
    fn label(&self) -> String {
        match self {
            SiteFeature::Ssl => "ssl".to_string(),
            SiteFeature::WordPress => "wp".to_string(),
            SiteFeature::Php(Some(v)) => format!("php {}", v),
            SiteFeature::Php(None) => "php ?".to_string(),
        }
    }
}

/// Builds the ordered feature list of a managed site: `ssl`, `wp`, then PHP.
///
/// PHP is always included because every managed config has `fastcgi_pass`;
/// a failed detection is shown as `php ?` rather than hidden.
///
/// # Arguments
///
/// * `has_ssl` - Whether HTTPS is configured.
/// * `has_wordpress` - Whether WordPress is installed.
/// * `php_version` - Detected PHP-FPM version, `None` if detection failed.
///
/// # Returns
///
/// The features in display order.
fn format_site_features(
    has_ssl: bool,
    has_wordpress: bool,
    php_version: Option<PhpVersion>,
) -> Vec<SiteFeature> {
    let mut features = Vec::with_capacity(3);
    if has_ssl {
        features.push(SiteFeature::Ssl);
    }
    if has_wordpress {
        features.push(SiteFeature::WordPress);
    }
    features.push(SiteFeature::Php(php_version));
    features
}

/// Maps a feature to its terminal colour, kept pure so it is unit-testable
/// without touching `colored`'s global override.
///
/// # Arguments
///
/// * `feature` - The feature to colour.
///
/// # Returns
///
/// Green for ssl, blue for wp, magenta for a detected PHP version and yellow
/// for an undetected one (`php ?`).
fn feature_color(feature: &SiteFeature) -> Color {
    match feature {
        SiteFeature::Ssl => Color::Green,
        SiteFeature::WordPress => Color::Blue,
        SiteFeature::Php(Some(_)) => Color::Magenta,
        SiteFeature::Php(None) => Color::Yellow,
    }
}

/// Colours a feature label for terminal output using [`feature_color`].
///
/// # Arguments
///
/// * `feature` - The feature to render.
///
/// # Returns
///
/// The coloured label.
fn colorize_feature(feature: &SiteFeature) -> String {
    feature.label().color(feature_color(feature)).to_string()
}

/// Detects the PHP-FPM version of a managed site's nginx config for `list`.
///
/// Any detection failure (no, foreign, malformed or disagreeing sockets) is
/// folded into `None`, which `list` renders as `php ?`.
///
/// # Arguments
///
/// * `content` - Full nginx config file content (HTTP and optional HTTPS block).
///
/// # Returns
///
/// The single version every block agrees on, or `None`.
fn detect_site_php_version(content: &str) -> Option<PhpVersion> {
    nginx::php_fpm::detect_php_version(content).ok()
}

/// Lists all configured sites with their status and features.
///
/// This function scans the Nginx configuration directory and displays information
/// about each site including:
/// - Whether it's managed by e2sp
/// - SSL status (if HTTPS is configured)
/// - WordPress status (if wp-config.php exists)
/// - PHP-FPM version (`php X.Y`, or `php ?` if it cannot be detected)
/// - Active/Deactivated status based on file extension
///
/// The output is color-coded for better readability.
pub fn list_sites() {
    use colored::*;

    let config_sites_path = Path::new(NGINX_CONF_D_PATH);
    if !config_sites_path.exists() || !config_sites_path.is_dir() {
        println!(
            "No Nginx configuration directory found at '{}'.",
            NGINX_CONF_D_PATH
        );
        return;
    }

    // Get all nginx config files (both .conf and .conf.deactivated)
    let sites_nginx_files = get_list_of_sites_nginx_file_paths().unwrap_or_else(|e| {
        eprintln!("✗ Failed to read Nginx configuration directory: {}", e);
        process::exit(1);
    });

    if sites_nginx_files.is_empty() {
        println!(
            "No sites found in Nginx configuration directory '{}'.",
            NGINX_CONF_D_PATH
        );
        return;
    }

    // Structure to hold site information
    struct SiteInfo {
        name: String,
        is_managed: bool,
        has_ssl: bool,
        has_wordpress: bool,
        php_version: Option<PhpVersion>,
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
        if !is_websites_config_file(&file_path) {
            continue;
        }

        // Get file name and determine status
        let file_name = Path::new(&file_path)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default()
            .to_string();

        // Determine if site is active based on file extension
        let is_active = is_active_site(&file_path);

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
        let is_managed = is_managed_by_this_tool(&file_path);
        if !is_managed {
            // If not managed, add with minimal info
            sites.push(SiteInfo {
                name: base,
                is_managed,
                has_ssl: false,
                has_wordpress: false,
                php_version: None,
                is_active,
            });
            continue;
        }
        // Check for SSL (only if managed by e2sp)
        let has_ssl = content.contains(NGINX_HTTPS_CONFIG_MARKER);

        // Construct the site path using SITES_PATH constant and base name
        let wp_config_path = format!("{}/{}/wp-config.php", SITES_PATH, base);
        // Check for WordPress by looking for wp-config.php in site root
        let has_wordpress = Path::new(&wp_config_path).exists();
        let php_version = detect_site_php_version(&content);

        sites.push(SiteInfo {
            name: base,
            is_managed,
            has_ssl,
            has_wordpress,
            php_version,
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
    println!("\n{}", "Site list:".bold().underline());
    println!();

    // Display each site with its status
    for site in &sites {
        if !site.is_managed {
            // Format the line based on what features exist
            let status = if site.is_active {
                "(active)".green()
            } else {
                "(deactivated)".yellow()
            };
            // Non-e2sp managed sites
            println!(
                "  {} - {} - {}",
                site.name.bright_white(),
                status,
                "not managed by e2sp".dimmed()
            );
        } else {
            let status = if site.is_active {
                "(active)".green()
            } else {
                "(deactivated)".yellow()
            };
            let features_str =
                format_site_features(site.has_ssl, site.has_wordpress, site.php_version)
                    .iter()
                    .map(colorize_feature)
                    .collect::<Vec<_>>()
                    .join(", ");
            println!(
                "  {} - {} - {}",
                site.name.bright_white(),
                features_str,
                status
            );
        }
    }

    println!();

    // Print summary
    let total = sites.len();
    let managed = sites.iter().filter(|s| s.is_managed).count();
    let active = sites.iter().filter(|s| s.is_active).count();
    let deactivated = sites.iter().filter(|s| !s.is_active).count();
    let unmanaged = sites.iter().filter(|s| !s.is_managed).count();

    println!("{}", "Summary:".bold());
    println!(
        "  Total sites: {} ({} active, {} deactivated)",
        total.to_string().bright_white(),
        active.to_string().green(),
        deactivated.to_string().yellow()
    );

    if managed > 0 {
        println!("  Managed by e2sp: {}", managed.to_string().cyan());
    }

    if unmanaged > 0 {
        println!("  Not managed by e2sp: {}", unmanaged.to_string().dimmed());
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
///    - Enables debug logging and `FS_METHOD` direct (see
///      [`crate::utils::sites::create_wp_config_file`])
///
/// 5. **Handover to the Web Server**
///    - Creates the `wp-content/uploads` directory WordPress does not ship
///    - Re-owns the whole tree to `www-data:www-data`, without which uploads,
///      plugin installs, and debug logging fail
///
/// # Files Created/Modified
///
/// ```text
/// /var/www/html/{site_name}/
/// ├── wp-admin/                  # WordPress admin files (created)
/// ├── wp-content/                # Themes and plugins (created)
/// │   └── uploads/               # Media directory (created, 777)
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
/// * [`crate::utils::db::create_wordpress_database`] - Database creation with retry logic
/// * [`crate::utils::sites::create_wp_config_file`] - Configuration file generation
/// * [`spawn_site`] - Creates new sites with WordPress from scratch
fn update_with_wordpress(nginx_config: &nginx::config::NginxConfig) -> Result<(), ()> {
    let site_name = &nginx_config.site_name;

    // Pre-installation check: Verify WordPress is not already installed
    let wp_config_path = format!("{}/wp-config.php", nginx_config.root);
    if Path::new(&wp_config_path).exists() {
        eprintln!(
            "✗ WordPress seems to already exist for site '{}'. Cannot update.",
            site_name
        );
        eprintln!("  Found existing wp-config.php at: {}", wp_config_path);
        return Err(());
    }

    // Check if database already exists (would indicate partial or previous installation)
    let db_name = db::create_db_name(site_name);
    match db::database_exists(&db_name, None) {
        Ok(exists) => {
            if exists {
                eprintln!(
                    "✗ Database '{}' already exists for site '{}'. Cannot update.",
                    db_name, site_name
                );
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
                    eprintln!(
                        "  WARNING: Failed to remove database '{}': {}",
                        db_name, drop_err
                    );
                    eprintln!("  Manual cleanup of the database may be required.");
                }
            }

            eprintln!("  WordPress files remain in the directory and need manual cleanup.");
            return Err(());
        }
    }

    // Step 4: Create the uploads directory WordPress does not ship
    if let Err(e) = sites::create_wp_uploads_directory(&nginx_config.root) {
        eprintln!("✗ Failed to create WordPress uploads directory: {}", e);
        eprintln!("  WordPress is installed but media uploads will ask for FTP credentials.");
        return Err(());
    }
    println!("✓ WordPress uploads directory created successfully");

    // Step 5: Hand the tree to the web server, which wrote none of these files
    if let Err(e) = sites::set_web_server_ownership(&nginx_config.root) {
        eprintln!("✗ Failed to set site directory ownership: {}", e);
        eprintln!("  WordPress is installed but its files still belong to root, so uploads,");
        eprintln!("  plugin installs, and debug logging will fail. Fix it with:");
        eprintln!(
            "    sudo chown -R {}:{} {}",
            WEB_SERVER_USER, WEB_SERVER_GROUP, nginx_config.root
        );
        return Err(());
    }
    println!("✓ Site files ownership set to {}", WEB_SERVER_USER);

    println!("✓ WordPress successfully installed on site '{}'", site_name);
    println!();
    println!("  Next steps:");
    println!(
        "  1. Navigate to http://{} to complete WordPress setup",
        site_name
    );
    println!("  2. Follow the installation wizard to set up your admin account");
    println!("  3. Configure your site settings and install themes/plugins as needed");

    Ok(())
}

/// Adds SSL/HTTPS support to an existing HTTP-only site.
///
/// Issues a Let's Encrypt certificate, installs it into the site's SSL
/// directory, and appends the HTTPS server block to the site's Nginx config.
/// Nginx is **not** reloaded here: [`update_site`] validates and reloads once
/// every requested sub-step has run.
///
/// # Arguments
///
/// * `nginx_config` - The site's Nginx configuration; must be built with SSL
///   enabled so `ssl_root` is set, and with the site's resolved PHP version
///   (see [`update_site`]) so the HTTPS block matches the HTTP block.
///
/// # Returns
///
/// * `Ok(())` - The certificate is installed and the HTTPS block appended and
///   validated (Nginx config changed, reload pending)
/// * `Err(StepFailure::ConfigIntact)` - SSL enablement failed and was already
///   reported; the config is unchanged or was restored, see Rollback Behavior
/// * `Err(StepFailure::ConfigLeftModified)` - The HTTPS block could not be
///   rolled back; [`finish_update`] retries the restore
///
/// # Process Flow
///
/// 1. **Pre-flight**: refuses if certificate files or an HTTPS block already
///    exist.
/// 2. **Certificate**: creates `/etc/nginx/ssl/{site_name}/` (mode 750), issues
///    and installs the certificate via [`ssl::generate_ssl`], then hands the
///    directory to `{sudo_user}:root` (a failure here is reported, not fatal).
/// 3. **Nginx**: backs up the current config (right before editing it, so
///    nothing written during issuance is lost on rollback), appends exactly one
///    HTTPS server block (`listen 443 ssl http2`, certificate paths, TLS 1.2/1.3
///    settings, the same site locations and PHP-FPM handler) and validates it
///    with `nginx -t`.
///
/// The HTTP block is left untouched: no HTTP → HTTPS redirect and no security
/// headers are added, so the site stays reachable on both ports.
///
/// # Files Modified
///
/// ```text
/// /etc/nginx/conf.d/{site_name}.conf     # HTTPS server block appended
/// /etc/nginx/ssl/{site_name}/
/// ├── privkey.pem                        # Private key (installed by acme.sh)
/// └── fullchain.pem                      # Certificate chain (installed by acme.sh)
/// ```
///
/// # Rollback Behavior
///
/// - Issuance fails → the SSL directory created by this step is removed.
/// - Backup read, append, or post-append `nginx -t` fails → the Nginx config is
///   restored from the backup (when it was taken), then the SSL directory is
///   removed so a later `update --ssl` is not blocked by leftover certificate
///   files. If the restore itself fails, the certificates are kept because the
///   config still references them.
/// - The certificate held in acme.sh's own state is never removed: acme.sh
///   still tracks it (with its install paths and reload command, so renewals
///   fail to install until fixed). Re-run `update --ssl` to reuse it, or run
///   `e2sp delete` / `acme.sh --remove -d <site>` to stop renewals.
///
/// # Prerequisites
///
/// - DNS for the domain points to this server and port 80 is reachable
///   (HTTP-01 challenge)
/// - acme.sh is installed for root (see [`ssl::generate_ssl`])
///
/// # See Also
///
/// * [`check_if_https_in_nginx_config_file`] - Detects an existing HTTPS block
/// * [`validate_nginx_configuration`] - Validates Nginx syntax
fn update_with_ssl(nginx_config: &nginx::config::NginxConfig) -> Result<(), StepFailure> {
    let site_name = &nginx_config.site_name;

    // Invariant: update_site builds the config with SSL enabled, so ssl_root is Some
    let ssl_root = nginx_config.ssl_root.as_ref().unwrap();

    // Either certificate files or an HTTPS block mean SSL was (partially) set up
    if ssl::check_if_ssl_files_exist(ssl_root)
        || check_if_https_in_nginx_config_file(&nginx_config.nginx_config_file_path)
    {
        eprintln!(
            "✗ SSL seems to already exist for site '{}'. Cannot update.",
            site_name
        );
        return Err(StepFailure::ConfigIntact);
    }

    println!("Attempting to enable SSL for this site...");

    issue_ssl_certificate(nginx_config, ssl_root).map_err(|()| StepFailure::ConfigIntact)?;
    hand_over_ssl_directory(ssl_root);

    let Ok(original_nginx_config) = read_nginx_config_backup(nginx_config) else {
        // Config untouched, so only the installed certificates need undoing
        remove_ssl_directory(ssl_root);
        print_acme_tracking_note(site_name);
        return Err(StepFailure::ConfigIntact);
    };
    if append_https_block(nginx_config).is_err() || validate_https_block().is_err() {
        let rolled_back = rollback_https_update(nginx_config, ssl_root, &original_nginx_config);
        return Err(StepFailure::after_restore(rolled_back));
    }

    println!("✓ SSL successfully enabled for site '{}'", site_name);
    Ok(())
}

/// Reads the site's current Nginx config so it can be restored later.
///
/// # Arguments
///
/// * `nginx_config` - The site whose config file is backed up.
///
/// # Returns
///
/// * `Ok(String)` - The file's current contents
/// * `Err(())` - The file could not be read (already reported)
fn read_nginx_config_backup(nginx_config: &nginx::config::NginxConfig) -> Result<String, ()> {
    fs::read_to_string(&nginx_config.nginx_config_file_path).map_err(|e| {
        eprintln!(
            "✗ Failed to read existing Nginx configuration file for site '{}': {}",
            nginx_config.site_name, e
        );
        eprintln!("  Cannot proceed with the update without a backup.");
    })
}

/// Creates the SSL directory and issues + installs the certificate into it.
///
/// On issuance failure the directory is removed again. That recursive removal
/// can only delete what this step created because:
/// - `ssl_root` is `/etc/nginx/ssl/{site_name}` with a site name already
///   validated as an RFC 1035 domain, so it cannot traverse elsewhere;
/// - [`sites::create_directory_if_not_exists`] refuses a path that already
///   `exists()` (a directory, file, or symlink), so the directory is always new
///   (missing parents are created by `create_dir_all`);
/// - `std::fs::remove_dir_all` removes symlinks inside it without following
///   them.
///
/// # Arguments
///
/// * `nginx_config` - The site to issue the certificate for.
/// * `ssl_root` - The site's SSL directory (`/etc/nginx/ssl/{site_name}`).
///
/// # Returns
///
/// * `Ok(())` - `privkey.pem` and `fullchain.pem` are installed in `ssl_root`
/// * `Err(())` - Directory creation or issuance failed (already reported)
fn issue_ssl_certificate(
    nginx_config: &nginx::config::NginxConfig,
    ssl_root: &str,
) -> Result<(), ()> {
    if let Err(e) = sites::create_directory_if_not_exists(ssl_root, Some(0o750)) {
        eprintln!("✗ Failed to create SSL directory: {}", e);
        if Path::new(ssl_root).exists() {
            eprintln!(
                "  '{}' is likely left over from an earlier attempt; inspect it and remove it manually before retrying.",
                ssl_root
            );
        }
        return Err(());
    }
    println!("✓ SSL directory created successfully");

    if let Err(e) = ssl::generate_ssl(nginx_config) {
        eprintln!("✗ SSL generation failed: {}", e);
        remove_ssl_directory(ssl_root);
        return Err(());
    }
    println!("✓ SSL certificates generated and installed successfully");
    Ok(())
}

/// Hands the SSL directory to `{sudo_user}:root`, matching what `spawn` does.
///
/// Failure is reported but not fatal: Nginx's master process runs as root and
/// can still read the certificates, so HTTPS works either way.
///
/// # Arguments
///
/// * `ssl_root` - The site's SSL directory.
fn hand_over_ssl_directory(ssl_root: &str) {
    let current_user = get_sudo_user();
    if let Err(e) = sites::set_path_owner_recursive(Some(&current_user), Some("root"), ssl_root) {
        eprintln!("✗ Failed to set SSL directory ownership: {}", e);
        eprintln!(
            "  HTTPS still works; fix it with: sudo chown -R {}:root {}",
            current_user, ssl_root
        );
    }
}

/// Appends the HTTPS server block to the site's config, exactly once.
///
/// # Arguments
///
/// * `nginx_config` - The site whose config file receives the HTTPS block;
///   must have `ssl_root` set.
///
/// # Returns
///
/// * `Ok(())` - The block was appended
/// * `Err(())` - Appending failed (already reported); the caller must restore
///   the backup
fn append_https_block(nginx_config: &nginx::config::NginxConfig) -> Result<(), ()> {
    let https_config = nginx_config.generate_config(nginx::config::NginxProtocol::Https);
    if let Err(e) = append_to_nginx_file(&nginx_config.nginx_config_file_path, &https_config) {
        eprintln!(
            "✗ Failed to update Nginx configuration file for HTTPS: {}",
            e
        );
        return Err(());
    }
    println!("✓ Nginx configuration file updated for HTTPS successfully");
    Ok(())
}

/// Checks the configuration with `nginx -t` right after the HTTPS append.
///
/// # Returns
///
/// * `Ok(())` - Nginx accepts the configuration
/// * `Err(())` - Validation failed (already reported); the caller must restore
///   the backup
fn validate_https_block() -> Result<(), ()> {
    validate_nginx_configuration().map_err(|e| {
        eprintln!(
            "✗ Nginx configuration validation failed after SSL update: {}",
            e
        );
    })
}

/// Writes `original_nginx_config` back to the site's config file, atomically
/// and refusing symlinks (via [`overwrite_nginx_file`]).
///
/// # Arguments
///
/// * `nginx_config` - The site whose config file is restored.
/// * `original_nginx_config` - The contents to restore.
///
/// # Returns
///
/// * `Ok(())` - The file holds the original contents again
/// * `Err(())` - The write failed (reported as CRITICAL)
fn restore_nginx_config(
    nginx_config: &nginx::config::NginxConfig,
    original_nginx_config: &str,
) -> Result<(), ()> {
    println!("Attempting to revert Nginx configuration...");
    if let Err(e) =
        overwrite_nginx_file(&nginx_config.nginx_config_file_path, original_nginx_config)
    {
        eprintln!(
            "✗ CRITICAL: Failed to revert Nginx configuration file: {}",
            e
        );
        eprintln!("  The Nginx configuration may be in an invalid state.");
        eprintln!(
            "  Manual intervention required to fix '{}'.",
            nginx_config.nginx_config_file_path
        );
        return Err(());
    }
    println!("✓ Successfully reverted Nginx configuration to original state");
    Ok(())
}

/// Undoes a failed HTTPS append: restores the Nginx config, then drops the
/// installed certificates.
///
/// The SSL directory is removed only once the config no longer references it;
/// if the restore fails the certificates are kept so the half-written config
/// is not made worse by pointing at missing files.
///
/// # Arguments
///
/// * `nginx_config` - The site whose config file is restored.
/// * `ssl_root` - The site's SSL directory, created by this update.
/// * `original_nginx_config` - The config contents read before the append.
///
/// # Returns
///
/// * `Ok(())` - The config was restored
/// * `Err(())` - The restore failed (reported); the SSL directory was kept
fn rollback_https_update(
    nginx_config: &nginx::config::NginxConfig,
    ssl_root: &str,
    original_nginx_config: &str,
) -> Result<(), ()> {
    if restore_nginx_config(nginx_config, original_nginx_config).is_err() {
        eprintln!("  SSL files kept in '{}'.", ssl_root);
        return Err(());
    }
    remove_ssl_directory(ssl_root);
    print_acme_tracking_note(&nginx_config.site_name);
    Ok(())
}

/// Tells the operator that acme.sh still tracks the site's certificate after
/// the installed copy was rolled back.
///
/// # Arguments
///
/// * `site_name` - The site whose certificate stays in acme.sh.
fn print_acme_tracking_note(site_name: &str) {
    eprintln!(
        "  acme.sh still tracks this certificate; re-run `e2sp update {} --ssl` to reuse it,",
        site_name
    );
    eprintln!(
        "  or `e2sp delete {}` / `acme.sh --remove -d {}` to stop renewals.",
        site_name, site_name
    );
}

/// What [`remove_ssl_directory`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SslDirCleanup {
    /// The directory existed and was removed.
    Removed,
    /// There was no directory to remove.
    Absent,
    /// Removal failed (already reported).
    Failed,
}

/// Removes the SSL directory created by `update_with_ssl`, reporting the
/// outcome.
///
/// Uses [`sites::remove_directory`] (recursive) because after installation the
/// directory holds the certificate files, which `std::fs::remove_dir` would
/// refuse to delete. acme.sh's own certificate state is left intact.
///
/// # Arguments
///
/// * `ssl_root` - The site's SSL directory.
///
/// # Returns
///
/// Whether the directory was removed, absent, or could not be removed.
fn remove_ssl_directory(ssl_root: &str) -> SslDirCleanup {
    if !Path::new(ssl_root).exists() {
        println!("  No SSL directory to remove at '{}'", ssl_root);
        return SslDirCleanup::Absent;
    }
    match sites::remove_directory(ssl_root) {
        Ok(()) => {
            println!("✓ SSL directory '{}' removed", ssl_root);
            SslDirCleanup::Removed
        }
        Err(e) => {
            eprintln!("✗ Failed to remove SSL directory: {}", e);
            eprintln!("  Remove it manually before retrying `update --ssl`.");
            SslDirCleanup::Failed
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    /// Renders features as plain labels for assertions.
    fn labels(features: &[SiteFeature]) -> Vec<String> {
        features.iter().map(SiteFeature::label).collect()
    }

    /// Parses a known-good version for tests.
    fn v(s: &str) -> Option<PhpVersion> {
        PhpVersion::parse(s).ok()
    }

    #[test]
    fn features_php_only() {
        assert_eq!(
            labels(&format_site_features(false, false, v("8.5"))),
            ["php 8.5"]
        );
    }

    #[test]
    fn features_ssl_and_php() {
        assert_eq!(
            labels(&format_site_features(true, false, v("8.1"))),
            ["ssl", "php 8.1"]
        );
    }

    #[test]
    fn features_wp_and_php() {
        assert_eq!(
            labels(&format_site_features(false, true, v("7.4"))),
            ["wp", "php 7.4"]
        );
    }

    #[test]
    fn features_all_in_order() {
        assert_eq!(
            labels(&format_site_features(true, true, v("10.0"))),
            ["ssl", "wp", "php 10.0"]
        );
    }

    #[test]
    fn features_undetected_php_shows_question_mark() {
        assert_eq!(labels(&format_site_features(false, false, None)), ["php ?"]);
        assert_eq!(
            labels(&format_site_features(true, true, None)),
            ["ssl", "wp", "php ?"]
        );
    }

    #[test]
    fn colorized_feature_keeps_label_text() {
        for f in format_site_features(true, true, v("8.3"))
            .iter()
            .chain(format_site_features(false, false, None).iter())
        {
            assert!(colorize_feature(f).contains(&f.label()));
        }
    }

    #[test]
    fn feature_colors_per_variant() {
        assert_eq!(feature_color(&SiteFeature::Ssl), Color::Green);
        assert_eq!(feature_color(&SiteFeature::WordPress), Color::Blue);
        assert_eq!(feature_color(&SiteFeature::Php(v("8.5"))), Color::Magenta);
        assert_eq!(feature_color(&SiteFeature::Php(None)), Color::Yellow);
    }

    #[test]
    fn real_config_with_mixed_php_blocks_shows_unknown_php() {
        // Same shape `update --ssl` produces: HTTP block followed by an HTTPS block
        let http = build_spawn_config("qa9.example.com", false, PhpVersion::default_version())
            .generate_config(nginx::config::NginxProtocol::Http);
        let https = build_spawn_config("qa9.example.com", true, PhpVersion::default_version())
            .generate_config(nginx::config::NginxProtocol::Https);
        let https =
            nginx::php_fpm::set_php_version(&https, PhpVersion::parse("8.1").expect("valid"))
                .expect("template has a socket");
        let content = format!("{http}\n{https}");
        assert!(content.contains("php8.5-fpm.sock") && content.contains("php8.1-fpm.sock"));
        assert_eq!(detect_site_php_version(&content), None);
        assert_eq!(
            labels(&format_site_features(
                true,
                false,
                detect_site_php_version(&content)
            )),
            ["ssl", "php ?"]
        );
        // Sanity: the unmixed real config is detected through the same path
        assert_eq!(detect_site_php_version(&http), v("8.5"));
    }

    #[test]
    fn detection_failures_map_to_unknown_php() {
        // Mirrors list_sites: every detection error must become `php ?`, never a panic
        let cases = [
            "server {}\n",
            "fastcgi_pass 127.0.0.1:9000;\n",
            "fastcgi_pass unix:/var/run/php/php8.1-fpm.sock;\nfastcgi_pass unix:/var/run/php/php8.5-fpm.sock;\n",
            "fastcgi_pass unix:/var/run/php/php8.x-fpm.sock;\n",
        ];
        for c in cases {
            let php = nginx::php_fpm::detect_php_version(c).ok();
            assert_eq!(labels(&format_site_features(false, false, php)), ["php ?"]);
        }
        let ok = nginx::php_fpm::detect_php_version(
            "  fastcgi_pass unix:/var/run/php/php8.4-fpm.sock;\n",
        )
        .ok();
        assert_eq!(labels(&format_site_features(false, false, ok)), ["php 8.4"]);
    }

    #[test]
    fn test_build_spawn_config_carries_chosen_php_version() {
        let php = PhpVersion::parse("8.3").expect("valid version");
        let config = build_spawn_config("qa9.example.com", true, php);
        assert_eq!(config.php_version, php);
        assert_eq!(
            config.php_version.fpm_socket_path(),
            "/var/run/php/php8.3-fpm.sock"
        );
        for protocol in [
            nginx::config::NginxProtocol::Http,
            nginx::config::NginxProtocol::Https,
        ] {
            let rendered = config.generate_config(protocol);
            assert!(rendered.contains("fastcgi_pass unix:/var/run/php/php8.3-fpm.sock;"));
            assert!(!rendered.contains("php8.5-fpm.sock"));
        }
    }

    #[test]
    fn test_build_spawn_config_default_version_and_paths() {
        let config = build_spawn_config("qa9.example.com", false, PhpVersion::default_version());
        assert_eq!(config.php_version, PhpVersion::default_version());
        assert_eq!(config.root, format!("{SITES_PATH}/qa9.example.com"));
        assert_eq!(
            config.nginx_config_file_path,
            format!("{NGINX_CONF_D_PATH}/qa9.example.com.conf")
        );
        assert!(config.ssl_root.is_none());
    }

    /// Shorthand for a failed sub-step outcome.
    const FAILED: UpdateStepOutcome = Err(StepFailure::ConfigIntact);
    /// Shorthand for a failed step that could not restore the config.
    const LEFT_MODIFIED: UpdateStepOutcome = Err(StepFailure::ConfigLeftModified);
    /// Shorthand for a successful step that left Nginx untouched.
    const UNCHANGED: UpdateStepOutcome = Ok(NginxChange::Unchanged);
    /// Shorthand for a successful step that changed the Nginx config.
    const CHANGED: UpdateStepOutcome = Ok(NginxChange::Changed);

    /// Original contents written to test config files.
    const ORIGINAL_CONFIG: &str = "server { listen 80; }\n";

    /// Builds the expected summary for terse assertions.
    fn summary(needs_reload: bool, any_failed: bool) -> UpdateSummary {
        UpdateSummary {
            needs_reload,
            any_failed,
            restore_needed: false,
        }
    }

    /// Builds an SSL-enabled config whose `.conf` file lives in `conf_dir`.
    fn config_in(conf_dir: &Path) -> nginx::config::NginxConfig {
        nginx::config::NginxConfig::new(
            "example.com".to_string(),
            "/var/www/html".to_string(),
            conf_dir.to_str().expect("utf-8 path").to_string(),
            true,
        )
    }

    /// Creates a non-empty SSL directory under `tmp`, like an installed cert.
    fn make_ssl_dir(tmp: &TempDir) -> std::path::PathBuf {
        let ssl_root = tmp.path().join("ssl");
        fs::create_dir(&ssl_root).expect("create ssl dir");
        fs::write(ssl_root.join("privkey.pem"), "key").expect("write key");
        fs::write(ssl_root.join("fullchain.pem"), "cert").expect("write cert");
        ssl_root
    }

    #[test]
    fn test_summary_of_no_steps_needs_nothing_and_succeeds() {
        let s = UpdateSummary::from_outcomes(&[]);
        assert_eq!(s, summary(false, false));
        assert_eq!(s.exit_code(), 0);
    }

    #[test]
    fn test_successful_wordpress_step_alone_does_not_reload() {
        let s = UpdateSummary::from_outcomes(&[UNCHANGED]);
        assert_eq!(s, summary(false, false));
        assert_eq!(s.exit_code(), 0);
    }

    #[test]
    fn test_successful_ssl_step_triggers_reload_and_succeeds() {
        let s = UpdateSummary::from_outcomes(&[CHANGED]);
        assert_eq!(s, summary(true, false));
        assert_eq!(s.exit_code(), 0);
    }

    #[test]
    fn test_both_steps_succeeding_reload_and_succeed() {
        let s = UpdateSummary::from_outcomes(&[UNCHANGED, CHANGED]);
        assert_eq!(s, summary(true, false));
        assert_eq!(s.exit_code(), 0);
    }

    #[test]
    fn test_failed_ssl_step_does_not_reload_and_fails() {
        let s = UpdateSummary::from_outcomes(&[FAILED]);
        assert_eq!(s, summary(false, true));
        assert_eq!(s.exit_code(), 1);
    }

    #[test]
    fn test_failed_wordpress_step_still_reloads_successful_ssl_change_but_fails() {
        let s = UpdateSummary::from_outcomes(&[FAILED, CHANGED]);
        assert_eq!(s, summary(true, true));
        assert_eq!(s.exit_code(), 1);
    }

    #[test]
    fn test_failed_ssl_after_successful_wordpress_fails_without_reload() {
        let s = UpdateSummary::from_outcomes(&[UNCHANGED, FAILED]);
        assert_eq!(s, summary(false, true));
        assert_eq!(s.exit_code(), 1);
    }

    #[test]
    fn test_all_steps_failing_fails_without_reload() {
        let s = UpdateSummary::from_outcomes(&[FAILED, FAILED]);
        assert_eq!(s, summary(false, true));
        assert_eq!(s.exit_code(), 1);
    }

    #[test]
    fn test_final_exit_code_is_zero_only_when_steps_and_nginx_succeed() {
        assert_eq!(summary(true, false).final_exit_code(Ok(())), 0);
        assert_eq!(summary(false, false).final_exit_code(Ok(())), 0);
    }

    #[test]
    fn test_final_exit_code_fails_when_nginx_apply_fails() {
        assert_eq!(summary(true, false).final_exit_code(Err(())), 1);
        assert_eq!(summary(true, true).final_exit_code(Err(())), 1);
    }

    #[test]
    fn test_final_exit_code_fails_when_a_step_failed() {
        assert_eq!(summary(true, true).final_exit_code(Ok(())), 1);
        assert_eq!(summary(false, true).final_exit_code(Ok(())), 1);
    }

    #[test]
    fn test_update_step_nginx_change_mapping() {
        assert_eq!(UpdateStep::WordPress.nginx_change(), NginxChange::Unchanged);
        assert_eq!(UpdateStep::Ssl.nginx_change(), NginxChange::Changed);
    }

    #[test]
    fn test_requested_steps_follow_flags_in_order() {
        assert_eq!(UpdateStep::requested(false, false, None), vec![]);
        assert_eq!(
            UpdateStep::requested(true, false, None),
            vec![UpdateStep::WordPress]
        );
        assert_eq!(
            UpdateStep::requested(false, true, None),
            vec![UpdateStep::Ssl]
        );
        assert_eq!(
            UpdateStep::requested(true, true, None),
            vec![UpdateStep::WordPress, UpdateStep::Ssl]
        );
    }

    /// Parses a known-good version literal for tests.
    fn ver(s: &str) -> PhpVersion {
        PhpVersion::parse(s).expect("valid test version")
    }

    #[test]
    fn test_php_step_nginx_change_is_changed() {
        assert_eq!(
            UpdateStep::Php(ver("8.3")).nginx_change(),
            NginxChange::Changed
        );
    }

    #[test]
    fn test_requested_steps_put_php_first() {
        let php = Some(ver("8.3"));
        assert_eq!(
            UpdateStep::requested(false, false, php),
            vec![UpdateStep::Php(ver("8.3"))]
        );
        assert_eq!(
            UpdateStep::requested(false, true, php),
            vec![UpdateStep::Php(ver("8.3")), UpdateStep::Ssl]
        );
        assert_eq!(
            UpdateStep::requested(true, true, php),
            vec![
                UpdateStep::Php(ver("8.3")),
                UpdateStep::WordPress,
                UpdateStep::Ssl
            ]
        );
    }

    #[test]
    fn test_only_ssl_is_blocked_by_a_failed_php_switch() {
        assert!(UpdateStep::Ssl.blocked_by_php_failure(true));
        assert!(!UpdateStep::Ssl.blocked_by_php_failure(false));
        assert!(!UpdateStep::WordPress.blocked_by_php_failure(true));
        assert!(!UpdateStep::Php(ver("8.3")).blocked_by_php_failure(true));
    }

    #[test]
    fn test_resolve_php_version_requested_wins_over_detected() {
        for ssl in [false, true] {
            assert_eq!(
                resolve_php_version(Some(ver("8.3")), &Ok(ver("8.1")), ssl),
                Ok(ver("8.3"))
            );
            let missing = Err(PhpFpmConfigError::NoFastcgiPass);
            assert_eq!(
                resolve_php_version(Some(ver("8.3")), &missing, ssl),
                Ok(ver("8.3"))
            );
        }
    }

    #[test]
    fn test_resolve_php_version_uses_detected_when_not_requested() {
        for ssl in [false, true] {
            assert_eq!(
                resolve_php_version(None, &Ok(ver("8.1")), ssl),
                Ok(ver("8.1"))
            );
        }
    }

    #[test]
    fn test_resolve_php_version_without_ssl_tolerates_undetected_version() {
        // Nothing writes the version (e.g. --wp alone), so no need to fail
        let undetected = Err(PhpFpmConfigError::NoFastcgiPass);
        assert_eq!(
            resolve_php_version(None, &undetected, false),
            Ok(PhpVersion::default_version())
        );
    }

    #[test]
    fn test_resolve_php_version_fails_closed_for_ssl_on_every_detection_error() {
        let errors = [
            PhpFpmConfigError::NoFastcgiPass,
            PhpFpmConfigError::Unrecognized("fastcgi_pass 127.0.0.1:9000;".to_string()),
            PhpFpmConfigError::Inconsistent(vec![ver("8.1"), ver("8.5")]),
        ];
        for e in errors {
            let message = resolve_php_version(None, &Err(e.clone()), true).expect_err("must fail");
            assert!(
                message.starts_with("Cannot detect the site's PHP version ("),
                "{message}"
            );
            assert!(message.contains(&e.to_string()), "{message}");
            assert!(!message.contains("default"), "{message}");
        }
    }

    #[test]
    fn test_undetectable_php_message_suggests_php_only_when_it_helps() {
        let mixed = PhpFpmConfigError::Inconsistent(vec![ver("8.1"), ver("8.5")]);
        assert!(undetectable_php_message(&mixed).ends_with("; pass --php X.Y to choose one"));
        let unfixable = [
            PhpFpmConfigError::NoFastcgiPass,
            PhpFpmConfigError::Unrecognized("fastcgi_pass 127.0.0.1:9000;".to_string()),
        ];
        for e in unfixable {
            let message = undetectable_php_message(&e);
            assert!(!message.contains("pass --php"), "{message}");
            assert!(
                message.contains("--php cannot rewrite this config"),
                "{message}"
            );
            assert!(
                message.contains("127.0.0.1:9000") || matches!(e, PhpFpmConfigError::NoFastcgiPass)
            );
        }
    }

    /// `--php X.Y` is the advertised remedy only where `set_php_version`
    /// accepts the config; this pins that assumption.
    #[test]
    fn test_set_php_version_supports_exactly_the_hinted_remedy() {
        let sock = |v: &str| format!("fastcgi_pass unix:/var/run/php/php{v}-fpm.sock;\n");
        let mixed = format!("{}{}", sock("8.1"), sock("8.5"));
        assert_eq!(
            set_php_version(&mixed, ver("8.3")),
            Ok(format!("{}{}", sock("8.3"), sock("8.3")))
        );
        assert!(set_php_version("server {}\n", ver("8.3")).is_err());
        assert!(set_php_version("fastcgi_pass 127.0.0.1:9000;\n", ver("8.3")).is_err());
    }

    /// Runs [`fold_step_outcomes`] with stubbed outcomes, returning the
    /// outcomes, the steps actually run and the number of skips reported.
    fn fold_with(
        steps: &[UpdateStep],
        stub: impl Fn(UpdateStep) -> UpdateStepOutcome,
    ) -> (Vec<UpdateStepOutcome>, Vec<UpdateStep>, usize) {
        let mut ran = Vec::new();
        let mut skips = 0;
        let outcomes = fold_step_outcomes(
            steps,
            |step| {
                ran.push(step);
                stub(step)
            },
            || skips += 1,
        );
        (outcomes, ran, skips)
    }

    #[test]
    fn test_fold_runs_every_step_when_php_succeeds() {
        let steps = UpdateStep::requested(true, true, Some(ver("8.3")));
        let (outcomes, ran, skips) = fold_with(&steps, |_| CHANGED);
        assert_eq!(outcomes, vec![CHANGED; 3]);
        assert_eq!(ran, steps);
        assert_eq!(skips, 0);
    }

    #[test]
    fn test_fold_skips_ssl_but_runs_wordpress_after_php_failure() {
        let steps = UpdateStep::requested(true, true, Some(ver("8.3")));
        for php_failure in [FAILED, LEFT_MODIFIED] {
            let (outcomes, ran, skips) = fold_with(&steps, |step| match step {
                UpdateStep::Php(_) => php_failure,
                _ => UNCHANGED,
            });
            assert_eq!(outcomes, vec![php_failure, UNCHANGED, FAILED]);
            assert_eq!(
                ran,
                vec![UpdateStep::Php(ver("8.3")), UpdateStep::WordPress]
            );
            assert_eq!(skips, 1);
        }
    }

    #[test]
    fn test_fold_keeps_running_after_non_php_failures() {
        let steps = UpdateStep::requested(true, true, None);
        let (outcomes, ran, skips) = fold_with(&steps, |_| FAILED);
        assert_eq!(outcomes, vec![FAILED, FAILED]);
        assert_eq!(ran, steps);
        assert_eq!(skips, 0);
    }

    #[test]
    fn test_step_failure_after_restore() {
        assert_eq!(
            StepFailure::after_restore(Ok(())),
            StepFailure::ConfigIntact
        );
        assert_eq!(
            StepFailure::after_restore(Err(())),
            StepFailure::ConfigLeftModified
        );
    }

    #[test]
    fn test_final_action_follows_outcomes() {
        let action = |o: &[UpdateStepOutcome]| UpdateSummary::from_outcomes(o).final_action();
        assert_eq!(action(&[]), FinalNginxAction::Nothing);
        assert_eq!(action(&[UNCHANGED, FAILED]), FinalNginxAction::Nothing);
        assert_eq!(action(&[CHANGED]), FinalNginxAction::ApplyChanges);
        assert_eq!(action(&[FAILED, CHANGED]), FinalNginxAction::ApplyChanges);
        assert_eq!(action(&[LEFT_MODIFIED]), FinalNginxAction::RestorePreUpdate);
        // A broken leftover config is never reloaded, even with other changes
        assert_eq!(
            action(&[CHANGED, LEFT_MODIFIED]),
            FinalNginxAction::RestorePreUpdate
        );
    }

    #[test]
    fn test_left_modified_step_fails_and_needs_restore() {
        let s = UpdateSummary::from_outcomes(&[LEFT_MODIFIED, UNCHANGED]);
        assert!(s.restore_needed && s.any_failed && !s.needs_reload);
        assert_eq!(s.final_exit_code(Ok(())), 1);
        assert_eq!(s.final_exit_code(Err(())), 1);
    }

    #[test]
    fn test_php_switch_needed() {
        assert!(!php_switch_needed(&Ok(ver("8.5")), ver("8.5")));
        assert!(php_switch_needed(&Ok(ver("8.1")), ver("8.5")));
        assert!(php_switch_needed(
            &Err(PhpFpmConfigError::NoFastcgiPass),
            ver("8.5")
        ));
        let mixed = Err(PhpFpmConfigError::Inconsistent(vec![
            ver("8.1"),
            ver("8.5"),
        ]));
        assert!(php_switch_needed(&mixed, ver("8.5")));
    }

    #[test]
    fn test_fpm_preflight_needed_for_every_written_socket() {
        let same = Ok(ver("8.5"));
        let other = Ok(ver("8.1"));
        let undetected = Err(PhpFpmConfigError::NoFastcgiPass);
        // --ssl always writes a socket path
        assert!(fpm_preflight_needed(None, &same, true));
        assert!(fpm_preflight_needed(None, &undetected, true));
        assert!(fpm_preflight_needed(Some(ver("8.5")), &same, true));
        // --php writes only when it differs from the current version
        assert!(fpm_preflight_needed(Some(ver("8.5")), &other, false));
        assert!(fpm_preflight_needed(Some(ver("8.5")), &undetected, false));
        assert!(!fpm_preflight_needed(Some(ver("8.5")), &same, false));
        // --wp alone writes nothing
        assert!(!fpm_preflight_needed(None, &other, false));
    }

    #[test]
    fn test_remove_ssl_directory_deletes_non_empty_directory() {
        let tmp = TempDir::new().expect("create temp dir");
        let ssl_root = make_ssl_dir(&tmp);

        let cleanup = remove_ssl_directory(ssl_root.to_str().expect("utf-8 path"));

        assert_eq!(cleanup, SslDirCleanup::Removed);
        assert!(!ssl_root.exists());
    }

    #[test]
    fn test_remove_ssl_directory_on_missing_directory_does_not_fail() {
        let tmp = TempDir::new().expect("create temp dir");
        let ssl_root = tmp.path().join("missing");

        let cleanup = remove_ssl_directory(ssl_root.to_str().expect("utf-8 path"));

        assert_eq!(cleanup, SslDirCleanup::Absent);
        assert!(tmp.path().exists());
    }

    #[test]
    fn test_write_nginx_config_replaces_existing_file() {
        let tmp = TempDir::new_in("/tmp").expect("create temp dir");
        let config = config_in(tmp.path());
        fs::write(&config.nginx_config_file_path, ORIGINAL_CONFIG).expect("write config");

        assert_eq!(
            write_nginx_config(&config, "server { listen 81; }\n"),
            Ok(())
        );
        let written = fs::read_to_string(&config.nginx_config_file_path).expect("read config");
        assert_eq!(written, "server { listen 81; }\n");
    }

    #[test]
    fn test_write_nginx_config_never_creates_a_missing_file() {
        let tmp = TempDir::new_in("/tmp").expect("create temp dir");
        let config = config_in(tmp.path());

        assert_eq!(write_nginx_config(&config, ORIGINAL_CONFIG), Err(()));
        assert!(!Path::new(&config.nginx_config_file_path).exists());
    }

    #[test]
    fn test_rollback_https_update_restores_config_and_removes_ssl_dir() {
        // Under /tmp: the restore goes through overwrite_nginx_file, which only
        // writes inside its allowed Nginx directories (macOS defaults to /var/folders)
        let tmp = TempDir::new_in("/tmp").expect("create temp dir");
        let config = config_in(tmp.path());
        fs::write(&config.nginx_config_file_path, "half-written https block")
            .expect("write config");
        let ssl_root = make_ssl_dir(&tmp);

        let result = rollback_https_update(&config, ssl_root.to_str().unwrap(), ORIGINAL_CONFIG);

        assert_eq!(result, Ok(()));
        let restored = fs::read_to_string(&config.nginx_config_file_path).expect("read config");
        assert_eq!(restored, ORIGINAL_CONFIG);
        assert!(!ssl_root.exists());
    }

    #[test]
    fn test_rollback_https_update_keeps_ssl_dir_when_restore_fails() {
        let tmp = TempDir::new().expect("create temp dir");
        // The config's parent directory does not exist, so the restore write fails
        let config = config_in(&tmp.path().join("missing-conf-dir"));
        let ssl_root = make_ssl_dir(&tmp);

        let result = rollback_https_update(&config, ssl_root.to_str().unwrap(), ORIGINAL_CONFIG);

        assert_eq!(result, Err(()));
        assert!(ssl_root.join("privkey.pem").exists());
        assert!(ssl_root.join("fullchain.pem").exists());
    }

    #[test]
    fn test_read_nginx_config_backup_of_missing_file_fails() {
        let tmp = TempDir::new().expect("create temp dir");
        let config = config_in(tmp.path());

        assert_eq!(read_nginx_config_backup(&config), Err(()));
    }

    #[test]
    fn test_read_nginx_config_backup_returns_contents() {
        let tmp = TempDir::new().expect("create temp dir");
        let config = config_in(tmp.path());
        fs::write(&config.nginx_config_file_path, ORIGINAL_CONFIG).expect("write config");

        assert_eq!(
            read_nginx_config_backup(&config),
            Ok(ORIGINAL_CONFIG.to_string())
        );
    }

    /// Creates a temp dir under `/tmp`, the only temp location
    /// `append_to_nginx_file` accepts (macOS' default temp dir is rejected).
    fn nginx_writable_tmp() -> TempDir {
        tempfile::Builder::new()
            .prefix("e2sp-commands-test-")
            .tempdir_in("/tmp")
            .expect("create temp dir under /tmp")
    }

    #[test]
    fn test_append_https_block_appends_exactly_one_block() {
        let tmp = nginx_writable_tmp();
        let config = config_in(tmp.path());
        fs::write(&config.nginx_config_file_path, ORIGINAL_CONFIG).expect("write config");

        assert_eq!(append_https_block(&config), Ok(()));

        let content = fs::read_to_string(&config.nginx_config_file_path).expect("read config");
        assert!(content.starts_with(ORIGINAL_CONFIG));
        // One block = one opening + one closing marker
        assert_eq!(content.matches(NGINX_HTTPS_CONFIG_MARKER).count(), 2);
        assert_eq!(content.matches("listen 443").count(), 1);
    }

    #[test]
    fn test_append_https_block_to_missing_file_fails() {
        let tmp = nginx_writable_tmp();
        let config = config_in(tmp.path());

        assert_eq!(append_https_block(&config), Err(()));
        assert!(!Path::new(&config.nginx_config_file_path).exists());
    }
}

use crate::constants::{DB_CHARSET, DB_PASSWORD, DB_USER};
/// Command module for the e2e-site-spawner CLI tool.
///
/// This module contains the implementation of various commands
/// for managing sites on an Nginx server. Each command function
/// serves as a placeholder for future implementation and prints
/// a description of its intended effect.
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
#[derive(Clone)]
pub enum SpawnSteps {
    /// When Nginx configuration file for HTTP was created
    CreateNginxConfig,
    /// When the site's root directory was created
    CreateSiteDirectory,
    /// When the directory to store SSL certificates was created
    CreateSSLDirectory,
    /// When SSL certificates were generated and installed
    CreateSSL,
    /// When Nginx configuration was updated to include HTTPS settings
    CreateNginxConfigWithSSL,
    /// When the database for the site was created (stores database name)
    CreateDatabase(String),
    /// When the WordPress configuration file (wp-config.php) was created
    CreateWPConfigFile,
}

/// Group of steps related to Nginx configuration removal.
/// 
/// This constant defines which spawn steps should be considered
/// as a group when reverting Nginx configuration changes.
pub const REMOVE_NGINX_CONFIG: [SpawnSteps; 2] = [
    SpawnSteps::CreateNginxConfig,
    SpawnSteps::CreateNginxConfigWithSSL,
];

/// Group of steps related to site directory removal.
/// 
/// This constant defines which spawn steps should be considered
/// as a group when reverting site directory changes.
pub const REMOVE_SITE_DIRECTORY: [SpawnSteps; 2] = [
    SpawnSteps::CreateSiteDirectory,
    SpawnSteps::CreateWPConfigFile,
];

/// Group of steps related to SSL directory removal.
/// 
/// This constant defines which spawn steps should be considered
/// as a group when reverting SSL-related changes.
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
pub fn spawn_site(site_name: &str, ssl: bool, no_wp: bool) {
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
    let mut steps_completed: Vec<SpawnSteps> = Vec::new();
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
    let _ = validate_nginx_configuration().unwrap_or_else(|e| {
        eprintln!(
            "✗ Nginx configuration validation failed after creating HTTP config. \n{}",
            e
        );
        revert_site_spawn(site_name, &steps_completed, &nginx_config);
    });
    if let Some(ssl_root) = &nginx_config.ssl_root {
        println!("SSL will be enabled for this site.");
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
        let path = format!("{}/index.html", nginx_config.root);
        create_file_with_content_if_not_exists(&path, HTML_DEFAULT_INDEX_FILE, None).unwrap_or(());
    }
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
/// # Panics
///
/// This function will exit the process with status code 1 if:
/// - Initial Nginx configuration validation fails
/// - Nginx configuration validation fails after deletion
/// - Nginx reload fails after deletion
///
/// # Safety
///
/// This operation is destructive and cannot be undone. All site data,
/// including databases and uploaded files, will be permanently deleted.
///
/// # Example
///
/// ```no_run
/// // Delete a site and all its resources
/// delete_site("example.local");
/// ```
pub fn delete_site(site_name: &str) {
    println!("Preparing to delete site: {}", site_name);
    println!("Validating Nginx configuration...");
    validate_nginx_configuration().unwrap_or_else(|e| {
        eprintln!("✗ Nginx configuration validation failed before deletion.");
        eprintln!("Make sure Nginx configuration is okay before deleting a site, since nginx reloads is required.");
        eprintln!("Nginx error: \n{}", e);
        process::exit(1);
    });
    let nginx_config = nginx::config::NginxConfig::new(
        site_name.to_string(),
        SITES_PATH.to_string(),
        NGINX_CONF_D_PATH.to_string(),
        true,
    );
    nginx_config.validate().unwrap_or_else(|e| {
        eprintln!("✗ Validation failed: {}", e);
        process::exit(1);
    });
    println!("Attempting to delete site resources...");
    let _ = sites::remove_directory(nginx_config.root.as_str()).unwrap_or_else(|e| {
        eprintln!("✗ Failed to remove site directory: {}", e);
    });
    println!("Attempting to remove Nginx configuration...");
    sites::remove_file(nginx_config.nginx_config_file_path.as_str()).unwrap_or_else(|e| {
        eprintln!("✗ Failed to remove Nginx configuration file: {}", e);
    });
    println!("Attempting to remove SSL files...");
    // Safe to call unwrap here as ssl_root is Some when ssl is true
    sites::remove_directory(nginx_config.ssl_root.as_ref().unwrap()).unwrap_or_else(|e| {
        eprintln!("✗ Failed to remove SSL directory: {}", e);
    });
    let db_name = db::create_db_name(site_name);
    println!("Attempting to drop database '{}'...", db_name);
    match db::drop_database(&db_name) {
        Ok(()) => (),
        // Ok(()) => println!("✓ Database deleted successfully: {}", db_name),
        Err(e) => eprintln!("✗ Failed to delete database: {}", e),
    }
    validate_nginx_configuration().unwrap_or_else(|e| {
        eprintln!("✗ Nginx configuration validation failed after deletion.");
        eprintln!("Make sure Nginx configuration is okay before reloading Nginx.");
        eprintln!("Nginx error: \n{}", e);
        process::exit(1);
    });
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
pub fn deactivate_site(site_name: &str) {
    println!("Attempting to deactivate site: {}", site_name);
    validate_nginx_configuration().unwrap_or_else(|e| {
        eprintln!("✗ Nginx configuration validation failed before deactivation.");
        eprintln!("Make sure Nginx configuration is okay, since nginx reloads is required.");
        eprintln!("Nginx error: \n{}", e);
        process::exit(1);
    });
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

    let active_path = Path::new(&nginx_config.nginx_config_file_path);
    let deactivated_path = active_path.with_extension("conf.deactivated");

    if !active_path.exists() {
        println!("Nothing to deactivate for site '{}'.", site_name);
        process::exit(0);
    }

    match fs::rename(&active_path, &deactivated_path) {
        Ok(()) => {
            println!("✓ Site '{}' deactivated successfully.", site_name);
        }
        Err(e) => {
            eprintln!("✗ Failed to deactivate site '{}': {}", site_name, e);
            process::exit(1);
        }
    }

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
pub fn activate_site(site_name: &str) {
    println!("Attempting to activate site: {}", site_name);
    validate_nginx_configuration().unwrap_or_else(|e| {
        eprintln!("✗ Nginx configuration validation failed before activation.");
        eprintln!("Make sure Nginx configuration is okay, since nginx reloads is required.");
        eprintln!("Nginx error: \n{}", e);
        process::exit(1);
    });
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

    let active_path = Path::new(&nginx_config.nginx_config_file_path);
    let deactivated_path = active_path.with_extension("conf.deactivated");

    if !deactivated_path.exists() {
        println!("Nothing to activate for site '{}'.", site_name);
        process::exit(0);
    }

    match fs::rename(&deactivated_path, &active_path) {
        Ok(()) => {
            println!("✓ Site '{}' activated successfully.", site_name);
        }
        Err(e) => {
            eprintln!("✗ Failed to activate site '{}': {}", site_name, e);
            process::exit(1);
        }
    }

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
// /// This function is currently not implemented and serves as a placeholder
// /// for future functionality.
// ///
// /// # Planned Features
// ///
// /// - Add WordPress to existing static sites
// /// - Enable SSL on sites without HTTPS
// /// - Update Nginx configuration parameters
// /// - Modify site directory permissions
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

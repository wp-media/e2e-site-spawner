/// Command module for the e2e-site-spawner CLI tool.
///
/// This module contains the implementation of various commands
/// for managing sites on an Nginx server. Each command function
/// serves as a placeholder for future implementation and prints
/// a description of its intended effect.


use crate::constants::{NGINX_CONF_D_PATH, SITES_PATH, SITES_SSL_PATH};
use crate::nginx;
use crate::nginx::config::validate_nginx_configuration;
use crate::utils::db;
use crate::utils::ssl;
use crate::utils::sites::{self, revert_site_spawn};
use crate::nginx::{create_nginx_file, append_to_nginx_file};
use crate::utils::validators::validate_site_name;
use std::process;
use std::env;

pub enum SpawnSteps {
    CreateNginxConfig,
    CreateSiteDirectory,
    CreateSSLDirectory,
    CreateSSL,
    CreateNginxConfigWithSSL,
    CreateDatabase(String),
}

/// Spawns a new site with the given name.
///
/// # Arguments
///
/// * `site_name` - The name of the site to create.
/// * `ssl` - Optional flag to enable SSL for the site.
/// * `no_wp` - Optional flag to create the site without WordPress.
pub fn spawn_site(site_name: &str, ssl: bool, no_wp: bool) {
    let ssl_path = if ssl {
        ssl::print_ssl_warning(site_name);
        Some(format!("{}/{}", SITES_SSL_PATH, site_name))
    } else {
        None
    };
    println!("Preparing to create site: {}", site_name);
    validate_site_name(site_name);
    let mut steps_completed: Vec<SpawnSteps> = Vec::new();
    let nginx_config = nginx::config::NginxConfig::new(
        site_name.to_string(),
        SITES_PATH.to_string(),
        NGINX_CONF_D_PATH.to_string(),
        ssl_path,
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
            eprintln!("✗ Failed to create Nginx configuration file for HTTP: {}", e);
            revert_site_spawn(site_name, &steps_completed, &nginx_config);
        }
    }
        match sites::create_directory_if_not_exists(site_name, Some(0o777)) {
            Ok(()) => {
                println!("✓ Site directory created successfully");
                steps_completed.push(SpawnSteps::CreateSiteDirectory);
            }
            Err(e) => {
                eprintln!("✗ Failed to create site directory: {}", e);
                revert_site_spawn(site_name, &steps_completed, &nginx_config);
            }
        }
        if validate_nginx_configuration().is_err() {
            eprintln!("✗ Nginx configuration validation failed after creating HTTP config.");
            revert_site_spawn(site_name, &steps_completed, &nginx_config);
        }
        if let Some(ssl_root) = &nginx_config.ssl_root {
            println!("SSL will be enabled for this site.");
            match sites::create_directory_if_not_exists(
                ssl_root,
                Some(0o750),
            ) {
                Ok(()) => {
                    // Change ownership of SSL directory to current user:root
                    
                    let current_user = env::var("USER").unwrap_or_else(|_| "www-data".to_string());
                    
                    if sites::set_path_owner(&current_user, ssl_root).is_err() {
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
                // println!("✓ SSL certificates generated and installed successfully");
                steps_completed.push(SpawnSteps::CreateSSL);
                let https_config = nginx_config.generate_config(nginx::config::NginxProtocol::Https);
                if let Some(ssl_root) = &nginx_config.ssl_root {
                    match append_to_nginx_file(ssl_root, &https_config) {
                        Ok(()) => {
                            println!("✓ Nginx configuration file updated for HTTPS successfully");
                            steps_completed.push(SpawnSteps::CreateNginxConfigWithSSL);
                        }
                        Err(e) => {
                            eprintln!("✗ Failed to update Nginx configuration file for HTTPS: {}", e);
                            revert_site_spawn(site_name, &steps_completed, &nginx_config);
                        }
                    }
                }
            }
            Err(e) => {
                eprintln!("✗ SSL generation failed: {}", e);
                revert_site_spawn(site_name, &steps_completed, &nginx_config);
            }
        }
        if validate_nginx_configuration().is_err() {
            eprintln!("✗ Nginx configuration validation failed after creating HTTPS config.");
            revert_site_spawn(site_name, &steps_completed, &nginx_config);
        }
        if no_wp {
            println!("WordPress will not be installed on this site.");
        } else {
            println!("WordPress will be installed on this site.");
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
        }
}
/// Deletes the specified site.
///
/// # Arguments
///
/// * `site_name` - The name of the site to delete.
pub fn delete_site(site_name: &str) {
    println!("Preparing to delete site: {}", site_name);
    let db_name = db::create_db_name(site_name);
    match db::drop_database(&db_name) {
        Ok(()) => println!("✓ Database deleted successfully: {}", db_name),
        Err(e) => eprintln!("✗ Failed to delete database: {}", e),
    }
}

// /// Deactivates the specified site.
// ///
// /// # Arguments
// ///
// /// * `site_name` - The name of the site to deactivate.
// pub fn deactivate_site(site_name: &str) {
//     println!("Preparing to deactivate site: {}", site_name);
//     // Future implementation goes here
// }

// /// Activates a previously deactivated site.
// ///
// /// # Arguments
// ///
// /// * `site_name` - The name of the site to activate.
// pub fn activate_site(site_name: &str) {
//     println!("Preparing to activate site: {}", site_name);
//     // Future implementation goes here
// }

// /// Updates the specified site with new configurations.
// ///
// /// # Arguments
// ///
// /// * `site_name` - The name of the site to update.
// /// * `wp` - Optional flag to install WordPress on the existing site.
// /// * `ssl` - Optional flag to install SSL on the existing site.
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
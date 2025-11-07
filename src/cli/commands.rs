use std::process;

/// Command module for the e2e-site-spawner CLI tool.
///
/// This module contains the implementation of various commands
/// for managing sites on an Nginx server. Each command function
/// serves as a placeholder for future implementation and prints
/// a description of its intended effect.

use crate::utils::sites;
use crate::utils::db;
use crate::nginx;
use crate::utils::sites::create_nginx_file;
use crate::utils::validators::validate_site_name;
use crate::constants::{NGINX_CONF_D_PATH, SITES_PATH, SITES_SSL_PATH};

pub enum SpawnSteps {
    CreateNginxConfig,
    CreateSiteDirectory,
    CreateSSLDirectory,
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
    println!("Preparing to create site: {}", site_name);
    validate_site_name(site_name);
    let mut steps_completed: Vec<SpawnSteps> = Vec::new();
    let mut revert = false;
    let ssl_path = if ssl {
            Some(format!("{}/{}", SITES_SSL_PATH, site_name))
        } else {
            None
        };
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
    create_nginx_file(nginx_config.nginx_config_file_path.as_str(), &nginx_config.generate_config()).unwrap_or_else(|e| {
        eprintln!("✗ Failed to create Nginx config file: {}", e);
        revert = true;
    });
    if ssl {
        println!("SSL will be enabled for this site.");
        steps_completed.push(SpawnSteps::CreateSSLDirectory);
    }
    if no_wp {
        println!("WordPress will not be installed on this site.");
    } else {
        println!("WordPress will be installed on this site.");
        // Create database for WordPress site
        let db_name = db::create_db_name(site_name);
        
        match db::create_wordpress_database(&db_name, false) {
            Ok(db_name) => println!("✓ Database created successfully: {}", db_name),
            Err(e) => {
                eprintln!("✗ Failed to create database: {}", e);
                revert = true;
            }
        }
    }
    if revert {
        eprintln!("✗ Site creation failed, reverting changes...");
        sites::revert_site_spawn(site_name, steps_completed, &nginx_config);
        process::exit(1);
    }
}
/// Deletes the specified site.
///
/// # Arguments
///
/// * `site_name` - The name of the site to delete.
pub fn delete_site(site_name: &str) {
    println!("Preparing to delete site: {}", site_name);
    // TODO: Get the actual database name associated with the site
    let db_name = format!("wp_{}", site_name.replace('.', "_").replace('-', "_"));
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
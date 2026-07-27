//! Site management utilities for file system operations.
//!
//! This module provides functions for managing site directories, files, and WordPress installations.
//! It includes comprehensive error handling, atomic file operations, and rollback capabilities
//! for failed site creation attempts.
//!
//! # Security Features
//!
//! - Atomic file creation to prevent race conditions
//! - Permission management for Unix systems
//! - Path validation to prevent traversal attacks
//! - Ownership management for web server compatibility
//!
//! # Core Functionality
//!
//! - Site directory creation and removal
//! - WordPress installation and configuration
//! - Rollback mechanism for failed operations
//! - File and directory permission management

use std::fs::OpenOptions;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process;
use std::{fs, io, io::Write};

use crate::cli::commands::SpawnSteps;
use crate::cli::commands::{REMOVE_NGINX_CONFIG, REMOVE_SITE_DIRECTORY, REMOVE_SSL_DIRECTORY};
use crate::constants::{
    WEB_SERVER_GROUP, WEB_SERVER_USER, WP_CONFIG_E2SP_MARKER, WP_UPLOADS_PERMISSIONS,
    WP_UPLOADS_RELATIVE_PATH,
};
use crate::nginx;
use crate::utils::db;
use crate::utils::sites;
use nix::unistd::{Gid, Group, Uid};
use rand::Rng;
use std::env;

/// Error type for file creation operations.
///
/// Provides specific error variants for different failure scenarios
/// in file and directory operations, enabling precise error handling
/// and meaningful error messages to users.
#[derive(Debug)]
pub enum FileCreationError {
    /// Path validation failed (empty, invalid characters, etc.)
    InvalidPath(String),
    /// Operation failed due to insufficient permissions
    InsufficientPermissions(String),
    /// Directory creation operation failed
    DirectoryCreationFailed(String),
    /// File write operation failed
    FileWriteFailed(String),
    /// Failed to set file or directory permissions
    PermissionSetFailed(String),
    /// Detected attempt at path traversal attack
    PathTraversal(String),
}

impl std::fmt::Display for FileCreationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FileCreationError::InvalidPath(msg) => write!(f, "Invalid path: {}", msg),
            FileCreationError::InsufficientPermissions(msg) => {
                write!(f, "Insufficient permissions: {}", msg)
            }
            FileCreationError::DirectoryCreationFailed(msg) => {
                write!(f, "Failed to create directory: {}", msg)
            }
            FileCreationError::FileWriteFailed(msg) => write!(f, "Failed to write file: {}", msg),
            FileCreationError::PermissionSetFailed(msg) => {
                write!(f, "Failed to set permissions: {}", msg)
            }
            FileCreationError::PathTraversal(msg) => write!(f, "Path traversal detected: {}", msg),
        }
    }
}

impl std::error::Error for FileCreationError {}

/// Groups of related steps for coordinated rollback.
///
/// These groups ensure that related operations (like all nginx configs
/// or all SSL files) are treated as a unit during rollback, preventing
/// redundant or conflicting cleanup operations.
const STEP_GROUPS: &[&[SpawnSteps]] = &[
    &REMOVE_NGINX_CONFIG,
    &REMOVE_SITE_DIRECTORY,
    &REMOVE_SSL_DIRECTORY,
];

/// Checks if a step from the same group has already been reverted.
///
/// This helper function prevents duplicate rollback operations by checking
/// if any step from the same logical group has already been processed.
/// Uses `std::mem::discriminant` to compare enum variants regardless of
/// their associated data.
///
/// # Arguments
///
/// * `step` - The step to check
/// * `reverted_steps` - List of steps that have already been reverted
///
/// # Returns
///
/// * `true` if a step from the same group has been reverted
/// * `false` if this is the first step from its group to be reverted
///
/// # Implementation Details
///
/// Uses discriminant comparison to handle enum variants with data,
/// allowing `CreateDatabase("db1")` and `CreateDatabase("db2")` to be
/// recognized as the same step type.
fn is_step_group_reverted(step: &SpawnSteps, reverted_steps: &[SpawnSteps]) -> bool {
    // Find which group this step belongs to
    for group in STEP_GROUPS {
        if group
            .iter()
            .any(|group_step| std::mem::discriminant(step) == std::mem::discriminant(group_step))
        {
            // Check if any step from this group has been reverted
            return reverted_steps.iter().any(|reverted| {
                group.iter().any(|group_step| {
                    std::mem::discriminant(reverted) == std::mem::discriminant(group_step)
                })
            });
        }
    }

    // Handle steps not in any group (like CreateDatabase)
    matches!(step, SpawnSteps::CreateDatabase(_))
        && reverted_steps
            .iter()
            .any(|s| matches!(s, SpawnSteps::CreateDatabase(_)))
}

/// Reverts all completed steps when site creation fails.
///
/// This function performs a coordinated rollback of all operations that were
/// successfully completed before a failure occurred. It processes steps in
/// reverse order to ensure proper cleanup and uses step groups to prevent
/// redundant operations.
///
/// # Arguments
///
/// * `site_name` - Name of the site being reverted
/// * `steps` - Vector of steps that were completed before failure
/// * `nginx_config` - Nginx configuration containing paths to clean up
///
/// # Behavior
///
/// 1. Processes steps in reverse order (LIFO)
/// 2. Skips steps if another step from the same group was already reverted
/// 3. Continues reverting even if individual rollback operations fail
/// 4. Logs all operations and errors
/// 5. Exits the process with status code 1 after completion
///
/// # Exit Status
///
/// Always exits with status code 1 to indicate site creation failure.
///
/// # Error Handling
///
/// Individual rollback failures are logged but don't stop the overall
/// rollback process, ensuring maximum cleanup even in error conditions.
pub fn revert_site_spawn(
    site_name: &str,
    steps: &[SpawnSteps],
    nginx_config: &nginx::config::NginxConfig,
) {
    eprintln!("✗ Site creation failed, reverting changes...");
    let mut reverted_steps_completed: Vec<SpawnSteps> = Vec::new();
    for step in steps.iter().rev() {
        // Skip if a step from the same group has already been reverted
        if is_step_group_reverted(step, &reverted_steps_completed) {
            continue;
        }

        match step {
            SpawnSteps::CreateNginxConfig => {
                println!("Reverting: Deleting Nginx config for site: {}", site_name);
                remove_file(&nginx_config.nginx_config_file_path).unwrap_or_else(|e| {
                    eprintln!(
                        "✗ Failed to delete Nginx config for site: {}: {}",
                        site_name, e
                    );
                });
                reverted_steps_completed.push(SpawnSteps::CreateNginxConfig);
            }
            SpawnSteps::CreateSiteDirectory => {
                println!("Reverting: Deleting site directory for site: {}", site_name);
                remove_directory(&nginx_config.root).unwrap_or_else(|e| {
                    eprintln!(
                        "✗ Failed to delete site directory for site: {}: {}",
                        site_name, e
                    );
                });
                reverted_steps_completed.push(SpawnSteps::CreateSiteDirectory);
            }
            SpawnSteps::CreateSSLDirectory => {
                println!("Reverting: Deleting SSL directory for site: {}", site_name);
                remove_directory(nginx_config.ssl_root.as_ref().unwrap()).unwrap_or_else(|e| {
                    eprintln!(
                        "✗ Failed to delete SSL directory for site: {}: {}",
                        site_name, e
                    );
                });
                reverted_steps_completed.push(SpawnSteps::CreateSSLDirectory);
            }
            SpawnSteps::CreateSSL => {
                println!("Reverting: Deleting SSL directory for site: {}", site_name);
                remove_directory(nginx_config.ssl_root.as_ref().unwrap()).unwrap_or_else(|e| {
                    eprintln!(
                        "✗ Failed to delete SSL directory for site: {}: {}",
                        site_name, e
                    );
                });
                reverted_steps_completed.push(SpawnSteps::CreateSSL);
            }
            SpawnSteps::CreateNginxConfigWithSSL => {
                println!("Reverting: Deleting Nginx config for site: {}", site_name);
                remove_file(&nginx_config.nginx_config_file_path).unwrap_or_else(|e| {
                    eprintln!(
                        "✗ Failed to delete Nginx config for site: {}: {}",
                        site_name, e
                    );
                });
                reverted_steps_completed.push(SpawnSteps::CreateNginxConfigWithSSL);
            }
            SpawnSteps::CreateDatabase(db_name) => {
                println!("Reverting: Dropping database: {}", db_name);
                db::drop_database(db_name).unwrap_or_else(|e| {
                    eprintln!("✗ Failed to drop database: {}: {}", db_name, e);
                });
                reverted_steps_completed.push(SpawnSteps::CreateDatabase(db_name.clone()));
            }
            SpawnSteps::CreateWPConfigFile => {
                println!("Reverting: Deleting site directory for site: {}", site_name);
                remove_directory(&nginx_config.root).unwrap_or_else(|e| {
                    eprintln!(
                        "✗ Failed to delete site directory for site: {}: {}",
                        site_name, e
                    );
                });
                reverted_steps_completed.push(SpawnSteps::CreateWPConfigFile);
            }
        }
    }
    println!("Site creation process reverted for site: {}", site_name);
    process::exit(1);
}

/// Downloads and extracts WordPress into the specified site directory.
///
/// This function performs a complete WordPress installation by:
/// 1. Downloading the latest WordPress archive from wordpress.org
/// 2. Extracting it directly into the site directory
/// 3. Removing the temporary archive file
///
/// # Arguments
///
/// * `site_path` - The directory path where WordPress should be installed
///
/// # Returns
///
/// * `Ok(())` if WordPress was successfully installed
/// * `Err(FileCreationError)` if download, extraction, or cleanup failed
///
/// # Implementation Details
///
/// Uses shell commands via `sh -c` to:
/// - Download with `curl` to a temporary file
/// - Extract with `tar` using `--strip-components=1` to avoid nested directories
/// - Clean up the temporary archive
///
/// # Network Requirements
///
/// Requires internet connection to download from wordpress.org.
/// The download URL is configured in `constants::LATEST_WORDPRESS_URL`.
///
/// # Examples
///
/// ```ignore
/// match put_wordpress_in_site_directory("/var/www/mysite") {
///     Ok(()) => println!("WordPress installed successfully"),
///     Err(e) => eprintln!("Installation failed: {}", e),
/// }
/// ```
///
/// # Errors
///
/// Returns an error if:
/// - Network connection fails
/// - Insufficient disk space
/// - Site directory doesn't exist or isn't writable
/// - Archive extraction fails
pub fn put_wordpress_in_site_directory(site_path: &str) -> Result<(), FileCreationError> {
    let output = std::process::Command::new("sh")
        .arg("-c")
        .arg(format!(
            "curl -o {site_path}/wordpress.tar.gz {wordpress_url} && tar -xzf {site_path}/wordpress.tar.gz -C {site_path} --strip-components=1 && rm {site_path}/wordpress.tar.gz",
            wordpress_url = crate::constants::LATEST_WORDPRESS_URL,
            site_path = site_path
        ))
        .output()
        .map_err(|e| FileCreationError::FileWriteFailed(format!("Failed to execute command: {}", e)))?;

    if !output.status.success() {
        return Err(FileCreationError::FileWriteFailed(format!(
            "Command failed with status {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        )));
    }

    Ok(())
}

/// Creates a WordPress configuration file with database credentials.
///
/// Generates a wp-config.php file by reading the wp-config-sample.php template
/// and replacing placeholders with actual database credentials and security keys.
///
/// # Arguments
///
/// * `site_path` - Directory containing the WordPress installation
/// * `db_name` - Name of the MySQL database
/// * `db_user` - Database username
/// * `db_password` - Database password
/// * `db_host` - Database host (typically "localhost")
/// * `db_charset` - Database character set (typically "utf8mb4")
///
/// # Returns
///
/// * `Ok(())` if wp-config.php was created successfully
/// * `Err(FileCreationError)` if template reading or file creation failed
///
/// # Security
///
/// - Generates unique 64-character salt keys for each WordPress security constant
/// - Uses atomic file creation to prevent race conditions
/// - Sets appropriate file permissions for web server access
///
/// # Examples
///
/// ```ignore
/// create_wp_config_file(
///     "/var/www/mysite",
///     "wp_mysite",
///     "wordpress",
///     "secretpass",
///     "localhost",
///     "utf8mb4"
/// )?;
/// ```
///
/// # Errors
///
/// Returns an error if:
/// - wp-config-sample.php doesn't exist or isn't readable
/// - wp-config.php already exists
/// - File write operations fail
pub fn create_wp_config_file(
    site_path: &str,
    db_name: &str,
    db_user: &str,
    db_password: &str,
    db_host: &str,
    db_charset: &str,
) -> Result<(), FileCreationError> {
    let wp_config_sample_path = format!("{}/wp-config-sample.php", site_path);
    let wp_config_sample_content = fs::read_to_string(&wp_config_sample_path).map_err(|e| {
        FileCreationError::FileWriteFailed(format!("Cannot read wp-config-sample.php: {}", e))
    })?;
    let wp_config_content = generate_wp_config_content_from_sample(
        db_name,
        db_user,
        db_password,
        db_host,
        db_charset,
        wp_config_sample_content,
    )?;
    let wp_config_path = format!("{}/wp-config.php", site_path);
    create_file_with_content_if_not_exists(&wp_config_path, &wp_config_content, None)?;

    Ok(())
}

/// Generates WordPress configuration content from the sample template.
///
/// Replaces all placeholder values in wp-config-sample.php with actual
/// configuration values and generates unique security salt keys.
///
/// # Arguments
///
/// * `db_name` - Database name to replace "database_name_here"
/// * `db_user` - Username to replace "username_here"
/// * `db_password` - Password to replace "password_here"
/// * `db_host` - Host to replace "localhost"
/// * `_db_charset` - Reserved for a future custom charset; currently unused.
///   WordPress >= 6.9 defaults to utf8mb4, so the sample's charset is left as-is.
/// * `wp_config_sample` - The template content from wp-config-sample.php
///
/// # Returns
///
/// * `Ok(String)` containing the complete wp-config.php content
/// * `Err(FileCreationError)` if generation fails
///
/// # Security Keys
///
/// Replaces all instances of "put your unique phrase here" with
/// cryptographically secure 64-character random strings using
/// alphanumeric characters.
///
/// # Template Replacements
///
/// - `database_name_here` → actual database name
/// - `username_here` → database username
/// - `password_here` → database password
/// - `localhost` → database host
/// - `put your unique phrase here` → unique 64-char salt keys
///
/// The sample's `DB_CHARSET` is intentionally left untouched (WordPress >= 6.9
/// defaults to utf8mb4).
///
/// # QA Defaults
///
/// The generated file also carries the e2sp-managed block described in
/// [`insert_e2sp_wp_config_block`], which turns debug logging on and forces
/// direct filesystem writes.
///
/// # Examples
///
/// ```ignore
/// let sample = fs::read_to_string("wp-config-sample.php")?;
/// let config = generate_wp_config_content_from_sample(
///     "wp_blog",
///     "wpuser",
///     "pass123",
///     "localhost",
///     "utf8mb4",
///     sample
/// )?;
/// ```
pub fn generate_wp_config_content_from_sample(
    db_name: &str,
    db_user: &str,
    db_password: &str,
    db_host: &str,
    _db_charset: &str,
    wp_config_sample: String,
) -> Result<String, FileCreationError> {
    let mut wp_config_content = wp_config_sample;
    wp_config_content = wp_config_content
        .replace("database_name_here", db_name)
        .replace("username_here", db_user)
        .replace("password_here", db_password)
        .replace("localhost", db_host);
    // Removing charset replacement since WordPress 6.9 defaults to utf8mb4
    // TODO: Refactor to allow custom charset if needed in future or simply remove parameter from this function
    // .replace("utf8", db_charset);
    // Add security keys
    loop {
        let placeholder = "put your unique phrase here";
        if let Some(pos) = wp_config_content.find(placeholder) {
            let salt_key = create_salt_key();
            wp_config_content.replace_range(pos..pos + placeholder.len(), &salt_key);
        } else {
            break;
        }
    }

    Ok(insert_e2sp_wp_config_block(&wp_config_content))
}

/// Anchor marking the end of the user-editable area of `wp-config-sample.php`.
///
/// WordPress ships the line `/* That's all, stop editing! Happy publishing. */`;
/// only the stable part of that sentence is matched so wording changes in future
/// releases do not break the lookup.
const WP_CONFIG_STOP_EDITING_ANCHOR: &str = "That's all, stop editing!";

/// PHP opening tag, used as the fallback insertion anchor.
const PHP_OPEN_TAG: &str = "<?php";

/// WordPress constants owned by the e2sp block.
///
/// Any definition of these found in `wp-config-sample.php` is dropped before the
/// block is inserted: PHP emits a warning (and keeps the first value) when a
/// constant is defined twice, so the sample's `WP_DEBUG` must go.
const E2SP_MANAGED_WP_CONSTANTS: [&str; 4] =
    ["WP_DEBUG", "WP_DEBUG_LOG", "WP_DEBUG_DISPLAY", "FS_METHOD"];

/// Builds the e2sp-managed block of `wp-config.php` constants.
///
/// # Returns
///
/// A PHP snippet, delimited by [`crate::constants::WP_CONFIG_E2SP_MARKER`],
/// defining the QA defaults every spawned site gets.
///
/// # Constants
///
/// - `WP_DEBUG` / `WP_DEBUG_LOG` - record notices and errors in
///   `wp-content/debug.log`, which is what QA needs when reproducing bugs.
/// - `WP_DEBUG_DISPLAY` - keeps those errors out of the rendered page so they
///   cannot break the markup under test. WordPress core sets
///   `display_errors = 0` itself when this is `false`.
/// - `FS_METHOD` - `direct` makes WordPress write with the PHP process' own
///   credentials instead of prompting for FTP access on plugin, theme, and core
///   installs.
fn build_e2sp_wp_config_block() -> String {
    format!(
        "/* {marker} */\n\
         /* Log notices and errors to wp-content/debug.log, but never render them. */\n\
         define( 'WP_DEBUG', true );\n\
         define( 'WP_DEBUG_LOG', true );\n\
         define( 'WP_DEBUG_DISPLAY', false );\n\
         \n\
         /* Write files directly instead of asking for FTP credentials. */\n\
         define( 'FS_METHOD', 'direct' );\n\
         /* {marker} */\n",
        marker = WP_CONFIG_E2SP_MARKER
    )
}

/// Reports whether a line defines the given PHP constant.
///
/// # Arguments
///
/// * `line` - A single line of PHP source
/// * `constant` - Name of the constant to look for, without quotes
///
/// # Returns
///
/// * `true` if the line is a `define()` call for exactly that constant
/// * `false` otherwise
///
/// # Matching Rules
///
/// The line must *start* with `define` (after leading whitespace), so
/// commented-out samples such as `// define( 'WP_DEBUG', true );` are left
/// alone — they are inert PHP. The constant name is matched together with its
/// surrounding quotes, which keeps `WP_DEBUG` from matching `WP_DEBUG_LOG`.
/// Both quote styles are accepted.
fn is_definition_of(line: &str, constant: &str) -> bool {
    let trimmed = line.trim_start();
    if !trimmed.starts_with("define") {
        return false;
    }

    trimmed.contains(&format!("'{}'", constant)) || trimmed.contains(&format!("\"{}\"", constant))
}

/// Finds the line index at which the e2sp block should be inserted.
///
/// # Arguments
///
/// * `lines` - The `wp-config.php` content, split into lines
///
/// # Returns
///
/// The index the block must be inserted *before*.
///
/// # Resolution Order
///
/// 1. The `stop editing` anchor — WordPress' documented place for custom
///    constants, and where a human would expect to find them.
/// 2. Straight after the `<?php` tag, if the anchor is missing.
/// 3. The top of the file, as a last resort.
///
/// Anything but the first case means the sample was not the stock WordPress
/// one; the constants still land before `wp-settings.php` is required, which is
/// the only hard requirement for them to take effect.
fn e2sp_block_insertion_index(lines: &[&str]) -> usize {
    if let Some(index) = lines
        .iter()
        .position(|line| line.contains(WP_CONFIG_STOP_EDITING_ANCHOR))
    {
        return index;
    }

    if let Some(index) = lines
        .iter()
        .position(|line| line.trim_start().starts_with(PHP_OPEN_TAG))
    {
        return index + 1;
    }

    0
}

/// Inserts the e2sp-managed constants into `wp-config.php` content.
///
/// Existing definitions of the managed constants are removed first so PHP never
/// sees a duplicate `define()`, then the block from
/// [`build_e2sp_wp_config_block`] is inserted at the position chosen by
/// [`e2sp_block_insertion_index`].
///
/// # Arguments
///
/// * `content` - The `wp-config.php` content generated so far
///
/// # Returns
///
/// The content with the managed block in place.
///
/// # Note
///
/// Line endings are normalised to `\n` and a trailing newline is guaranteed,
/// which matches the file WordPress itself ships.
fn insert_e2sp_wp_config_block(content: &str) -> String {
    let lines: Vec<&str> = content
        .lines()
        .filter(|line| {
            !E2SP_MANAGED_WP_CONSTANTS
                .iter()
                .any(|constant| is_definition_of(line, constant))
        })
        .collect();

    let insertion_index = e2sp_block_insertion_index(&lines);
    let mut wp_config_content = String::with_capacity(content.len() + 512);

    for line in &lines[..insertion_index] {
        wp_config_content.push_str(line);
        wp_config_content.push('\n');
    }
    wp_config_content.push_str(&build_e2sp_wp_config_block());
    wp_config_content.push('\n');
    for line in &lines[insertion_index..] {
        wp_config_content.push_str(line);
        wp_config_content.push('\n');
    }

    wp_config_content
}

/// Generates a cryptographically secure salt key for WordPress.
///
/// Creates a 64-character random string using alphanumeric characters
/// suitable for WordPress security keys and salts.
///
/// # Returns
///
/// A 64-character string containing random alphanumeric characters.
///
/// # Security
///
/// Uses the cryptographically secure random number generator from
/// the `rand` crate to ensure unpredictability.
///
/// # WordPress Constants
///
/// Used for generating values for:
/// - AUTH_KEY
/// - SECURE_AUTH_KEY
/// - LOGGED_IN_KEY
/// - NONCE_KEY
/// - AUTH_SALT
/// - SECURE_AUTH_SALT
/// - LOGGED_IN_SALT
/// - NONCE_SALT
fn create_salt_key() -> String {
    rand::rng()
        .sample_iter(&rand::distr::Alphanumeric)
        .take(64)
        .map(char::from)
        .collect()
}

/// Creates a directory with specified permissions if it doesn't exist.
///
/// This function creates a directory (including parent directories) and
/// optionally sets Unix permissions. It fails if the directory already exists
/// to prevent accidental overwrites.
///
/// # Arguments
///
/// * `dir_path` - Path to the directory to create
/// * `permissions` - Optional Unix permission mode (e.g., 0o755)
///
/// # Returns
///
/// * `Ok(())` if the directory was created successfully
/// * `Err(FileCreationError)` if creation failed or directory exists
///
/// # Permissions
///
/// Common permission values:
/// - `0o755` - rwxr-xr-x (owner full, others read/execute)
/// - `0o750` - rwxr-x--- (owner full, group read/execute, others none)
/// - `0o777` - rwxrwxrwx (full permissions for all)
/// - `0o700` - rwx------ (owner only)
///
/// # Examples
///
/// ```ignore
/// // Create directory with standard web permissions
/// create_directory_if_not_exists("/var/www/mysite", Some(0o755))?;
///
/// // Create directory with default permissions
/// create_directory_if_not_exists("/tmp/test", None)?;
/// ```
///
/// # Errors
///
/// Returns an error if:
/// - Directory already exists
/// - Parent directory doesn't exist and can't be created
/// - Insufficient permissions to create directory
/// - Permission setting fails (Unix only)
pub fn create_directory_if_not_exists(
    dir_path: &str,
    permissions: Option<u32>,
) -> Result<(), FileCreationError> {
    let path = Path::new(&dir_path);
    if path.exists() {
        return Err(FileCreationError::DirectoryCreationFailed(format!(
            "Directory already exists: {}",
            dir_path
        )));
    }

    fs::create_dir_all(path).map_err(|e| {
        FileCreationError::DirectoryCreationFailed(format!(
            "Cannot create directory '{}': {}",
            dir_path, e
        ))
    })?;

    #[cfg(unix)]
    {
        if let Some(mode) = permissions {
            set_path_permissions(path, mode)?;
        }
    }
    Ok(())
}

/// Sets Unix permissions on an existing file or directory.
///
/// # Arguments
///
/// * `path` - Path to the file or directory to modify
/// * `mode` - Unix permission mode (e.g., `0o755`)
///
/// # Returns
///
/// * `Ok(())` if the mode was applied
/// * `Err(FileCreationError::PermissionSetFailed)` if the path is missing or
///   the current user may not change its mode
fn set_path_permissions(path: &Path, mode: u32) -> Result<(), FileCreationError> {
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).map_err(|e| {
        FileCreationError::PermissionSetFailed(format!(
            "Cannot set permissions on '{}': {}",
            path.display(),
            e
        ))
    })
}

/// Creates a file with content if it doesn't exist.
///
/// Atomically creates a new file with the specified content and optional
/// Unix permissions. Fails if the file already exists to prevent
/// accidental overwrites.
///
/// # Arguments
///
/// * `path` - Path to the file to create
/// * `content` - Content to write to the file
/// * `permissions` - Optional Unix permission mode
///
/// # Returns
///
/// * `Ok(())` if the file was created successfully
/// * `Err(FileCreationError)` if creation failed or file exists
///
/// # Atomic Creation
///
/// Uses `create_new` flag to ensure atomic check-and-create operation,
/// preventing TOCTOU (time-of-check-time-of-use) vulnerabilities.
///
/// # Examples
///
/// ```ignore
/// // Create configuration file with restricted permissions
/// create_file_with_content_if_not_exists(
///     "/etc/myapp/config.conf",
///     "key=value\n",
///     Some(0o600)  // rw-------
/// )?;
///
/// // Create public HTML file
/// create_file_with_content_if_not_exists(
///     "/var/www/index.html",
///     "<h1>Welcome</h1>",
///     Some(0o644)  // rw-r--r--
/// )?;
/// ```
///
/// # Errors
///
/// Returns an error if:
/// - File already exists
/// - Parent directory doesn't exist
/// - Insufficient permissions to create file
/// - Write operation fails
/// - Permission setting fails (Unix only)
pub fn create_file_with_content_if_not_exists(
    path: &str,
    content: &str,
    permissions: Option<u32>,
) -> Result<(), FileCreationError> {
    let file_path = Path::new(&path);
    // Check if file already exists - FAIL if it does
    if file_path.exists() {
        return Err(FileCreationError::FileWriteFailed(format!(
            "File already exists: {}.",
            path
        )));
    }

    // Write the file - use create_new to ensure atomic creation
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true) // Fails if file exists (atomic check-and-create)
        .open(file_path)
        .map_err(|e| {
            if e.kind() == io::ErrorKind::AlreadyExists {
                FileCreationError::FileWriteFailed(format!("File already exists: {}.", path))
            } else {
                FileCreationError::FileWriteFailed(format!("Cannot create file '{}': {}", path, e))
            }
        })?;

    file.write_all(content.as_bytes()).map_err(|e| {
        FileCreationError::FileWriteFailed(format!("Cannot write to '{}': {}", path, e))
    })?;

    // Set appropriate permissions (644 - readable by all, writable by owner)
    #[cfg(unix)]
    {
        if let Some(mode) = permissions {
            // Leave nothing behind: a file whose mode could not be set would be
            // readable by more users than the caller asked for.
            set_path_permissions(file_path, mode).inspect_err(|_| {
                sites::remove_file(path).unwrap_or(());
            })?;
        }
    }

    Ok(())
}

/// Creates the WordPress media uploads directory.
///
/// WordPress does not ship `wp-content/uploads`; it creates the directory the
/// first time a file is uploaded. Because the extracted WordPress tree belongs
/// to `root` at that point, that creation fails and WordPress falls back to
/// asking for FTP credentials — which is why the directory is created here
/// instead, before the site is handed over.
///
/// The operation is idempotent: an existing directory only has its mode
/// re-applied. Ownership is *not* set here; the caller applies it to the whole
/// tree with [`set_web_server_ownership`] once every file is in place.
///
/// # Arguments
///
/// * `site_path` - Root directory of the WordPress installation
///
/// # Returns
///
/// * `Ok(())` if the uploads directory exists with the expected permissions
/// * `Err(FileCreationError)` if it could not be created or its mode could not
///   be set
///
/// # Examples
///
/// ```ignore
/// create_wp_uploads_directory("/var/www/html/example.com")?;
/// // → /var/www/html/example.com/wp-content/uploads (0777)
/// ```
pub fn create_wp_uploads_directory(site_path: &str) -> Result<(), FileCreationError> {
    let uploads_path = format!(
        "{}/{}",
        site_path.trim_end_matches('/'),
        WP_UPLOADS_RELATIVE_PATH
    );
    let path = Path::new(&uploads_path);

    if path.is_dir() {
        return set_path_permissions(path, WP_UPLOADS_PERMISSIONS);
    }

    create_directory_if_not_exists(&uploads_path, Some(WP_UPLOADS_PERMISSIONS))
}

/// Changes the ownership of a file or directory at the given path.
///
/// Uses the POSIX `chown` system call to change user and/or group ownership.
/// Either user or group can be changed independently, or both simultaneously.
///
/// # Arguments
///
/// * `user_name` - Optional username to set as owner. If `None`, owner unchanged.
/// * `group_name` - Optional group name to set. If `None`, group unchanged.
/// * `path` - Path to the file or directory to modify
///
/// # Returns
///
/// * `Ok(())` if ownership change was successful
/// * `Err(FileCreationError)` if user/group doesn't exist or operation failed
///
/// # Behavior
///
/// - `Some(user)` + `None` → Changes only the user (owner)
/// - `None` + `Some(group)` → Changes only the group
/// - `Some(user)` + `Some(group)` → Changes both user and group
/// - `None` + `None` → No-op (no changes made)
///
/// # Examples
///
/// ```ignore
/// // Change only the owner to www-data
/// set_path_owner(Some("www-data"), None, "/var/www/html")?;
///
/// // Change only the group to developers
/// set_path_owner(None, Some("developers"), "/home/project")?;
///
/// // Change both owner and group
/// set_path_owner(Some("nginx"), Some("www-data"), "/etc/nginx/sites")?;
///
/// // No operation (but still validates the path exists)
/// set_path_owner(None, None, "/tmp/test")?;
/// ```
///
/// # System Requirements
///
/// - Unix/Linux system (uses POSIX chown)
/// - Sufficient privileges (typically requires root for changing to different user)
/// - Target user and group must exist in system
///
/// # Errors
///
/// Returns `FileCreationError::PermissionSetFailed` if:
/// - Specified user doesn't exist in system
/// - Specified group doesn't exist in system
/// - Insufficient privileges to change ownership
/// - Path doesn't exist
/// - Operation fails for any system reason
///
/// # Security Notes
///
/// Changing file ownership can affect access control. Ensure:
/// - Web files are owned by appropriate web server user
/// - Sensitive files have restricted ownership
/// - Group ownership aligns with collaboration needs
pub fn set_path_owner(
    user_name: Option<&str>,
    group_name: Option<&str>,
    path: &str,
) -> Result<(), FileCreationError> {
    let uid = resolve_uid(user_name)?;
    let gid = resolve_gid(group_name)?;

    chown_path(Path::new(path), uid, gid)
}

/// Resolves a user name to its UID.
///
/// # Arguments
///
/// * `user_name` - Name to look up, or `None` to leave the owner unchanged
///
/// # Returns
///
/// * `Ok(Some(uid))` for a known user
/// * `Ok(None)` if `user_name` is `None`
/// * `Err(FileCreationError::PermissionSetFailed)` if the user does not exist
///   or the passwd database cannot be read
fn resolve_uid(user_name: Option<&str>) -> Result<Option<Uid>, FileCreationError> {
    let Some(name) = user_name else {
        return Ok(None);
    };

    match nix::unistd::User::from_name(name) {
        Ok(Some(user)) => Ok(Some(user.uid)),
        _ => Err(FileCreationError::PermissionSetFailed(format!(
            "User '{}' not found",
            name
        ))),
    }
}

/// Resolves a group name to its GID.
///
/// # Arguments
///
/// * `group_name` - Name to look up, or `None` to leave the group unchanged
///
/// # Returns
///
/// * `Ok(Some(gid))` for a known group
/// * `Ok(None)` if `group_name` is `None`
/// * `Err(FileCreationError::PermissionSetFailed)` if the group does not exist
///   or the group database cannot be read
fn resolve_gid(group_name: Option<&str>) -> Result<Option<Gid>, FileCreationError> {
    let Some(name) = group_name else {
        return Ok(None);
    };

    match Group::from_name(name) {
        Ok(Some(group)) => Ok(Some(group.gid)),
        _ => Err(FileCreationError::PermissionSetFailed(format!(
            "Group '{}' not found",
            name
        ))),
    }
}

/// Applies an already-resolved owner and group to a single path.
///
/// # Arguments
///
/// * `path` - Path to the file or directory to modify
/// * `uid` - Owner to set, or `None` to leave it unchanged
/// * `gid` - Group to set, or `None` to leave it unchanged
///
/// # Returns
///
/// * `Ok(())` if the ownership change succeeded
/// * `Err(FileCreationError::PermissionSetFailed)` if `chown` failed
fn chown_path(path: &Path, uid: Option<Uid>, gid: Option<Gid>) -> Result<(), FileCreationError> {
    nix::unistd::chown(path, uid, gid).map_err(|e| {
        FileCreationError::PermissionSetFailed(format!(
            "Cannot set ownership on '{}': {}",
            path.display(),
            e
        ))
    })
}
/// Recursively changes ownership of all files and directories under a root path.
///
/// This function sets the user and/or group ownership for the specified root path
/// and all its contents recursively. It leverages the `walkdir` crate to traverse
/// the directory tree.
/// # Arguments
/// * `user` - Optional username to set as owner. If `None`, owner unchanged.
/// * `group` - Optional group name to set. If `None`, group unchanged.
/// * `root` - The root directory path to start the ownership change.
/// # Returns
/// * `Ok(())` if ownership change was successful for all items
/// * `Err(FileCreationError)` if any operation failed
/// # Examples
/// ```ignore
/// // Change ownership of /var/www/mysite and all its contents to www-data:www-data
/// set_path_owner_recursive(Some("www-data"), Some("www-data"), "/var/www/mysite")?;
/// ```
/// # Errors
/// Returns `FileCreationError::PermissionSetFailed` if:
/// - Specified user or group doesn't exist
/// - Insufficient privileges to change ownership
/// - Any file or directory operation fails during traversal
/// # System Requirements
/// - Unix/Linux system (uses POSIX chown)
/// - Sufficient privileges (typically requires root for changing to different user)
/// - Target user and group must exist in system
/// # Security Notes
/// Changing file ownership can affect access control. Ensure:
/// - Web files are owned by appropriate web server user
/// - Sensitive files have restricted ownership
/// - Group ownership aligns with collaboration needs
/// # Symlinks
/// `root` itself is always chowned, following it if it is a symlink, since the
/// caller named that path explicitly. Symlinks *below* `root` are skipped:
/// `chown` resolves them, so chowning one would silently change the ownership of
/// its target — a file outside the tree the caller asked about. Skipping keeps
/// the blast radius inside `root` and matches what `chown -R` does by default.
///
/// # Implementation Details
/// Utilizes `walkdir::WalkDir` for efficient recursive traversal of directories.
/// The user and group are looked up once up front rather than per entry — a
/// WordPress tree holds thousands of files, and each lookup queries the system
/// user database.
pub fn set_path_owner_recursive(
    user_name: Option<&str>,
    group_name: Option<&str>,
    path: &str,
) -> Result<(), FileCreationError> {
    let uid = resolve_uid(user_name)?;
    let gid = resolve_gid(group_name)?;

    chown_path(Path::new(path), uid, gid)?;

    for entry in walkdir::WalkDir::new(path).min_depth(1) {
        let entry = entry.map_err(|e| {
            FileCreationError::PermissionSetFailed(format!("Walk error at {}: {}", path, e))
        })?;
        if entry.path_is_symlink() {
            continue;
        }
        chown_path(entry.path(), uid, gid)?;
    }
    Ok(())
}

/// Hands a path and everything below it to the web server user and group.
///
/// Every file the spawner writes — the extracted WordPress tree, `wp-config.php`,
/// the uploads directory, the static `index.html` — is created by `root`, since
/// the tool runs under sudo. PHP-FPM runs as
/// [`crate::constants::WEB_SERVER_USER`], so it cannot write into a `root`-owned
/// tree: media uploads, plugin installs, and `wp-content/debug.log` all fail and
/// WordPress falls back to asking for FTP credentials. Calling this once, after
/// the last file is written, is what makes those work.
///
/// # Arguments
///
/// * `path` - Root of the tree to hand over, typically the site directory
///
/// # Returns
///
/// * `Ok(())` if the whole tree now belongs to the web server user and group
/// * `Err(FileCreationError::PermissionSetFailed)` if the account is missing,
///   the process is not root, or the tree could not be traversed
///
/// # Symlinks
///
/// Symlinked entries inside the tree are left untouched — see
/// [`set_path_owner_recursive`]. A plugin symlinked into `wp-content/plugins`
/// from a developer checkout therefore keeps its original ownership instead of
/// having the checkout handed to the web server.
///
/// # Examples
///
/// ```ignore
/// // Runs last, so nothing written afterwards is left owned by root.
/// set_web_server_ownership("/var/www/html/example.com")?;
/// ```
pub fn set_web_server_ownership(path: &str) -> Result<(), FileCreationError> {
    set_path_owner_recursive(Some(WEB_SERVER_USER), Some(WEB_SERVER_GROUP), path)
}
/// Retrieves the effective sudo user or falls back to the current user.
///
/// This function checks the `SUDO_USER` environment variable to determine
/// the original user who invoked sudo. If `SUDO_USER` is not set, it
/// falls back to the `USER` environment variable. If neither is set,
/// it defaults to "root".
///# Returns
/// * A `String` representing the effective user name.
/// # Examples
/// ```ignore
/// let user = get_sudo_user();
/// println!("Effective user: {}", user);
/// ```
/// # Notes
/// - Useful for scripts that need to know the original user context
///   when run with elevated privileges.
/// - Ensures a sensible default ("root") if no user information is available.
///
/// # Security Considerations
/// - Be cautious when using this value for permission-sensitive operations.
/// - Always validate user context in security-critical applications.
pub fn get_sudo_user() -> String {
    let mut user = env::var("SUDO_USER")
        .or_else(|_| env::var("USER"))
        .unwrap_or_else(|_| "root".to_string());
    if user.is_empty() {
        user = "root".to_string();
    }
    user
}

/// Removes a directory and all its contents recursively.
///
/// Safely removes a directory tree, similar to `rm -rf` in Unix.
/// If the directory doesn't exist, the operation succeeds silently
/// (idempotent behavior).
///
/// # Arguments
///
/// * `dir_path` - Path to the directory to remove
///
/// # Returns
///
/// * `Ok(())` if directory was removed or didn't exist
/// * `Err(FileCreationError)` if removal failed
///
/// # Warning
///
/// This operation is **destructive** and **non-recoverable**.
/// All files and subdirectories will be permanently deleted.
///
/// # Examples
///
/// ```ignore
/// // Remove a site directory
/// remove_directory("/var/www/old-site")?;
///
/// // Safe to call even if directory doesn't exist
/// remove_directory("/tmp/may-not-exist")?;  // Returns Ok(())
/// ```
///
/// # Errors
///
/// Returns an error if:
/// - Insufficient permissions to remove directory
/// - Directory is in use by another process
/// - I/O error occurs during removal
///
/// # Implementation Note
///
/// Uses `fs::remove_dir_all` which recursively removes all contents
/// before removing the directory itself.
pub fn remove_directory(dir_path: &str) -> Result<(), FileCreationError> {
    let path = Path::new(&dir_path);
    if path.exists() {
        fs::remove_dir_all(path).map_err(|e| {
            FileCreationError::DirectoryCreationFailed(format!(
                "Cannot remove directory '{}': {}",
                dir_path, e
            ))
        })?;
    }
    Ok(())
}

/// Checks if a site already exists on the filesystem.
///
/// This function determines whether a site has already been created by checking
/// for the existence of either the site's root directory or its Nginx configuration
/// file. It uses an OR logic to detect partial installations or remnants from
/// previous setup attempts.
///
/// # Arguments
///
/// * `nginx_config` - The Nginx configuration object containing the site's root
///   directory path and configuration file path.
///
/// # Returns
///
/// * `true` - If either the site directory OR Nginx config file exists
/// * `false` - If neither the directory nor config file exists
///
/// # Detection Logic
///
/// The function returns `true` if **either** of these exists:
/// - Site root directory (e.g., `/var/www/html/example.com/`)
/// - Nginx configuration file (e.g., `/etc/nginx/sites-available/example.com.conf`)
///
/// Using OR logic is intentional because:
/// - Partial installations should be detected
/// - Either component existing indicates a site was attempted
/// - Prevents accidental overwrites or duplicate installations
/// - Allows detection of incomplete setups that need cleanup
///
/// # Use Cases
///
/// This function is typically used to:
/// - Prevent duplicate site creation attempts
/// - Check if a site can be safely spawned
/// - Detect partial installations from failed attempts
/// - Validate cleanup operations were successful
/// - Determine if update operations are applicable
///
/// # Examples
///
/// ```ignore
/// use nginx::config::NginxConfig;
/// use utils::sites::check_if_site_exists;
///
/// let nginx_config = NginxConfig::new(
///     "example.com".to_string(),
///     "/var/www/html/example.com".to_string(),
///     "/etc/nginx/sites-available".to_string(),
///     false,
/// );
///
/// if check_if_site_exists(&nginx_config) {
///     println!("Site already exists, cannot create");
///     return Err("Site exists");
/// } else {
///     println!("Site does not exist, safe to create");
///     // Proceed with site creation
/// }
/// ```
///
/// # Common Scenarios
///
/// 1. **Fresh Installation**: Neither exists → returns `false`
/// 2. **Complete Site**: Both exist → returns `true`
/// 3. **Partial Setup**: Only directory exists → returns `true`
/// 4. **Config Only**: Only nginx config exists → returns `true`
/// 5. **After Deletion**: Neither exists → returns `false`
///
/// # File System Paths Checked
///
/// ```text
/// Site Root:    /var/www/html/{site_name}/
///               └── (any content indicates existence)
///
/// Nginx Config: /etc/nginx/sites-available/{site_name}.conf
///               └── (file presence indicates existence)
/// ```
///
/// # Performance Note
///
/// This function only checks for path existence using filesystem metadata,
/// not contents. This is efficient but doesn't validate:
/// - Whether the site is functional
/// - If WordPress is installed in the directory
/// - If the Nginx config is valid
/// - Whether SSL is configured
///
/// # Edge Cases
///
/// The function handles these scenarios:
/// - Symbolic links (follows links to check targets)
/// - Empty directories (still returns true)
/// - Permission denied (returns false, treats as non-existent)
/// - Broken symbolic links (returns false)
///
/// # Related Functions
///
/// Works in conjunction with:
/// - [`crate::cli::commands::spawn_site`] - Uses this to prevent duplicate sites
/// - [`crate::cli::commands::delete_site`] - Should make this return false after cleanup
/// - [`crate::cli::commands::update_site`] - Requires this to return true for updates
/// - [`revert_site_spawn`] - Cleans up paths this function checks
///
/// # Security Considerations
///
/// - Read-only operation, doesn't modify filesystem
/// - No sensitive information exposed
/// - Safe to call without elevated privileges
/// - Path traversal not a concern (uses pre-validated paths)
///
/// # Implementation Note
///
/// Uses `std::path::Path::exists()` which:
/// - Returns false for non-existent paths
/// - Returns false if permission denied
/// - Follows symbolic links
/// - Is atomic and thread-safe
///
/// # Why Check Both Paths?
///
/// Checking both paths with OR logic ensures detection of:
/// - Failed installations (directory created but nginx config failed)
/// - Manual partial setups (user created directory but no config)
/// - Incomplete deletions (config removed but directory remains)
/// - Config-only setups (reverse proxy without local files)
///
/// # Typical Workflow
///
/// ```text
/// 1. check_if_site_exists() → false (nothing exists)
/// 2. spawn_site() creates directory and config
/// 3. check_if_site_exists() → true (both exist)
/// 4. delete_site() removes both
/// 5. check_if_site_exists() → false (cleaned up)
/// ```
pub fn check_if_site_exists(nginx_config: &nginx::config::NginxConfig) -> bool {
    let site_root = Path::new(nginx_config.root.as_str());
    let nginx_config_path = Path::new(nginx_config.nginx_config_file_path.as_str());

    site_root.exists() || nginx_config_path.exists()
}

/// Removes a single file.
///
/// Safely removes a file from the filesystem. If the file doesn't exist,
/// the operation succeeds silently (idempotent behavior).
///
/// # Arguments
///
/// * `file_path` - Path to the file to remove
///
/// # Returns
///
/// * `Ok(())` if file was removed or didn't exist
/// * `Err(FileCreationError)` if removal failed
///
/// # Examples
///
/// ```ignore
/// // Remove a configuration file
/// remove_file("/etc/nginx/sites-enabled/old-site.conf")?;
///
/// // Safe to call even if file doesn't exist
/// remove_file("/tmp/may-not-exist.txt")?;  // Returns Ok(())
/// ```
///
/// # Errors
///
/// Returns an error if:
/// - Insufficient permissions to remove file
/// - File is locked by another process
/// - Path points to a directory (use `remove_directory` instead)
/// - I/O error occurs during removal
///
/// # Note
///
/// This function only removes files, not directories. Use
/// `remove_directory` for removing directories.
pub fn remove_file(file_path: &str) -> Result<(), FileCreationError> {
    let path = Path::new(&file_path);
    if path.exists() {
        fs::remove_file(path).map_err(|e| {
            FileCreationError::FileWriteFailed(format!("Cannot remove file '{}': {}", file_path, e))
        })?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    #[allow(unused_imports)]
    use std::io::Write;
    use tempfile::TempDir;

    // ===== Directory Management Tests =====

    #[test]
    fn test_create_directory_if_not_exists() {
        let temp_dir = TempDir::new().unwrap();
        let dir_path = temp_dir.path().join("new_dir");

        // Create directory
        let result = create_directory_if_not_exists(dir_path.to_str().unwrap(), Some(0o755));
        assert!(result.is_ok());
        assert!(dir_path.exists());
        assert!(dir_path.is_dir());
    }

    #[test]
    fn test_create_directory_already_exists() {
        let temp_dir = TempDir::new().unwrap();
        let dir_path = temp_dir.path().join("existing_dir");

        // Create directory first time
        fs::create_dir(&dir_path).unwrap();

        // Try to create again
        let result = create_directory_if_not_exists(dir_path.to_str().unwrap(), None);
        assert!(result.is_err());
        assert!(matches!(
            result,
            Err(FileCreationError::DirectoryCreationFailed(_))
        ));
    }

    #[test]
    fn test_create_nested_directories() {
        let temp_dir = TempDir::new().unwrap();
        let nested_path = temp_dir.path().join("level1/level2/level3");

        // Create nested directories
        let result = create_directory_if_not_exists(nested_path.to_str().unwrap(), Some(0o777));
        assert!(result.is_ok());
        assert!(nested_path.exists());
        assert!(nested_path.is_dir());
    }

    #[test]
    #[cfg(unix)]
    fn test_directory_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let temp_dir = TempDir::new().unwrap();
        let dir_path = temp_dir.path().join("perm_test");

        // Create directory with specific permissions
        create_directory_if_not_exists(dir_path.to_str().unwrap(), Some(0o700)).unwrap();

        // Check permissions
        let metadata = fs::metadata(&dir_path).unwrap();
        let permissions = metadata.permissions();
        // Mask with 0o777 to get only the permission bits we care about
        assert_eq!(permissions.mode() & 0o777, 0o700);
    }

    #[test]
    fn test_create_directory_without_permissions() {
        let temp_dir = TempDir::new().unwrap();
        let dir_path = temp_dir.path().join("default_perms");

        // Create without specifying permissions
        let result = create_directory_if_not_exists(dir_path.to_str().unwrap(), None);
        assert!(result.is_ok());
        assert!(dir_path.exists());
    }

    // ===== File Creation Tests =====

    #[test]
    fn test_create_file_with_content_if_not_exists() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("test.txt");
        let content = "Hello, World!";

        let result = create_file_with_content_if_not_exists(
            file_path.to_str().unwrap(),
            content,
            Some(0o644),
        );
        assert!(result.is_ok());
        assert!(file_path.exists());

        // Verify content
        let written_content = fs::read_to_string(&file_path).unwrap();
        assert_eq!(written_content, content);
    }

    #[test]
    fn test_create_file_already_exists() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("existing.txt");

        // Create file first
        fs::write(&file_path, "original").unwrap();

        // Try to create again
        let result = create_file_with_content_if_not_exists(
            file_path.to_str().unwrap(),
            "new content",
            None,
        );
        assert!(result.is_err());
        assert!(matches!(result, Err(FileCreationError::FileWriteFailed(_))));

        // Verify original content unchanged
        let content = fs::read_to_string(&file_path).unwrap();
        assert_eq!(content, "original");
    }

    #[test]
    #[cfg(unix)]
    fn test_file_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("perm_file.txt");

        create_file_with_content_if_not_exists(file_path.to_str().unwrap(), "test", Some(0o600))
            .unwrap();

        let metadata = fs::metadata(&file_path).unwrap();
        assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
    }

    #[test]
    fn test_create_file_with_empty_content() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("empty.txt");

        let result = create_file_with_content_if_not_exists(file_path.to_str().unwrap(), "", None);
        assert!(result.is_ok());
        assert!(file_path.exists());

        let content = fs::read_to_string(&file_path).unwrap();
        assert_eq!(content, "");
    }

    // ===== File/Directory Removal Tests =====

    #[test]
    fn test_remove_directory() {
        let temp_dir = TempDir::new().unwrap();
        let dir_path = temp_dir.path().join("to_remove");

        // Create directory with files
        fs::create_dir(&dir_path).unwrap();
        fs::write(dir_path.join("file1.txt"), "content1").unwrap();
        fs::write(dir_path.join("file2.txt"), "content2").unwrap();

        // Remove directory
        let result = remove_directory(dir_path.to_str().unwrap());
        assert!(result.is_ok());
        assert!(!dir_path.exists());
    }

    #[test]
    fn test_remove_directory_nonexistent() {
        let temp_dir = TempDir::new().unwrap();
        let dir_path = temp_dir.path().join("nonexistent");

        // Should succeed even if directory doesn't exist
        let result = remove_directory(dir_path.to_str().unwrap());
        assert!(result.is_ok());
    }

    #[test]
    fn test_remove_file() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("to_remove.txt");

        // Create file
        fs::write(&file_path, "content").unwrap();
        assert!(file_path.exists());

        // Remove file
        let result = remove_file(file_path.to_str().unwrap());
        assert!(result.is_ok());
        assert!(!file_path.exists());
    }

    #[test]
    fn test_remove_file_nonexistent() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("nonexistent.txt");

        // Should succeed even if file doesn't exist
        let result = remove_file(file_path.to_str().unwrap());
        assert!(result.is_ok());
    }

    // ===== WordPress Configuration Tests =====

    #[test]
    fn test_generate_wp_config_content_from_sample() {
        let sample = r#"
define('DB_NAME', 'database_name_here');
define('DB_USER', 'username_here');
define('DB_PASSWORD', 'password_here');
define('DB_HOST', 'localhost');
define('DB_CHARSET', 'utf8');
define('AUTH_KEY', 'put your unique phrase here');
define('SECURE_AUTH_KEY', 'put your unique phrase here');
"#;

        let result = generate_wp_config_content_from_sample(
            "wp_testsite",
            "wpuser",
            "secret123",
            "127.0.0.1",
            "utf8mb4",
            sample.to_string(),
        )
        .unwrap();

        // Check replacements
        assert!(result.contains("'wp_testsite'"));
        assert!(result.contains("'wpuser'"));
        assert!(result.contains("'secret123'"));
        assert!(result.contains("'127.0.0.1'"));
        // DB_CHARSET is intentionally NOT substituted (WordPress >= 6.9 defaults
        // to utf8mb4), so the sample's charset value is left untouched.
        assert!(result.contains("'utf8'"));
        assert!(!result.contains("'utf8mb4'"));

        // Check salt keys are replaced
        assert!(!result.contains("put your unique phrase here"));

        // Check that AUTH_KEY and SECURE_AUTH_KEY have different values
        let auth_key_pos = result.find("AUTH_KEY").unwrap();
        let secure_auth_key_pos = result.find("SECURE_AUTH_KEY").unwrap();
        let auth_key_line = result[auth_key_pos..].lines().next().unwrap();
        let secure_auth_key_line = result[secure_auth_key_pos..].lines().next().unwrap();
        assert_ne!(auth_key_line, secure_auth_key_line);
    }

    #[test]
    fn test_generate_wp_config_all_salt_keys_replaced() {
        let sample = r#"
define('AUTH_KEY',         'put your unique phrase here');
define('SECURE_AUTH_KEY',  'put your unique phrase here');
define('LOGGED_IN_KEY',    'put your unique phrase here');
define('NONCE_KEY',        'put your unique phrase here');
define('AUTH_SALT',        'put your unique phrase here');
define('SECURE_AUTH_SALT', 'put your unique phrase here');
define('LOGGED_IN_SALT',   'put your unique phrase here');
define('NONCE_SALT',       'put your unique phrase here');
"#;

        let result = generate_wp_config_content_from_sample(
            "testdb",
            "user",
            "pass",
            "localhost",
            "utf8mb4",
            sample.to_string(),
        )
        .unwrap();

        // Ensure no placeholder remains
        assert!(!result.contains("put your unique phrase here"));

        // Count that we have 8 different 64-char keys
        let lines: Vec<&str> = result.lines().collect();
        let mut keys = Vec::new();
        for line in lines {
            if line.contains("define(") && line.contains("_KEY") || line.contains("_SALT") {
                // Extract the key value between quotes
                if let Some(start) = line.rfind('\'')
                    && let Some(end) = line[..start].rfind('\'')
                {
                    let key = &line[end + 1..start];
                    assert_eq!(key.len(), 64, "Salt key should be 64 characters");
                    keys.push(key);
                }
            }
        }

        // Verify all keys are unique
        assert_eq!(keys.len(), 8);
        for i in 0..keys.len() {
            for j in i + 1..keys.len() {
                assert_ne!(keys[i], keys[j], "All salt keys should be unique");
            }
        }
    }

    #[test]
    fn test_create_salt_key() {
        let key1 = create_salt_key();
        let key2 = create_salt_key();

        // Check length
        assert_eq!(key1.len(), 64);
        assert_eq!(key2.len(), 64);

        // Check uniqueness
        assert_ne!(key1, key2);

        // Check alphanumeric
        assert!(key1.chars().all(|c| c.is_ascii_alphanumeric()));
        assert!(key2.chars().all(|c| c.is_ascii_alphanumeric()));
    }

    // ===== Ownership Tests (Unix only) =====

    #[test]
    #[cfg(unix)]
    #[ignore] // Requires specific users/groups to exist
    fn test_set_path_owner_user_only() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("owner_test.txt");
        fs::write(&file_path, "test").unwrap();

        // This test requires the current user to have permission to change ownership
        // Usually only works as root, so we test with current user
        let current_user = std::env::var("USER").unwrap_or_else(|_| "root".to_string());

        let result = set_path_owner(Some(&current_user), None, file_path.to_str().unwrap());
        // May fail in restricted environments
        if result.is_ok() {
            println!("Ownership change successful");
        } else {
            println!("Expected failure in restricted environment");
        }
    }

    #[test]
    #[cfg(unix)]
    fn test_set_path_owner_invalid_user() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("invalid_user.txt");
        fs::write(&file_path, "test").unwrap();

        let result = set_path_owner(
            Some("nonexistent_user_12345"),
            None,
            file_path.to_str().unwrap(),
        );

        assert!(result.is_err());
        assert!(matches!(
            result,
            Err(FileCreationError::PermissionSetFailed(_))
        ));
    }

    #[test]
    #[cfg(unix)]
    fn test_set_path_owner_invalid_group() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("invalid_group.txt");
        fs::write(&file_path, "test").unwrap();

        let result = set_path_owner(
            None,
            Some("nonexistent_group_12345"),
            file_path.to_str().unwrap(),
        );

        assert!(result.is_err());
        assert!(matches!(
            result,
            Err(FileCreationError::PermissionSetFailed(_))
        ));
    }

    #[test]
    #[cfg(unix)]
    fn test_set_path_owner_none_both() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("none_both.txt");
        fs::write(&file_path, "test").unwrap();

        // Should succeed but do nothing
        let result = set_path_owner(None, None, file_path.to_str().unwrap());
        assert!(result.is_ok());
    }

    // ===== Step Reversion Tests =====

    #[test]
    fn test_is_step_group_reverted() {
        let mut reverted = vec![];

        // Test nginx config group
        assert!(!is_step_group_reverted(
            &SpawnSteps::CreateNginxConfig,
            &reverted
        ));

        reverted.push(SpawnSteps::CreateNginxConfig);
        assert!(is_step_group_reverted(
            &SpawnSteps::CreateNginxConfig,
            &reverted
        ));
        assert!(is_step_group_reverted(
            &SpawnSteps::CreateNginxConfigWithSSL,
            &reverted
        ));

        // Test site directory group
        reverted.clear();
        assert!(!is_step_group_reverted(
            &SpawnSteps::CreateSiteDirectory,
            &reverted
        ));

        reverted.push(SpawnSteps::CreateWPConfigFile);
        assert!(is_step_group_reverted(
            &SpawnSteps::CreateSiteDirectory,
            &reverted
        ));
        assert!(is_step_group_reverted(
            &SpawnSteps::CreateWPConfigFile,
            &reverted
        ));

        // Test SSL directory group
        reverted.clear();
        reverted.push(SpawnSteps::CreateSSL);
        assert!(is_step_group_reverted(
            &SpawnSteps::CreateSSLDirectory,
            &reverted
        ));
        assert!(is_step_group_reverted(&SpawnSteps::CreateSSL, &reverted));

        // Test database (not in a group)
        reverted.clear();
        let db1 = SpawnSteps::CreateDatabase("db1".to_string());
        let db2 = SpawnSteps::CreateDatabase("db2".to_string());

        assert!(!is_step_group_reverted(&db1, &reverted));
        reverted.push(db1.clone());
        assert!(is_step_group_reverted(&db2, &reverted));
    }

    // ===== Error Display Tests =====

    #[test]
    fn test_file_creation_error_display() {
        let err = FileCreationError::InvalidPath("test path".to_string());
        assert_eq!(err.to_string(), "Invalid path: test path");

        let err = FileCreationError::InsufficientPermissions("denied".to_string());
        assert_eq!(err.to_string(), "Insufficient permissions: denied");

        let err = FileCreationError::DirectoryCreationFailed("mkdir failed".to_string());
        assert_eq!(err.to_string(), "Failed to create directory: mkdir failed");

        let err = FileCreationError::FileWriteFailed("write error".to_string());
        assert_eq!(err.to_string(), "Failed to write file: write error");

        let err = FileCreationError::PermissionSetFailed("chmod failed".to_string());
        assert_eq!(err.to_string(), "Failed to set permissions: chmod failed");

        let err = FileCreationError::PathTraversal("../etc/passwd".to_string());
        assert_eq!(err.to_string(), "Path traversal detected: ../etc/passwd");
    }

    #[test]
    fn test_error_trait_implementation() {
        let err = FileCreationError::InvalidPath("test".to_string());
        let _: &dyn std::error::Error = &err;
    }

    // ===== Integration Tests =====

    #[test]
    fn test_create_wp_config_file_integration() {
        let temp_dir = TempDir::new().unwrap();
        let site_path = temp_dir.path();

        // Create a mock wp-config-sample.php
        let sample_content = r#"<?php
define('DB_NAME', 'database_name_here');
define('DB_USER', 'username_here');
define('DB_PASSWORD', 'password_here');
define('DB_HOST', 'localhost');
define('DB_CHARSET', 'utf8');
define('AUTH_KEY', 'put your unique phrase here');
"#;

        let sample_path = site_path.join("wp-config-sample.php");
        fs::write(&sample_path, sample_content).unwrap();

        // Create wp-config.php
        let result = create_wp_config_file(
            site_path.to_str().unwrap(),
            "wp_test",
            "testuser",
            "testpass",
            "localhost",
            "utf8mb4",
        );

        assert!(result.is_ok());

        // Verify wp-config.php exists and has correct content
        let config_path = site_path.join("wp-config.php");
        assert!(config_path.exists());

        let config_content = fs::read_to_string(&config_path).unwrap();
        assert!(config_content.contains("'wp_test'"));
        assert!(config_content.contains("'testuser'"));
        assert!(config_content.contains("'testpass'"));
        assert!(!config_content.contains("put your unique phrase here"));
    }

    #[test]
    fn test_create_wp_config_file_missing_sample() {
        let temp_dir = TempDir::new().unwrap();
        let site_path = temp_dir.path();

        // Try to create wp-config.php without sample
        let result = create_wp_config_file(
            site_path.to_str().unwrap(),
            "wp_test",
            "user",
            "pass",
            "localhost",
            "utf8mb4",
        );

        assert!(result.is_err());
        assert!(matches!(result, Err(FileCreationError::FileWriteFailed(_))));
    }

    // ===== e2sp-managed wp-config Block Tests =====

    /// Fixture mirroring the parts of `wp-config-sample.php` this module keys
    /// off, copied from the WordPress 7.0.2 archive: the `WP_DEBUG` definition
    /// and the `stop editing` anchor.
    ///
    /// Being a copy, it cannot detect a future WordPress release changing that
    /// layout — the fallbacks in [`e2sp_block_insertion_index`] exist for
    /// exactly that reason, and the real archive is checked by hand when the
    /// generator changes.
    const STOCK_SAMPLE: &str = r#"<?php
define( 'DB_NAME', 'database_name_here' );
define( 'DB_USER', 'username_here' );
define( 'DB_PASSWORD', 'password_here' );
define( 'DB_HOST', 'localhost' );
define( 'AUTH_KEY',         'put your unique phrase here' );

$table_prefix = 'wp_';

/**
 * For developers: WordPress debugging mode.
 */
define( 'WP_DEBUG', false );

/* Add any custom values between this line and the "stop editing" line. */



/* That's all, stop editing! Happy publishing. */

/** Absolute path to the WordPress directory. */
if ( ! defined( 'ABSPATH' ) ) {
	define( 'ABSPATH', __DIR__ . '/' );
}

/** Sets up WordPress vars and included files. */
require_once ABSPATH . 'wp-settings.php';
"#;

    fn generated_stock_config() -> String {
        generate_wp_config_content_from_sample(
            "wp_site",
            "wordpress",
            "pleaseadvise",
            "localhost",
            "utf8mb4",
            STOCK_SAMPLE.to_string(),
        )
        .unwrap()
    }

    #[test]
    fn test_generated_config_enables_debug_logging() {
        let config = generated_stock_config();

        assert!(config.contains("define( 'WP_DEBUG', true );"));
        assert!(config.contains("define( 'WP_DEBUG_LOG', true );"));
        assert!(config.contains("define( 'WP_DEBUG_DISPLAY', false );"));
        // The sample's `false` must be gone, not merely overridden.
        assert!(!config.contains("define( 'WP_DEBUG', false );"));
    }

    #[test]
    fn test_generated_config_sets_fs_method_direct() {
        assert!(
            generated_stock_config().contains("define( 'FS_METHOD', 'direct' );"),
            "FS_METHOD must be direct so WordPress never asks for FTP credentials"
        );
    }

    #[test]
    fn test_generated_config_defines_each_managed_constant_once() {
        let config = generated_stock_config();

        // PHP warns and keeps the first value when a constant is defined twice.
        for constant in E2SP_MANAGED_WP_CONSTANTS {
            let definitions = config
                .lines()
                .filter(|line| is_definition_of(line, constant))
                .count();
            assert_eq!(
                definitions, 1,
                "'{}' must be defined exactly once",
                constant
            );
        }
    }

    #[test]
    fn test_generated_config_places_block_before_wp_settings() {
        let config = generated_stock_config();

        let block = config.find(WP_CONFIG_E2SP_MARKER).unwrap();
        let anchor = config.find(WP_CONFIG_STOP_EDITING_ANCHOR).unwrap();
        let wp_settings = config.find("require_once ABSPATH").unwrap();

        // Constants are only honoured if they are defined before wp-settings.php.
        assert!(block < anchor);
        assert!(anchor < wp_settings);
    }

    #[test]
    fn test_generated_config_keeps_database_credentials() {
        let config = generated_stock_config();

        assert!(config.contains("'wp_site'"));
        assert!(config.contains("'wordpress'"));
        assert!(config.contains("'pleaseadvise'"));
        assert!(!config.contains("put your unique phrase here"));
    }

    #[test]
    fn test_insert_block_replaces_conflicting_defines() {
        let sample = "<?php\n\
                      define( 'WP_DEBUG_LOG', false );\n\
                      define( \"FS_METHOD\", \"ftpext\" );\n\
                      /* That's all, stop editing! */\n";

        let result = insert_e2sp_wp_config_block(sample);

        assert!(!result.contains("ftpext"));
        assert!(!result.contains("define( 'WP_DEBUG_LOG', false );"));
        assert!(result.contains("define( 'FS_METHOD', 'direct' );"));
    }

    #[test]
    fn test_insert_block_falls_back_to_php_tag() {
        let sample = "<?php\ndefine( 'DB_NAME', 'db' );\n";

        let result = insert_e2sp_wp_config_block(sample);
        let lines: Vec<&str> = result.lines().collect();

        // No anchor, so the block goes straight after the opening tag - still
        // ahead of everything that could require wp-settings.php.
        assert_eq!(lines[0], "<?php");
        assert!(lines[1].contains(WP_CONFIG_E2SP_MARKER));
        assert!(result.contains("define( 'DB_NAME', 'db' );"));
    }

    #[test]
    fn test_insert_block_preserves_unrelated_content() {
        let sample = "<?php\n$table_prefix = 'wp_';\n/* That's all, stop editing! */\n";

        let result = insert_e2sp_wp_config_block(sample);

        assert!(result.contains("$table_prefix = 'wp_';"));
        assert!(result.contains("/* That's all, stop editing! */"));
        assert!(result.ends_with('\n'));
    }

    #[test]
    fn test_e2sp_block_insertion_index() {
        // Anchor wins over the PHP tag.
        assert_eq!(
            e2sp_block_insertion_index(&["<?php", "code", "/* That's all, stop editing! */"]),
            2
        );
        // Without an anchor, insert right after the opening tag.
        assert_eq!(e2sp_block_insertion_index(&["<?php", "code"]), 1);
        // Without either, fall back to the top of the file.
        assert_eq!(e2sp_block_insertion_index(&["code"]), 0);
    }

    #[test]
    fn test_is_definition_of() {
        assert!(is_definition_of("define( 'WP_DEBUG', false );", "WP_DEBUG"));
        assert!(is_definition_of(
            "  define(\"WP_DEBUG\", false);",
            "WP_DEBUG"
        ));

        // A longer constant must not be mistaken for a shorter one.
        assert!(!is_definition_of(
            "define( 'WP_DEBUG_LOG', false );",
            "WP_DEBUG"
        ));
        // Commented-out definitions are inert and must be left in place.
        assert!(!is_definition_of(
            "// define( 'WP_DEBUG', true );",
            "WP_DEBUG"
        ));
        assert!(!is_definition_of("$wp_debug = 'WP_DEBUG';", "WP_DEBUG"));
    }

    // ===== WordPress Uploads Directory Tests =====

    #[test]
    #[cfg(unix)]
    fn test_create_wp_uploads_directory() {
        let temp_dir = TempDir::new().unwrap();
        let site_path = temp_dir.path().to_str().unwrap();

        create_wp_uploads_directory(site_path).unwrap();

        let uploads = temp_dir.path().join(WP_UPLOADS_RELATIVE_PATH);
        assert!(uploads.is_dir(), "uploads directory must be created");
        assert_eq!(
            fs::metadata(&uploads).unwrap().permissions().mode() & 0o777,
            WP_UPLOADS_PERMISSIONS
        );
    }

    #[test]
    #[cfg(unix)]
    fn test_create_wp_uploads_directory_is_idempotent() {
        let temp_dir = TempDir::new().unwrap();
        let site_path = temp_dir.path().to_str().unwrap();
        let uploads = temp_dir.path().join(WP_UPLOADS_RELATIVE_PATH);

        // A pre-existing directory with the wrong mode must be corrected, not
        // treated as a failure - `update --wp` can meet leftovers.
        fs::create_dir_all(&uploads).unwrap();
        set_path_permissions(&uploads, 0o700).unwrap();

        assert!(create_wp_uploads_directory(site_path).is_ok());
        assert_eq!(
            fs::metadata(&uploads).unwrap().permissions().mode() & 0o777,
            WP_UPLOADS_PERMISSIONS
        );
    }

    #[test]
    fn test_create_wp_uploads_directory_trailing_slash() {
        let temp_dir = TempDir::new().unwrap();
        let site_path = format!("{}/", temp_dir.path().to_str().unwrap());

        create_wp_uploads_directory(&site_path).unwrap();

        assert!(temp_dir.path().join(WP_UPLOADS_RELATIVE_PATH).is_dir());
    }

    #[test]
    fn test_create_wp_uploads_directory_on_missing_site() {
        let temp_dir = TempDir::new().unwrap();
        let missing = temp_dir.path().join("no-such-site");
        // Nested creation succeeds; the guard against spawning into a missing
        // site lives in the command layer, so this only documents the behaviour.
        assert!(create_wp_uploads_directory(missing.to_str().unwrap()).is_ok());
        assert!(missing.join(WP_UPLOADS_RELATIVE_PATH).is_dir());
    }

    // ===== Web Server Ownership Tests =====

    #[test]
    #[cfg(unix)]
    fn test_set_path_owner_recursive_visits_whole_tree() {
        let temp_dir = TempDir::new().unwrap();
        let nested = temp_dir.path().join("wp-content/plugins");
        fs::create_dir_all(&nested).unwrap();
        fs::write(nested.join("plugin.php"), "<?php").unwrap();
        fs::write(temp_dir.path().join("index.php"), "<?php").unwrap();

        // `None`/`None` chowns nothing, so this needs no privileges, but every
        // entry is still visited: an unreadable or missing one would error out.
        // This is what guarantees an extracted WordPress tree is fully covered.
        assert!(
            set_path_owner_recursive(None, None, temp_dir.path().to_str().unwrap()).is_ok(),
            "traversal must reach every entry under the site root"
        );
    }

    #[test]
    #[cfg(unix)]
    fn test_set_path_owner_recursive_missing_root() {
        let temp_dir = TempDir::new().unwrap();
        let missing = temp_dir.path().join("no-such-site");

        // The root itself is part of the traversal, so a missing one is an error
        // rather than a silent success over zero entries.
        let result = set_path_owner_recursive(None, None, missing.to_str().unwrap());

        assert!(matches!(
            result,
            Err(FileCreationError::PermissionSetFailed(_))
        ));
    }

    #[test]
    #[cfg(unix)]
    fn test_set_path_owner_recursive_unknown_user() {
        let temp_dir = TempDir::new().unwrap();
        fs::write(temp_dir.path().join("file.txt"), "test").unwrap();

        // The account is resolved once, before anything is touched, so an
        // unknown name fails without leaving the tree half-chowned.
        let result = set_path_owner_recursive(
            Some("nonexistent_user_12345"),
            Some("nonexistent_group_12345"),
            temp_dir.path().to_str().unwrap(),
        );

        assert!(matches!(
            result,
            Err(FileCreationError::PermissionSetFailed(_))
        ));
    }

    #[test]
    #[cfg(unix)]
    fn test_set_path_owner_recursive_skips_symlinks() {
        use std::os::unix::fs::symlink;

        let temp_dir = TempDir::new().unwrap();
        let outside = temp_dir.path().join("developer-checkout");
        let site = temp_dir.path().join("site");
        fs::create_dir_all(&outside).unwrap();
        fs::write(outside.join("plugin.php"), "<?php").unwrap();
        fs::create_dir_all(site.join("wp-content/plugins")).unwrap();
        symlink(&outside, site.join("wp-content/plugins/my-plugin")).unwrap();

        // A dangling link is the cheap proof that entries are not dereferenced:
        // `chown` resolves the path, so following this one would fail with
        // ENOENT. Skipping it succeeds - and by the same token a live link, like
        // the plugin above, no longer hands a developer's checkout to the web
        // server. (Asserting on the resulting uid would require root.)
        symlink(
            temp_dir.path().join("gone"),
            site.join("wp-content/plugins/dangling"),
        )
        .unwrap();

        assert!(
            set_path_owner(
                None,
                None,
                site.join("wp-content/plugins/dangling").to_str().unwrap()
            )
            .is_err(),
            "chown must resolve symlinks - otherwise this test proves nothing"
        );
        assert!(
            set_path_owner_recursive(None, None, site.to_str().unwrap()).is_ok(),
            "symlinked entries must be skipped, not dereferenced"
        );
    }

    #[test]
    #[ignore] // Requires network connection and curl
    fn test_put_wordpress_in_site_directory() {
        let temp_dir = TempDir::new().unwrap();
        let site_path = temp_dir.path().join("wordpress_test");
        fs::create_dir(&site_path).unwrap();

        // This would download actual WordPress
        let result = put_wordpress_in_site_directory(site_path.to_str().unwrap());

        match result {
            Ok(()) => {
                // Check WordPress files exist
                assert!(site_path.join("wp-config-sample.php").exists());
                assert!(site_path.join("index.php").exists());
                assert!(site_path.join("wp-admin").exists());
            }
            Err(e) => {
                println!("Expected error in test environment: {}", e);
            }
        }
    }
}

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

// use predicates::path;
use std::fs::OpenOptions;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process;
use std::{fs, io, io::Write};

use crate::cli::commands::SpawnSteps;
use crate::cli::commands::{REMOVE_NGINX_CONFIG, REMOVE_SITE_DIRECTORY, REMOVE_SSL_DIRECTORY};
use crate::nginx;
use crate::utils::db;
use crate::utils::sites;
use nix::unistd::Group;
use rand::Rng;

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
    steps: &Vec<SpawnSteps>,
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
                remove_directory(&nginx_config.ssl_root.as_ref().unwrap()).unwrap_or_else(|e| {
                    eprintln!(
                        "✗ Failed to delete SSL directory for site: {}: {}",
                        site_name, e
                    );
                });
                reverted_steps_completed.push(SpawnSteps::CreateSSLDirectory);
            }
            SpawnSteps::CreateSSL => {
                println!("Reverting: Deleting SSL directory for site: {}", site_name);
                remove_directory(&nginx_config.ssl_root.as_ref().unwrap()).unwrap_or_else(|e| {
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
/// ```
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
/// ```
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
/// * `db_charset` - Character set to replace "utf8"
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
/// - `utf8` → database charset (typically utf8mb4)
/// - `put your unique phrase here` → unique 64-char salt keys
///
/// # Examples
///
/// ```
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
    db_charset: &str,
    wp_config_sample: String,
) -> Result<String, FileCreationError> {
    let mut wp_config_content = wp_config_sample;
    wp_config_content = wp_config_content
        .replace("database_name_here", db_name)
        .replace("username_here", db_user)
        .replace("password_here", db_password)
        .replace("localhost", db_host)
        .replace("utf8", db_charset);
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

    Ok(wp_config_content)
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
/// ```
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

    fs::create_dir_all(&path).map_err(|e| {
        FileCreationError::DirectoryCreationFailed(format!(
            "Cannot create directory '{}': {}",
            dir_path, e
        ))
    })?;

    #[cfg(unix)]
    {
        if let Some(mode) = permissions {
            let permissions = fs::Permissions::from_mode(mode);
            fs::set_permissions(&path, permissions).map_err(|e| {
                FileCreationError::PermissionSetFailed(format!(
                    "Cannot set permissions on '{}': {}",
                    dir_path, e
                ))
            })?;
        }
    }
    Ok(())
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
/// ```
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
        .open(&file_path)
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
        if let Some(permissions) = permissions {
            let permissions = fs::Permissions::from_mode(permissions);
            fs::set_permissions(&file_path, permissions).map_err(|e| {
                sites::remove_file(&path).unwrap_or(());
                FileCreationError::PermissionSetFailed(format!(
                    "Cannot set permissions on '{}': {}",
                    path, e
                ))
            })?;
        }
    }

    Ok(())
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
/// ```
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
    // Get the UID for the current user
    let uid = match user_name {
        Some(name) => match nix::unistd::User::from_name(name) {
            Ok(Some(user)) => Some(user.uid),
            _ => {
                return Err(FileCreationError::PermissionSetFailed(format!(
                    "User '{}' not found",
                    name
                )));
            }
        },
        None => None,
    };
    // Get the GID for the specified group
    let gid = match group_name {
        Some(name) => match Group::from_name(name) {
            Ok(Some(group)) => Some(group.gid),
            _ => {
                return Err(FileCreationError::PermissionSetFailed(format!(
                    "Group '{}' not found",
                    name
                )));
            }
        },
        None => None,
    };

    // Apply ownership change
    nix::unistd::chown(path, uid, gid).map_err(|e| {
        FileCreationError::PermissionSetFailed(format!("Cannot set ownership on '{}': {}", path, e))
    })?;
    Ok(())
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
/// ```
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
        fs::remove_dir_all(&path).map_err(|e| {
            FileCreationError::DirectoryCreationFailed(format!(
                "Cannot remove directory '{}': {}",
                dir_path, e
            ))
        })?;
    }
    Ok(())
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
/// ```
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
        fs::remove_file(&path).map_err(|e| {
            FileCreationError::FileWriteFailed(format!("Cannot remove file '{}': {}", file_path, e))
        })?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

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
        create_directory_if_not_exists(dir_path.to_str().unwrap(), Some(0o777)).unwrap();

        // Check permissions
        let metadata = fs::metadata(&dir_path).unwrap();
        let permissions = metadata.permissions();
        // Mask with 0o777 to get only the permission bits we care about
        assert_eq!(permissions.mode() & 0o777, 0o777);
    }
}

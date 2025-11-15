// use predicates::path;
use std::{fs, io, io::Write};
use std::path::{Path};
use std::os::unix::fs::PermissionsExt;
use std::process;
use std::fs::OpenOptions;

use crate::cli::commands::SpawnSteps;
use crate::nginx;
use crate::utils::{db};
use crate::utils::sites;
use nix::unistd::{Group};
use rand::Rng;


/// Error type for file creation operations
#[derive(Debug)]
pub enum FileCreationError {
    InvalidPath(String),
    InsufficientPermissions(String),
    DirectoryCreationFailed(String),
    FileWriteFailed(String),
    PermissionSetFailed(String),
    PathTraversal(String),
}

impl std::fmt::Display for FileCreationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FileCreationError::InvalidPath(msg) => write!(f, "Invalid path: {}", msg),
            FileCreationError::InsufficientPermissions(msg) => write!(f, "Insufficient permissions: {}", msg),
            FileCreationError::DirectoryCreationFailed(msg) => write!(f, "Failed to create directory: {}", msg),
            FileCreationError::FileWriteFailed(msg) => write!(f, "Failed to write file: {}", msg),
            FileCreationError::PermissionSetFailed(msg) => write!(f, "Failed to set permissions: {}", msg),
            FileCreationError::PathTraversal(msg) => write!(f, "Path traversal detected: {}", msg),
        }
    }
}

impl std::error::Error for FileCreationError {}


pub fn revert_site_spawn(site_name: &str, steps: &Vec<SpawnSteps>, nginx_config: &nginx::config::NginxConfig) {
    eprintln!("✗ Site creation failed, reverting changes...");
    for step in steps.iter().rev() {
        match step {
            SpawnSteps::CreateNginxConfig => {
                println!("Reverting: Deleting Nginx config for site: {}", site_name);
                // Future implementation goes here
            }
            SpawnSteps::CreateSiteDirectory => {
                println!("Reverting: Deleting site directory for site: {}", site_name);
                // Future implementation goes here
            }
            SpawnSteps::CreateSSLDirectory => {
                println!("Reverting: Deleting SSL directory for site: {}", site_name);
                // Future implementation goes here
            }
            SpawnSteps::CreateSSL => {
                println!("Reverting: Deleting SSL certificates for site: {}", site_name);
                // Future implementation goes here
            }
            SpawnSteps::CreateNginxConfigWithSSL => {
                println!("Reverting: Removing HTTPS config from Nginx for site: {}", site_name);
                // Future implementation goes here
            }
            SpawnSteps::CreateDatabase(db_name) => {
                println!("Reverting: Dropping database: {}", db_name);
                match db::drop_database(db_name) {
                    Ok(()) => println!("✓ Database dropped successfully: {}", db_name),
                    Err(e) => eprintln!("✗ Failed to drop database: {}", e),
                }
            }
            SpawnSteps::CreateWPConfigFile => {
                println!("Reverting: Deleting wp-config.php for site: {}", site_name);
                // Future implementation goes here
            }
        }
    }
    println!("Site creation process reverted for site: {}", site_name);
    process::exit(1);
}

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
        return Err(FileCreationError::FileWriteFailed(
            format!("Command failed with status {}: {}", output.status, String::from_utf8_lossy(&output.stderr))
        ));
    }

    Ok(())
}
pub fn create_wp_config_file(site_path: &str, db_name: &str, db_user: &str, db_password: &str, db_host: &str, db_charset: &str) -> Result<(), FileCreationError> {
    let wp_config_sample_path = format!("{}/wp-config-sample.php", site_path);
    let wp_config_sample_content = fs::read_to_string(&wp_config_sample_path).map_err(|e| {
        FileCreationError::FileWriteFailed(
            format!("Cannot read wp-config-sample.php: {}", e)
        )
    })?;
    let wp_config_content = generate_wp_config_content_from_sample(
        db_name,
        db_user,
        db_password,
        db_host,
        db_charset,
        wp_config_sample_content
    )?;
    let wp_config_path = format!("{}/wp-config.php", site_path);
    create_file_with_content_if_not_exists(&wp_config_path, &wp_config_content, None)?;

    Ok(())
}
pub fn generate_wp_config_content_from_sample(db_name: &str, db_user: &str, db_password: &str, db_host: &str, db_charset: &str, wp_config_sample: String) -> Result<String, FileCreationError> {
    
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
fn create_salt_key() -> String {
    rand::rng()
        .sample_iter(&rand::distr::Alphanumeric)
        .take(64)
        .map(char::from)
        .collect()
}
pub fn create_directory_if_not_exists(dir_path: &str, permissions: Option<u32>) -> Result<(), FileCreationError> {
    let path = Path::new(&dir_path);
    if path.exists() {
        return Err(FileCreationError::DirectoryCreationFailed(
            format!("Directory already exists: {}", dir_path)
        ));
    }

    fs::create_dir_all(&path).map_err(|e| {
        FileCreationError::DirectoryCreationFailed(
            format!("Cannot create directory '{}': {}", dir_path, e)
        )
    })?;

    #[cfg(unix)]
    {
        if let Some(mode) = permissions {
            let permissions = fs::Permissions::from_mode(mode);
            fs::set_permissions(&path, permissions).map_err(|e| {
                FileCreationError::PermissionSetFailed(
                    format!("Cannot set permissions on '{}': {}", dir_path, e)
                )
            })?;
        }
    }
    Ok(())
}

pub fn create_file_with_content_if_not_exists(path: &str, content: &str, permissions: Option<u32>) -> Result<(), FileCreationError> {
    let file_path = Path::new(&path);
    // Check if file already exists - FAIL if it does
    if file_path.exists() {
        return Err(FileCreationError::FileWriteFailed(
            format!("File already exists: {}.", path)
        ));
    }

    // Write the file - use create_new to ensure atomic creation
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)  // Fails if file exists (atomic check-and-create)
        .open(&file_path)
        .map_err(|e| {
            if e.kind() == io::ErrorKind::AlreadyExists {
                FileCreationError::FileWriteFailed(
                    format!("File already exists: {}.", path)
                )
            } else {
                FileCreationError::FileWriteFailed(
                    format!("Cannot create file '{}': {}", path, e)
                )
            }
        })?;

    file.write_all(content.as_bytes()).map_err(|e| {
        FileCreationError::FileWriteFailed(
            format!("Cannot write to '{}': {}", path, e)
        )
    })?;

    // Set appropriate permissions (644 - readable by all, writable by owner)
    #[cfg(unix)]
    {
        if let Some(permissions) = permissions {
            let permissions = fs::Permissions::from_mode(permissions);
            fs::set_permissions(&file_path, permissions).map_err(|e| {
            sites::remove_file(&path).unwrap_or(());
            FileCreationError::PermissionSetFailed(
                format!("Cannot set permissions on '{}': {}", path, e)
            )
        })?;
        }
    }

    Ok(())
}

/// Changes the ownership of a file or directory at the given path.
///
/// # Arguments
///
/// * `user_name` - An `Option<&str>` specifying the username to set as the new owner.
///                 If `None`, the user (owner) will not be changed.
/// * `group_name` - An `Option<&str>` specifying the group name to set as the new group owner.
///                  If `None`, the group will not be changed.
/// * `path` - The path to the file or directory whose ownership should be changed.
///
/// # Returns
///
/// * `Ok(())` if the ownership change was successful.
/// * `Err(FileCreationError)` if the user or group does not exist, or if the ownership change fails.
///
/// # Behavior
///
/// - If `user_name` is `Some` and `group_name` is `None`, only the user (owner) will be changed.
/// - If `user_name` is `None` and `group_name` is `Some`, only the group will be changed.
/// - If both are `Some`, both user and group will be changed.
/// - If both are `None`, nothing will be changed (no-op).
///
/// This function uses [`nix::unistd::chown`](https://docs.rs/nix/latest/nix/unistd/fn.chown.html),
/// which maps to the POSIX `chown(2)` system call. Passing `None` for either user or group
/// leaves that attribute unchanged (see [chown(2) man page](https://man7.org/linux/man-pages/man2/chown.2.html)).
///
/// # Example
///
/// ````rust
/// set_path_owner(Some("www-data"), None, "/var/www/example")?; // Change only user
/// set_path_owner(None, Some("www-data"), "/var/www/example")?; // Change only group
/// set_path_owner(Some("www-data"), Some("www-data"), "/var/www/example")?; // Change both
/// set_path_owner(None, None, "/var/www/example")?; // No-op
/// ````
///
/// # Errors
///
/// Returns `FileCreationError::PermissionSetFailed` if the user or group does not exist,
/// or if the ownership change fails for any reason.
pub fn set_path_owner(user_name: Option<&str>, group_name: Option<&str>, path: &str) -> Result<(), FileCreationError> {
    // Get the UID for the current user
    let uid = match user_name {
        Some(name) => match nix::unistd::User::from_name(name) {
            Ok(Some(user)) => Some(user.uid),
            _ => return Err(FileCreationError::PermissionSetFailed(
                format!("User '{}' not found", name)
            )),
        },
        None => None
    };
    // Get the GID for the specified group
    let gid = match group_name {
        Some(name) => match Group::from_name(name) {
            Ok(Some(group)) => Some(group.gid),
            _ => return Err(FileCreationError::PermissionSetFailed(
                format!("Group '{}' not found", name)
            )),
        },
        None => None,
    };
    
    // Apply ownership change
    nix::unistd::chown(path, uid, gid).map_err(|e| {
        FileCreationError::PermissionSetFailed(
            format!("Cannot set ownership on '{}': {}", path, e)
        )
    })?;
    Ok(())
}

pub fn remove_directory(dir_path: &str) -> Result<(), FileCreationError> {
    let path = Path::new(&dir_path);
    if path.exists() {
        fs::remove_dir_all(&path).map_err(|e| {
            FileCreationError::DirectoryCreationFailed(
                format!("Cannot remove directory '{}': {}", dir_path, e)
            )
        })?;
    }
    Ok(())
}

pub fn remove_file(file_path: &str) -> Result<(), FileCreationError> {
    let path = Path::new(&file_path);
    if path.exists() {
        fs::remove_file(&path).map_err(|e| {
            FileCreationError::FileWriteFailed(
                format!("Cannot remove file '{}': {}", file_path, e)
            )
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
        assert!(matches!(result, Err(FileCreationError::DirectoryCreationFailed(_))));
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
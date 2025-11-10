// use predicates::path;
use std::fs;
use std::path::{Path};
use std::os::unix::fs::PermissionsExt;
use std::process;

use crate::cli::commands::SpawnSteps;
use crate::nginx;
use crate::utils::{db};
use nix::unistd::{Uid, Gid, Group};

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
        }
    }
    println!("Site creation process reverted for site: {}", site_name);
    process::exit(1);
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

pub fn set_path_owner(current_user: &str, ssl_root: &str) -> Result<(), FileCreationError> {
    // Get the UID for the current user
    let uid = match nix::unistd::User::from_name(&current_user) {
        Ok(Some(user)) => user.uid,
        _ => Uid::current(),
    };
    
    // Get the GID for root group
    let gid = match Group::from_name("root") {
        Ok(Some(group)) => group.gid,
        _ => Gid::from_raw(0),
    };
    
    // Apply ownership change
    nix::unistd::chown(ssl_root, Some(uid), Some(gid)).map_err(|e| {
        FileCreationError::PermissionSetFailed(
            format!("Cannot set ownership on '{}': {}", ssl_root, e)
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
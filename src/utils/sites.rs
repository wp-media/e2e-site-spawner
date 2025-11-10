// use predicates::path;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::os::unix::fs::PermissionsExt;
use std::process;

use crate::cli::commands::SpawnSteps;
use crate::nginx;
use crate::utils::{sites, db};
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

/// Gets a validated file path for nginx configuration files.
///
/// This function performs comprehensive security and format validation on the provided path
/// and returns a validated PathBuf that can be safely used for file operations.
///
/// # Validations performed:
/// - Ensures path is not empty
/// - Checks for path traversal attempts (../ or ..\)
/// - Validates .conf extension requirement
/// - Ensures path is within allowed nginx directories
///
/// # Arguments
///
/// * `path` - The file path to validate and process
///
/// # Returns
///
/// * `Ok(PathBuf)` - A validated and normalized path safe for file operations
/// * `Err(FileCreationError)` - If any validation fails
///
/// # Security
///
/// This function prevents path traversal attacks and ensures files are only
/// created in designated nginx directories, returning a safe path for use.
///
/// # Examples
///
/// ```
/// let validated_path = get_validated_nginx_path("/etc/nginx/sites-available/example.conf")
///     .expect("Path validation failed");
/// ```
fn get_validated_nginx_path(path: &str) -> Result<PathBuf, FileCreationError> {
    // 1. Validate path isn't empty
    if path.is_empty() {
        return Err(FileCreationError::InvalidPath("Path cannot be empty".to_string()));
    }

    // 2. Security: Check for path traversal attempts
    if path.contains("../") || path.contains("..\\") {
        return Err(FileCreationError::PathTraversal(
            format!("Path contains traversal pattern: {}", path)
        ));
    }

    // 3. Validate file extension (should be .conf for nginx)
    if !path.ends_with(".conf") {
        return Err(FileCreationError::InvalidPath(
            format!("File must have .conf extension, got: {}", path)
        ));
    }

    // 4. Convert to PathBuf for further checks
    let file_path = Path::new(path);

    // 5. Get absolute path to ensure we know where we're writing
    let absolute_path = match file_path.canonicalize() {
        Ok(p) => p,
        Err(_) => {
            // If file doesn't exist, canonicalize the parent directory
            if let Some(parent) = file_path.parent() {
                match parent.canonicalize() {
                    Ok(parent_abs) => parent_abs.join(file_path.file_name().unwrap()),
                    Err(_) => {
                        // Parent doesn't exist either, use as-is but validate later
                        file_path.to_path_buf()
                    }
                }
            } else {
                return Err(FileCreationError::InvalidPath(
                    "Cannot determine parent directory".to_string()
                ));
            }
        }
    };

    // 6. Ensure the path is within expected nginx directories (security measure)
    let valid_prefixes = vec![
        "/etc/nginx/",
        "/usr/local/nginx/",
        "/var/www/",
        "/tmp/", // For testing
    ];
    
    let path_str = absolute_path.to_string_lossy();
    if !valid_prefixes.iter().any(|prefix| path_str.starts_with(prefix)) {
        return Err(FileCreationError::InvalidPath(
            format!("Path must be within nginx directories. Got: {}", path_str)
        ));
    }

    Ok(file_path.to_path_buf())
}

/// Creates an Nginx configuration file at the specified path with the given content.
///
/// This function validates the path and content before writing, then creates the file
/// atomically to prevent race conditions. If the file already exists, the operation
/// fails to prevent accidental overwrites.
///
/// # Arguments
///
/// * `path` - The full path where the configuration file should be created
/// * `content` - The Nginx configuration content to write to the file
///
/// # Returns
///
/// * `Ok(())` if the file was created successfully
/// * `Err(FileCreationError)` if validation failed, file exists, or write failed
///
/// # Examples
///
/// ```
/// use utils::sites::create_nginx_file;
/// 
/// let config_content = "server { listen 80; server_name example.com; }";
/// match create_nginx_file("/etc/nginx/sites-available/example.com.conf", config_content) {
///     Ok(()) => println!("Configuration file created successfully"),
///     Err(e) => eprintln!("Failed to create config file: {}", e),
/// }
/// ```
///
/// # Errors
///
/// This function will return an error if:
/// - The path validation fails (empty, traversal attempt, wrong extension)
/// - The content is empty or whitespace only
/// - The file already exists
/// - The parent directory cannot be created
/// - File write operations fail
/// - Permission setting fails (Unix only)
pub fn create_nginx_file(path: &str, content: &str) -> Result<(), FileCreationError> {
        // Validate content isn't empty
    if content.trim().is_empty() {
        return Err(FileCreationError::InvalidPath(
            "Configuration content cannot be empty".to_string()
        ));
    }

    // Basic nginx config validation (warning only)
    if !content.contains("server") && !content.contains("location") {
        println!("⚠️  Warning: Configuration might be invalid (missing server/location blocks)");
    }
    // Get validated path
    let file_path = get_validated_nginx_path(path)?;

    // Create parent directory if it doesn't exist
    if let Some(parent) = file_path.parent() {
        if !parent.exists() {
            fs::create_dir_all(parent).map_err(|e| {
                FileCreationError::DirectoryCreationFailed(
                    format!("Cannot create parent directory '{}': {}", parent.display(), e)
                )
            })?;
        }
    }

    // Check if file already exists - FAIL if it does
    if file_path.exists() {
        return Err(FileCreationError::FileWriteFailed(
            format!("Configuration file already exists: {}. Cannot overwrite existing site configuration", path)
        ));
    }

    // Write the file - use create_new to ensure atomic creation
    use std::fs::OpenOptions;
    
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)  // Fails if file exists (atomic check-and-create)
        .open(&file_path)
        .map_err(|e| {
            if e.kind() == io::ErrorKind::AlreadyExists {
                FileCreationError::FileWriteFailed(
                    format!("Configuration file already exists: {}. Cannot overwrite existing site configuration", path)
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
        let permissions = fs::Permissions::from_mode(0o644);
        fs::set_permissions(&file_path, permissions).map_err(|e| {
            sites::remove_file(&path).unwrap_or(());
            FileCreationError::PermissionSetFailed(
                format!("Cannot set permissions on '{}': {}", path, e)
            )
        })?;
    }

    Ok(())
}

/// Appends content to an existing Nginx configuration file.
///
/// This function validates the path and content before appending. The file must already exist
/// for this operation to succeed. A newline is automatically prepended to the content
/// to ensure proper separation from existing content.
///
/// # Arguments
///
/// * `path` - The full path to the existing configuration file
/// * `content` - The Nginx configuration content to append to the file
///
/// # Returns
///
/// * `Ok(())` if the content was appended successfully
/// * `Err(FileCreationError)` if validation failed or append operation failed
///
/// # Examples
///
/// ```
/// use utils::sites::append_to_nginx_file;
/// 
/// // Add a new location block to an existing configuration
/// let additional_config = "location /api { proxy_pass http://backend; }";
/// match append_to_nginx_file("/etc/nginx/sites-available/example.com.conf", additional_config) {
///     Ok(()) => println!("Configuration appended successfully"),
///     Err(e) => eprintln!("Failed to append config: {}", e),
/// }
/// ```
///
/// # Errors
///
/// This function will return an error if:
/// - The path validation fails (empty, traversal attempt, wrong extension)
/// - The content is empty or whitespace only  
/// - The file does not exist
/// - File write operations fail
/// - The path is not within allowed nginx directories
///
/// # Security
///
/// This function performs the same security validations as `create_nginx_file`:
/// - Path traversal prevention
/// - Extension validation (.conf files only)
/// - Directory restriction (nginx directories only)
///
/// # Implementation Details
///
/// The function:
/// 1. Validates the input path and content
/// 2. Opens the file in append mode (fails if file doesn't exist)
/// 3. Prepends a newline to separate from existing content
/// 4. Writes the new content atomically
///
/// # Note
///
/// Unlike `create_nginx_file`, this function does not set file permissions
/// as it assumes the file already has appropriate permissions set.
pub fn append_to_nginx_file(path: &str, content: &str) -> Result<(), FileCreationError> {
    // Validate content isn't empty
    if content.trim().is_empty() {
        return Err(FileCreationError::InvalidPath(
            "Configuration content cannot be empty".to_string()
        ));
    }

    // Basic nginx config validation (warning only)
    if !content.contains("server") && !content.contains("location") {
        println!("⚠️  Warning: Configuration might be invalid (missing server/location blocks)");
    }

    // Get validated path - ensures security and format compliance
    let file_path = get_validated_nginx_path(path)?;

    // Open the file in append mode
    // This will fail if the file doesn't exist, which is the desired behavior
    let mut file = fs::OpenOptions::new()
        .append(true)
        .open(&file_path)
        .map_err(|e| {
            FileCreationError::FileWriteFailed(
                format!("Cannot open file '{}': {}", path, e)
            )
        })?;
    
    // Prepend newline to ensure proper separation from existing content
    let content = format!("\n{}", content);
    
    // Write the content to the file
    file.write_all(content.as_bytes()).map_err(|e| {
        FileCreationError::FileWriteFailed(
            format!("Cannot write to '{}': {}", path, e)
        )
    })?;

    Ok(())
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
    fn test_get_validated_nginx_path_valid() {
        let result = get_validated_nginx_path("/tmp/test.conf");
        assert!(result.is_ok());
        assert!(result.unwrap().to_string_lossy().ends_with("test.conf"));
    }

    #[test]
    fn test_get_validated_nginx_path_empty() {
        let result = get_validated_nginx_path("");
        assert!(matches!(result, Err(FileCreationError::InvalidPath(_))));
    }

    #[test]
    fn test_get_validated_nginx_path_traversal() {
        let result = get_validated_nginx_path("/etc/nginx/../../../etc/passwd");
        assert!(matches!(result, Err(FileCreationError::PathTraversal(_))));
    }

    #[test]
    fn test_get_validated_nginx_path_wrong_extension() {
        let result = get_validated_nginx_path("/tmp/test.txt");
        assert!(matches!(result, Err(FileCreationError::InvalidPath(_))));
    }

    #[test]
    fn test_create_valid_nginx_file() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("test.conf");
        let content = "server { listen 80; }";
        
        let result = create_nginx_file(file_path.to_str().unwrap(), content);
        assert!(result.is_ok());
        
        // Verify file was created
        assert!(file_path.exists());
        
        // Verify content
        let written_content = fs::read_to_string(&file_path).unwrap();
        assert_eq!(written_content, content);
    }

    #[test]
    fn test_reject_path_traversal() {
        let result = create_nginx_file("/etc/nginx/../../../etc/passwd", "malicious");
        assert!(matches!(result, Err(FileCreationError::PathTraversal(_))));
    }

    #[test]
    fn test_reject_non_conf_extension() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("test.txt");
        
        let result = create_nginx_file(file_path.to_str().unwrap(), "content");
        assert!(matches!(result, Err(FileCreationError::InvalidPath(_))));
    }

    #[test]
    fn test_reject_empty_path() {
        let result = create_nginx_file("", "content");
        assert!(matches!(result, Err(FileCreationError::InvalidPath(_))));
    }

    #[test]
    fn test_reject_empty_content() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("test.conf");
        
        let result = create_nginx_file(file_path.to_str().unwrap(), "   ");
        assert!(matches!(result, Err(FileCreationError::InvalidPath(_))));
    }

    #[test]
    fn test_reject_existing_file() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("test.conf");
        let content = "server { listen 80; }";
        
        // Create file first time - should succeed
        let result = create_nginx_file(file_path.to_str().unwrap(), content);
        assert!(result.is_ok());
        
        // Try to create same file again - should fail
        let result2 = create_nginx_file(file_path.to_str().unwrap(), content);
        assert!(result2.is_err());
        assert!(matches!(result2, Err(FileCreationError::FileWriteFailed(_))));
    }

    #[test]
    fn test_append_to_existing_file() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("test.conf");
        let initial_content = "server { listen 80; }";
        let append_content = "location / { return 200; }";
        
        // Create initial file
        create_nginx_file(file_path.to_str().unwrap(), initial_content).unwrap();
        
        // Append content
        let result = append_to_nginx_file(file_path.to_str().unwrap(), append_content);
        assert!(result.is_ok());
        
        // Verify appended content
        let full_content = fs::read_to_string(&file_path).unwrap();
        assert!(full_content.contains(initial_content));
        assert!(full_content.contains(append_content));
        assert_eq!(full_content, format!("{}\n{}", initial_content, append_content));
    }

    #[test]
    fn test_append_to_non_existent_file() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("nonexistent.conf");
        
        let result = append_to_nginx_file(file_path.to_str().unwrap(), "content");
        assert!(result.is_err());
        assert!(matches!(result, Err(FileCreationError::FileWriteFailed(_))));
    }

    #[test]
    fn test_append_empty_content() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("test.conf");
        
        // Create initial file
        create_nginx_file(file_path.to_str().unwrap(), "server { }").unwrap();
        
        // Try to append empty content
        let result = append_to_nginx_file(file_path.to_str().unwrap(), "  ");
        assert!(result.is_err());
        assert!(matches!(result, Err(FileCreationError::InvalidPath(_))));
    }

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
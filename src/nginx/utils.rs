//! Utility functions for Nginx configuration file operations.
//!
//! This module provides secure, validated functions for creating, modifying,
//! and managing Nginx configuration files. All functions include comprehensive
//! security checks to prevent path traversal attacks and ensure files are only
//! created in appropriate directories.
//!
//! # Security Features
//!
//! - Path traversal prevention
//! - File extension validation
//! - Directory restriction to nginx-specific paths
//! - Atomic file operations to prevent race conditions
//! - Proper Unix permission settings
//!
//! # Examples
//!
//! ```ignore
//! use nginx::utils::{create_nginx_file, append_to_nginx_file, reload_nginx};
//!
//! // Create a new configuration file
//! let config = "server { listen 80; server_name example.com; }";
//! create_nginx_file("/etc/nginx/sites-available/example.conf", config)?;
//!
//! // Add additional configuration
//! let extra = "location /api { proxy_pass http://backend; }";
//! append_to_nginx_file("/etc/nginx/sites-available/example.conf", extra)?;
//!
//! // Reload nginx to apply changes
//! reload_nginx()?;
//! ```

use std::fs;
use std::io::{self, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use crate::utils::sites;
use crate::utils::sites::FileCreationError;

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
/// ```ignore
/// let validated_path = get_validated_nginx_path("/etc/nginx/sites-available/example.conf")
///     .expect("Path validation failed");
/// ```
fn get_validated_nginx_path(path: &str) -> Result<PathBuf, FileCreationError> {
    // 1. Validate path isn't empty
    if path.is_empty() {
        return Err(FileCreationError::InvalidPath(
            "Path cannot be empty".to_string(),
        ));
    }

    // 2. Security: Check for path traversal attempts
    if path.contains("../") || path.contains("..\\") {
        return Err(FileCreationError::PathTraversal(format!(
            "Path contains traversal pattern: {}",
            path
        )));
    }

    // 3. Validate file extension (should be .conf for nginx)
    if !path.ends_with(".conf") {
        return Err(FileCreationError::InvalidPath(format!(
            "File must have .conf extension, got: {}",
            path
        )));
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
                    "Cannot determine parent directory".to_string(),
                ));
            }
        }
    };

    // 6. Ensure the path is within expected nginx directories (security measure)
    let valid_prefixes = vec![
        "/etc/nginx/",
        "/usr/local/nginx/",
        "/var/www/",
        "/tmp/",
        "/private/tmp/", // macOS canonical form of /tmp
    ];

    let path_str = absolute_path.to_string_lossy();
    if !valid_prefixes
        .iter()
        .any(|prefix| path_str.starts_with(prefix))
    {
        return Err(FileCreationError::InvalidPath(format!(
            "Path must be within nginx directories. Got: {}",
            path_str
        )));
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
/// ```ignore
/// use nginx::utils::create_nginx_file;
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
///
/// # Security Considerations
///
/// - Files are created with 644 permissions (readable by all, writable by owner)
/// - Atomic creation prevents TOCTOU vulnerabilities
/// - Path validation prevents directory traversal attacks
///
/// # Warnings
///
/// The function will print a warning if the content doesn't contain
/// typical nginx directives (server or location blocks), but will still
/// create the file.
pub fn create_nginx_file(path: &str, content: &str) -> Result<(), FileCreationError> {
    // Validate content isn't empty
    if content.trim().is_empty() {
        return Err(FileCreationError::InvalidPath(
            "Configuration content cannot be empty".to_string(),
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
                FileCreationError::DirectoryCreationFailed(format!(
                    "Cannot create parent directory '{}': {}",
                    parent.display(),
                    e
                ))
            })?;
        }
    }

    // Check if file already exists - FAIL if it does
    if file_path.exists() {
        return Err(FileCreationError::FileWriteFailed(format!(
            "Configuration file already exists: {}. Cannot overwrite existing site configuration",
            path
        )));
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
        FileCreationError::FileWriteFailed(format!("Cannot write to '{}': {}", path, e))
    })?;

    // Set appropriate permissions (644 - readable by all, writable by owner)
    #[cfg(unix)]
    {
        let permissions = fs::Permissions::from_mode(0o644);
        fs::set_permissions(&file_path, permissions).map_err(|e| {
            sites::remove_file(&path).unwrap_or(());
            FileCreationError::PermissionSetFailed(format!(
                "Cannot set permissions on '{}': {}",
                path, e
            ))
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
/// ```ignore
/// use nginx::utils::append_to_nginx_file;
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
            "Configuration content cannot be empty".to_string(),
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
            FileCreationError::FileWriteFailed(format!("Cannot open file '{}': {}", path, e))
        })?;

    // Prepend newline to ensure proper separation from existing content
    let content = format!("\n{}", content);

    // Write the content to the file
    file.write_all(content.as_bytes()).map_err(|e| {
        FileCreationError::FileWriteFailed(format!("Cannot write to '{}': {}", path, e))
    })?;

    Ok(())
}

/// Reloads the Nginx service to apply configuration changes.
///
/// This function executes the `nginx -s reload` command to gracefully reload
/// the Nginx service. This allows Nginx to apply new configuration changes
/// without dropping active connections.
///
/// # Returns
///
/// * `Ok(())` if Nginx was successfully reloaded
/// * `Err(String)` if the reload failed, containing the error details
///
/// # Examples
///
/// ```ignore
/// use nginx::utils::reload_nginx;
///
/// // After making configuration changes
/// match reload_nginx() {
///     Ok(()) => println!("✓ Nginx reloaded successfully"),
///     Err(e) => eprintln!("✗ Failed to reload Nginx: {}", e),
/// }
/// ```
///
/// # Errors
///
/// This function will return an error if:
/// - The `nginx` command is not found in PATH
/// - The user lacks permission to reload Nginx (usually requires sudo/root)
/// - Nginx is not running
/// - The current configuration has errors (nginx won't reload with invalid config)
///
/// # Prerequisites
///
/// - Nginx must be installed and available in the system PATH
/// - The user must have sufficient permissions (typically root/sudo)
/// - Nginx configuration must be valid (use `nginx -t` to verify)
///
/// # Graceful Reload
///
/// The reload signal (`-s reload`) tells Nginx to:
/// 1. Check the configuration file for syntax errors
/// 2. Open new log files
/// 3. Start new worker processes with the new configuration
/// 4. Gracefully shut down old worker processes
///
/// This ensures zero downtime during configuration updates.
///
/// # Security Note
///
/// This function typically requires elevated privileges. In production environments,
/// ensure proper sudo configuration or run the application with appropriate permissions.
pub fn reload_nginx() -> Result<(), String> {
    use std::process::Command;

    let status = Command::new("nginx")
        .arg("-s")
        .arg("reload")
        .status()
        .map_err(|e| format!("Failed to execute nginx command: {}", e))?;

    if !status.success() {
        return Err(format!("Nginx reload failed with status: {}", status));
    }

    Ok(())
}

/// Checks if HTTPS/SSL is configured in an Nginx configuration file.
///
/// This function examines an existing Nginx configuration file to determine whether
/// HTTPS support is already enabled. It looks for specific SSL-related directives
/// that indicate a properly configured HTTPS server block.
///
/// # Arguments
///
/// * `nginx_config_file_path` - The full path to the Nginx configuration file to check
///
/// # Returns
///
/// * `true` - If both HTTPS listener (port 443) and SSL certificate are configured
/// * `false` - If either directive is missing or the file cannot be read
///
/// # Detection Logic
///
/// The function considers HTTPS to be configured when **both** of the following
/// conditions are met:
/// 1. The configuration contains `listen 443` (HTTPS port listener)
/// 2. The configuration contains `ssl_certificate` (SSL certificate path)
///
/// Both directives must be present because:
/// - `listen 443` alone doesn't guarantee SSL is enabled (could be plain HTTP on 443)
/// - `ssl_certificate` alone doesn't mean the server is listening on HTTPS port
///
/// # Examples
///
/// ```ignore
/// use nginx::utils::check_if_https_in_nginx_config_file;
///
/// // Check if a site already has HTTPS configured
/// let config_path = "/etc/nginx/sites-available/example.com.conf";
/// if check_if_https_in_nginx_config_file(config_path) {
///     println!("HTTPS is already configured for this site");
/// } else {
///     println!("Site is HTTP-only, SSL can be added");
/// }
/// ```
///
/// # Error Handling
///
/// If the file cannot be read (doesn't exist, permission denied, etc.),
/// the function returns `false` rather than panicking. This is intentional
/// to allow the calling code to proceed with SSL setup when uncertain about
/// the current state.
///
/// # Use Cases
///
/// This function is typically used to:
/// - Prevent duplicate SSL configuration attempts
/// - Determine if SSL removal is possible
/// - Check site status for reporting or migration
/// - Validate SSL setup after configuration changes
///
/// # Limitations
///
/// The function performs a simple text search and may not detect:
/// - Commented-out SSL configurations
/// - SSL configured through included files
/// - Non-standard SSL configurations (custom ports, SNI, etc.)
/// - Malformed configurations that wouldn't work anyway
///
/// # Performance Note
///
/// The entire file is read into memory. For very large configuration files,
/// this might be inefficient. However, Nginx configuration files are typically
/// small enough that this is not a concern.
///
/// # Security Considerations
///
/// - The function only reads the file, never modifies it
/// - No sensitive information (certificates, keys) is exposed
/// - Returns a simple boolean to avoid leaking configuration details
///
/// # Common Nginx HTTPS Configuration
///
/// A typical HTTPS server block that would be detected:
/// ```nginx
/// server {
///     listen 443 ssl;
///     server_name example.com;
///     
///     ssl_certificate /etc/nginx/ssl/example.com/fullchain.pem;
///     ssl_certificate_key /etc/nginx/ssl/example.com/privkey.pem;
///     
///     # ... rest of configuration
/// }
/// ```
///
/// # See Also
///
/// * [`create_nginx_file`] - Creates new Nginx configuration files
/// * [`append_to_nginx_file`] - Adds HTTPS configuration to existing files
/// * [`ssl::generate_ssl`] - Generates SSL certificates for sites
pub fn check_if_https_in_nginx_config_file(nginx_config_file_path: &str) -> bool {
    // Read the configuration file, returning empty string if it fails
    // This allows graceful handling of missing or inaccessible files
    let content = fs::read_to_string(nginx_config_file_path).unwrap_or_default();
    
    // Check for both HTTPS port listener and SSL certificate directive
    // Both must be present for a valid HTTPS configuration
    content.contains("listen 443") && content.contains("ssl_certificate")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::sync::atomic::{AtomicUsize, Ordering};

    // Counter for unique test directory names
    static TEST_COUNTER: AtomicUsize = AtomicUsize::new(0);

    // Helper function to create test paths in /tmp with unique names
    fn create_test_dir() -> std::path::PathBuf {
        let counter = TEST_COUNTER.fetch_add(1, Ordering::SeqCst);
        let test_dir = format!("/tmp/nginx_test_{}_{}", std::process::id(), counter);
        fs::create_dir_all(&test_dir).unwrap();
        std::path::PathBuf::from(test_dir)
    }

    // Helper to clean up test directories
    fn cleanup_test_dir(path: &std::path::Path) {
        let _ = fs::remove_dir_all(path);
    }

    // ===== Path Validation Tests =====

    /// Tests that valid nginx paths are accepted
    #[test]
    fn test_get_validated_nginx_path_valid() {
        // Test multiple valid prefixes
        let test_paths = vec![
            "/tmp/test.conf",
            "/etc/nginx/sites-available/test.conf",
            "/usr/local/nginx/conf.d/test.conf",
            "/var/www/configs/test.conf",
        ];

        for path in test_paths {
            let result = get_validated_nginx_path(path);
            assert!(result.is_ok(), "Path {} should be valid", path);
            assert!(
                result.unwrap().to_string_lossy().ends_with("test.conf"),
                "Path should end with test.conf"
            );
        }
    }

    /// Tests that empty paths are rejected
    #[test]
    fn test_get_validated_nginx_path_empty() {
        let result = get_validated_nginx_path("");
        assert!(matches!(result, Err(FileCreationError::InvalidPath(_))));
        if let Err(FileCreationError::InvalidPath(msg)) = result {
            assert!(msg.contains("empty"), "Error should mention empty path");
        }
    }

    /// Tests that path traversal attempts are detected and rejected
    #[test]
    fn test_get_validated_nginx_path_traversal() {
        let traversal_paths = vec![
            "/etc/nginx/../../../etc/passwd",
            "/tmp/../../../root/.ssh/id_rsa.conf",
            "/etc/nginx/sites-available/../../shadow.conf",
            "/tmp/..\\..\\windows\\system32\\config.conf", // Windows-style traversal
            "/tmp/test/../../../etc/passwd.conf",
        ];

        for path in traversal_paths {
            let result = get_validated_nginx_path(path);
            assert!(
                matches!(result, Err(FileCreationError::PathTraversal(_))),
                "Path {} should be rejected as traversal",
                path
            );
        }
    }

    /// Tests that files without .conf extension are rejected
    #[test]
    fn test_get_validated_nginx_path_wrong_extension() {
        let invalid_extensions = vec![
            "/tmp/test.txt",
            "/tmp/test.cfg",
            "/tmp/test.config",
            "/tmp/test",
            "/tmp/test.conf.bak",
            "/etc/nginx/test.ini",
        ];

        for path in invalid_extensions {
            let result = get_validated_nginx_path(path);
            assert!(
                matches!(result, Err(FileCreationError::InvalidPath(_))),
                "Path {} should be rejected for wrong extension",
                path
            );
            
            if let Err(FileCreationError::InvalidPath(msg)) = result {
                assert!(
                    msg.contains(".conf"),
                    "Error should mention .conf requirement"
                );
            }
        }
    }

    /// Tests that paths outside allowed directories are rejected
    #[test]
    fn test_get_validated_nginx_path_invalid_directory() {
        let invalid_paths = vec![
            "/home/user/test.conf",
            "/opt/app/nginx.conf",
            "/root/configs/test.conf",
            "/bin/test.conf",
        ];

        for path in invalid_paths {
            let result = get_validated_nginx_path(path);
            assert!(
                matches!(result, Err(FileCreationError::InvalidPath(_))),
                "Path {} should be rejected as outside allowed directories",
                path
            );
        }
    }

    // ===== File Creation Tests =====

    /// Tests successful creation of a valid nginx configuration file
    #[test]
    fn test_create_valid_nginx_file() {
        let test_dir = create_test_dir();
        let file_path = test_dir.join("test.conf");
        let content = "server { listen 80; server_name example.com; }";

        let result = create_nginx_file(file_path.to_str().unwrap(), content);
        assert!(result.is_ok());

        // Verify file was created
        assert!(file_path.exists());

        // Verify content matches exactly
        let written_content = fs::read_to_string(&file_path).unwrap();
        assert_eq!(written_content, content);

        // Verify permissions on Unix
        #[cfg(unix)]
        {
            let metadata = fs::metadata(&file_path).unwrap();
            let permissions = metadata.permissions();
            assert_eq!(
                permissions.mode() & 0o777,
                0o644,
                "File should have 644 permissions"
            );
        }

        cleanup_test_dir(&test_dir);
    }

    /// Tests creation with various valid nginx configurations
    #[test]
    fn test_create_nginx_file_various_configs() {
        let test_dir = create_test_dir();
        
        let test_cases = vec![
            ("minimal.conf", "server { listen 80; }"),
            ("with_location.conf", "location /api { proxy_pass http://backend; }"),
            (
                "full.conf",
                r#"server {
                    listen 443 ssl;
                    server_name example.com;
                    ssl_certificate /etc/ssl/cert.pem;
                    location / {
                        try_files $uri $uri/ =404;
                    }
                }"#
            ),
        ];

        for (filename, content) in test_cases {
            let file_path = test_dir.join(filename);
            let result = create_nginx_file(file_path.to_str().unwrap(), content);
            assert!(result.is_ok(), "Failed to create {}", filename);
            
            let written = fs::read_to_string(&file_path).unwrap();
            assert_eq!(written, content);
        }

        cleanup_test_dir(&test_dir);
    }

    /// Tests that path traversal attempts are rejected during file creation
    #[test]
    fn test_reject_path_traversal() {
        let result = create_nginx_file("/etc/nginx/../../../etc/passwd", "malicious");
        assert!(matches!(result, Err(FileCreationError::PathTraversal(_))));
    }

    /// Tests that non-.conf files are rejected
    #[test]
    fn test_reject_non_conf_extension() {
        let test_dir = create_test_dir();
        let file_path = test_dir.join("test.txt");

        let result = create_nginx_file(file_path.to_str().unwrap(), "content");
        assert!(matches!(result, Err(FileCreationError::InvalidPath(_))));
    }

    /// Tests that empty paths are rejected
    #[test]
    fn test_reject_empty_path() {
        let result = create_nginx_file("", "content");
        assert!(matches!(result, Err(FileCreationError::InvalidPath(_))));
    }

    /// Tests that empty content is rejected
    #[test]
    fn test_reject_empty_content() {
        let test_dir = create_test_dir();
        let file_path = test_dir.join("test.conf");

        // Test various forms of empty content
        let empty_contents = vec!["", "   ", "\t\n", "\n\n\n"];

        for content in empty_contents {
            let result = create_nginx_file(file_path.to_str().unwrap(), content);
            assert!(
                matches!(result, Err(FileCreationError::InvalidPath(_))),
                "Content '{}' should be rejected as empty",
                content.escape_debug()
            );
        }

        cleanup_test_dir(&test_dir);
    }

    /// Tests that existing files cannot be overwritten
    #[test]
    fn test_reject_existing_file() {
        let test_dir = create_test_dir();
        let file_path = test_dir.join("test.conf");
        let content = "server { listen 80; }";

        // Create file first time - should succeed
        let result = create_nginx_file(file_path.to_str().unwrap(), content);
        assert!(result.is_ok());

        // Try to create same file again - should fail
        let result2 = create_nginx_file(file_path.to_str().unwrap(), content);
        assert!(result2.is_err());
        
        if let Err(FileCreationError::FileWriteFailed(msg)) = result2 {
            assert!(
                msg.contains("already exists"),
                "Error should mention file exists"
            );
        } else {
            panic!("Expected FileWriteFailed error");
        }

        cleanup_test_dir(&test_dir);
    }

    /// Tests that parent directories are created if missing
    #[test]
    fn test_create_parent_directories() {
        let test_dir = create_test_dir();
        let nested_path = test_dir.join("nested/deep/dir/test.conf");
        let content = "server { listen 80; }";

        let result = create_nginx_file(nested_path.to_str().unwrap(), content);
        assert!(result.is_ok());
        assert!(nested_path.exists());
        
        // Verify all parent directories were created
        assert!(nested_path.parent().unwrap().exists());

        cleanup_test_dir(&test_dir);
    }

    // ===== Append Tests =====

    /// Tests successful appending to an existing file
    #[test]
    fn test_append_to_existing_file() {
        let test_dir = create_test_dir();
        let file_path = test_dir.join("test.conf");
        let initial_content = "server { listen 80; }";
        let append_content = "location / { return 200; }";

        // Create initial file
        create_nginx_file(file_path.to_str().unwrap(), initial_content).unwrap();

        // Append content
        let result = append_to_nginx_file(file_path.to_str().unwrap(), append_content);
        assert!(result.is_ok());

        // Verify appended content with newline separator
        let full_content = fs::read_to_string(&file_path).unwrap();
        assert!(full_content.contains(initial_content));
        assert!(full_content.contains(append_content));
        assert_eq!(
            full_content,
            format!("{}\n{}", initial_content, append_content)
        );

        cleanup_test_dir(&test_dir);
    }

    /// Tests multiple appends maintain proper formatting
    #[test]
    fn test_multiple_appends() {
        let test_dir = create_test_dir();
        let file_path = test_dir.join("test.conf");
        
        // Create initial file
        create_nginx_file(file_path.to_str().unwrap(), "server {").unwrap();
        
        // Append multiple times
        let appends = vec![
            "    listen 80;",
            "    server_name example.com;",
            "    location / {",
            "        return 200;",
            "    }",
            "}",
        ];
        
        for content in &appends {
            append_to_nginx_file(file_path.to_str().unwrap(), content).unwrap();
        }
        
        let final_content = fs::read_to_string(&file_path).unwrap();
        
        // Each append should be on its own line
        let lines: Vec<&str> = final_content.lines().collect();
        assert_eq!(lines[0], "server {");
        for (i, expected) in appends.iter().enumerate() {
            assert_eq!(lines[i + 1], *expected);
        }

        cleanup_test_dir(&test_dir);
    }

    /// Tests that appending to non-existent files fails
    #[test]
    fn test_append_to_non_existent_file() {
        let test_dir = create_test_dir();
        let file_path = test_dir.join("nonexistent.conf");

        let result = append_to_nginx_file(file_path.to_str().unwrap(), "content");
        assert!(result.is_err());
        
        if let Err(FileCreationError::FileWriteFailed(msg)) = result {
            assert!(
                msg.contains("Cannot open file"),
                "Error should mention cannot open file"
            );
        } else {
            panic!("Expected FileWriteFailed error");
        }

        cleanup_test_dir(&test_dir);
    }

    /// Tests that empty content cannot be appended
    #[test]
    fn test_append_empty_content() {
        let test_dir = create_test_dir();
        let file_path = test_dir.join("test.conf");

        // Create initial file
        create_nginx_file(file_path.to_str().unwrap(), "server { }").unwrap();

        // Try to append various empty contents
        let empty_contents = vec!["", "  ", "\n\n", "\t"];
        
        for content in empty_contents {
            let result = append_to_nginx_file(file_path.to_str().unwrap(), content);
            assert!(
                result.is_err(),
                "Empty content '{}' should be rejected",
                content.escape_debug()
            );
            assert!(matches!(result, Err(FileCreationError::InvalidPath(_))));
        }

        cleanup_test_dir(&test_dir);
    }

    /// Tests append with path validation
    #[test]
    fn test_append_path_validation() {
        // Test that append also validates paths properly
        let invalid_paths = vec![
            "/etc/nginx/../passwd",
            "/home/user/test.conf",
            "/tmp/test.txt",
        ];
        
        for path in invalid_paths {
            let result = append_to_nginx_file(path, "server { }");
            assert!(result.is_err(), "Path {} should be rejected", path);
        }
    }

    // ===== Integration Tests =====

    /// Tests the complete workflow: create, append, and verify
    #[test]
    fn test_complete_workflow() {
        let test_dir = create_test_dir();
        let file_path = test_dir.join("workflow.conf");
        let path_str = file_path.to_str().unwrap();
        
        // Step 1: Create initial config
        let initial = "server {\n    listen 80;\n    server_name example.com;";
        create_nginx_file(path_str, initial).unwrap();
        
        // Step 2: Add location block
        let location = "    location / {\n        try_files $uri $uri/ =404;\n    }";
        append_to_nginx_file(path_str, location).unwrap();
        
        // Step 3: Close server block
        append_to_nginx_file(path_str, "}").unwrap();
        
        // Verify final structure
        let final_content = fs::read_to_string(&file_path).unwrap();
        assert!(final_content.contains("server {"));
        assert!(final_content.contains("listen 80"));
        assert!(final_content.contains("location /"));
        assert!(final_content.ends_with("}\n}"));

        cleanup_test_dir(&test_dir);
    }

    /// Tests concurrent file operations behavior
    #[test]
    fn test_concurrent_operations() {
        use std::sync::{Arc, Barrier};
        use std::thread;
        
        let test_dir = create_test_dir();
        let file_path = Arc::new(test_dir.join("concurrent.conf"));
        let barrier = Arc::new(Barrier::new(2));
        
        // Create initial file
        create_nginx_file(file_path.to_str().unwrap(), "server { listen 80; }").unwrap();
        
        let path1 = Arc::clone(&file_path);
        let barrier1 = Arc::clone(&barrier);
        let handle1 = thread::spawn(move || {
            barrier1.wait();
            append_to_nginx_file(path1.to_str().unwrap(), "# Thread 1")
        });
        
        let path2 = Arc::clone(&file_path);
        let barrier2 = Arc::clone(&barrier);
        let handle2 = thread::spawn(move || {
            barrier2.wait();
            append_to_nginx_file(path2.to_str().unwrap(), "# Thread 2")
        });
        
        let result1 = handle1.join().unwrap();
        let result2 = handle2.join().unwrap();
        
        // Both should succeed
        assert!(result1.is_ok());
        assert!(result2.is_ok());
        
        // File should contain both appends
        let content = fs::read_to_string(file_path.as_ref()).unwrap();
        assert!(content.contains("# Thread 1"));
        assert!(content.contains("# Thread 2"));

        cleanup_test_dir(&test_dir.to_path_buf());
    }

    // ===== Nginx Reload Tests =====
    
    /// Tests reload_nginx with mock (actual test would require nginx)
    #[test]
    #[ignore] // Requires nginx to be installed
    fn test_reload_nginx_integration() {
        use tempfile::TempDir;
        // This test would only work on systems with nginx installed
        // and proper permissions
        
        // Create a test config first
        let temp_dir = TempDir::new().unwrap();
        let config_path = temp_dir.path().join("test.conf");
        create_nginx_file(
            config_path.to_str().unwrap(),
            "server { listen 8888; server_name test.local; }"
        ).unwrap();
        
        // Try to reload (will fail without proper setup)
        let result = reload_nginx();
        
        // We can't assert success without nginx, but function should return Result
        match result {
            Ok(()) => println!("Nginx reloaded successfully"),
            Err(e) => println!("Expected error without nginx: {}", e),
        }
    }
}

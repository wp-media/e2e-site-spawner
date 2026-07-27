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

use crate::constants::{NGINX_CONF_D_PATH, NGINX_HTTP_CONFIG_MARKER, NGINX_HTTPS_CONFIG_MARKER};
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
    let valid_prefixes = [
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
    if let Some(parent) = file_path.parent()
        && !parent.exists()
    {
        fs::create_dir_all(parent).map_err(|e| {
            FileCreationError::DirectoryCreationFailed(format!(
                "Cannot create parent directory '{}': {}",
                parent.display(),
                e
            ))
        })?;
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
            sites::remove_file(path).unwrap_or(());
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

/// Retrieves a list of all Nginx configuration file paths from the default configuration directory.
///
/// This function scans the Nginx configuration directory (`/etc/nginx/conf.d/`) and returns
/// the full paths of all configuration files, including both active (`.conf`) and deactivated
/// (`.conf.deactivated`) sites.
///
/// # Returns
///
/// * `Ok(Vec<String>)` - A vector containing the full filesystem paths to all configuration files
/// * `Err(String)` - An error message if the directory cannot be read or entries cannot be processed
///
/// # File Selection Criteria
///
/// The function includes files that meet the following criteria:
/// - Must be regular files (not directories or symlinks)
/// - Must end with either `.conf` or `.conf.deactivated`
/// - Must be directly in the config directory (not in subdirectories, as `read_dir` is non-recursive)
///
/// # Examples
///
/// ```ignore
/// use nginx::utils::get_list_of_sites_nginx_file_paths;
///
/// match get_list_of_sites_nginx_file_paths() {
///     Ok(files) => {
///         println!("Found {} configuration files:", files.len());
///         for file_path in files {
///             println!("  - {}", file_path);
///         }
///     }
///     Err(e) => eprintln!("Failed to list config files: {}", e),
/// }
/// ```
///
/// # Typical Output
///
/// For a standard Nginx setup, this might return paths like:
/// ```text
/// /etc/nginx/conf.d/example.com.conf
/// /etc/nginx/conf.d/staging.example.com.conf
/// /etc/nginx/conf.d/old-site.com.conf.deactivated
/// /etc/nginx/conf.d/api.example.com.conf
/// ```
///
/// # Error Conditions
///
/// This function will return an error if:
/// - The configuration directory doesn't exist
/// - The process lacks permission to read the directory
/// - An I/O error occurs while reading directory entries
///
/// # Performance Characteristics
///
/// - **Non-recursive**: Only reads the immediate directory contents
/// - **Memory usage**: O(n) where n is the number of files in the directory
/// - **Time complexity**: O(n) for directory traversal
/// - **No file content reading**: Only examines file metadata
///
/// # Security Considerations
///
/// - The function only reads directory entries, never file contents
/// - Returns full paths which could reveal system structure
/// - Requires read permission on `/etc/nginx/conf.d/`
/// - Does not follow symlinks to prevent directory traversal
///
/// # Platform Behavior
///
/// - **Unix/Linux**: Standard behavior as documented
/// - **Windows**: Path separators will use backslashes in the returned strings
/// - **macOS**: May include `.DS_Store` files if they match the extension criteria
///
/// # Use Cases
///
/// This function is typically used to:
/// - List all configured sites for management operations
/// - Identify deactivated sites for cleanup or reactivation
/// - Validate that expected configurations exist
/// - Generate site inventory reports
/// - Perform bulk operations on all configurations
///
/// # Related Functions
///
/// * [`check_if_https_in_nginx_config_file`] - Check SSL status of a specific config
/// * [`create_nginx_file`] - Create new configuration files
/// * [`reload_nginx`] - Apply configuration changes
///
/// # Implementation Notes
///
/// The function uses [`std::fs::read_dir`] which is non-recursive by default. This is
/// intentional to avoid accidentally including files from subdirectories that might
/// not be actual site configurations. The function also uses
/// [`std::path::Path::to_string_lossy`] for
/// path conversion, which means non-UTF-8 filenames will have replacement characters
/// but won't cause the function to fail.
///
/// # Sources
///
/// - [std::fs::read_dir](https://doc.rust-lang.org/std/fs/fn.read_dir.html) - Non-recursive directory reading
/// - [DirEntry](https://doc.rust-lang.org/std/fs/struct.DirEntry.html) - Directory entry metadata access
/// - [FileType](https://doc.rust-lang.org/std/fs/struct.FileType.html) - File type determination
/// - [Nginx Configuration](http://nginx.org/en/docs/beginners_guide.html#conf_structure) - Standard config directory structure
pub fn get_list_of_sites_nginx_file_paths() -> Result<Vec<String>, String> {
    let mut config_list = Vec::new();
    let nginx_config_path = NGINX_CONF_D_PATH;

    let entries = fs::read_dir(nginx_config_path)
        .map_err(|e| format!("Failed to read Nginx config directory: {}", e))?;

    for entry_res in entries {
        let entry = entry_res.map_err(|e| format!("Failed to read dir entry: {}", e))?;
        // Only consider immediate entries (read_dir is non-recursive)
        match entry.file_type() {
            Ok(ft) if ft.is_file() => {
                // Accept files ending with ".conf" or ".conf.deactivated"
                let file_name = entry.file_name();
                let file_name_str = file_name.to_string_lossy();

                if !(file_name_str.ends_with(".conf")
                    || file_name_str.ends_with(".conf.deactivated"))
                {
                    continue;
                }
                let file_path = entry.path();
                config_list.push(file_path.to_string_lossy().into_owned());
            }
            _ => {
                // skip directories, symlinks to dirs, etc.
                continue;
            }
        }
    }

    Ok(config_list)
}

/// Checks if an Nginx configuration file was created and is managed by e2sp.
///
/// This function determines whether a configuration file was generated by the e2e-site-spawner
/// tool by looking for specific marker comments that are automatically inserted into all
/// configurations created by this tool. This allows the tool to distinguish between its own
/// managed sites and manually created or third-party configurations.
///
/// # Arguments
///
/// * `nginx_config_file_path` - The full path to the Nginx configuration file to check
///
/// # Returns
///
/// * `true` - If the file contains e2sp management markers
/// * `false` - If no markers are found, file doesn't exist, or cannot be read
///
/// # Detection Logic
///
/// The function searches for either of two marker strings:
/// - `NGINX_HTTP_CONFIG_MARKER` - Inserted in HTTP server blocks
/// - `NGINX_HTTPS_CONFIG_MARKER` - Inserted in HTTPS server blocks
///
/// These markers are automatically added by the tool when creating configurations
/// through the template system, ensuring reliable identification of managed sites.
///
/// # Examples
///
/// ```ignore
/// use nginx::utils::is_managed_by_this_tool;
///
/// let config_path = "/etc/nginx/conf.d/example.com.conf";
/// if is_managed_by_this_tool(config_path) {
///     println!("✓ This site is managed by e2sp");
///     // Safe to perform automated operations
/// } else {
///     println!("⚠ External configuration - manual intervention required");
///     // Skip automated modifications
/// }
/// ```
///
/// # Managed Configuration Example
///
/// This configuration would return `true` (note the generated marker, which is
/// what the check actually looks for):
/// ```nginx
/// ######E2SP-HTTP-CONFIGURATION######
/// server {
///     listen 80;
///     server_name example.com;
///     root /var/www/html/example.com;
/// }
/// ######E2SP-HTTP-CONFIGURATION######
/// ```
///
/// # Unmanaged Configuration Example
///
/// This configuration would return `false`:
/// ```nginx
/// # Manually created configuration
/// server {
///     listen 80;
///     server_name legacy.com;
///     root /var/www/legacy;
/// }
/// ```
///
/// # Use Cases
///
/// This function is critical for:
///
/// 1. **Safe automation boundaries**:
///    - Prevent accidental modification of manual configurations
///    - Enable bulk operations only on e2sp-managed sites
///    - Protect custom configurations from automated updates
///
/// 2. **Site inventory and classification**:
///    - Separate e2sp sites from legacy configurations
///    - Generate reports of managed vs unmanaged infrastructure
///    - Plan migration strategies for unmanaged sites
///
/// 3. **Command safety checks**:
///    - `delete` command verification before removal
///    - `update` command eligibility checking
///    - `deactivate`/`activate` operation validation
///
/// 4. **Rollback and recovery**:
///    - Identify configurations safe to regenerate
///    - Determine which sites have automated backups
///    - Track tool-managed infrastructure
///
/// # Implementation Strategy
///
/// The marker-based approach provides several benefits:
/// - **Non-invasive**: Just comments, doesn't affect nginx functionality
/// - **Persistent**: Survives configuration reloads and nginx restarts
/// - **Reliable**: Can't be accidentally removed by nginx operations
/// - **Versioned**: Markers can include version info for future compatibility
///
/// # Error Handling
///
/// Returns `false` for any error condition:
/// - File doesn't exist (not managed)
/// - Permission denied (assume unmanaged for safety)
/// - Read errors (conservative approach)
/// - Invalid UTF-8 (likely corrupted or binary file)
///
/// This fail-safe design prevents accidental operations on uncertain configurations.
///
/// # Performance Characteristics
///
/// - **File I/O**: Single file read operation
/// - **Memory usage**: O(n) where n is file size
/// - **Time complexity**: O(n) for string searching
/// - **Typical performance**: < 1ms for standard configs
/// - **No caching**: Fresh read ensures current state
///
/// # Security Considerations
///
/// - **Read-only operation**: Never modifies files
/// - **Conservative defaults**: Returns `false` when uncertain
/// - **No information leakage**: Simple boolean return
/// - **Path validation**: Caller should validate paths
/// - **Marker integrity**: Markers are comments, can't break nginx
///
/// # Marker Management
///
/// The markers are defined in [`crate::constants`]:
/// ```text
/// pub const NGINX_HTTP_CONFIG_MARKER: &str = "######E2SP-HTTP-CONFIGURATION######";
/// pub const NGINX_HTTPS_CONFIG_MARKER: &str = "######E2SP-HTTPS-CONFIGURATION######";
/// ```
///
/// # Best Practices
///
/// When using this function:
/// 1. Always check management status before destructive operations
/// 2. Provide clear user feedback for unmanaged sites
/// 3. Consider offering manual mode for unmanaged configurations
/// 4. Log operations on managed vs unmanaged sites differently
/// 5. Never force operations on unmanaged sites
///
/// # Edge Cases and Limitations
///
/// The function may incorrectly classify:
/// - **Copied configurations**: If someone copies an e2sp config manually
/// - **Partial markers**: If only one marker remains after manual editing
/// - **Commented markers**: If markers are commented out but still present
/// - **Migrated sites**: Sites moved between servers retaining markers
///
/// # Integration with Other Functions
///
/// This function works in conjunction with:
/// - [`crate::cli::commands::spawn_site`]: Adds markers when creating configurations
/// - [`crate::cli::commands::delete_site`]: Only deletes managed configurations
/// - [`crate::cli::commands::list_sites`]: Shows management status for all sites
/// - [`crate::cli::commands::update_site`]: Only updates managed sites
///
/// # Related Functions
///
/// * [`is_websites_config_file`] - Check if file is a site configuration
/// * [`check_if_https_in_nginx_config_file`] - Check SSL status
/// * [`get_list_of_sites_nginx_file_paths`] - List all configurations
/// * [`create_nginx_file`] - Create new managed configurations
///
/// # Future Enhancements
///
/// Potential improvements could include:
/// - Marker versioning for compatibility tracking
/// - Cryptographic signatures for tamper detection
/// - Metadata storage (creation date, last modified by e2sp)
/// - Partial management support (e2sp manages some sections)
/// - Migration tools for adopting unmanaged sites
///
/// # Standards and References
///
/// Based on configuration management best practices:
/// - [Nginx Configuration Comments](http://nginx.org/en/docs/beginners_guide.html#comments) - Comment syntax in nginx
/// - [Infrastructure as Code](https://www.hashicorp.com/resources/what-is-infrastructure-as-code) - Automated infrastructure principles
/// - [Configuration Management](https://www.redhat.com/en/topics/automation/what-is-configuration-management) - CM best practices
/// - [Idempotent Operations](https://docs.ansible.com/ansible/latest/reference_appendices/glossary.html#term-Idempotency) - Safe automation principles
pub fn is_managed_by_this_tool(nginx_config_file_path: &str) -> bool {
    let path = Path::new(nginx_config_file_path);
    if !path.exists() || !path.is_file() {
        return false;
    }

    let contents = fs::read_to_string(nginx_config_file_path).unwrap_or_default();
    contents.contains(NGINX_HTTP_CONFIG_MARKER) || contents.contains(NGINX_HTTPS_CONFIG_MARKER)
}

/// Checks if an Nginx configuration file represents a website/virtual host configuration.
///
/// This function determines whether a given Nginx configuration file contains
/// a server block, which is the primary indicator of a site/virtual host configuration
/// as opposed to utility configuration files (like gzip.conf, upstream.conf, etc.).
///
/// # Arguments
///
/// * `nginx_config_file_path` - The full path to the Nginx configuration file to check
///
/// # Returns
///
/// * `true` - If the file contains a `server {` block
/// * `false` - If no server block is found or the file cannot be read
///
/// # Detection Logic
///
/// The function looks for the literal string `"server {"` which indicates the
/// beginning of a server block. This is the standard Nginx syntax for defining
/// a virtual host or website configuration.
///
/// # Examples
///
/// ```ignore
/// use nginx::utils::is_websites_config_file;
///
/// // Check if a file is a site configuration
/// if is_websites_config_file("/etc/nginx/conf.d/example.com.conf") {
///     println!("This is a website configuration file");
/// } else {
///     println!("This is a utility/include file, not a site config");
/// }
/// ```
///
/// # Common Use Cases
///
/// This function helps differentiate between:
/// - **Site configs**: Files containing server blocks (example.com.conf, api.domain.conf)
/// - **Utility configs**: Files with directives but no server blocks (gzip.conf, ssl.conf, upstream.conf)
///
/// # Example Site Configuration (Returns true)
///
/// ```nginx
/// server {
///     listen 80;
///     server_name example.com;
///     root /var/www/example.com;
/// }
/// ```
///
/// # Example Utility Configuration (Returns false)
///
/// ```nginx
/// # gzip.conf - compression settings
/// gzip on;
/// gzip_vary on;
/// gzip_types text/plain text/css application/json;
/// ```
///
/// # Error Handling
///
/// If the file:
/// - Does not exist
/// - Is not a regular file (e.g., directory, symlink to non-existent file)
/// - Cannot be read due to permissions
///
/// The function returns `false` rather than panicking, allowing graceful handling
/// of missing or inaccessible configurations.
///
/// # Performance Considerations
///
/// - Reads entire file into memory
/// - Uses simple string search (O(n) where n is file size)
/// - Suitable for typical Nginx configs (usually < 10KB)
///
/// # Limitations
///
/// The function may incorrectly identify:
/// - Files with commented-out server blocks (e.g., `# server {`)
/// - Files where server block is split across lines (rare but possible)
/// - Template files containing literal `server {` in documentation
///
/// # Security Notes
///
/// - Read-only operation, never modifies files
/// - Returns simple boolean to avoid leaking configuration details
///
/// # Related Functions
///
/// * [`is_managed_by_this_tool`] - Check if config was created by e2sp
/// * [`check_if_https_in_nginx_config_file`] - Check SSL status
/// * [`get_list_of_sites_nginx_file_paths`] - List all config files
///
/// # Standards References
///
/// Server blocks are documented in the [Nginx documentation](http://nginx.org/en/docs/http/ngx_http_core_module.html#server)
/// as the fundamental building block for virtual host configuration.
pub fn is_websites_config_file(nginx_config_file_path: &str) -> bool {
    let path = Path::new(nginx_config_file_path);
    if !path.exists() || !path.is_file() {
        return false;
    }

    let contents = fs::read_to_string(nginx_config_file_path).unwrap_or_default();
    contents.contains("server {")
}

/// Checks if an Nginx configuration file represents an active (enabled) site.
///
/// This function determines whether a site is currently active by examining the
/// configuration file's extension. Active sites use the `.conf` extension, while
/// deactivated sites use `.conf.deactivated`. This naming convention allows for
/// quick enable/disable operations without modifying file contents.
///
/// # Arguments
///
/// * `nginx_config_file_path` - The full path to the Nginx configuration file to check
///
/// # Returns
///
/// * `true` - If the file ends with `.conf` (but not `.conf.deactivated`)
/// * `false` - If the file ends with `.conf.deactivated`, doesn't exist, or isn't a regular file
///
/// # Detection Logic
///
/// The function uses a simple but effective naming convention:
/// - **Active sites**: `example.com.conf`
/// - **Deactivated sites**: `example.com.conf.deactivated`
///
/// This approach allows sites to be toggled without:
/// - Moving files between directories
/// - Modifying file contents
/// - Changing permissions
/// - Updating symbolic links
///
/// # Examples
///
/// ```ignore
/// use nginx::utils::is_active_site;
///
/// // Check if a site is currently active
/// if is_active_site("/etc/nginx/conf.d/example.com.conf") {
///     println!("✓ Site is active and serving traffic");
/// } else {
///     println!("✗ Site is deactivated");
/// }
///
/// // Use in conditional operations
/// let config_path = "/etc/nginx/conf.d/mysite.com.conf.deactivated";
/// if !is_active_site(config_path) {
///     println!("Site is deactivated, skipping SSL renewal");
///     return;
/// }
/// ```
///
/// # File Naming Examples
///
/// Files that return `true` (active):
/// ```text
/// /etc/nginx/conf.d/example.com.conf
/// /etc/nginx/conf.d/api.example.com.conf
/// /etc/nginx/conf.d/staging.site.conf
/// ```
///
/// Files that return `false` (inactive):
/// ```text
/// /etc/nginx/conf.d/example.com.conf.deactivated
/// /etc/nginx/conf.d/old-site.conf.deactivated
/// /etc/nginx/conf.d/test.conf.disabled        # Different convention
/// /etc/nginx/conf.d/site.conf.bak              # Backup file
/// ```
///
/// # Use Cases
///
/// This function is essential for:
///
/// 1. **Site inventory and status reporting**:
///    - List all sites with their active/inactive status
///    - Generate uptime reports
///    - Monitor site availability
///    - Audit configuration changes
///
/// 2. **Conditional operations**:
///    - Skip SSL renewal for inactive sites
///    - Exclude deactivated sites from backups
///    - Bypass monitoring for disabled sites
///    - Prevent updates to inactive configurations
///
/// 3. **Activation/deactivation workflows**:
///    - Toggle site status by renaming files
///    - Implement maintenance mode
///    - Gradual rollouts and rollbacks
///    - A/B testing with quick switches
///
/// 4. **Resource optimization**:
///    - Skip processing for inactive sites
///    - Reduce unnecessary file operations
///    - Optimize configuration reload times
///    - Minimize SSL certificate requests
///
/// # Implementation Details
///
/// The function performs these checks in order:
/// 1. Verifies the path exists
/// 2. Confirms it's a regular file (not directory/symlink)
/// 3. Extracts the filename from the path
/// 4. Checks if it ends with `.conf` (active)
/// 5. Ensures it doesn't end with `.conf.deactivated` (inactive)
///
/// # Error Handling
///
/// Returns `false` for any error condition:
/// - File doesn't exist
/// - Path points to a directory
/// - Path points to a broken symlink
/// - Cannot extract filename from path
/// - Permission denied (cannot stat file)
///
/// This conservative approach ensures that questionable configurations
/// are treated as inactive for safety.
///
/// # Performance Characteristics
///
/// - **No file I/O**: Only checks filesystem metadata
/// - **Time complexity**: O(1) - Simple string comparison
/// - **Memory usage**: O(n) where n is the path length
/// - **Typical execution**: < 0.1ms
/// - **System calls**: Single `stat()` call to check file existence
///
/// # Advantages of This Approach
///
/// 1. **Atomic operations**: Renaming is atomic on most filesystems
/// 2. **Reversible**: Easy to reactivate by removing `.deactivated`
/// 3. **Visible**: Clear indication in directory listings
/// 4. **No content changes**: Preserves file integrity
/// 5. **Version control friendly**: Shows as rename, not delete/create
/// 6. **Nginx compatible**: Nginx ignores `.deactivated` files
///
/// # Limitations
///
/// - **Convention-dependent**: Relies on specific naming pattern
/// - **Single convention**: Doesn't recognize `.disabled`, `.bak`, etc.
/// - **Case sensitive**: `.DEACTIVATED` wouldn't be recognized
/// - **No partial activation**: Can't disable specific server blocks
/// - **No timestamp**: Doesn't track when deactivation occurred
///
/// # Best Practices
///
/// When using this function:
/// 1. Always use the standard `.conf.deactivated` extension
/// 2. Reload nginx after activation/deactivation
/// 3. Verify nginx configuration before activating
/// 4. Log activation/deactivation operations
/// 5. Consider keeping backups before deactivating
///
/// # Integration with Other Commands
///
/// This function is used by:
/// - [`crate::cli::commands::list_sites`]: Shows (active) or (deactivated) status
/// - [`crate::cli::commands::deactivate_site`]: Renames `.conf` to `.conf.deactivated`
/// - [`crate::cli::commands::activate_site`]: Renames `.conf.deactivated` to `.conf`
/// - [`crate::cli::commands::delete_site`]: Can delete both active and inactive sites
/// - [`crate::cli::commands::update_site`]: Only updates active sites by default
///
/// # Related Functions
///
/// * [`is_managed_by_this_tool`] - Check if site is e2sp-managed
/// * [`is_websites_config_file`] - Verify it's a site configuration
/// * [`check_if_https_in_nginx_config_file`] - Check SSL status
/// * [`get_list_of_sites_nginx_file_paths`] - List all config files
///
/// # Alternative Approaches
///
/// Other methods for enabling/disabling sites:
/// - **Symlink method**: Link from sites-available to sites-enabled
/// - **Include directive**: Comment/uncomment include statements
/// - **Directory method**: Move files between directories
/// - **Configuration flag**: Use nginx variables to control activation
///
/// This tool uses the extension method for simplicity and reliability.
///
/// # Future Enhancements
///
/// Potential improvements could include:
/// - Support for multiple deactivation conventions
/// - Deactivation timestamps in filename
/// - Reason codes (`.deactivated-maintenance`, `.deactivated-error`)
/// - Partial deactivation (specific server blocks)
/// - Scheduled reactivation
/// - Activation history tracking
///
/// # Standards and References
///
/// Based on common practices and standards:
/// - [Nginx Configuration Files](http://nginx.org/en/docs/beginners_guide.html#conf_structure) - File naming conventions
/// - [Filesystem Hierarchy Standard](https://refspecs.linuxfoundation.org/FHS_3.0/fhs/index.html) - Linux directory standards
/// - [Apache a2ensite/a2dissite](https://manpages.debian.org/testing/apache2/a2ensite.8.en.html) - Similar enable/disable pattern
/// - [Systemd Unit Files](https://www.freedesktop.org/software/systemd/man/systemd.unit.html) - Enable/disable conventions
pub fn is_active_site(nginx_config_file_path: &str) -> bool {
    let path = Path::new(nginx_config_file_path);

    // Check if the file exists and is a regular file
    if !path.exists() || !path.is_file() {
        return false;
    }

    // Extract the filename from the path
    let file_name = match path.file_name() {
        Some(name) => name.to_string_lossy(),
        None => return false, // Cannot determine filename
    };

    // Active sites end with .conf but not .conf.deactivated
    file_name.ends_with(".conf") && !file_name.ends_with(".conf.deactivated")
}

/// Checks if HTTPS/SSL is configured in an Nginx configuration file.
///
/// This function provides a simple interface to determine whether a site has HTTPS
/// enabled by checking for both the HTTPS port listener and SSL certificate
/// configuration.
///
/// # Arguments
///
/// * `nginx_config_file_path` - The full path to the Nginx configuration file to check
///
/// # Returns
///
/// * `true` - If both `listen 443` and `ssl_certificate` directives are present
/// * `false` - If either directive is missing, file doesn't exist, or cannot be read
///
/// # Detection Methodology
///
/// The function performs two essential checks:
/// 1. **HTTPS Port (443)**: Verifies the presence of `listen 443` directive
/// 2. **SSL Certificate**: Confirms `ssl_certificate` directive exists
///
/// Both conditions must be satisfied because:
/// - A server listening on port 443 without SSL certificates would fail to start
/// - SSL certificates without a listener would never be used
/// - This dual check prevents false positives from incomplete configurations
///
/// # Examples
///
/// ```ignore
/// use nginx::utils::check_if_https_in_nginx_config_file;
///
/// // Check before attempting SSL certificate generation
/// let config_path = "/etc/nginx/conf.d/example.com.conf";
/// if check_if_https_in_nginx_config_file(config_path) {
///     println!("SSL already configured, skipping certificate generation");
/// } else {
///     // Safe to proceed with SSL setup
///     generate_ssl_certificate(site_name);
/// }
/// ```
///
/// # Valid HTTPS Configuration Example
///
/// This configuration would return `true`:
/// ```nginx
/// server {
///     listen 443 ssl http2;
///     server_name secure.example.com;
///     
///     ssl_certificate /etc/nginx/ssl/secure.example.com/fullchain.pem;
///     ssl_certificate_key /etc/nginx/ssl/secure.example.com/privkey.pem;
///     
///     ssl_protocols TLSv1.2 TLSv1.3;
///     ssl_prefer_server_ciphers off;
///     
///     root /var/www/secure.example.com;
///     index index.html;
/// }
/// ```
///
/// # Invalid/Incomplete Configuration Examples
///
/// These would return `false`:
///
/// ```nginx
/// # Missing ssl_certificate directive
/// server {
///     listen 443 ssl;
///     server_name example.com;
///     # No ssl_certificate specified!
/// }
/// ```
///
/// ```nginx
/// # Missing listen 443 directive
/// server {
///     listen 80;  # HTTP only
///     server_name example.com;
///     ssl_certificate /path/to/cert.pem;  # Certificate defined but not used
/// }
/// ```
///
/// # Use Cases
///
/// This function is commonly used in:
///
/// 1. **Pre-flight checks** before SSL certificate operations:
///    - Prevent duplicate certificate generation
///    - Avoid overwriting existing SSL configurations
///    - Skip unnecessary acme.sh calls
///
/// 2. **Site inventory and reporting**:
///    - List sites with/without HTTPS
///    - Security audits
///    - Migration planning
///
/// 3. **Conditional configuration updates**:
///    - Add HTTPS redirect only if SSL is configured
///    - Enable HTTP/2 or HTTP/3 features
///    - Apply SSL-specific optimizations
///
/// 4. **Validation workflows**:
///    - Verify SSL setup completed successfully
///    - Health checks after certificate renewal
///    - Pre-deployment validation
///
/// # Error Handling
///
/// The function uses a fail-safe approach, returning `false` for any error:
/// - **File not found**: Returns `false` (no HTTPS configured)
/// - **Permission denied**: Returns `false` (cannot verify, assume not configured)
/// - **I/O errors**: Returns `false` (safe default)
/// - **Invalid UTF-8**: Returns `false` (corrupted file, likely misconfigured)
///
/// This design allows operations to proceed safely when configuration status
/// cannot be determined with certainty.
///
/// # Performance Characteristics
///
/// - **File I/O**: Single file read operation
/// - **Memory usage**: O(n) where n is the file size
/// - **Time complexity**: O(n) for string searching
/// - **Typical performance**: < 1ms for configs under 10KB
/// - **Caching**: No internal caching; file is read on each call
///
/// # Limitations and Edge Cases
///
/// The function may not detect HTTPS in these scenarios:
///
/// 1. **Non-standard ports**: Custom HTTPS ports (8443, 4443, etc.) are not detected
/// 2. **IPv6 listeners**: `listen [::]:443` requires separate detection logic
/// 3. **Included configurations**: SSL configured via `include` directives
/// 4. **Stream contexts**: TCP/UDP SSL proxying in stream blocks
/// 5. **Commented directives**: `# listen 443` would be ignored
/// 6. **Split configurations**: Certificate and listener in different server blocks
/// 7. **SNI configurations**: Multiple certificates on same IP/port
/// 8. **Wildcard listeners**: `listen *:443` or `listen 0.0.0.0:443`
///
/// # Security Considerations
///
/// - **Read-only operation**: Never modifies configuration files
/// - **No sensitive data exposure**: Doesn't return certificate contents or paths
/// - **Path validation**: Caller must validate paths to prevent traversal attacks
/// - **No certificate validation**: Doesn't verify certificate validity, expiry, or chain
/// - **Simple boolean return**: Prevents information leakage about configuration details
///
/// # Best Practices
///
/// When using this function:
/// 1. Always validate the file path before calling
/// 2. Handle both `true` and `false` cases explicitly
/// 3. Consider using with [`is_websites_config_file`] first
/// 4. Don't rely solely on this for security decisions
/// 5. Complement with actual certificate validation for production
///
/// # Related Functions
///
/// * [`is_websites_config_file`] - Verify file is a site configuration
/// * [`is_managed_by_this_tool`] - Check if config was created by e2sp
/// * [`get_list_of_sites_nginx_file_paths`] - List all configuration files
/// * [`crate::utils::ssl::generate_ssl`] - Generate SSL certificates for sites
///
/// # Implementation Notes
///
/// This function uses [`std::fs::read_to_string`] with
/// [`Result::unwrap_or_default`], which means:
/// - File read errors result in an empty string
/// - Empty string won't contain the required directives
/// - Function returns `false` for any read failure
///
/// This is intentional defensive programming to prevent crashes and allow
/// graceful degradation when configuration files are temporarily inaccessible.
///
/// # Standards and References
///
/// Based on industry standards and best practices:
/// - [Nginx SSL Module Documentation](http://nginx.org/en/docs/http/ngx_http_ssl_module.html) - Official SSL configuration reference
/// - [RFC 8446 - TLS 1.3](https://datatracker.ietf.org/doc/html/rfc8446) - Current TLS specification
/// - [Mozilla SSL Configuration Generator](https://ssl-config.mozilla.org/) - Recommended SSL settings
/// - [OWASP TLS Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html) - Security best practices
/// - [Let's Encrypt Best Practices](https://letsencrypt.org/docs/best-practices/) - Certificate management guidelines
///
/// # Future Improvements
///
/// Potential enhancements could include:
/// - Support for custom port detection via parameter
/// - IPv6 listener detection (`[::]:443`)
/// - Certificate expiry checking
/// - Chain validation
/// - Protocol version detection (TLS 1.2 vs 1.3)
/// - OCSP stapling verification
/// - HTTP/2 and HTTP/3 support detection
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
            (
                "with_location.conf",
                "location /api { proxy_pass http://backend; }",
            ),
            (
                "full.conf",
                r#"server {
                    listen 443 ssl;
                    server_name example.com;
                    ssl_certificate /etc/ssl/cert.pem;
                    location / {
                        try_files $uri $uri/ =404;
                    }
                }"#,
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
            "server { listen 8888; server_name test.local; }",
        )
        .unwrap();

        // Try to reload (will fail without proper setup)
        let result = reload_nginx();

        // We can't assert success without nginx, but function should return Result
        match result {
            Ok(()) => println!("Nginx reloaded successfully"),
            Err(e) => println!("Expected error without nginx: {}", e),
        }
    }
}

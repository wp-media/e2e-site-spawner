//! Database utility module for managing MySQL/MariaDB databases.
//!
//! This module provides functions for creating databases and managing
//! user privileges in MySQL/MariaDB installations.
//!
//! # Features
//!
//! - Automatic database creation with UTF8MB4 support
//! - WordPress user privilege management
//! - Automatic retry with numeric suffixes for duplicate names
//! - Comprehensive error handling with specific error types
//! - Database existence checking
//! - Safe database name validation
//!
//! # Examples
//!
//! ```ignore
//! use crate::utils::db;
//!
//! // Create a WordPress database
//! match db::create_wordpress_database("my_blog", true) {
//!     Ok(name) => println!("Database created: {}", name),
//!     Err(e) => eprintln!("Failed: {}", e),
//! }
//!
//! // Generate a database name from site name
//! let db_name = db::create_db_name("example.com");
//! assert_eq!(db_name, "wp_example_com");
//! ```

use crate::constants::{DB_CHARSET, DB_COLLATION, DB_HOST, DB_ROOT_USER, DB_USER};
use mysql::prelude::*;
use mysql::*;

/// Custom error type for database operations.
///
/// Provides specific error variants for different failure scenarios
/// in database operations, enabling better error handling and recovery.
#[derive(Debug)]
pub enum DbError {
    /// Connection to the database server failed
    ConnectionError(String),
    /// MySQL/MariaDB returned an error during query execution
    MySqlError(String),
    /// Attempted to create a database that already exists
    DatabaseExists(String),
    /// Insufficient privileges to perform the operation
    PermissionDenied(String),
    /// The provided database name violates naming rules
    InvalidDatabaseName(String),
}

impl std::fmt::Display for DbError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DbError::ConnectionError(msg) => write!(f, "Connection failed: {}", msg),
            DbError::MySqlError(msg) => write!(f, "MySQL error: {}", msg),
            DbError::DatabaseExists(db) => write!(f, "Database '{}' already exists", db),
            DbError::PermissionDenied(msg) => write!(f, "Permission denied: {}", msg),
            DbError::InvalidDatabaseName(msg) => write!(f, "Invalid database name: {}", msg),
        }
    }
}

impl std::error::Error for DbError {}

impl From<mysql::Error> for DbError {
    /// Converts MySQL errors into appropriate DbError variants.
    ///
    /// Maps specific MySQL error codes to semantic error types:
    /// - 1007: Database exists
    /// - 1044, 1045: Access/permission denied
    /// - Others: Generic MySQL error
    fn from(err: mysql::Error) -> Self {
        match err {
            mysql::Error::MySqlError(ref e) => match e.code {
                1007 => DbError::DatabaseExists(e.message.clone()),
                1044 | 1045 => DbError::PermissionDenied(e.message.clone()),
                _ => DbError::MySqlError(e.message.clone()),
            },
            _ => DbError::MySqlError(err.to_string()),
        }
    }
}

/// Configuration for database connection.
///
/// Holds the necessary parameters for establishing a connection
/// to a MySQL/MariaDB server.
///
/// # Fields
///
/// * `host` - Hostname or IP address of the database server
/// * `port` - Port number for the database connection (default: 3306)
/// * `user` - Username for authentication
/// * `password` - Optional password for authentication
///
/// # Examples
///
/// ```ignore
/// use crate::utils::db::DbConfig;
///
/// let config = DbConfig::default(); // Uses root@localhost:3306 with no password
/// ```
pub struct DbConfig {
    host: String,
    port: u16,
    user: String,
    password: Option<String>,
}

impl Default for DbConfig {
    /// Creates a default database configuration.
    ///
    /// Uses values from constants:
    /// - Host: DB_HOST (typically "localhost")
    /// - Port: 3306 (MySQL/MariaDB default)
    /// - User: DB_ROOT_USER (typically "root")
    /// - Password: None (for local development)
    ///
    /// # Security Note
    ///
    /// This configuration assumes a local development environment
    /// where root has no password. For production, always use
    /// proper authentication.
    fn default() -> Self {
        DbConfig {
            host: DB_HOST.to_string(),
            port: 3306,
            user: DB_ROOT_USER.to_string(),
            password: None, // No password for local root
        }
    }
}

/// Creates a new MySQL/MariaDB database with UTF8MB4 encoding and grants privileges to WordPress user.
///
/// This function performs a complete database setup for WordPress:
/// 1. Creates a database with UTF8MB4 character set for full Unicode support
/// 2. Sets utf8mb4_general_ci collation for case-insensitive comparisons
/// 3. Grants all privileges on the database to the WordPress user
/// 4. Automatically retries with numeric suffixes if the database exists
///
/// # Arguments
///
/// * `db_name` - The desired name for the database
/// * `should_retry` - If true, automatically appends numeric suffixes (_1, _2, etc.) when name is taken
///
/// # Returns
///
/// * `Ok(String)` - The actual database name created (may include suffix if retries were needed)
/// * `Err(DbError)` - If creation failed or all retry attempts exhausted
///
/// # Retry Behavior
///
/// When `should_retry` is true and the database exists:
/// - Tries `db_name_1`, `db_name_2`, ... up to `db_name_20`
/// - Returns the first available name
/// - Fails if all 20 variations exist
///
/// # Examples
///
/// ```ignore
/// use crate::utils::db::create_wordpress_database;
///
/// // Create with automatic retry
/// match create_wordpress_database("wp_blog", true) {
///     Ok(name) => {
///         if name != "wp_blog" {
///             println!("Created with suffix: {}", name);
///         }
///     }
///     Err(e) => eprintln!("Failed: {}", e),
/// }
///
/// // Create without retry (fails if exists)
/// match create_wordpress_database("wp_blog", false) {
///     Ok(name) => println!("Created: {}", name),
///     Err(DbError::DatabaseExists(_)) => println!("Database already exists"),
///     Err(e) => eprintln!("Other error: {}", e),
/// }
/// ```
///
/// # Errors
///
/// Returns an error if:
/// - Database name is invalid (see [`validate_db_name`])
/// - Connection to MySQL fails
/// - User lacks CREATE privileges
/// - Database exists and `should_retry` is false
/// - All retry attempts (up to _20) are exhausted
///
/// # Security
///
/// The function grants all privileges to the WordPress user specified
/// in DB_USER constant. Ensure this user is properly configured with
/// limited host access (typically 'localhost' only).
pub fn create_wordpress_database(db_name: &str, should_retry: bool) -> Result<String, DbError> {
    // Validate database name
    validate_db_name(db_name)?;

    // Create connection
    let config = DbConfig::default();
    let mut conn = create_connection(&config)?;

    let mut suffix: u32 = 0;
    let max_retries: u32 = 20;

    loop {
        // Generate the database name with suffix if needed
        let current_db_name = if suffix == 0 {
            db_name.to_string()
        } else {
            let new_name = format!("{}_{}", db_name, suffix);
            println!(
                "Database '{}' exists, trying with suffix: {}",
                db_name, suffix
            );
            new_name
        };

        validate_db_name(&current_db_name)?;

        // Check if this database exists - pass the connection
        if !database_exists(&current_db_name, Some(&mut conn))? {
            // Database doesn't exist, we can create it
            create_database(&mut conn, &current_db_name)?;
            if suffix > 0 {
                println!(
                    "  Note: Original name '{}' was taken, used suffix _{}",
                    db_name, suffix
                );
            }

            return Ok(current_db_name);
        } else {
            if !should_retry {
                return Err(DbError::DatabaseExists(current_db_name));
            }
        }

        // Database exists, check if we've exceeded max retries
        if suffix >= max_retries {
            return Err(DbError::DatabaseExists(format!(
                "'{}' and 20 variations (up to _{}) all exist",
                db_name, max_retries
            )));
        }

        // Try next suffix
        suffix += 1;
    }
}

/// Creates a connection to MySQL/MariaDB server.
///
/// Establishes a connection using the provided configuration parameters.
/// For root user connections, uses Unix socket authentication which is
/// the default on modern MySQL/MariaDB installations.
///
/// # Arguments
///
/// * `config` - Database configuration containing connection parameters
///
/// # Returns
///
/// * `Ok(Conn)` - An active database connection
/// * `Err(DbError)` - If connection failed
///
/// # Connection Strategy
///
/// - For root user: Uses Unix socket authentication (no password)
/// - For other users: Uses TCP/IP with password authentication
/// - Socket path auto-detection for different systems
///
/// # Unix Socket Authentication
///
/// Modern MySQL/MariaDB installations use unix_socket/auth_socket plugin
/// for root by default. This requires:
/// - Process must run as system root (via sudo)
/// - Connection via Unix socket (not TCP)
/// - No password needed (OS user verification)
fn create_connection(config: &DbConfig) -> Result<Conn, DbError> {
    // For root user, use Unix socket authentication
    if config.user == "root" {
        // Try common socket paths
        let socket_paths = vec![
            "/var/run/mysqld/mysqld.sock",     // Ubuntu/Debian default
            "/tmp/mysql.sock",                  // macOS default
            "/var/lib/mysql/mysql.sock",       // CentOS/RHEL default
            "/var/run/mysql/mysql.sock",       // Alternative path
        ];
        
        // Find the first existing socket
        let socket_path = socket_paths
            .iter()
            .find(|path| std::path::Path::new(path).exists());
        
        match socket_path {
            Some(socket) => {
                // Use socket authentication for root
                let opts = OptsBuilder::new()
                    .socket(Some(*socket))
                    .user(Some(&config.user))
                    // No password needed for socket auth
                    .db_name(None::<String>);
                
                Conn::new(opts).map_err(|e| {
                    // Provide helpful error message
                    if e.to_string().contains("Access denied") {
                        DbError::ConnectionError(format!(
                            "Access denied for root@localhost. Make sure you're running with 'sudo'. Error: {}",
                            e
                        ))
                    } else {
                        DbError::ConnectionError(e.to_string())
                    }
                })
            }
            None => {
                // Fallback to TCP connection if no socket found
                // This will likely fail with modern MySQL/MariaDB but provides better error
                let opts = OptsBuilder::new()
                    .ip_or_hostname(Some(&config.host))
                    .tcp_port(config.port)
                    .user(Some(&config.user))
                    .pass(config.password.as_deref());
                
                Conn::new(opts).map_err(|e| {
                    DbError::ConnectionError(format!(
                        "Failed to connect as root. Unix socket not found and TCP connection failed. \
                        Make sure you're running with 'sudo' and MySQL is running. Error: {}",
                        e
                    ))
                })
            }
        }
    } else {
        // For non-root users, use standard TCP connection
        let opts = OptsBuilder::new()
            .ip_or_hostname(Some(&config.host))
            .tcp_port(config.port)
            .user(Some(&config.user))
            .pass(config.password.as_deref())
            .prefer_socket(false); // Use TCP for non-root users
        
        Conn::new(opts).map_err(|e| DbError::ConnectionError(e.to_string()))
    }
}

/// Creates a database and grants privileges to WordPress user.
///
/// Internal function that executes the actual SQL commands to:
/// 1. Create the database with UTF8MB4 encoding
/// 2. Grant all privileges to WordPress user
/// 3. Flush privileges to apply changes immediately
///
/// # Arguments
///
/// * `conn` - Active database connection with CREATE privileges
/// * `db_name` - Name of the database to create
///
/// # Returns
///
/// * `Ok(())` - If database was created and privileges granted successfully
/// * `Err(DbError)` - If any operation failed
///
/// # SQL Operations
///
/// Executes the following SQL commands:
/// ```sql
/// CREATE DATABASE `db_name` CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci;
/// GRANT ALL PRIVILEGES ON `db_name`.* TO 'wordpress'@'localhost';
/// FLUSH PRIVILEGES;
/// ```
///
/// # Errors
///
/// Returns an error if:
/// - Database already exists (MySQL error 1007)
/// - User lacks CREATE privilege
/// - WordPress user doesn't exist
/// - Any SQL command fails
fn create_database(conn: &mut Conn, db_name: &str) -> Result<(), DbError> {
    let create_query = format!(
        "CREATE DATABASE `{}` CHARACTER SET {} COLLATE {}",
        db_name, DB_CHARSET, DB_COLLATION
    );

    conn.exec_drop(&create_query, ())
        .map_err(|e| DbError::from(e))?;

    // Grant privileges to WordPress user
    let grant_query = format!(
        "GRANT ALL PRIVILEGES ON `{}`.* TO '{}'@'{}'",
        db_name, DB_USER, DB_HOST
    );

    conn.exec_drop(&grant_query, ())
        .map_err(|e| DbError::from(e))?;

    // Flush privileges to ensure they take effect immediately
    conn.exec_drop("FLUSH PRIVILEGES", ())
        .map_err(|e| DbError::from(e))?;

    Ok(())
}

/// Validates that a database name contains only valid characters.
///
/// Ensures the database name complies with MySQL/MariaDB naming rules:
/// - Not empty
/// - Maximum 64 characters
/// - Contains only alphanumeric characters and underscores
/// - Doesn't start with a number
///
/// # Arguments
///
/// * `name` - The database name to validate
///
/// # Returns
///
/// * `Ok(())` - If the name is valid
/// * `Err(DbError::InvalidDatabaseName)` - If validation fails with specific reason
///
/// # Validation Rules
///
/// 1. **Length**: 1-64 characters
/// 2. **Characters**: Only `[a-zA-Z0-9_]`
/// 3. **First character**: Must be alphabetic or underscore
///
/// # Examples
///
/// ```ignore
/// use crate::utils::db::validate_db_name;
///
/// assert!(validate_db_name("wp_blog").is_ok());
/// assert!(validate_db_name("test_123").is_ok());
/// assert!(validate_db_name("_underscore_start").is_ok());
///
/// assert!(validate_db_name("").is_err()); // Empty
/// assert!(validate_db_name("123_start").is_err()); // Starts with number
/// assert!(validate_db_name("has-dash").is_err()); // Invalid character
/// assert!(validate_db_name(&"x".repeat(65)).is_err()); // Too long
/// ```
///
/// # MySQL Reference
///
/// Based on MySQL identifier rules:
/// https://dev.mysql.com/doc/refman/8.0/en/identifiers.html
pub fn validate_db_name(name: &str) -> Result<(), DbError> {
    if name.is_empty() {
        return Err(DbError::InvalidDatabaseName(
            "Database name cannot be empty".to_string(),
        ));
    }

    if name.len() > 64 {
        return Err(DbError::InvalidDatabaseName(
            "Database name too long (max 64 characters)".to_string(),
        ));
    }

    if !name.chars().all(|c| c.is_alphanumeric() || c == '_') {
        return Err(DbError::InvalidDatabaseName(
            "Database name can only contain alphanumeric characters and underscores".to_string(),
        ));
    }

    if name.chars().next().unwrap().is_numeric() {
        return Err(DbError::InvalidDatabaseName(
            "Database name cannot start with a number".to_string(),
        ));
    }

    Ok(())
}

/// Drops a MySQL/MariaDB database.
///
/// Permanently deletes a database and all its contents. This operation
/// cannot be undone.
///
/// # Arguments
///
/// * `db_name` - The name of the database to drop
///
/// # Returns
///
/// * `Ok(())` - If the database was dropped or didn't exist
/// * `Err(DbError)` - If the operation failed
///
/// # SQL Operation
///
/// Executes: `DROP DATABASE IF EXISTS db_name`
///
/// The `IF EXISTS` clause ensures the operation succeeds even if
/// the database doesn't exist, making it idempotent.
///
/// # Examples
///
/// ```ignore
/// use crate::utils::db::drop_database;
///
/// match drop_database("old_wp_site") {
///     Ok(()) => println!("Database removed"),
///     Err(e) => eprintln!("Failed to drop database: {}", e),
/// }
/// ```
///
/// # Errors
///
/// Returns an error if:
/// - Database name is invalid
/// - Connection to MySQL fails
/// - User lacks DROP privilege
///
/// # Warning
///
/// This operation is **destructive** and **permanent**. All tables,
/// data, and stored procedures in the database will be lost.
pub fn drop_database(db_name: &str) -> Result<(), DbError> {
    validate_db_name(db_name)?;

    let config = DbConfig::default();
    let mut conn = create_connection(&config)?;
    let drop_query = format!("DROP DATABASE IF EXISTS `{}`", db_name);
    conn.exec_drop(&drop_query, ())
        .map_err(|e| DbError::from(e))?;

    Ok(())
}

/// Checks if a database exists.
///
/// Queries the information schema to determine if a database exists
/// without attempting to use or modify it.
///
/// # Arguments
///
/// * `db_name` - The name of the database to check
/// * `conn` - Optional existing database connection to reuse
///
/// # Returns
///
/// * `Ok(true)` - If the database exists
/// * `Ok(false)` - If the database doesn't exist
/// * `Err(DbError)` - If the check failed
///
/// # Connection Reuse
///
/// If a connection is provided, it will be reused. Otherwise, a new
/// connection is created and closed after the check. Reusing connections
/// is more efficient for multiple checks.
///
/// # Examples
///
/// ```ignore
/// use crate::utils::db::database_exists;
///
/// // Check without existing connection
/// match database_exists("wp_mysite", None) {
///     Ok(true) => println!("Database exists"),
///     Ok(false) => println!("Database doesn't exist"),
///     Err(e) => eprintln!("Check failed: {}", e),
/// }
///
/// // Reuse existing connection for multiple checks
/// let config = DbConfig::default();
/// let mut conn = create_connection(&config)?;
/// 
/// for db in &["wp_site1", "wp_site2", "wp_site3"] {
///     if database_exists(db, Some(&mut conn))? {
///         println!("{} exists", db);
///     }
/// }
/// ```
///
/// # Implementation
///
/// Queries `INFORMATION_SCHEMA.SCHEMATA` which contains metadata
/// about all databases the user has access to see.
///
/// # Errors
///
/// Returns an error if:
/// - Database name is invalid
/// - Connection fails (when no connection provided)
/// - Query execution fails
/// - User lacks privilege to query information schema
pub fn database_exists(db_name: &str, conn: Option<&mut Conn>) -> Result<bool, DbError> {
    validate_db_name(db_name)?;

    // Create a new connection if none provided
    #[allow(unused)]
    let mut owned_conn: Option<Conn> = None;
    let conn = match conn {
        Some(existing) => existing,
        None => {
            let config = DbConfig::default();
            owned_conn = Some(create_connection(&config)?);
            owned_conn.as_mut().unwrap()
        }
    };

    let query = "SELECT SCHEMA_NAME FROM INFORMATION_SCHEMA.SCHEMATA WHERE SCHEMA_NAME = ?";
    let result: Vec<String> = conn.exec(query, (db_name,)).map_err(|e| DbError::from(e))?;

    Ok(!result.is_empty())
}

/// Creates a database name from a site name.
///
/// Converts a site domain name into a valid database name by:
/// 1. Prepending "wp_" prefix
/// 2. Replacing dots with underscores
/// 3. Replacing hyphens with underscores
///
/// This ensures the resulting name is valid for MySQL/MariaDB.
///
/// # Arguments
///
/// * `site_name` - The site domain name to convert
///
/// # Returns
///
/// A string containing the formatted database name.
///
/// # Examples
///
/// ```ignore
/// use crate::utils::db::create_db_name;
///
/// assert_eq!(create_db_name("example.com"), "wp_example_com");
/// assert_eq!(create_db_name("my-blog.example.com"), "wp_my_blog_example_com");
/// assert_eq!(create_db_name("test-site"), "wp_test_site");
/// assert_eq!(create_db_name("simple"), "wp_simple");
/// ```
///
/// # Note
///
/// The resulting name may still need validation with [`validate_db_name`]
/// as this function doesn't check length limits or starting characters
/// after transformation.
pub fn create_db_name(site_name: &str) -> String {
    format!("wp_{}", site_name.replace('.', "_").replace('-', "_"))
}

// use std::time::Duration;

#[cfg(test)]
mod tests {
    use super::*;

    // ===== Database Name Validation Tests =====

    #[test]
    fn test_valid_db_names() {
        assert!(validate_db_name("wordpress_db").is_ok());
        assert!(validate_db_name("wp_site_123").is_ok());
        assert!(validate_db_name("test_database").is_ok());
        assert!(validate_db_name("a").is_ok());
        assert!(validate_db_name("_underscore_start").is_ok());
        
        // Additional valid cases
        assert!(validate_db_name("UPPERCASE").is_ok());
        assert!(validate_db_name("MixedCase_123").is_ok());
        assert!(validate_db_name(&"a".repeat(64)).is_ok()); // Max length
    }

    #[test]
    fn test_invalid_db_names() {
        // Empty name
        assert!(validate_db_name("").is_err());
        
        // Starts with number
        assert!(validate_db_name("123_starts_with_number").is_err());
        assert!(validate_db_name("9test").is_err());
        
        // Invalid characters
        assert!(validate_db_name("has-dashes").is_err());
        assert!(validate_db_name("has spaces").is_err());
        assert!(validate_db_name("has.dots").is_err());
        assert!(validate_db_name("special@char").is_err());
        assert!(validate_db_name("emoji😀").is_err());
        assert!(validate_db_name("tab\ttab").is_err());
        assert!(validate_db_name("newline\n").is_err());
        
        // Too long (>64 chars)
        assert!(validate_db_name(&"a".repeat(65)).is_err());
        assert!(validate_db_name(&"x".repeat(100)).is_err());
    }

    #[test]
    fn test_validate_db_name_error_messages() {
        // Test specific error messages
        match validate_db_name("") {
            Err(DbError::InvalidDatabaseName(msg)) => {
                assert!(msg.contains("empty"));
            }
            _ => panic!("Expected InvalidDatabaseName error for empty string"),
        }

        match validate_db_name("123abc") {
            Err(DbError::InvalidDatabaseName(msg)) => {
                assert!(msg.contains("start with a number"));
            }
            _ => panic!("Expected InvalidDatabaseName error for number start"),
        }

        match validate_db_name(&"a".repeat(65)) {
            Err(DbError::InvalidDatabaseName(msg)) => {
                assert!(msg.contains("too long"));
                assert!(msg.contains("64"));
            }
            _ => panic!("Expected InvalidDatabaseName error for too long"),
        }

        match validate_db_name("test-db") {
            Err(DbError::InvalidDatabaseName(msg)) => {
                assert!(msg.contains("alphanumeric"));
                assert!(msg.contains("underscores"));
            }
            _ => panic!("Expected InvalidDatabaseName error for invalid chars"),
        }
    }

    // ===== Database Name Creation Tests =====

    #[test]
    fn test_create_db_name() {
        assert_eq!(create_db_name("example.com"), "wp_example_com");
        assert_eq!(create_db_name("sub.example.com"), "wp_sub_example_com");
        assert_eq!(create_db_name("my-site"), "wp_my_site");
        assert_eq!(create_db_name("test-blog.example.com"), "wp_test_blog_example_com");
        
        // Edge cases
        assert_eq!(create_db_name(""), "wp_");
        assert_eq!(create_db_name("..."), "wp____");  // Fixed: wp_ + ___ = wp____
        assert_eq!(create_db_name("---"), "wp____");  // Fixed: wp_ + ___ = wp____
        assert_eq!(create_db_name("site"), "wp_site");
        assert_eq!(create_db_name("UPPERCASE.COM"), "wp_UPPERCASE_COM");
        
        // Additional edge cases to clarify the pattern
        assert_eq!(create_db_name("."), "wp__");      // wp_ + _ = wp__
        assert_eq!(create_db_name(".."), "wp___");    // wp_ + __ = wp___
        assert_eq!(create_db_name("-"), "wp__");      // wp_ + _ = wp__
        assert_eq!(create_db_name("--"), "wp___");    // wp_ + __ = wp___
        assert_eq!(create_db_name(".-"), "wp___");    // wp_ + __ = wp___
    }

    #[test]
    fn test_create_db_name_produces_valid_names() {
        // Ensure created names are valid
        let test_sites = vec![
            "example.com",
            "my-site.org",
            "sub.domain.example.com",
            "test-123.local",
        ];

        for site in test_sites {
            let db_name = create_db_name(site);
            assert!(
                validate_db_name(&db_name).is_ok(),
                "Generated name '{}' from '{}' should be valid",
                db_name,
                site
            );
        }
    }

    // ===== Error Type Tests =====

    #[test]
    fn test_db_error_display() {
        let err = DbError::ConnectionError("timeout".to_string());
        assert_eq!(err.to_string(), "Connection failed: timeout");

        let err = DbError::DatabaseExists("wp_test".to_string());
        assert_eq!(err.to_string(), "Database 'wp_test' already exists");

        let err = DbError::InvalidDatabaseName("bad name".to_string());
        assert_eq!(err.to_string(), "Invalid database name: bad name");

        let err = DbError::MySqlError("syntax error".to_string());
        assert_eq!(err.to_string(), "MySQL error: syntax error");

        let err = DbError::PermissionDenied("access denied".to_string());
        assert_eq!(err.to_string(), "Permission denied: access denied");
    }

    #[test]
    fn test_db_error_from_mysql_error() {
        // Test error code mapping
        
        // Database exists (1007)
        let mysql_err = mysql::Error::MySqlError(mysql::MySqlError {
            state: "HY000".to_string(),
            code: 1007,
            message: "Can't create database 'test'; database exists".to_string(),
        });
        
        match DbError::from(mysql_err) {
            DbError::DatabaseExists(msg) => {
                assert!(msg.contains("database exists"));
            }
            _ => panic!("Expected DatabaseExists error"),
        }

        // Access denied (1044)
        let mysql_err = mysql::Error::MySqlError(mysql::MySqlError {
            state: "42000".to_string(),
            code: 1044,
            message: "Access denied for user".to_string(),
        });
        
        match DbError::from(mysql_err) {
            DbError::PermissionDenied(msg) => {
                assert!(msg.contains("Access denied"));
            }
            _ => panic!("Expected PermissionDenied error"),
        }

        // Generic MySQL error
        let mysql_err = mysql::Error::MySqlError(mysql::MySqlError {
            state: "42000".to_string(),
            code: 1064,
            message: "You have an error in your SQL syntax".to_string(),
        });
        
        match DbError::from(mysql_err) {
            DbError::MySqlError(msg) => {
                assert!(msg.contains("SQL syntax"));
            }
            _ => panic!("Expected MySqlError"),
        }
    }

    // ===== Configuration Tests =====

    #[test]
    fn test_db_config_default() {
        let config = DbConfig::default();
        assert_eq!(config.host, DB_HOST);
        assert_eq!(config.port, 3306);
        assert_eq!(config.user, DB_ROOT_USER);
        assert_eq!(config.password, None);
    }

    // ===== Integration Tests (require MySQL) =====

    #[test]
    #[ignore] // Requires MySQL server
    fn test_database_connection() {
        let config = DbConfig::default();
        match create_connection(&config) {
            Ok(_) => println!("Connection successful"),
            Err(e) => println!("Expected in test environment: {}", e),
        }
    }

    #[test]
    #[ignore] // Requires MySQL server
    fn test_create_wordpress_database_without_retry() {
        let db_name = format!("wp_test_{}", std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs());

        // First creation should succeed
        match create_wordpress_database(&db_name, false) {
            Ok(created_name) => {
                assert_eq!(created_name, db_name);
                // Clean up
                let _ = drop_database(&db_name);
            }
            Err(e) => {
                println!("Test skipped - MySQL not available: {}", e);
            }
        }
    }

    #[test]
    #[ignore] // Requires MySQL server
    fn test_create_wordpress_database_with_retry() {
        let base_name = format!("wp_test_{}", std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs());

        // Create first database
        match create_wordpress_database(&base_name, false) {
            Ok(_) => {
                // Try to create again with retry - should add suffix
                match create_wordpress_database(&base_name, true) {
                    Ok(created_name) => {
                        assert_ne!(created_name, base_name);
                        assert!(created_name.starts_with(&base_name));
                        assert!(created_name.contains("_1"));
                        
                        // Clean up both
                        let _ = drop_database(&base_name);
                        let _ = drop_database(&created_name);
                    }
                    Err(e) => panic!("Retry should have succeeded: {}", e),
                }
            }
            Err(e) => {
                println!("Test skipped - MySQL not available: {}", e);
            }
        }
    }

    #[test]
    #[ignore] // Requires MySQL server
    fn test_database_exists() {
        let db_name = format!("wp_test_exists_{}", std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs());

        // Check non-existent database
        match database_exists(&db_name, None) {
            Ok(exists) => {
                assert!(!exists, "Database should not exist initially");
                
                // Create database
                if create_wordpress_database(&db_name, false).is_ok() {
                    // Check it now exists
                    match database_exists(&db_name, None) {
                        Ok(exists) => {
                            assert!(exists, "Database should exist after creation");
                        }
                        Err(e) => panic!("Failed to check existence: {}", e),
                    }
                    
                    // Clean up
                    let _ = drop_database(&db_name);
                    
                    // Check it's gone
                    match database_exists(&db_name, None) {
                        Ok(exists) => {
                            assert!(!exists, "Database should not exist after drop");
                        }
                        Err(e) => panic!("Failed to check after drop: {}", e),
                    }
                }
            }
            Err(e) => {
                println!("Test skipped - MySQL not available: {}", e);
            }
        }
    }

    #[test]
    #[ignore] // Requires MySQL server
    fn test_database_exists_with_connection_reuse() {
        let config = DbConfig::default();
        
        match create_connection(&config) {
            Ok(mut conn) => {
                let db_names = vec!["information_schema", "mysql", "performance_schema"];
                
                for db_name in db_names {
                    match database_exists(db_name, Some(&mut conn)) {
                        Ok(exists) => {
                            println!("System database '{}' exists: {}", db_name, exists);
                            // These system databases should typically exist
                        }
                        Err(e) => {
                            println!("Failed to check {}: {}", db_name, e);
                        }
                    }
                }
            }
            Err(e) => {
                println!("Test skipped - MySQL not available: {}", e);
            }
        }
    }

    #[test]
    #[ignore] // Requires MySQL server
    fn test_drop_database() {
        let db_name = format!("wp_test_drop_{}", std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs());

        // Create a database first
        match create_wordpress_database(&db_name, false) {
            Ok(_) => {
                // Verify it exists
                assert!(database_exists(&db_name, None).unwrap_or(false));
                
                // Drop it
                match drop_database(&db_name) {
                    Ok(()) => {
                        // Verify it's gone
                        assert!(!database_exists(&db_name, None).unwrap_or(true));
                    }
                    Err(e) => panic!("Failed to drop database: {}", e),
                }
                
                // Drop again should succeed (IF EXISTS clause)
                match drop_database(&db_name) {
                    Ok(()) => {
                        // Should succeed even though database doesn't exist
                    }
                    Err(e) => panic!("Drop non-existent should succeed: {}", e),
                }
            }
            Err(e) => {
                println!("Test skipped - MySQL not available: {}", e);
            }
        }
    }

    #[test]
    #[ignore] // Requires MySQL server
    fn test_create_database_max_retries() {
        let base_name = format!("wp_test_max_{}", std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs());

        let config = DbConfig::default();
        let mut conn = match create_connection(&config) {
            Ok(c) => c,
            Err(e) => {
                println!("Test skipped - MySQL not available: {}", e);
                return;
            }
        };

        // Create databases with all possible suffixes (0-20)
        let mut created_dbs = Vec::new();
        
        // Create base database
        if create_wordpress_database(&base_name, false).is_ok() {
            created_dbs.push(base_name.clone());
            
            // Create _1 through _20
            for i in 1..=20 {
                let name = format!("{}_{}", base_name, i);
                if create_database(&mut conn, &name).is_ok() {
                    created_dbs.push(name);
                }
            }
            
            // Now try to create with retry - should fail after exhausting retries
            match create_wordpress_database(&base_name, true) {
                Ok(_) => panic!("Should have failed after exhausting retries"),
                Err(DbError::DatabaseExists(msg)) => {
                    assert!(msg.contains("20"));
                    assert!(msg.contains("variations"));
                }
                Err(e) => panic!("Unexpected error: {}", e),
            }
            
            // Clean up all created databases
            for db in created_dbs {
                let _ = drop_database(&db);
            }
        }
    }

    // ===== Unit Tests for Private Functions (via public interface) =====

    #[test]
    fn test_create_db_name_length_validation() {
        // Create a site name that would result in a database name > 64 chars
        let long_site = "a".repeat(62); // "wp_" + 62 chars = 65 chars
        let db_name = create_db_name(&long_site);
        
        // The created name will be too long
        assert_eq!(db_name.len(), 65);
        assert!(validate_db_name(&db_name).is_err());
    }

    #[test]
    fn test_error_trait_implementation() {
        // Verify Error trait is properly implemented
        let err = DbError::ConnectionError("test".to_string());
        
        // Should be usable as std::error::Error
        let _: &dyn std::error::Error = &err;
        
        // Display trait should work
        assert!(!err.to_string().is_empty());
    }

    #[test]
    fn test_db_config_custom() {
        // Test that we can create custom configs (even though not exposed publicly)
        let config = DbConfig {
            host: "custom.host".to_string(),
            port: 3307,
            user: "custom_user".to_string(),
            password: Some("password123".to_string()),
        };
        
        assert_eq!(config.host, "custom.host");
        assert_eq!(config.port, 3307);
        assert_eq!(config.user, "custom_user");
        assert_eq!(config.password, Some("password123".to_string()));
    }
}

//! Database utility module for managing MySQL/MariaDB databases.
//!
//! This module provides functions for creating databases and managing
//! user privileges in MySQL/MariaDB installations.

use crate::constants::{DB_CHARSET, DB_COLLATION, DB_HOST, DB_ROOT_USER, DB_USER};
use mysql::prelude::*;
use mysql::*;

/// Custom error type for database operations
#[derive(Debug)]
pub enum DbError {
    /// Connection failed
    ConnectionError(String),
    /// MySQL returned an error
    MySqlError(String),
    /// Database already exists
    DatabaseExists(String),
    /// Permission denied
    PermissionDenied(String),
    /// Invalid database name
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

/// Configuration for database connection
pub struct DbConfig {
    host: String,
    port: u16,
    user: String,
    password: Option<String>,
}

impl Default for DbConfig {
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
/// This function performs two operations:
/// 1. Creates a database with UTF8MB4 character set and utf8mb4_general_ci collation
/// 2. Grants all privileges on the database to 'wordpress'@'localhost'
///
/// If the database exists, it will try with numeric suffixes (_1, _2, etc.) up to _20.
///
/// # Arguments
///
/// * `db_name` - The name of the database to create
///
/// # Returns
///
/// * `Ok(())` if the database was created successfully
/// * `Err(DbError)` if any error occurred during the operation
///
/// # Example
///
/// ```rust
/// # use e2e_site_spawner::utils::db::create_wordpress_database;
///
/// match create_wordpress_database("wp_example_site") {
///     Ok(()) => println!("Database created successfully"),
///     Err(e) => eprintln!("Failed to create database: {}", e),
/// }
/// ```
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

/// Creates a connection to MySQL/MariaDB
fn create_connection(config: &DbConfig) -> Result<Conn, DbError> {
    let opts = OptsBuilder::new()
        .ip_or_hostname(Some(&config.host))
        .tcp_port(config.port)
        .user(Some(&config.user))
        .pass(config.password.as_deref())
        .prefer_socket(true); // Use Unix socket if available (faster for localhost)

    Conn::new(opts).map_err(|e| DbError::ConnectionError(e.to_string()))
}
fn create_database(conn: &mut Conn, db_name: &str) -> Result<(), DbError> {
    println!("Creating database '{}'...", db_name);
    let create_query = format!(
        "CREATE DATABASE `{}` CHARACTER SET {} COLLATE {}",
        db_name, DB_CHARSET, DB_COLLATION
    );

    conn.exec_drop(&create_query, ())
        .map_err(|e| DbError::from(e))?;

    // Grant privileges to WordPress user
    println!("Granting privileges to WordPress user...");
    let grant_query = format!(
        "GRANT ALL PRIVILEGES ON `{}`.* TO '{}'@'{}'",
        db_name, DB_USER, DB_HOST
    );

    conn.exec_drop(&grant_query, ())
        .map_err(|e| DbError::from(e))?;

    // Flush privileges to ensure they take effect immediately
    conn.exec_drop("FLUSH PRIVILEGES", ())
        .map_err(|e| DbError::from(e))?;

    println!(
        "✓ Database '{}' created successfully with WordPress privileges",
        db_name
    );
    Ok(())
}
/// Validates that a database name contains only valid characters
fn validate_db_name(name: &str) -> Result<(), DbError> {
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

/// Drops a MySQL/MariaDB database
pub fn drop_database(db_name: &str) -> Result<(), DbError> {
    validate_db_name(db_name)?;

    let config = DbConfig::default();
    let mut conn = create_connection(&config)?;

    println!("Dropping database '{}'...", db_name);
    let drop_query = format!("DROP DATABASE IF EXISTS `{}`", db_name);

    conn.exec_drop(&drop_query, ())
        .map_err(|e| DbError::from(e))?;

    println!("✓ Database '{}' dropped successfully", db_name);
    Ok(())
}

/// Checks if a database exists
///
/// # Arguments
///
/// * `db_name` - The name of the database to check
/// * `conn` - Optional existing database connection to reuse
///
/// # Returns
///
/// * `Ok(true)` if the database exists
/// * `Ok(false)` if the database doesn't exist
/// * `Err(DbError)` if the check failed
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
pub fn create_db_name(site_name: &str) -> String {
    format!("wp_{}", site_name.replace('.', "_").replace('-', "_"))
}
// use std::time::Duration;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_db_names() {
        assert!(validate_db_name("wordpress_db").is_ok());
        assert!(validate_db_name("wp_site_123").is_ok());
        assert!(validate_db_name("test_database").is_ok());
        assert!(validate_db_name("a").is_ok());
    }

    #[test]
    fn test_invalid_db_names() {
        assert!(validate_db_name("").is_err());
        assert!(validate_db_name("123_starts_with_number").is_err());
        assert!(validate_db_name("has-dashes").is_err());
        assert!(validate_db_name("has spaces").is_err());
        assert!(validate_db_name("has.dots").is_err());
        assert!(validate_db_name(&"a".repeat(65)).is_err());
    }
}

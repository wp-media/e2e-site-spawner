//! Input validation module for the e2e-site-spawner.
//!
//! This module contains validation functions for input parameters,
//! ensuring they meet the required criteria for the e2e-site-spawner CLI tool.
//!
//! # Overview
//!
//! The validators in this module enforce RFC-compliant domain name validation
//! and other input constraints to ensure safe and correct operation of the
//! site spawner. All validation functions are pure and side-effect free.
//!
//! # Standards Compliance
//!
//! Domain name validation follows:
//! - RFC 1035 (Domain Names - Implementation and Specification)
//! - RFC 1123 (Requirements for Internet Hosts)
//! - RFC 2181 (Clarifications to the DNS Specification)

/// Validates the site name to ensure it meets the required criteria for a valid domain or subdomain.
///
/// A valid domain name must:
/// - Consist of labels separated by dots
/// - Each label can contain letters (a-z), numbers (0-9), and hyphens (-)
/// - Each label must start and end with an alphanumeric character
/// - Each label must be 1-63 characters long
/// - The total length must not exceed 253 characters
/// - Must have at least one dot (TLD required)
///
/// # Arguments
///
/// * `site_name` - A string slice that holds the name of the site.
///
/// # Returns
///
/// Returns `true` if the site name is a valid domain/subdomain, otherwise returns `false`.
///
/// # Examples
///
/// ```
/// use crate::utils::validators::validate_site_name;
///
/// assert!(validate_site_name("example.com"));
/// assert!(validate_site_name("sub.example.com"));
/// assert!(validate_site_name("my-site.e2e.rocketlabsqa.ovh"));
/// assert!(!validate_site_name("example"));  // No TLD
/// assert!(!validate_site_name("-example.com"));  // Starts with hyphen
/// assert!(!validate_site_name("example..com"));  // Double dot
/// ```
///
/// # RFC Compliance
///
/// This function implements domain name validation according to:
/// - **RFC 1035 Section 2.3.1**: Labels are 1-63 octets, case-insensitive
/// - **RFC 1123 Section 2.1**: Allows digits at the start of labels
/// - **RFC 2181 Section 11**: Total length limit of 253 characters
///
/// # Implementation Notes
///
/// - Case-insensitive: Both "Example.COM" and "example.com" are valid
/// - IDN (Internationalized Domain Names) are NOT supported (ASCII only)
/// - IP addresses are NOT considered valid domain names
/// - Single-label domains (like "localhost") are rejected as they lack a TLD
pub fn validate_site_name(site_name: &str) -> bool {
    // Check if empty
    if site_name.is_empty() {
        return false;
    }

    // Check total length (RFC 1035 specifies max 253 characters)
    if site_name.len() > 253 {
        return false;
    }

    // Must contain at least one dot (to have a TLD)
    if !site_name.contains('.') {
        return false;
    }

    // Check for leading/trailing dots
    if site_name.starts_with('.') || site_name.ends_with('.') {
        return false;
    }

    // Check for consecutive dots
    if site_name.contains("..") {
        return false;
    }

    // Split into labels and validate each
    let labels: Vec<&str> = site_name.split('.').collect();

    // Must have at least 2 labels (domain + TLD)
    if labels.len() < 2 {
        return false;
    }

    // Validate each label
    for label in &labels {
        if !validate_label(label) {
            return false;
        }
    }

    // Validate TLD (last label) - must contain only letters
    let tld = labels.last().unwrap();
    if !tld.chars().all(|c| c.is_ascii_alphabetic()) {
        return false;
    }

    // TLD must be at least 2 characters
    if tld.len() < 2 {
        return false;
    }

    true
}

/// Validates a single label of a domain name according to RFC 1035.
///
/// A label is a single component of a domain name, separated by dots.
/// For example, in "www.example.com", there are three labels: "www", "example", and "com".
///
/// # Arguments
///
/// * `label` - A string slice containing a single label
///
/// # Returns
///
/// Returns `true` if the label is valid, otherwise returns `false`.
///
/// # Validation Rules
///
/// According to RFC 1035 and RFC 1123:
/// - **Length**: 1-63 characters (RFC 1035 Section 2.3.4)
/// - **Start/End**: Must begin and end with alphanumeric characters
/// - **Middle**: Can contain alphanumeric characters and hyphens
/// - **Case**: Case-insensitive (a-z, A-Z are equivalent)
///
/// # Examples
///
/// ```
/// // Valid labels
/// assert!(validate_label("example"));
/// assert!(validate_label("test-123"));
/// assert!(validate_label("a"));
/// assert!(validate_label("123"));
/// 
/// // Invalid labels
/// assert!(!validate_label(""));           // Empty
/// assert!(!validate_label("-test"));      // Starts with hyphen
/// assert!(!validate_label("test-"));      // Ends with hyphen
/// assert!(!validate_label("test_123"));   // Contains underscore
/// assert!(!validate_label(&"a".repeat(64))); // Too long (>63 chars)
/// ```
///
/// # Performance
///
/// This function performs validation in O(n) time where n is the length
/// of the label, with early returns for common invalid cases.
fn validate_label(label: &str) -> bool {
    // Check length (1-63 characters per RFC 1035)
    if label.is_empty() || label.len() > 63 {
        return false;
    }

    // Must start with alphanumeric
    if !label.chars().next().unwrap().is_ascii_alphanumeric() {
        return false;
    }

    // Must end with alphanumeric
    if !label.chars().last().unwrap().is_ascii_alphanumeric() {
        return false;
    }

    // Check all characters are valid (alphanumeric or hyphen)
    // and convert to lowercase for case-insensitive validation
    for c in label.chars() {
        if !c.is_ascii_alphanumeric() && c != '-' {
            return false;
        }
    }

    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_domains() {
        // Standard domains
        assert!(validate_site_name("example.com"));
        assert!(validate_site_name("subdomain.example.com"));
        assert!(validate_site_name("my-site.example.org"));
        assert!(validate_site_name("test.e2e.rocketlabsqa.ovh"));
        
        // Multiple subdomains
        assert!(validate_site_name("a.b.c.d.example.com"));
        
        // Numeric labels
        assert!(validate_site_name("123.456.example.com"));
        assert!(validate_site_name("a1b2c3.example.com"));
        
        // Case variations (should all be valid)
        assert!(validate_site_name("EXAMPLE.COM"));
        assert!(validate_site_name("Example.Com"));
        assert!(validate_site_name("eXaMpLe.CoM"));
    }

    #[test]
    fn test_invalid_domains() {
        // No TLD
        assert!(!validate_site_name("example"));
        assert!(!validate_site_name("localhost"));

        // Empty or whitespace
        assert!(!validate_site_name(""));
        assert!(!validate_site_name(" "));
        assert!(!validate_site_name("example .com"));

        // Invalid characters
        assert!(!validate_site_name("exam_ple.com"));
        assert!(!validate_site_name("exam ple.com"));
        assert!(!validate_site_name("example!.com"));
        assert!(!validate_site_name("exämple.com"));
        assert!(!validate_site_name("example@.com"));
        assert!(!validate_site_name("example#.com"));

        // Invalid hyphens
        assert!(!validate_site_name("-example.com"));
        assert!(!validate_site_name("example-.com"));
        assert!(!validate_site_name("example.-com"));
        assert!(!validate_site_name("example.com-"));

        // Invalid dots
        assert!(!validate_site_name(".example.com"));
        assert!(!validate_site_name("example.com."));
        assert!(!validate_site_name("example..com"));
        assert!(!validate_site_name("example."));
        assert!(!validate_site_name("..."));

        // Too long label (over 63 chars)
        let long_label = format!("{}.com", "a".repeat(64));
        assert!(!validate_site_name(&long_label));

        // Invalid TLD
        assert!(!validate_site_name("example.123"));      // Numeric TLD
        assert!(!validate_site_name("example.c"));        // Single char TLD
        assert!(!validate_site_name("example.com-"));     // TLD with hyphen
        assert!(!validate_site_name("example.c0m"));      // TLD with number
    }

    #[test]
    fn test_edge_cases() {
        // Minimum valid domain (2 chars + dot + 2 chars = 5 chars total)
        assert!(validate_site_name("a.co"));

        // Maximum label length (63 chars)
        let max_label = format!("{}.com", "a".repeat(63));
        assert!(validate_site_name(&max_label));
        
        // Just over max label length (64 chars) - should fail
        let over_max_label = format!("{}.com", "a".repeat(64));
        assert!(!validate_site_name(&over_max_label));

        // Multiple subdomains
        assert!(validate_site_name("a.b.c.d.e.f.example.com"));

        // Numbers in domain
        assert!(validate_site_name("123.456.example.com"));

        // Hyphen in middle
        assert!(validate_site_name("my-awesome-site.example.com"));
        
        // Maximum total length (253 chars)
        // Create a domain with multiple 63-char labels
        let long_domain = format!(
            "{}.{}.{}.com",
            "a".repeat(63),
            "b".repeat(63),
            "c".repeat(63)
        );
        assert!(long_domain.len() <= 253);
        assert!(validate_site_name(&long_domain));
    }

    #[test]
    fn test_label_validation() {
        // Valid labels
        assert!(validate_label("example"));
        assert!(validate_label("test-123"));
        assert!(validate_label("a"));
        assert!(validate_label("1"));
        assert!(validate_label("a1"));
        assert!(validate_label("1a"));
        
        // 63 character label (maximum)
        assert!(validate_label(&"a".repeat(63)));
        
        // Invalid labels
        assert!(!validate_label(""));                    // Empty
        assert!(!validate_label("-test"));               // Starts with hyphen
        assert!(!validate_label("test-"));               // Ends with hyphen
        assert!(!validate_label("test_123"));            // Contains underscore
        assert!(!validate_label("test.com"));            // Contains dot
        assert!(!validate_label(&"a".repeat(64)));       // Too long (64 chars)
        assert!(!validate_label("test name"));           // Contains space
        assert!(!validate_label("test@123"));            // Contains @
    }

    #[test]
    fn test_real_world_domains() {
        // Common real-world patterns
        assert!(validate_site_name("www.google.com"));
        assert!(validate_site_name("mail.google.com"));
        assert!(validate_site_name("api.v2.example.com"));
        assert!(validate_site_name("cdn-images.example.org"));
        assert!(validate_site_name("blog.john-doe.example.net"));
        assert!(validate_site_name("test-123.staging.mycompany.io"));
        
        // WordPress multisite patterns
        assert!(validate_site_name("site1.network.example.com"));
        assert!(validate_site_name("user-blog.wpmu.example.org"));
        
        // E2E testing patterns
        assert!(validate_site_name("test-001.e2e.example.com"));
        assert!(validate_site_name("feature-branch-123.staging.example.dev"));
    }
}

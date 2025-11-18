/// This module contains validation functions for input parameters,
/// ensuring they meet the required criteria for the e2e-site-spawner CLI tool.

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
/// assert!(validate_site_name("example.com"));
/// assert!(validate_site_name("sub.example.com"));
/// assert!(validate_site_name("my-site.e2e.rocketlabsqa.ovh"));
/// assert!(!validate_site_name("example"));  // No TLD
/// assert!(!validate_site_name("-example.com"));  // Starts with hyphen
/// assert!(!validate_site_name("example..com"));  // Double dot
/// ```
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

/// Validates a single label of a domain name according to RFC 1035
///
/// # Arguments
///
/// * `label` - A string slice containing a single label
///
/// # Returns
///
/// Returns `true` if the label is valid, otherwise returns `false`
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
        assert!(validate_site_name("example.com"));
        assert!(validate_site_name("subdomain.example.com"));
        assert!(validate_site_name("my-site.example.org"));
        assert!(validate_site_name("test.e2e.rocketlabsqa.ovh"));
        assert!(validate_site_name("a.b.c.d.example.com"));
        assert!(validate_site_name("123.456.example.com"));
        assert!(validate_site_name("a1b2c3.example.com"));
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

        // Too long label (over 63 chars)
        let long_label = format!("{}.com", "a".repeat(64));
        assert!(!validate_site_name(&long_label));

        // Invalid TLD
        assert!(!validate_site_name("example.123"));
        assert!(!validate_site_name("example.c"));
        assert!(!validate_site_name("example.com-"));
    }

    #[test]
    fn test_edge_cases() {
        // Minimum valid domain
        assert!(validate_site_name("a.co"));

        // Maximum label length (63 chars)
        let max_label = format!("{}.com", "a".repeat(63));
        assert!(validate_site_name(&max_label));

        // Multiple subdomains
        assert!(validate_site_name("a.b.c.d.e.f.example.com"));

        // Numbers in domain
        assert!(validate_site_name("123.456.example.com"));

        // Hyphen in middle
        assert!(validate_site_name("my-awesome-site.example.com"));
    }
}

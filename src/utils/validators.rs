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

        // Mixed numeric and alphabetic
        assert!(validate_site_name("3com.example.org"));
        assert!(validate_site_name("1and1.hosting.com"));
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
        assert!(!validate_site_name(" example.com"));
        assert!(!validate_site_name("example.com "));
        assert!(!validate_site_name("\t"));
        assert!(!validate_site_name("\n"));

        // Invalid characters
        assert!(!validate_site_name("exam_ple.com"));
        assert!(!validate_site_name("exam ple.com"));
        assert!(!validate_site_name("example!.com"));
        assert!(!validate_site_name("exämple.com"));
        assert!(!validate_site_name("example@.com"));
        assert!(!validate_site_name("example#.com"));
        assert!(!validate_site_name("example$.com"));
        assert!(!validate_site_name("example%.com"));
        assert!(!validate_site_name("example^.com"));
        assert!(!validate_site_name("example&.com"));
        assert!(!validate_site_name("example*.com"));
        assert!(!validate_site_name("example(.com"));
        assert!(!validate_site_name("example).com"));
        assert!(!validate_site_name("example[.com"));
        assert!(!validate_site_name("example].com"));
        assert!(!validate_site_name("example{.com"));
        assert!(!validate_site_name("example}.com"));
        assert!(!validate_site_name("example\\.com"));
        assert!(!validate_site_name("example/.com"));
        assert!(!validate_site_name("example:.com"));
        assert!(!validate_site_name("example;.com"));
        assert!(!validate_site_name("example'.com"));
        assert!(!validate_site_name("example\".com"));
        assert!(!validate_site_name("example<.com"));
        assert!(!validate_site_name("example>.com"));
        assert!(!validate_site_name("example?.com"));
        assert!(!validate_site_name("example,.com"));
        assert!(!validate_site_name("example|.com"));
        assert!(!validate_site_name("example~.com"));
        assert!(!validate_site_name("example`.com"));
        assert!(!validate_site_name("example=.com"));
        assert!(!validate_site_name("example+.com"));

        // Invalid hyphens
        assert!(!validate_site_name("-example.com"));
        assert!(!validate_site_name("example-.com"));
        assert!(!validate_site_name("example.-com"));
        assert!(!validate_site_name("example.com-"));
        assert!(!validate_site_name("--example.com"));
        assert!(!validate_site_name("example--.com"));

        // Invalid dots
        assert!(!validate_site_name(".example.com"));
        assert!(!validate_site_name("example.com."));
        assert!(!validate_site_name("example..com"));
        assert!(!validate_site_name("example."));
        assert!(!validate_site_name("..."));
        assert!(!validate_site_name("example...com"));
        assert!(!validate_site_name("."));
        assert!(!validate_site_name(".."));

        // Too long label (over 63 chars)
        let long_label = format!("{}.com", "a".repeat(64));
        assert!(!validate_site_name(&long_label));

        // Invalid TLD
        assert!(!validate_site_name("example.123")); // Numeric TLD
        assert!(!validate_site_name("example.c")); // Single char TLD
        assert!(!validate_site_name("example.com-")); // TLD with hyphen
        assert!(!validate_site_name("example.c0m")); // TLD with number
        assert!(!validate_site_name("example.-com")); // TLD starting with hyphen
        assert!(!validate_site_name("example.co-m")); // TLD containing hyphen
    }

    #[test]
    fn test_edge_cases() {
        // Minimum valid domain (2 chars + dot + 2 chars = 5 chars total)
        assert!(validate_site_name("a.co"));
        assert!(validate_site_name("aa.bb"));
        assert!(validate_site_name("a1.co"));
        assert!(validate_site_name("1a.co"));

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
        assert!(validate_site_name("a-b-c.d-e-f.example.com"));

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

        // Domain at exactly 253 characters
        // 63 + 1 + 63 + 1 + 63 + 1 + 61 = 253
        let exact_253 = format!(
            "{}.{}.{}.{}",
            "a".repeat(63),
            "b".repeat(63),
            "c".repeat(63),
            "d".repeat(61)
        );
        assert_eq!(exact_253.len(), 253);
        assert!(validate_site_name(&exact_253));

        // Domain at 254 characters (should fail)
        let over_253 = format!(
            "{}.{}.{}.{}",
            "a".repeat(63),
            "b".repeat(63),
            "c".repeat(63),
            "d".repeat(62)
        );
        assert_eq!(over_253.len(), 254);
        assert!(!validate_site_name(&over_253));
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
        assert!(validate_label("A"));
        assert!(validate_label("Z"));
        assert!(validate_label("aZ"));
        assert!(validate_label("Za"));
        assert!(validate_label("a-b"));
        assert!(validate_label("a-b-c"));
        assert!(validate_label("test-123-abc"));

        // 63 character label (maximum)
        assert!(validate_label(&"a".repeat(63)));
        assert!(validate_label(&format!("a{}b", "-".repeat(61))));

        // Invalid labels
        assert!(!validate_label("")); // Empty
        assert!(!validate_label("-test")); // Starts with hyphen
        assert!(!validate_label("test-")); // Ends with hyphen
        assert!(!validate_label("-")); // Just hyphen
        assert!(!validate_label("--")); // Just hyphens
        assert!(!validate_label("test_123")); // Contains underscore
        assert!(!validate_label("test.com")); // Contains dot
        assert!(!validate_label(&"a".repeat(64))); // Too long (64 chars)
        assert!(!validate_label("test name")); // Contains space
        assert!(!validate_label("test@123")); // Contains @
        assert!(!validate_label("test!")); // Contains !
        assert!(!validate_label("test?")); // Contains ?
        assert!(!validate_label("test#")); // Contains #
        assert!(!validate_label("test$")); // Contains $
        assert!(!validate_label("test%")); // Contains %
        assert!(!validate_label("test^")); // Contains ^
        assert!(!validate_label("test&")); // Contains &
        assert!(!validate_label("test*")); // Contains *
        assert!(!validate_label("test(")); // Contains (
        assert!(!validate_label("test)")); // Contains )
        assert!(!validate_label("test[")); // Contains [
        assert!(!validate_label("test]")); // Contains ]
        assert!(!validate_label("test{")); // Contains {
        assert!(!validate_label("test}")); // Contains }
        assert!(!validate_label("test\\")); // Contains \
        assert!(!validate_label("test/")); // Contains /
        assert!(!validate_label("test:")); // Contains :
        assert!(!validate_label("test;")); // Contains ;
        assert!(!validate_label("test'")); // Contains '
        assert!(!validate_label("test\"")); // Contains "
        assert!(!validate_label("test<")); // Contains <
        assert!(!validate_label("test>")); // Contains >
        assert!(!validate_label("test,")); // Contains ,
        assert!(!validate_label("test|")); // Contains |
        assert!(!validate_label("test~")); // Contains ~
        assert!(!validate_label("test`")); // Contains `
        assert!(!validate_label("test=")); // Contains =
        assert!(!validate_label("test+")); // Contains +

        // Unicode characters (should fail - ASCII only)
        assert!(!validate_label("café"));
        assert!(!validate_label("北京"));
        assert!(!validate_label("मुंबई"));
        assert!(!validate_label("🚀"));
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

        // Common TLDs
        assert!(validate_site_name("example.com"));
        assert!(validate_site_name("example.net"));
        assert!(validate_site_name("example.org"));
        assert!(validate_site_name("example.edu"));
        assert!(validate_site_name("example.gov"));
        assert!(validate_site_name("example.mil"));
        assert!(validate_site_name("example.info"));
        assert!(validate_site_name("example.biz"));
        assert!(validate_site_name("example.name"));
        assert!(validate_site_name("example.museum"));
        assert!(validate_site_name("example.coop"));
        assert!(validate_site_name("example.aero"));
        assert!(validate_site_name("example.pro"));
        assert!(validate_site_name("example.tel"));
        assert!(validate_site_name("example.travel"));
        assert!(validate_site_name("example.xxx"));
        assert!(validate_site_name("example.io"));
        assert!(validate_site_name("example.app"));
        assert!(validate_site_name("example.dev"));
        assert!(validate_site_name("example.ai"));
        assert!(validate_site_name("example.cloud"));

        // Country code TLDs
        assert!(validate_site_name("example.uk"));
        assert!(validate_site_name("example.us"));
        assert!(validate_site_name("example.ca"));
        assert!(validate_site_name("example.au"));
        assert!(validate_site_name("example.de"));
        assert!(validate_site_name("example.fr"));
        assert!(validate_site_name("example.jp"));
        assert!(validate_site_name("example.cn"));
        assert!(validate_site_name("example.in"));
        assert!(validate_site_name("example.br"));

        // Multi-level TLDs
        assert!(validate_site_name("example.co.uk"));
        assert!(validate_site_name("example.co.jp"));
        assert!(validate_site_name("example.com.au"));
        assert!(validate_site_name("example.com.br"));
        assert!(validate_site_name("example.co.in"));
        assert!(validate_site_name("example.org.uk"));
        assert!(validate_site_name("example.ac.uk"));
        assert!(validate_site_name("example.gov.uk"));
    }

    /// Tests for boundary conditions and RFC compliance
    #[test]
    fn test_rfc_compliance() {
        // RFC 1035: Labels must be 63 octets or less
        let label_63 = format!("{}.com", "a".repeat(63));
        assert!(validate_site_name(&label_63));

        let label_64 = format!("{}.com", "a".repeat(64));
        assert!(!validate_site_name(&label_64));

        // RFC 1035: Total domain name must be 253 characters or less
        // This is for the wire format, excluding the final dot
        let domain_253 = format!(
            "{}.{}.{}.{}",
            "a".repeat(63),
            "b".repeat(63),
            "c".repeat(63),
            "d".repeat(61)
        );
        assert_eq!(domain_253.len(), 253);
        assert!(validate_site_name(&domain_253));

        let domain_254 = format!("{}.com", "a".repeat(250));
        assert!(domain_254.len() > 253);
        assert!(!validate_site_name(&domain_254));

        // RFC 1123: Allows digits at the start of labels
        assert!(validate_site_name("123start.example.com"));
        assert!(validate_site_name("999.example.com"));

        // RFC 952: Originally didn't allow digits at start, but RFC 1123 relaxed this
        assert!(validate_site_name("3com.example.com"));
    }

    /// Tests specific patterns that have caused issues in the past
    #[test]
    fn test_regression_cases() {
        // Double hyphens in middle (should be valid)
        assert!(validate_site_name("test--site.example.com"));

        // Single character labels (valid)
        assert!(validate_site_name("a.b.example.com"));
        assert!(validate_site_name("1.2.example.com"));

        // All numeric subdomain (valid)
        assert!(validate_site_name("192.168.example.com"));

        // Looks like IP but has TLD (valid as domain)
        assert!(validate_site_name("192.168.1.example.com"));

        // Not actually an IP (has non-numeric parts)
        assert!(validate_site_name("192.168.1.1.com"));

        // Mixed case throughout
        assert!(validate_site_name("WwW.GoOgLe.CoM"));
        assert!(validate_site_name("API.v2.Example.COM"));
    }

    /// Performance test for validation function
    #[test]
    fn test_performance_characteristics() {
        // Test that validation is efficient even for maximum-length domains
        let start = std::time::Instant::now();

        // Create and validate 1000 maximum-length domains
        for i in 0..1000 {
            let domain = format!("test{}.{}.{}.com", i % 100, "a".repeat(60), "b".repeat(60));
            let _ = validate_site_name(&domain);
        }

        let duration = start.elapsed();

        // Should complete in reasonable time (< 100ms for 1000 validations)
        assert!(
            duration.as_millis() < 100,
            "Validation took too long: {:?}",
            duration
        );
    }

    /// Tests for common typos and user errors
    #[test]
    fn test_common_user_errors() {
        // URL instead of domain
        assert!(!validate_site_name("http://example.com"));
        assert!(!validate_site_name("https://example.com"));
        assert!(!validate_site_name("ftp://example.com"));
        assert!(!validate_site_name("www.example.com/path"));
        assert!(!validate_site_name("example.com:8080"));
        assert!(!validate_site_name("user@example.com"));

        // IP addresses (not valid domains for our purposes)
        assert!(!validate_site_name("192.168.1.1"));
        assert!(!validate_site_name("10.0.0.1"));
        assert!(!validate_site_name("::1"));
        assert!(!validate_site_name("2001:db8::1"));

        // Common typos
        assert!(!validate_site_name("example,com")); // Comma instead of dot
        assert!(!validate_site_name("example;com")); // Semicolon instead of dot
        assert!(!validate_site_name("example:com")); // Colon instead of dot
        assert!(!validate_site_name("example com")); // Space instead of dot
    }
}

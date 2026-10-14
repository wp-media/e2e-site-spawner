//! PHP version model and PHP-FPM socket helpers.
//!
//! [`crate::utils::php::PhpVersion`] is a strictly validated `X.Y` version. The strict format
//! matters because the value is interpolated into a filesystem path and into
//! Nginx config, so anything outside `<digits>.<digits>` (including path
//! separators, whitespace, or prefixes) is rejected at parse time.
//!
//! Socket helpers take an explicit directory where possible so they can be
//! unit-tested against a `TempDir` instead of [`crate::constants::PHP_FPM_SOCKET_DIR`].

use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use crate::constants::{DEFAULT_PHP_VERSION, PHP_FPM_SOCKET_DIR};

/// Maximum number of digits accepted in each version component.
const MAX_COMPONENT_DIGITS: usize = 2;

/// Prefix of a PHP-FPM socket file name (`php8.5-fpm.sock`).
const SOCKET_PREFIX: &str = "php";

/// Suffix of a PHP-FPM socket file name (`php8.5-fpm.sock`).
const SOCKET_SUFFIX: &str = "-fpm.sock";

/// Fallback used by [`PhpVersion::default_version`] if
/// [`DEFAULT_PHP_VERSION`] ever fails to parse. A unit test asserts both agree,
/// so this only exists to avoid a runtime panic.
const FALLBACK_DEFAULT: PhpVersion = PhpVersion { major: 8, minor: 5 };

/// A validated PHP `major.minor` version, e.g. `8.5`.
///
/// Ordering is numeric (`8.10 > 8.9`), so sorted lists read naturally.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PhpVersion {
    /// Major version (e.g. `8`).
    major: u8,
    /// Minor version (e.g. `5`).
    minor: u8,
}

impl PhpVersion {
    /// Returns the version named by [`DEFAULT_PHP_VERSION`].
    ///
    /// # Returns
    ///
    /// The parsed default; never panics (falls back to `8.5`, which a test
    /// keeps identical to the constant).
    pub fn default_version() -> Self {
        DEFAULT_PHP_VERSION.parse().unwrap_or(FALLBACK_DEFAULT)
    }

    /// Parses a strict `X.Y` version (1–2 digits per part, no leading zeros).
    ///
    /// # Arguments
    ///
    /// * `s` - Raw input, e.g. `"8.5"`. Not trimmed.
    ///
    /// # Errors
    ///
    /// Returns a human-readable message for any other shape, e.g. `8`,
    /// `8.5.1`, `v8.5`, `" 8.5"`, `8.x`, `-8.5`, `08.5`, empty, or `8/5`.
    pub fn parse(s: &str) -> Result<Self, String> {
        let invalid = || format!("invalid PHP version '{s}': expected MAJOR.MINOR, e.g. 8.5");
        let (major, minor) = s.split_once('.').ok_or_else(invalid)?;
        Ok(Self {
            major: parse_component(major).ok_or_else(invalid)?,
            minor: parse_component(minor).ok_or_else(invalid)?,
        })
    }

    /// Clap `value_parser` for `--php`; clap reports the error and exits 2.
    ///
    /// # Arguments
    ///
    /// * `s` - The raw CLI value.
    ///
    /// # Errors
    ///
    /// Same message as [`PhpVersion::parse`].
    pub fn parse_cli(s: &str) -> Result<Self, String> {
        Self::parse(s)
    }

    /// Socket file name for this version, e.g. `php8.5-fpm.sock`.
    fn socket_file_name(&self) -> String {
        format!("{SOCKET_PREFIX}{self}{SOCKET_SUFFIX}")
    }

    /// Absolute socket path under [`PHP_FPM_SOCKET_DIR`].
    ///
    /// # Returns
    ///
    /// e.g. `"/var/run/php/php8.5-fpm.sock"`, as used in `fastcgi_pass unix:…;`.
    pub fn fpm_socket_path(&self) -> String {
        self.fpm_socket_path_in(Path::new(PHP_FPM_SOCKET_DIR))
            .to_string_lossy()
            .into_owned()
    }

    /// Socket path for this version inside `dir`.
    ///
    /// # Arguments
    ///
    /// * `dir` - Directory holding PHP-FPM sockets.
    ///
    /// # Returns
    ///
    /// `dir/php<X.Y>-fpm.sock` (not checked for existence).
    pub fn fpm_socket_path_in(&self, dir: &Path) -> PathBuf {
        dir.join(self.socket_file_name())
    }

    /// Whether this version's FPM socket exists in [`PHP_FPM_SOCKET_DIR`].
    ///
    /// A socket only exists while that PHP-FPM version is installed **and
    /// running**, so `false` can also mean "installed but stopped".
    pub fn is_fpm_available(&self) -> bool {
        self.is_fpm_available_in(Path::new(PHP_FPM_SOCKET_DIR))
    }

    /// Whether this version's FPM socket exists in `dir`.
    ///
    /// # Arguments
    ///
    /// * `dir` - Directory holding PHP-FPM sockets.
    pub fn is_fpm_available_in(&self, dir: &Path) -> bool {
        self.fpm_socket_path_in(dir).exists()
    }
}

impl Default for PhpVersion {
    /// Same as [`PhpVersion::default_version`].
    fn default() -> Self {
        Self::default_version()
    }
}

impl FromStr for PhpVersion {
    type Err = String;

    /// Delegates to [`PhpVersion::parse`].
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

impl fmt::Display for PhpVersion {
    /// Formats as `MAJOR.MINOR`, e.g. `8.5`; round-trips through `parse`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}", self.major, self.minor)
    }
}

/// Parses one version component: 1–2 ASCII digits, no leading zero unless `0`.
///
/// Leading zeros are rejected so every accepted string is canonical and
/// `Display` round-trips exactly (`08.5` would otherwise become `8.5`).
///
/// # Returns
///
/// `Some(n)` on success, `None` otherwise.
fn parse_component(s: &str) -> Option<u8> {
    let valid_len = !s.is_empty() && s.len() <= MAX_COMPONENT_DIGITS;
    let all_digits = s.bytes().all(|b| b.is_ascii_digit());
    let no_leading_zero = s.len() == 1 || !s.starts_with('0');
    if !(valid_len && all_digits && no_leading_zero) {
        return None;
    }
    s.parse().ok()
}

/// Lists PHP versions that have a `php<X.Y>-fpm.sock` file in `dir`.
///
/// Entries whose name does not match the strict pattern (e.g. `php-fpm.sock`,
/// `php8.5-fpm.pid`) are ignored.
///
/// # Arguments
///
/// * `dir` - Directory to scan, normally [`PHP_FPM_SOCKET_DIR`].
///
/// # Returns
///
/// Sorted, de-duplicated versions; empty if `dir` is missing or unreadable.
pub fn installed_fpm_versions(dir: &Path) -> Vec<PhpVersion> {
    let Ok(entries) = fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut versions: Vec<PhpVersion> = entries
        .filter_map(Result::ok)
        .filter_map(|e| version_from_socket_name(&e.file_name().to_string_lossy()))
        .collect();
    versions.sort_unstable();
    versions.dedup();
    versions
}

/// Extracts the version from a socket file name like `php8.5-fpm.sock`.
///
/// # Returns
///
/// `Some(version)` if the name matches exactly, `None` otherwise.
fn version_from_socket_name(name: &str) -> Option<PhpVersion> {
    let version = name
        .strip_prefix(SOCKET_PREFIX)?
        .strip_suffix(SOCKET_SUFFIX)?;
    PhpVersion::parse(version).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    /// Shorthand constructor for expected values.
    fn v(major: u8, minor: u8) -> PhpVersion {
        PhpVersion { major, minor }
    }

    #[test]
    fn parses_valid_versions() {
        assert_eq!(PhpVersion::parse("8.5"), Ok(v(8, 5)));
        assert_eq!(PhpVersion::parse("7.4"), Ok(v(7, 4)));
        assert_eq!(PhpVersion::parse("10.12"), Ok(v(10, 12)));
        assert_eq!(PhpVersion::parse("10.0"), Ok(v(10, 0)));
        assert_eq!(PhpVersion::parse("0.0"), Ok(v(0, 0)));
        assert_eq!("99.99".parse::<PhpVersion>(), Ok(v(99, 99)));
    }

    #[test]
    fn rejects_invalid_forms() {
        let bad = [
            "", ".", "8", "8.", ".5", "8.5.1", "v8.5", " 8.5", "8.5 ", "8.x", "x.5", "-8.5",
            "8.-5", "+8.5", "8/5", "8.5/", "../8.5", "8,5", "08.5", "8.05", "100.1", "8.123",
            "8..5", "８.５", "8.5\n", "8.5;",
        ];
        for s in bad {
            assert!(PhpVersion::parse(s).is_err(), "should reject {s:?}");
        }
    }

    #[test]
    fn display_round_trips() {
        for s in ["8.5", "7.4", "10.12", "10.0"] {
            let parsed = PhpVersion::parse(s);
            assert_eq!(parsed.map(|p| p.to_string()), Ok(s.to_string()));
        }
    }

    #[test]
    fn orders_numerically() {
        assert!(v(8, 10) > v(8, 9));
        assert!(v(10, 0) > v(9, 9));
    }

    #[test]
    fn socket_paths_have_expected_format() {
        assert_eq!(v(8, 5).fpm_socket_path(), "/var/run/php/php8.5-fpm.sock");
        assert_eq!(
            v(7, 4).fpm_socket_path_in(Path::new("/x")),
            PathBuf::from("/x/php7.4-fpm.sock")
        );
    }

    #[test]
    fn fpm_availability_follows_socket_existence() {
        let dir = TempDir::new().expect("tempdir");
        assert!(!v(8, 5).is_fpm_available_in(dir.path()));
        fs::write(v(8, 5).fpm_socket_path_in(dir.path()), "").expect("write");
        assert!(v(8, 5).is_fpm_available_in(dir.path()));
        assert!(!v(8, 1).is_fpm_available_in(dir.path()));
    }

    #[test]
    fn installed_versions_empty_dir() {
        let dir = TempDir::new().expect("tempdir");
        assert!(installed_fpm_versions(dir.path()).is_empty());
    }

    #[test]
    fn installed_versions_missing_dir() {
        let dir = TempDir::new().expect("tempdir");
        assert!(installed_fpm_versions(&dir.path().join("nope")).is_empty());
    }

    #[test]
    fn installed_versions_filters_and_sorts() {
        let dir = TempDir::new().expect("tempdir");
        let names = [
            "php8.5-fpm.sock",
            "php8.10-fpm.sock",
            "php8.1-fpm.sock",
            "php-fpm.sock",
            "php8.5-fpm.pid",
            "phpx.y-fpm.sock",
            "php08.1-fpm.sock",
            "other.sock",
        ];
        for n in names {
            fs::write(dir.path().join(n), "").expect("write");
        }
        // A directory with a matching name still counts; only the name is checked.
        fs::create_dir(dir.path().join("php7.4-fpm.sock")).expect("mkdir");
        assert_eq!(
            installed_fpm_versions(dir.path()),
            vec![v(7, 4), v(8, 1), v(8, 5), v(8, 10)]
        );
    }

    #[test]
    fn version_from_socket_name_cases() {
        assert_eq!(version_from_socket_name("php8.5-fpm.sock"), Some(v(8, 5)));
        assert_eq!(version_from_socket_name("php8.5-fpm.sock.bak"), None);
        assert_eq!(version_from_socket_name("xphp8.5-fpm.sock"), None);
    }

    #[test]
    fn default_constant_parses_and_matches_fallback() {
        assert_eq!(PhpVersion::parse(DEFAULT_PHP_VERSION), Ok(FALLBACK_DEFAULT));
        assert_eq!(PhpVersion::default_version(), FALLBACK_DEFAULT);
        assert_eq!(PhpVersion::default(), FALLBACK_DEFAULT);
    }

    #[test]
    fn parse_cli_error_text() {
        let err = PhpVersion::parse_cli("abc").unwrap_err();
        assert_eq!(
            err,
            "invalid PHP version 'abc': expected MAJOR.MINOR, e.g. 8.5"
        );
        assert_eq!(PhpVersion::parse_cli("8.3"), Ok(v(8, 3)));
    }
}

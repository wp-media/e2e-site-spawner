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
use std::os::unix::fs::FileTypeExt;
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
/// [`DEFAULT_PHP_VERSION`] ever fails to parse. Must be changed together with
/// that constant; the `default_constant_parses_and_matches_fallback` test
/// fails if they disagree. It only exists to avoid a runtime panic.
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
    /// # Returns
    ///
    /// The parsed [`PhpVersion`].
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
    /// # Returns
    ///
    /// The parsed [`PhpVersion`].
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

    /// Whether this version's FPM socket is present in [`PHP_FPM_SOCKET_DIR`].
    ///
    /// A socket only exists while that PHP-FPM version is installed **and
    /// running**, so `false` can also mean "installed but stopped".
    ///
    /// # Returns
    ///
    /// `true` if `php<X.Y>-fpm.sock` resolves (following symlinks) to a Unix
    /// socket, `false` otherwise. See [`PhpVersion::is_fpm_available_in`].
    pub fn is_fpm_available(&self) -> bool {
        self.is_fpm_available_in(Path::new(PHP_FPM_SOCKET_DIR))
    }

    /// Whether this version's FPM socket is present in `dir`.
    ///
    /// Uses the same check as [`installed_fpm_versions`], so the two never
    /// disagree.
    ///
    /// # Arguments
    ///
    /// * `dir` - Directory holding PHP-FPM sockets.
    ///
    /// # Returns
    ///
    /// `true` only if the entry is a Unix socket or a symlink to one. Missing
    /// entries, plain files, directories, and dangling symlinks yield `false`.
    pub fn is_fpm_available_in(&self, dir: &Path) -> bool {
        is_socket(&self.fpm_socket_path_in(dir))
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

/// Lists PHP versions that have a live `php<X.Y>-fpm.sock` socket in `dir`.
///
/// An entry counts only if its name matches the strict pattern **and** it
/// passes the same socket check as [`PhpVersion::is_fpm_available_in`]
/// (a Unix socket, or a symlink to one). Non-matching names (e.g.
/// `php-fpm.sock`, `php8.5-fpm.pid`), plain files, directories, dangling
/// symlinks, and entries `read_dir` fails to read are skipped.
///
/// No de-duplication is needed: directory entry names are unique and only
/// canonical version strings parse, so each version appears at most once.
///
/// # Arguments
///
/// * `dir` - Directory to scan, normally [`PHP_FPM_SOCKET_DIR`].
///
/// # Returns
///
/// Versions sorted ascending; empty if `dir` is missing or unreadable.
pub fn installed_fpm_versions(dir: &Path) -> Vec<PhpVersion> {
    let Ok(entries) = fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut versions: Vec<PhpVersion> = entries
        .filter_map(Result::ok)
        .filter_map(|e| {
            let version = version_from_socket_name(&e.file_name().to_string_lossy())?;
            is_socket(&e.path()).then_some(version)
        })
        .collect();
    versions.sort_unstable();
    versions
}

/// Whether `path` resolves to a Unix socket.
///
/// Uses [`fs::metadata`], which follows symlinks, so a symlink to a live
/// socket counts while a dangling one does not.
///
/// # Arguments
///
/// * `path` - Path to inspect.
///
/// # Returns
///
/// `true` for a socket (directly or via symlink); `false` for anything else,
/// including missing or inaccessible paths.
fn is_socket(path: &Path) -> bool {
    fs::metadata(path).is_ok_and(|m| m.file_type().is_socket())
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

/// Preflight: ensures `version`'s PHP-FPM socket is live in `dir`.
///
/// Must run before any state mutation so `spawn`/`update` never write a
/// config whose `fastcgi_pass` targets a missing socket (`nginx -t` would
/// accept it, but PHP requests would return 502).
///
/// # Arguments
///
/// * `version` - Version the generated config will target.
/// * `dir` - Directory holding PHP-FPM sockets, normally [`PHP_FPM_SOCKET_DIR`].
///
/// # Errors
///
/// Returns the message built by [`fpm_unavailable_message`] when the socket
/// is missing (or is not a socket).
pub fn ensure_fpm_available_in(version: PhpVersion, dir: &Path) -> Result<(), String> {
    if version.is_fpm_available_in(dir) {
        return Ok(());
    }
    let socket = version.fpm_socket_path_in(dir);
    let installed = installed_fpm_versions(dir);
    Err(fpm_unavailable_message(version, &socket, &installed))
}

/// [`ensure_fpm_available_in`] against [`PHP_FPM_SOCKET_DIR`].
///
/// # Arguments
///
/// * `version` - Version the generated config will target.
///
/// # Errors
///
/// Same as [`ensure_fpm_available_in`].
pub fn ensure_fpm_available(version: PhpVersion) -> Result<(), String> {
    ensure_fpm_available_in(version, Path::new(PHP_FPM_SOCKET_DIR))
}

/// Formats the "PHP-FPM not available" error (pure; no I/O).
///
/// # Arguments
///
/// * `version` - The unavailable version.
/// * `socket` - Socket path that was expected.
/// * `installed` - Versions with a live socket (see [`installed_fpm_versions`]).
///
/// # Returns
///
/// e.g. `PHP-FPM 8.5 is not available (socket /var/run/php/php8.5-fpm.sock
/// not found; is php8.5-fpm installed and running?). Installed: 8.1, 8.3.`;
/// `Installed: none.` when the list is empty.
pub fn fpm_unavailable_message(
    version: PhpVersion,
    socket: &Path,
    installed: &[PhpVersion],
) -> String {
    let list = if installed.is_empty() {
        "none".to_string()
    } else {
        installed
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(", ")
    };
    format!(
        "PHP-FPM {version} is not available (socket {} not found; is php{version}-fpm installed and running?). Installed: {list}.",
        socket.display()
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;
    use std::os::unix::net::UnixListener;
    use tempfile::TempDir;

    /// Temp dir with a short name so socket paths stay under the ~104-byte
    /// `sun_path` limit on macOS.
    fn short_tempdir() -> TempDir {
        tempfile::Builder::new()
            .prefix("p")
            .tempdir()
            .expect("tempdir")
    }

    /// Binds a real Unix socket at `path`; keep the listener alive for the test.
    fn bind(path: &Path) -> UnixListener {
        UnixListener::bind(path).expect("bind socket")
    }

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
        let dir = short_tempdir();
        assert!(!v(8, 5).is_fpm_available_in(dir.path()));
        let _l = bind(&v(8, 5).fpm_socket_path_in(dir.path()));
        assert!(v(8, 5).is_fpm_available_in(dir.path()));
        assert!(!v(8, 1).is_fpm_available_in(dir.path()));
    }

    #[test]
    fn fpm_availability_rejects_non_sockets() {
        let dir = short_tempdir();
        fs::write(v(8, 1).fpm_socket_path_in(dir.path()), "").expect("write");
        fs::create_dir(v(8, 2).fpm_socket_path_in(dir.path())).expect("mkdir");
        symlink(
            dir.path().join("gone"),
            v(8, 3).fpm_socket_path_in(dir.path()),
        )
        .expect("symlink");
        for minor in 1..=3 {
            assert!(!v(8, minor).is_fpm_available_in(dir.path()), "8.{minor}");
        }
    }

    #[test]
    fn fpm_availability_accepts_symlink_to_socket() {
        let dir = short_tempdir();
        let target = dir.path().join("real.sock");
        let _l = bind(&target);
        symlink(&target, v(8, 4).fpm_socket_path_in(dir.path())).expect("symlink");
        assert!(v(8, 4).is_fpm_available_in(dir.path()));
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
        let dir = short_tempdir();
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
        let _listeners: Vec<UnixListener> =
            names.iter().map(|n| bind(&dir.path().join(n))).collect();
        // A symlink to a live socket counts.
        symlink(
            dir.path().join("php8.5-fpm.sock"),
            dir.path().join("php7.4-fpm.sock"),
        )
        .expect("symlink");
        assert_eq!(
            installed_fpm_versions(dir.path()),
            vec![v(7, 4), v(8, 1), v(8, 5), v(8, 10)]
        );
    }

    #[test]
    fn installed_versions_skip_non_sockets_with_matching_names() {
        let dir = short_tempdir();
        fs::write(dir.path().join("php8.1-fpm.sock"), "").expect("write");
        fs::create_dir(dir.path().join("php8.2-fpm.sock")).expect("mkdir");
        symlink(dir.path().join("gone"), dir.path().join("php8.3-fpm.sock")).expect("symlink");
        let _l = bind(&dir.path().join("php8.4-fpm.sock"));
        assert_eq!(installed_fpm_versions(dir.path()), vec![v(8, 4)]);
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

    #[test]
    fn unavailable_message_lists_installed_versions() {
        let msg = fpm_unavailable_message(
            v(8, 5),
            Path::new("/var/run/php/php8.5-fpm.sock"),
            &[v(8, 1), v(8, 3)],
        );
        assert_eq!(
            msg,
            "PHP-FPM 8.5 is not available (socket /var/run/php/php8.5-fpm.sock not found; \
             is php8.5-fpm installed and running?). Installed: 8.1, 8.3."
        );
    }

    #[test]
    fn unavailable_message_with_nothing_installed() {
        let msg = fpm_unavailable_message(v(8, 5), Path::new("/s"), &[]);
        assert!(msg.ends_with("Installed: none."), "{msg}");
    }

    #[test]
    fn ensure_available_ok_when_socket_live() {
        let dir = short_tempdir();
        let _l = bind(&v(8, 5).fpm_socket_path_in(dir.path()));
        assert_eq!(ensure_fpm_available_in(v(8, 5), dir.path()), Ok(()));
    }

    #[test]
    fn ensure_available_err_names_socket_and_installed() {
        let dir = short_tempdir();
        let _l = bind(&v(8, 1).fpm_socket_path_in(dir.path()));
        let err = ensure_fpm_available_in(v(8, 5), dir.path()).unwrap_err();
        let socket = v(8, 5).fpm_socket_path_in(dir.path());
        assert_eq!(err, fpm_unavailable_message(v(8, 5), &socket, &[v(8, 1)]));
        assert!(err.contains(&socket.display().to_string()));
    }

    #[test]
    fn ensure_available_err_for_missing_dir() {
        let dir = TempDir::new().expect("tempdir");
        let err = ensure_fpm_available_in(v(8, 5), &dir.path().join("nope")).unwrap_err();
        assert!(err.ends_with("Installed: none."), "{err}");
    }

    #[test]
    fn ensure_available_default_dir_matches_message_shape() {
        // Host-independent: either the socket exists or the error names it.
        if let Err(e) = ensure_fpm_available(v(8, 5)) {
            assert!(e.contains("/var/run/php/php8.5-fpm.sock"), "{e}");
        }
    }
}

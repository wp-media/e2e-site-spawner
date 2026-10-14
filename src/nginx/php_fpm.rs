//! Detects and rewrites the PHP-FPM version used by an existing site config.
//!
//! Managed configs route PHP through
//! `fastcgi_pass unix:{PHP_FPM_SOCKET_DIR}/phpX.Y-fpm.sock;`. These helpers are
//! pure functions over the file's text, so the I/O (reading, backup, writing,
//! `nginx -t`) stays in the command layer. They do **not** check the managed
//! marker; callers must run `is_managed_by_this_tool` first.
//!
//! A line counts as a `fastcgi_pass` directive when, after leading whitespace,
//! it starts with `fastcgi_pass` followed by whitespace. Commented lines
//! (`# fastcgi_pass …`) and sibling directives such as `fastcgi_pass_header`
//! are therefore ignored.
//!
//! Parsing fails closed: any other line that still mentions `fastcgi_pass` as
//! a whole word outside a comment (a one-line `location { fastcgi_pass …; }`
//! block, a directive split across lines, two directives on one line, …) is
//! reported as [`crate::nginx::php_fpm::PhpFpmConfigError::Unrecognized`] instead of being skipped,
//! so a rewrite is never silently partial.

use std::fmt;
use std::ops::Range;

use crate::constants::PHP_FPM_SOCKET_DIR;
use crate::utils::php::PhpVersion;

/// The directive whose socket path carries the PHP version.
const FASTCGI_PASS: &str = "fastcgi_pass";

/// Why a config's PHP-FPM version could not be detected or rewritten.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PhpFpmConfigError {
    /// The config has no active `fastcgi_pass` directive (e.g. a static site
    /// edited by hand); there is nothing to detect or rewrite.
    NoFastcgiPass,
    /// A `fastcgi_pass` line does not match the managed socket format (e.g. a
    /// hand-edited TCP upstream `127.0.0.1:9000`). Holds the trimmed line.
    /// The tool refuses to touch such configs.
    Unrecognized(String),
    /// The `fastcgi_pass` lines name different versions. Holds the distinct
    /// versions, sorted ascending.
    Inconsistent(Vec<PhpVersion>),
}

impl fmt::Display for PhpFpmConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoFastcgiPass => write!(f, "no fastcgi_pass directive found"),
            Self::Unrecognized(line) => write!(
                f,
                "unrecognized fastcgi_pass (expected unix:{PHP_FPM_SOCKET_DIR}/phpX.Y-fpm.sock;): {line}"
            ),
            Self::Inconsistent(versions) => {
                let list: Vec<String> = versions.iter().map(ToString::to_string).collect();
                write!(
                    f,
                    "fastcgi_pass lines use different PHP versions: {}",
                    list.join(", ")
                )
            }
        }
    }
}

impl std::error::Error for PhpFpmConfigError {}

/// One recognized `fastcgi_pass` socket reference inside the config text.
#[derive(Debug, Clone, PartialEq, Eq)]
struct SocketRef {
    /// Version named by the socket path.
    version: PhpVersion,
    /// Byte range of the `X.Y` token within the whole content.
    span: Range<usize>,
}

/// Returns the PHP version shared by every `fastcgi_pass` line.
///
/// # Arguments
///
/// * `content` - Full text of an Nginx site config.
///
/// # Returns
///
/// The single version used by all active `fastcgi_pass` directives.
///
/// # Errors
///
/// * [`PhpFpmConfigError::NoFastcgiPass`] - no active directive;
/// * [`PhpFpmConfigError::Unrecognized`] - a directive is not a managed socket;
/// * [`PhpFpmConfigError::Inconsistent`] - directives disagree on the version.
pub fn detect_php_version(content: &str) -> Result<PhpVersion, PhpFpmConfigError> {
    let refs = collect_socket_refs(content)?;
    let mut versions: Vec<PhpVersion> = refs.iter().map(|r| r.version).collect();
    versions.sort();
    versions.dedup();
    match versions.as_slice() {
        [single] => Ok(*single),
        _ => Err(PhpFpmConfigError::Inconsistent(versions)),
    }
}

/// Rewrites every `fastcgi_pass` socket to use `version`.
///
/// Only the `X.Y` token inside each socket path changes; indentation, line
/// endings, comments and every other byte are preserved. The operation is
/// idempotent. Mixed versions are unified, since every line is validated
/// before anything is rewritten.
///
/// # Arguments
///
/// * `content` - Full text of an Nginx site config.
/// * `version` - Version to write into every socket path.
///
/// # Returns
///
/// The rewritten config text.
///
/// # Errors
///
/// [`PhpFpmConfigError::NoFastcgiPass`] or
/// [`PhpFpmConfigError::Unrecognized`]; the content is then left untouched.
pub fn set_php_version(content: &str, version: PhpVersion) -> Result<String, PhpFpmConfigError> {
    let refs = collect_socket_refs(content)?;
    let replacement = version.to_string();
    let mut out = String::with_capacity(content.len());
    let mut cursor = 0;
    // Spans are collected in ascending order and never overlap.
    for r in refs {
        out.push_str(&content[cursor..r.span.start]);
        out.push_str(&replacement);
        cursor = r.span.end;
    }
    out.push_str(&content[cursor..]);
    Ok(out)
}

/// Finds and parses every active `fastcgi_pass` line.
///
/// # Arguments
///
/// * `content` - Full config text.
///
/// # Returns
///
/// The socket references in file order (at least one).
///
/// # Errors
///
/// `NoFastcgiPass` when none exist, `Unrecognized` on the first bad line.
fn collect_socket_refs(content: &str) -> Result<Vec<SocketRef>, PhpFpmConfigError> {
    let mut refs = Vec::new();
    let mut offset = 0;
    for line in content.split_inclusive('\n') {
        if mentions_fastcgi_pass(line) {
            let r = directive_value_start(line)
                .and_then(|value_start| parse_socket_value(line, value_start))
                .ok_or_else(|| PhpFpmConfigError::Unrecognized(line.trim().to_string()))?;
            refs.push(SocketRef {
                version: r.version,
                span: offset + r.span.start..offset + r.span.end,
            });
        }
        offset += line.len();
    }
    if refs.is_empty() {
        return Err(PhpFpmConfigError::NoFastcgiPass);
    }
    Ok(refs)
}

/// Tells whether `line` mentions the `fastcgi_pass` keyword as a whole word
/// before any `#` comment.
///
/// Siblings such as `fastcgi_pass_header` do not count, because the keyword
/// must not be followed (or preceded) by an identifier character. Any line
/// for which this returns `true` must parse as a managed directive, or the
/// whole config is rejected.
///
/// # Arguments
///
/// * `line` - One line, possibly with its trailing newline.
///
/// # Returns
///
/// `true` when the active (uncommented) part contains the keyword.
fn mentions_fastcgi_pass(line: &str) -> bool {
    let active = line.split('#').next().unwrap_or_default();
    let bytes = active.as_bytes();
    let is_ident = |b: u8| b.is_ascii_alphanumeric() || b == b'_';
    active.match_indices(FASTCGI_PASS).any(|(start, _)| {
        let end = start + FASTCGI_PASS.len();
        let before = start.checked_sub(1).and_then(|i| bytes.get(i));
        before.is_none_or(|&b| !is_ident(b)) && bytes.get(end).is_none_or(|&b| !is_ident(b))
    })
}

/// Returns the byte index (within `line`) where a `fastcgi_pass` value
/// starts, or `None` if the line is not an active `fastcgi_pass` directive.
///
/// # Arguments
///
/// * `line` - One line, possibly with its trailing newline.
fn directive_value_start(line: &str) -> Option<usize> {
    let body = line.trim_start();
    let rest = body.strip_prefix(FASTCGI_PASS)?;
    // Require whitespace so `fastcgi_pass_header` etc. do not match.
    if !rest.starts_with([' ', '\t']) {
        return None;
    }
    let value = rest.trim_start();
    Some(line.len() - value.len())
}

/// Parses `unix:{DIR}/phpX.Y-fpm.sock;` (optionally followed by whitespace
/// and/or a `#` comment) starting at `value_start` in `line`.
///
/// # Arguments
///
/// * `line` - The directive line.
/// * `value_start` - Byte index of the directive's value within `line`.
///
/// # Returns
///
/// The version and its byte span relative to `line`, or `None` when the
/// value is not a managed socket.
fn parse_socket_value(line: &str, value_start: usize) -> Option<SocketRef> {
    let prefix = format!("unix:{PHP_FPM_SOCKET_DIR}/php");
    let after_prefix = line[value_start..].strip_prefix(prefix.as_str())?;
    let version_len = after_prefix.find("-fpm.sock")?;
    let version = PhpVersion::parse(&after_prefix[..version_len]).ok()?;
    let tail = after_prefix[version_len..]
        .strip_prefix("-fpm.sock")?
        .trim_start()
        .strip_prefix(';')?
        .trim();
    if !tail.is_empty() && !tail.starts_with('#') {
        return None;
    }
    let start = value_start + prefix.len();
    Some(SocketRef {
        version,
        span: start..start + version_len,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::{NGINX_HTTP_TEMPLATE, NGINX_HTTPS_TEMPLATE};

    /// Parses a test version literal.
    fn v(s: &str) -> PhpVersion {
        PhpVersion::parse(s).unwrap()
    }

    /// Renders a template the way pre-P2.1 releases did (legacy socket).
    fn legacy(template: &str, version: &str) -> String {
        template
            .replace("!{{site_name}}!", "qa2.example.com")
            .replace("!{{site_path}}!", "/var/www/html/qa2.example.com")
            .replace("!{{ssl_path}}!", "/etc/nginx/ssl/qa2.example.com")
            .replace(
                "!{{php_fpm_socket}}!",
                &format!("/var/run/php/php{version}-fpm.sock"),
            )
    }

    /// Legacy HTTP-only config with the hard-coded 8.1 socket.
    fn legacy_http() -> String {
        legacy(NGINX_HTTP_TEMPLATE, "8.1")
    }

    /// Legacy HTTP + HTTPS config (as `update --ssl` appends it).
    fn legacy_http_https() -> String {
        format!(
            "{}\n{}",
            legacy(NGINX_HTTP_TEMPLATE, "8.1"),
            legacy(NGINX_HTTPS_TEMPLATE, "8.1")
        )
    }

    // ===== detect_php_version =====

    #[test]
    fn detects_single_block() {
        assert_eq!(detect_php_version(&legacy_http()), Ok(v("8.1")));
    }

    #[test]
    fn detects_two_blocks() {
        assert_eq!(detect_php_version(&legacy_http_https()), Ok(v("8.1")));
    }

    #[test]
    fn detects_current_default_template() {
        let c = legacy(NGINX_HTTPS_TEMPLATE, "8.5");
        assert_eq!(detect_php_version(&c), Ok(v("8.5")));
    }

    #[test]
    fn mixed_versions_are_inconsistent_sorted_and_deduped() {
        let c = format!(
            "{}\n{}\n{}",
            legacy(NGINX_HTTP_TEMPLATE, "8.5"),
            legacy(NGINX_HTTPS_TEMPLATE, "8.1"),
            legacy(NGINX_HTTPS_TEMPLATE, "8.5"),
        );
        assert_eq!(
            detect_php_version(&c),
            Err(PhpFpmConfigError::Inconsistent(vec![v("8.1"), v("8.5")]))
        );
    }

    #[test]
    fn tcp_upstream_is_unrecognized() {
        let c = legacy_http().replace("unix:/var/run/php/php8.1-fpm.sock", "127.0.0.1:9000");
        assert_eq!(
            detect_php_version(&c),
            Err(PhpFpmConfigError::Unrecognized(
                "fastcgi_pass 127.0.0.1:9000;".to_string()
            ))
        );
    }

    #[test]
    fn foreign_socket_shapes_are_unrecognized() {
        for value in [
            "unix:/run/php/php8.1-fpm.sock;",       // other dir
            "unix:/var/run/php/php-fpm.sock;",      // no version
            "unix:/var/run/php/php8.1.2-fpm.sock;", // bad version
            "unix:/var/run/php/phpv8.1-fpm.sock;",  // bad version
            "unix:/var/run/php/php8.1-fpm.sock",    // missing ';'
            "unix:/var/run/php/php8.1-fpm.sockx;",  // trailing junk
            "unix:/var/run/php/php8.1-fpm.sock; x", // trailing junk
            "unix:/var/run/php/php8.1-fpm.socket;", // wrong suffix
            "UNIX:/var/run/php/php8.1-fpm.sock;",   // case
            "$upstream;",                           // variable
        ] {
            let c = format!("location ~ \\.php$ {{\n    fastcgi_pass {value}\n}}\n");
            assert!(
                matches!(
                    detect_php_version(&c),
                    Err(PhpFpmConfigError::Unrecognized(_))
                ),
                "{value}"
            );
        }
    }

    #[test]
    fn missing_directive_is_no_fastcgi_pass() {
        let c = legacy_http().replace("fastcgi_pass", "# removed");
        assert_eq!(
            detect_php_version(&c),
            Err(PhpFpmConfigError::NoFastcgiPass)
        );
        assert_eq!(
            detect_php_version(""),
            Err(PhpFpmConfigError::NoFastcgiPass)
        );
        assert_eq!(
            detect_php_version("<html>not nginx</html>"),
            Err(PhpFpmConfigError::NoFastcgiPass)
        );
    }

    #[test]
    fn commented_directives_are_ignored() {
        let c = format!(
            "# fastcgi_pass 127.0.0.1:9000;\n    #fastcgi_pass unix:/var/run/php/php7.4-fpm.sock;\n{}",
            legacy_http()
        );
        assert_eq!(detect_php_version(&c), Ok(v("8.1")));
        // Only commented directives → nothing active.
        assert_eq!(
            detect_php_version("  # fastcgi_pass unix:/var/run/php/php8.1-fpm.sock;\n"),
            Err(PhpFpmConfigError::NoFastcgiPass)
        );
    }

    #[test]
    fn sibling_directives_are_ignored() {
        let c = format!(
            "fastcgi_pass_header Authorization;\nfastcgi_pass_request_body on;\n{}",
            legacy_http()
        );
        assert_eq!(detect_php_version(&c), Ok(v("8.1")));
    }

    #[test]
    fn whitespace_variants_are_accepted() {
        for line in [
            "fastcgi_pass unix:/var/run/php/php8.3-fpm.sock;",
            "\tfastcgi_pass\tunix:/var/run/php/php8.3-fpm.sock;",
            "   fastcgi_pass    unix:/var/run/php/php8.3-fpm.sock ;   ",
            "fastcgi_pass unix:/var/run/php/php8.3-fpm.sock;\r",
            "fastcgi_pass unix:/var/run/php/php8.3-fpm.sock; # trailing comment",
        ] {
            assert_eq!(detect_php_version(line), Ok(v("8.3")), "{line:?}");
        }
    }

    #[test]
    fn first_bad_line_wins_over_good_ones() {
        let c = format!("{}\nfastcgi_pass 127.0.0.1:9000;\n", legacy_http());
        assert!(matches!(
            detect_php_version(&c),
            Err(PhpFpmConfigError::Unrecognized(_))
        ));
    }

    #[test]
    fn error_display_texts() {
        assert_eq!(
            PhpFpmConfigError::NoFastcgiPass.to_string(),
            "no fastcgi_pass directive found"
        );
        assert!(
            PhpFpmConfigError::Unrecognized("fastcgi_pass x;".into())
                .to_string()
                .ends_with(": fastcgi_pass x;")
        );
        assert_eq!(
            PhpFpmConfigError::Inconsistent(vec![v("8.1"), v("8.5")]).to_string(),
            "fastcgi_pass lines use different PHP versions: 8.1, 8.5"
        );
    }

    // ===== set_php_version =====

    #[test]
    fn rewrite_changes_only_the_version_token() {
        let before = legacy_http_https();
        let after = set_php_version(&before, v("8.5")).unwrap();
        assert_eq!(after, before.replace("php8.1-fpm.sock", "php8.5-fpm.sock"));
        assert_eq!(after.len(), before.len());
        // Byte-level: only positions inside the version tokens differ.
        let diffs = before
            .bytes()
            .zip(after.bytes())
            .filter(|(a, b)| a != b)
            .count();
        assert_eq!(diffs, 2, "one digit per block");
        assert_eq!(detect_php_version(&after), Ok(v("8.5")));
    }

    #[test]
    fn rewrite_preserves_indentation_and_line_endings() {
        let before = "\t  fastcgi_pass   unix:/var/run/php/php8.1-fpm.sock ; # keep\r\nnext\r\n";
        let after = set_php_version(before, v("10.12")).unwrap();
        assert_eq!(
            after,
            "\t  fastcgi_pass   unix:/var/run/php/php10.12-fpm.sock ; # keep\r\nnext\r\n"
        );
    }

    #[test]
    fn rewrite_handles_length_change() {
        let before = legacy_http_https();
        let after = set_php_version(&before, v("10.0")).unwrap();
        assert_eq!(after, before.replace("php8.1-fpm.sock", "php10.0-fpm.sock"));
    }

    #[test]
    fn rewrite_is_idempotent() {
        let once = set_php_version(&legacy_http_https(), v("8.5")).unwrap();
        let twice = set_php_version(&once, v("8.5")).unwrap();
        assert_eq!(once, twice);
        // Same version as present → identical output.
        assert_eq!(
            set_php_version(&legacy_http(), v("8.1")).unwrap(),
            legacy_http()
        );
    }

    #[test]
    fn rewrite_unifies_mixed_versions() {
        let before = format!(
            "{}\n{}",
            legacy(NGINX_HTTP_TEMPLATE, "8.5"),
            legacy(NGINX_HTTPS_TEMPLATE, "8.1")
        );
        let after = set_php_version(&before, v("8.3")).unwrap();
        assert_eq!(detect_php_version(&after), Ok(v("8.3")));
    }

    #[test]
    fn rewrite_leaves_comments_and_siblings_untouched() {
        let before = format!(
            "# fastcgi_pass unix:/var/run/php/php8.1-fpm.sock;\nfastcgi_pass_header X;\n{}",
            legacy_http()
        );
        let after = set_php_version(&before, v("8.5")).unwrap();
        assert!(after.starts_with(
            "# fastcgi_pass unix:/var/run/php/php8.1-fpm.sock;\nfastcgi_pass_header X;\n"
        ));
        assert_eq!(detect_php_version(&after), Ok(v("8.5")));
    }

    #[test]
    fn rewrite_refuses_unrecognized_and_missing() {
        let tcp = format!("{}\nfastcgi_pass 127.0.0.1:9000;\n", legacy_http());
        assert!(matches!(
            set_php_version(&tcp, v("8.5")),
            Err(PhpFpmConfigError::Unrecognized(_))
        ));
        assert_eq!(
            set_php_version("server { listen 80; }", v("8.5")),
            Err(PhpFpmConfigError::NoFastcgiPass)
        );
    }

    #[test]
    fn rewrite_without_trailing_newline() {
        let before = "fastcgi_pass unix:/var/run/php/php8.1-fpm.sock;";
        assert_eq!(
            set_php_version(before, v("8.4")).unwrap(),
            "fastcgi_pass unix:/var/run/php/php8.4-fpm.sock;"
        );
    }

    // ===== fail-closed layouts and edge cases =====

    /// Asserts that both detect and set reject `content` as `Unrecognized`.
    fn assert_unrecognized(content: &str) {
        assert!(
            matches!(
                detect_php_version(content),
                Err(PhpFpmConfigError::Unrecognized(_))
            ),
            "detect: {content:?}"
        );
        assert!(
            matches!(
                set_php_version(content, v("8.5")),
                Err(PhpFpmConfigError::Unrecognized(_))
            ),
            "set: {content:?}"
        );
    }

    #[test]
    fn one_line_block_is_unrecognized() {
        let c = format!(
            "{}\nlocation ~ \\.php$ {{ fastcgi_pass unix:/var/run/php/php8.1-fpm.sock; }}\n",
            legacy_http()
        );
        assert_unrecognized(&c);
    }

    #[test]
    fn split_directive_is_unrecognized() {
        for c in [
            "fastcgi_pass\n    unix:/var/run/php/php8.1-fpm.sock;\n",
            "  fastcgi_pass\r\n unix:/var/run/php/php8.1-fpm.sock;\r\n",
            "fastcgi_pass",
            "fastcgi_pass # value on next line\nunix:/var/run/php/php8.1-fpm.sock;\n",
        ] {
            assert_unrecognized(c);
        }
    }

    #[test]
    fn trailing_directive_on_same_line_is_unrecognized() {
        assert_unrecognized(
            "fastcgi_pass unix:/var/run/php/php8.1-fpm.sock; fastcgi_index index.php;\n",
        );
    }

    #[test]
    fn upstream_name_is_unrecognized() {
        assert_unrecognized("location ~ \\.php$ {\n    fastcgi_pass php_backend;\n}\n");
    }

    #[test]
    fn mention_after_comment_hash_is_ignored() {
        let c = "fastcgi_pass unix:/var/run/php/php8.1-fpm.sock; # fastcgi_pass x\n";
        assert_eq!(detect_php_version(c), Ok(v("8.1")));
        assert_eq!(
            detect_php_version("listen 80; # fastcgi_pass gone\n"),
            Err(PhpFpmConfigError::NoFastcgiPass)
        );
    }

    #[test]
    fn include_line_is_ignored() {
        let c = format!(
            "include fastcgi_params;\ninclude /etc/nginx/fastcgi_pass.conf.d/*.conf;\n{}",
            legacy_http()
        );
        // The second include mentions `fastcgi_pass` only as part of a path
        // segment followed by `.`, which is a word boundary: fail closed.
        assert_unrecognized(&c);
        let c = format!("include fastcgi_params;\n{}", legacy_http());
        assert_eq!(detect_php_version(&c), Ok(v("8.1")));
        assert_eq!(
            set_php_version(&c, v("8.5")).unwrap(),
            c.replace("php8.1-fpm", "php8.5-fpm")
        );
    }

    #[test]
    fn non_ascii_content_around_directive() {
        let c = "# café ☕ — config ñ\nserver_name ñandú.example;\n  fastcgi_pass unix:/var/run/php/php8.1-fpm.sock; # ü 日本\nroot /var/www/ü;\n";
        assert_eq!(detect_php_version(c), Ok(v("8.1")));
        assert_eq!(
            set_php_version(c, v("10.2")).unwrap(),
            c.replace("php8.1-fpm", "php10.2-fpm")
        );
    }

    #[test]
    fn crlf_config_with_multiple_blocks() {
        let c = legacy_http_https().replace('\n', "\r\n");
        assert_eq!(detect_php_version(&c), Ok(v("8.1")));
        let after = set_php_version(&c, v("8.5")).unwrap();
        assert_eq!(after, c.replace("php8.1-fpm", "php8.5-fpm"));
        assert_eq!(after.matches("\r\n").count(), c.matches("\r\n").count());
    }

    #[test]
    fn very_long_line() {
        let pad = "x".repeat(200_000);
        let c = format!("# {pad}\nfastcgi_pass unix:/var/run/php/php8.1-fpm.sock; # {pad}\n");
        assert_eq!(detect_php_version(&c), Ok(v("8.1")));
        assert_eq!(
            set_php_version(&c, v("8.5")).unwrap(),
            c.replace("php8.1-fpm", "php8.5-fpm")
        );
        assert_unrecognized(&format!("fastcgi_pass {pad};\n"));
    }
}

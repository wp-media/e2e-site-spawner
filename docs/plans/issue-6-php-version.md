# Plan — Issue #6: Configurable PHP version (default 8.5)

## TLDR

- The PHP-FPM socket is hard-coded to `php8.1-fpm.sock` in both Nginx templates. It becomes a `!{{php_fpm_socket}}!` placeholder, and the default version becomes **8.5**.
- New `--php <X.Y>` flag:
  - `spawn --php 8.3` writes the site with that version (default 8.5).
  - `update <site> --php 8.4` rewrites the `fastcgi_pass` lines of an existing managed site. It backs up the file, runs `nginx -t`, reverts on failure, and reloads.
- A strict `PhpVersion` type checks the value at parse time (`X.Y` only). If the FPM socket is missing, the command **fails early** and lists the installed versions.
- `update --ssl` reuses the site's *current* PHP version, so HTTP and HTTPS never disagree. `list` shows `php X.Y`.
- P0 first fixes two existing `update` bugs: it never reloads Nginx, and `update --ssl` appends the HTTPS block twice.

---

## Context

Issue <https://github.com/wp-media/e2e-site-spawner/issues/6>: `src/assets/http.conf.template:26` and `src/assets/https.conf.template:47` hard-code `fastcgi_pass unix:/var/run/php/php8.1-fpm.sock;`. 8.1 is outdated. The issue asks for a default of at least 8.5 (PHP 8.5.0 GA'd 2025-11-20) and for the version to be configurable on `spawn` and `update`.

Problems found while exploring, which this plan also fixes (user-approved):
- `update_site` (`src/cli/commands.rs:924`) never calls `reload_nginx()`, so changes made by `update` are not applied until something else reloads Nginx. It also swallows sub-step errors (`unwrap_or(())`) and exits 0.
- `update_with_ssl` appends the HTTPS block **twice** (`commands.rs:1626-1627` and `:1651-1655`). Nginx only warns about the duplicate `server_name` and `nginx -t` passes, so the bug goes unnoticed.

Decisions (confirmed with the user):
- Missing FPM socket → **hard fail** before any state changes, listing the installed versions.
- Fix the `update` bugs in a dedicated phase.
- `list` shows each managed site's PHP version.

## Stack

Rust edition 2024 (rustc 1.97.1). No new dependencies: `clap` 4.6.7 (locked) with the builder API and a custom `value_parser` (`Fn(&str) -> Result<T, String>`, checked against the clap docs), `std` for parsing and filesystem work, and `tempfile` for tests. No regex crate: parsing uses simple `strip_prefix`/`strip_suffix`.

## Design

**`PhpVersion`** (new `src/utils/php.rs`, helper layer, no panics)
- `#[derive(Debug, Clone, Copy, PartialEq, Eq)] pub struct PhpVersion { major: u8, minor: u8 }`.
- `FromStr`/`parse`: accepts exactly `<digits>.<digits>`, with 1–2 digits per part (e.g. `8.5`, `7.4`, `10.0`). It rejects `8`, `8.5.1`, `v8.5`, ` 8.5`, `8.x`, `-8.5`, empty values, and anything containing `/`. The strict format matters because the value ends up in a filesystem path and in Nginx config, so it also blocks injection.
- `Display` → `"8.5"`. `fpm_socket_path(&self) -> String` → `"{PHP_FPM_SOCKET_DIR}/php8.5-fpm.sock"`.
- `fpm_socket_path_in(&self, dir: &Path)` and `installed_fpm_versions(dir: &Path) -> Vec<PhpVersion>` (scans for `php*-fpm.sock`, sorted, deduped). These take a directory argument so tests can use a `TempDir`.
- `is_fpm_available(&self) -> bool`: checks whether the socket exists. A socket only exists while FPM is **installed and running**, and the error message says this.
- `parse_cli(s) -> Result<PhpVersion, String>`: the clap `value_parser`, which gives a friendly error on invalid input (exit 2).

**Constants** (`src/constants.rs`, documented like the existing ones): `DEFAULT_PHP_VERSION: &str = "8.5"` and `PHP_FPM_SOCKET_DIR: &str = "/var/run/php"` (the existing path; `/var/run` → `/run` on Debian/Ubuntu).

**Nginx model** (`src/nginx/config.rs`)
- `NginxConfig` gets `pub php_version: PhpVersion`. `new(...)` keeps its signature and uses the default. A builder `with_php_version(self, PhpVersion) -> Self` avoids touching the 10+ existing `new` call sites.
- The default is built from `DEFAULT_PHP_VERSION` through a helper (`PhpVersion::default_version()`). A unit test asserts that the constant parses. `impl Default` returns it, so no `unwrap` is needed at runtime.
- Templates: `fastcgi_pass unix:!{{php_fpm_socket}}!;`. `generate_config` replaces it for both protocols.

**Config inspection/rewrite** (new `src/nginx/php_fpm.rs`, pure functions over `&str`)
- `detect_php_version(content) -> Result<PhpVersion, PhpFpmConfigError>`. It finds every line whose trimmed form starts with `fastcgi_pass`, and requires every one to be `unix:{PHP_FPM_SOCKET_DIR}/phpX.Y-fpm.sock;` with the **same** version.
- `set_php_version(content, PhpVersion) -> Result<String, PhpFpmConfigError>` rewrites those lines and keeps indentation and all other bytes unchanged.
- `PhpFpmConfigError` (`Display` + `Error`) has three variants: `NoFastcgiPass`, `Unrecognized(String)` (e.g. a hand-edited `127.0.0.1:9000`, which the tool refuses to touch), and `Inconsistent(Vec<PhpVersion>)`.
- New I/O helper in `src/nginx/utils.rs`: `overwrite_nginx_file(path, content)`. It reuses `get_validated_nginx_path` and requires the file to already exist. It is used for the PHP rewrite and for reverting a backup. `update_with_ssl` currently reverts with a raw `fs::write`; that becomes this helper (DRY).

**Command flow (`update`)**
```text
parse flags → validate name → nginx -t → exists? → managed?
→ resolve php: requested --php  OR  detect_php_version(current file) (fallback: default + warning)
→ [--php] preflight socket → backup → rewrite → nginx -t → revert on failure      (skip if same version)
→ [--wp]  update_with_wordpress (unchanged)
→ [--ssl] update_with_ssl, with the HTTPS block built from the *resolved* php version
→ if any nginx change succeeded: nginx -t + reload_nginx()
→ exit 1 if any requested step failed
```
The order is PHP → WP → SSL so that the HTTPS block appended last uses the new version. There is a single reload at the end.

---

## Phases

### P0 — Fix existing `update` bugs
- **Depends:** none · **Parallel with:** P1, P2.1
- **Goal:** `update` applies its changes and reports failures correctly.
- **Changes (`src/cli/commands.rs` only):**
  - Remove the second `generate_config(Https)` + `append_to_nginx_file` block in `update_with_ssl` (`:1651-1679`). Move the `set_path_owner_recursive` call so it still runs after the first append.
  - In `update_site`: collect each sub-step's `Result`. If an Nginx-changing step succeeded, run `validate_nginx_configuration()` then `reload_nginx()`. `process::exit(1)` if any requested step failed. Fix the stale doc comments, including the `update_with_ssl` doc's "Configures HTTP to HTTPS redirect" claim, which the template does not do.
- **DoD:** the validation suite is green. On a QA VM, `update --ssl` produces a file with exactly one `NGINX_HTTPS_CONFIG_MARKER` pair, and the site serves HTTPS right away without a manual reload.
- **Commit:** `fix(update): reload nginx after updates and stop appending the HTTPS block twice`

### P1 — `PhpVersion` type + constants
- **Depends:** none · **Parallel with:** P0
- **Changes:** new `src/utils/php.rs` and `pub mod php;` in `src/utils/mod.rs`; `DEFAULT_PHP_VERSION` and `PHP_FPM_SOCKET_DIR` in `src/constants.rs`.
- **Tests (unit):**
  - valid versions: `8.5`, `7.4`, `10.12`;
  - every rejected form listed above;
  - `Display` round-trip; socket path format;
  - `installed_fpm_versions` on a `TempDir`: empty dir, mixed files (`php8.1-fpm.sock`, `php8.5-fpm.sock`, `php-fpm.sock`, `php8.5-fpm.pid`, `phpx.y-fpm.sock`), sorted output, missing dir → empty;
  - `fpm_socket_path_in` existence check;
  - `DEFAULT_PHP_VERSION` parses; `parse_cli` error text.
- **DoD:** suite green; no `unwrap`/`panic!` outside tests.
- **Commit:** `feat(php): add validated PhpVersion type and PHP-FPM socket helpers`

### P2.1 — Template placeholder + default 8.5
- **Depends:** P1 · **Parallel with:** P0, P2.2
- **Changes:** both templates (`!{{php_fpm_socket}}!`); `NginxConfig` field + `with_php_version` + replacement in `generate_config`; doc updates (module doc, struct doc, placeholder list).
- **Tests:**
  - HTTP and HTTPS output contain `php8.5-fpm.sock` by default and `php8.3-fpm.sock` after `with_php_version(8.3)`;
  - no `8.1` remains anywhere in the generated output;
  - the existing `test_template_replacement_completeness` keeps proving that no `!{{` placeholders are left.
  - The three struct-literal tests in `config.rs` (`test_validate_invalid_site_names`, `test_validate_paths_nonexistent`, `test_validate_paths_file_not_directory`) need a `php_version` field only so they compile. Their assertions stay unchanged, and the commit message explains this, as your testing rules require.
- **DoD:** suite green. New spawns, even without a flag, get 8.5.
- **Commit:** `feat(nginx): template the PHP-FPM socket and default to PHP 8.5`
- **Interim guard (follow-up fix):** `spawn` and `update --ssl` now run `utils::php::ensure_fpm_available` for the config's version (the default until P3) right before any mutation, and exit 1 with the missing socket path and installed versions. This keeps develop from silently writing configs for a missing socket. P3 (`spawn --php`) and P4 (`update --php`) reuse and extend this same preflight instead of adding a new one.
- **Follow-up commit:** `fix(spawn,update): refuse to write configs for a missing PHP-FPM socket`

### P2.2 — Detect / rewrite PHP version in existing configs
- **Depends:** P1 · **Parallel with:** P0, P2.1, P3
- **Changes:** new `src/nginx/php_fpm.rs` (+ `src/nginx/mod.rs` export); `overwrite_nginx_file` in `src/nginx/utils.rs`.
- **Tests (unit, fixtures = real legacy 8.1 HTTP-only + HTTP+HTTPS files):**
  - detection: single block, two blocks, mixed versions → `Inconsistent`, TCP upstream → `Unrecognized`, missing → `NoFastcgiPass`, commented-out `# fastcgi_pass` ignored;
  - rewrite: preserves indentation and every byte except the version; is idempotent;
  - `overwrite_nginx_file`: rejects a non-`.conf` path, a traversal path, or a missing file, and succeeds on an existing file (`TempDir`).
- **DoD:** suite green.
- **Commit:** `feat(nginx): detect and rewrite the PHP-FPM version of managed configs`

### P3 — `spawn --php`
- **Depends:** P2.1 · **Parallel with:** P2.2
- **Changes:**
  - `src/cli/args.rs`: `--php <VERSION>` with `value_parser(PhpVersion::parse_cli)`, `default_value(DEFAULT_PHP_VERSION)` so help shows `[default: 8.5]`, help text, and an `after_help` example. Also fix the stale module/`build_cli` docs that say `update` is "not yet implemented" and don't mention `list`.
  - `src/main.rs`: `get_one::<PhpVersion>("php")`.
  - `spawn_site(site_name, ssl, no_wp, php)`: preflight `is_fpm_available()` right after the existing validations and **before** any mutation. On failure: `✗ PHP-FPM 8.3 is not available (socket … not found; is php8.3-fpm installed and running?). Installed: 8.1, 8.5.` then exit 1. Then `NginxConfig::new(..).with_php_version(php)`. Update the doc and examples.
  - `README.md`: command table + "What gets provisioned?" (PHP-FPM socket line), prerequisites (8.5 is the default PHP-FPM version; any installed `X.Y` can be chosen with `spawn --php X.Y`). State that static (`--no-wp`) sites also need a live PHP-FPM socket, because both templates always emit `fastcgi_pass`.
- **Tests:** integration tests that run without root, because clap parses before the privilege gate:
  - `spawn x.com --php abc` → exit 2 with the error text;
  - `spawn x.com --php 8.5.1` → exit 2;
  - `spawn --help` contains `--php` and `default: 8.5`;
  - `spawn x.com --php 8.3` without root → still the "ELEVATED PRIVILEGES REQUIRED" path;
  - an `#[ignore]`d root test spawns with `--php` on the QA VM.
- **DoD:** suite green; help output and README match.
- **Commit:** `feat(spawn): add --php option to choose the PHP-FPM version`

### P4 — `update --php` + version-consistent `update --ssl`
- **Depends:** P0, P2.2, P3 · **Parallel with:** P5
- **Changes:**
  - `args.rs`: `--php <VERSION>` on `update`, with **no default** (absent = leave unchanged), plus help and examples.
  - `main.rs`: pass `Option<PhpVersion>`.
  - `commands.rs`:
    - The "no updates" guard now includes `php`.
    - A new private `update_with_php(&NginxConfig, PhpVersion) -> Result<bool, ()>` (`true` = changed). It reads the backup, detects the current version (if it is the same, it prints "already uses PHP X.Y" and returns `Ok(false)`), runs the socket preflight, then `set_php_version` → `overwrite_nginx_file` → `nginx -t`. On failure it restores the backup with `overwrite_nginx_file`.
    - A resolver helper picks the requested version, or the detected one, or the default with a `⚠` warning. `update_with_ssl` uses it so the appended HTTPS block matches the HTTP block.
    - Keep each function under ~20 lines where practical by extracting small helpers.
  - `README.md` updated.
  - Switch `update_with_ssl`'s raw `fs::write` revert to `overwrite_nginx_file` (deferred from the P2.2 audit).
- **Tests:**
  - integration: `update x.com --php bad` → exit 2; `update --help` shows `--php` with no default; without root → privilege error;
  - the unit-testable resolver logic is a pure function `resolve_php_version(requested: Option<PhpVersion>, detected: Result<PhpVersion, _>) -> (PhpVersion, Option<warning>)`, with tests for all branches;
  - an `#[ignore]`d root test covers spawn 8.1-style → `update --php 8.5` → file contains only 8.5.
- **DoD:** suite green. On a QA VM, a legacy 8.1 site moves to 8.5 with `update --php 8.5`, and `update --php 9.9` fails without changing the file.
- **Commit:** `feat(update): add --php option to switch an existing site's PHP-FPM version`
- **Implementation notes:** the socket preflight runs once in `update_site`, before any step (so `--php --wp` never installs WordPress for a missing socket), instead of inside `update_with_php`; it is skipped only for `--php X.Y` alone when the site already uses `X.Y`. `--ssl` is skipped (counted as failed) when the `--php` step failed, so the HTTPS block never disagrees with the HTTP block. The detection-failure fallback (default + `⚠`) is printed only when `--ssl` uses it.

### P5 — `list` shows PHP version
- **Depends:** P2.2 · **Parallel with:** P3, P4
- **Changes:**
  - `list_sites`: add `php_version: Option<PhpVersion>` to `SiteInfo`, filled from `detect_php_version(&content)` (content is already read).
  - Show `php X.Y` among the features, or `php ?` when detection fails.
  - Extract the feature-string formatting into a pure helper so it can be unit-tested.
  - Update the `after_help` OUTPUT FORMAT in `args.rs` and the README.
- **Tests:** unit tests for the formatting helper covering every combination: ssl/wp/php, and a version that could not be detected.
- **DoD:** suite green; help text and README match.
- **Commit:** `feat(list): show each managed site's PHP version`

---

## Critical files
`src/assets/{http,https}.conf.template`, `src/constants.rs`, `src/utils/php.rs` (new), `src/nginx/php_fpm.rs` (new), `src/nginx/{config,utils,mod}.rs`, `src/cli/{args,commands}.rs`, `src/main.rs`, `README.md`, `tests/integration_tests.rs`. After P5, update the test count in CLAUDE.md's "Current baseline" section.

Reused helpers: `get_validated_nginx_path` (`src/nginx/utils.rs:73`), `validate_nginx_configuration`, `reload_nginx`, `is_managed_by_this_tool`, `check_if_site_exists` (`src/utils/sites.rs:1365`), the `NginxConfig::generate_config` placeholder pattern, and the existing `✓`/`✗` + `colored` output style.

## Out of scope (noted, not changed)
- `update` on a **deactivated** site is rejected as "not managed", because it only looks at `.conf`. This is existing behavior.
- Installing PHP-FPM itself is the server's job; the tool only checks the socket.
- Bumping the crate version (0.1.2 → 0.2.0, since this adds a feature) is left to your usual separate `chore: bump version` commit.

## Verification
1. After each phase, run the validation suite in one execution:
   `cargo fmt --check; cargo clippy --all-targets --all-features -- -D warnings; cargo test; cargo doc --no-deps`.
2. Local, no root:
   - `cargo run -- spawn a.example.com --php nope` → exit 2 with a clear error;
   - `cargo run -- spawn --help` and `update --help` show `--php`.
3. Disposable QA LNMP VM (with php8.1-fpm and php8.5-fpm installed):
   - `spawn s.e2e… ` → config has `php8.5-fpm.sock` and the site renders;
   - `spawn t.e2e… --php 8.1 --ssl` → both blocks use 8.1;
   - `update t.e2e… --php 8.5` → both blocks use 8.5, reloaded, site renders;
   - `update t.e2e… --php 9.9` → fails before writing, and the file is identical (check with `sha256sum`);
   - `update u.e2e… --ssl` on an HTTP-only 8.1 site → exactly one HTTPS block, using 8.1;
   - `list` shows `php X.Y`;
   - `cargo test -- --ignored` as root.

# E2E Site Spawner

[![CI](https://github.com/wp-media/e2e-site-spawner/actions/workflows/ci.yml/badge.svg?branch=develop)](https://github.com/wp-media/e2e-site-spawner/actions/workflows/ci.yml)

CLI for provisioning and managing WordPress or static sites on the QA LNMP server fleet. The tool orchestrates nginx, filesystem layout, SSL certificates, and MySQL/MariaDB databases so that each site follows the same hardened baseline.

## Feature Highlights

- **End-to-end lifecycle** – `spawn`, `delete`, `deactivate`, `activate`, `update`, and `list` commands cover the entire site lifecycle.
- **Safe automation** – every provisioning step is tracked so the tool can roll back partial work automatically when failures occur.
- **WordPress aware** – downloads the latest WordPress build, creates a dedicated database, and generates a salted `wp-config.php` file.
- **HTTPS ready** – integrates with [`acme.sh`](https://github.com/acmesh-official/acme.sh) to request and install Let's Encrypt certificates, then appends the HTTPS server block to nginx.
- **Static sites supported** – `--no-wp` produces a static site skeleton backed by the bundled `default-index.html` template.
- **Site inventory** – `list` command provides a comprehensive overview of all configured sites with their status and features.

> **IMPORTANT**
>
> This binary is tailored for the WP Media QA LNMP environment documented in the [QA LNMP runbook](https://www.notion.so/wpmedia/LNMP-WordPress-site-on-Nginx-137b1ef929d14b029a940567f0605a4c). Paths, users, and services are hard-coded to match that stack. Other LNMP servers that share similar configuration might be compatible as well. However, it should be possible to use in environments with different configuration if values of constants are adapted for it.

## Prerequisites

### System requirements

- Linux host with nginx, PHP-FPM, and systemd (the tool reloads nginx via `systemctl`).
- Root or sudo privileges. All commands exit early if they are not executed by root.
- `curl` and `tar` for downloading and unpacking WordPress.
- `mysql`/`mariadb` server reachable at `localhost` (host constant can be changed) with a root account that can create databases and grant privileges.
- Writable directories that match the built-in paths:
  - Sites root: `/var/www/html`
  - Nginx configs: `/etc/nginx/conf.d`
  - SSL certs: `/etc/nginx/ssl`

### SSL requirements

- [`acme.sh`](https://github.com/acmesh-official/acme.sh) must be installed as root / sudo and in `$PATH` for any `--ssl` or `update --ssl` operation. The tool checks `acme.sh --version` before continuing.
- DNS must already point the requested domain to the server and port 80 must be reachable for the HTTP-01 challenge.

## Installation

Install Rust by following the instructions at [rust-lang.org](https://www.rust-lang.org/tools/install), then build and install the CLI:

```bash
git clone <repository-url>
cd e2e-site-spawner

# Build and install to /usr/local/bin for system-wide access
cargo build --release
sudo cp target/release/e2sp /usr/local/bin/
sudo chown root:root /usr/local/bin/e2sp
sudo chmod 755 /usr/local/bin/e2sp
```

The binary is now available system-wide and can be run with `sudo e2sp` without PATH issues.

### Alternative: Install to custom location

If you prefer to use Cargo's install mechanism:

```bash
# Install to a temporary location
cargo install --path . --root /tmp/e2sp-install

# Copy to system location
sudo cp /tmp/e2sp-install/bin/e2sp /usr/local/bin/
sudo chown root:root /usr/local/bin/e2sp
sudo chmod 755 /usr/local/bin/e2sp

# Clean up temporary files
rm -rf /tmp/e2sp-install
```

### Upgrading

To upgrade to the latest version:

```bash
cd e2e-site-spawner
git pull

# Rebuild and replace the binary
cargo build --release
sudo cp target/release/e2sp /usr/local/bin/
sudo chown root:root /usr/local/bin/e2sp
sudo chmod 755 /usr/local/bin/e2sp
```

### Uninstalling

To remove the binary:

```bash
sudo rm /usr/local/bin/e2sp
```

If you originally installed with `cargo install --path .` to your user directory:

```bash
# Also remove from user's cargo bin if it exists there
cargo uninstall e2e-site-spawner
```

## Usage

All lifecycle commands require elevated privileges:

```bash
sudo e2sp --help
```

| Command | Description |
| --- | --- |
| `spawn <site> [--ssl] [--no-wp]` | Creates a new site, sets up nginx, filesystem, default WordPress install, optional SSL. |
| `delete <site>` | Removes nginx configs, site files, SSL certificates, and the MySQL database. |
| `deactivate <site>` | Renames the nginx config to `.conf.deactivated` to take the site offline without deleting assets. |
| `activate <site>` | Reverts the `.deactivated` config back to `.conf` and reloads nginx. |
| `update <site> [--wp] [--ssl]` | Adds WordPress to a static site and/or enables SSL on an existing HTTP-only deployment. |
| `list` | Displays all configured sites with their status, features, and management information. |

Use `e2sp <command> --help` for command-specific usage text and examples.

### Command details

#### `spawn`

Creates `/var/www/html/<site>` along with `/etc/nginx/conf.d/<site>.conf`. When WordPress is enabled (default):

- Downloads the latest WordPress release.
- Creates a MySQL database named `wp_<site>` (punctuation replaced with `_`).
- Generates `wp-config.php` with salts and the credentials defined in `src/constants.rs`.

Flags:

- `--ssl` – triggers certificate issuance via acme.sh and appends the HTTPS server block.
- `--no-wp` – skips the WordPress install and drops in the default static `index.html`.

#### `delete`

Destroys everything created by `spawn`, including SSL directories and databases, then reloads nginx. This command is destructive and cannot be undone.

#### `deactivate` / `activate`

Toggle site availability by renaming the nginx configuration (`example.conf` ↔ `example.conf.deactivated`). Site files, SSL assets, and databases remain untouched.

#### `update`

Extends an existing site in-place:

- `--wp` – installs WordPress into an existing static site after ensuring no previous installation or database exists.
- `--ssl` – generates certificates, backs up the nginx config, appends the HTTPS block, validates nginx, and reverts on failure.

#### `list`

Provides a comprehensive inventory of all configured sites on the server. The command scans `/etc/nginx/conf.d/` for configuration files and displays:

- **Site name** – The domain name extracted from the config filename
- **Features** – Indicates if SSL and/or WordPress are enabled (color-coded)
- **Status** – Shows if the site is active or deactivated
- **Management** – Identifies sites managed by e2sp vs. external configurations

Output format:

```text
Sites list:

  example.com - ssl, wp - (active)
  test-site.com - wp - (deactivated)
  static-site.com - (active)
  old-site.com - (active) - not managed by e2sp

Summary:
  Total sites: 4 (3 active, 1 deactivated)
  Managed by e2sp: 3
  Not managed by e2sp: 1
```

Color coding:

- Site names: bright white
- SSL indicator: green
- WordPress indicator: blue
- Active status: green
- Deactivated status: yellow
- Unmanaged sites: dimmed gray

The command detects:

- **SSL status** by checking for HTTPS configuration markers in the nginx config
- **WordPress** by verifying the presence of `wp-config.php` in the site directory
- **Active/Deactivated** based on the config file extension (`.conf` vs `.conf.deactivated`)
- **e2sp management** by looking for specific configuration markers added by the tool

No arguments are required:

```bash
sudo e2sp list
```

## What gets provisioned?

| Resource | Location | Notes |
| --- | --- | --- |
| Site root | `/var/www/html/<site>` | Owned by `www-data:root`, chmod `0777` for compatibility with existing workflows. |
| Nginx config | `/etc/nginx/conf.d/<site>.conf` | HTTP block is always present; HTTPS block is appended when SSL is enabled. |
| SSL material | `/etc/nginx/ssl/<site>/` | Contains `privkey.pem` and `fullchain.pem`. Created only when SSL is requested. |
| Database | `wp_<site>` | Created through the MySQL root account and granted to the `wordpress` user with password `pleaseadvise` (see `src/constants.rs`). |

Each provisioning phase validates nginx syntax via `nginx -t`; failures trigger an automatic rollback using the tracked step list defined in `SpawnSteps`.

## Development

- Build the binary locally:

  ```bash
  cargo build
  ```

- Run the full test suite (some integration tests expect root access and a configured nginx/MySQL stack; run them inside a disposable VM):

  ```bash
  cargo test
  ```

- Format and lint before sending patches:

  ```bash
  cargo fmt
  cargo clippy --all-targets --all-features
  ```

Test doubles for nginx/MySQL are not provided—tests interact with the real system. When running without root the tests assert that permission errors are surfaced correctly.

### Continuous integration

[`.github/workflows/ci.yml`](.github/workflows/ci.yml) runs on every push and pull request against `develop`, weekly on a schedule, and on demand. It never writes to the repository.

| Job | What it does |
| --- | --- |
| `Check` | `cargo fmt --all --check`, `cargo clippy --all-targets --all-features --locked -- -D warnings`, and `cargo doc --no-deps --locked` with `RUSTDOCFLAGS=-D warnings`. |
| `Test (linux-x64)`, `Test (linux-arm64)` | `cargo test --locked` as an unprivileged user; the job aborts if the runner is root, since the CLI tests assert the privilege-refusal path. `#[ignore]`d tests (root / nginx / MySQL / network / acme.sh) are compiled and listed, never executed. |
| `Test (beta, advisory)` | Same suite on the beta toolchain. Advisory—never blocks a merge. |
| `Build (x86_64-unknown-linux-gnu)`, `Build (aarch64-unknown-linux-gnu)` | `cargo build --release --locked` natively on each architecture, smoke-tests `--version` / `--help`, and uploads `e2sp-<version>-<commit>-<target>.tar.gz` (30-day retention) so QA can grab any `develop` build. |
| `Security audit (advisory)` | `cargo audit` against `Cargo.lock`. Advisory, so an advisory freshly published against a transitive dependency cannot block unrelated PRs. |
| `CI` | Aggregate gate with a stable name—configure **this** one as the required status check in branch protection, since the matrix job names change whenever the matrix does. |

The arm64 legs use the `ubuntu-24.04-arm` runner, which is free for public repositories and unavailable in private ones.

### Releases

[`.github/workflows/release-cli.yml`](.github/workflows/release-cli.yml) owns `v*` tags and is the only workflow that writes anything:

```bash
# 1. bump `version` in Cargo.toml, refresh Cargo.lock, commit and merge to develop
# 2. tag the merged commit — the tag must be v<Cargo.toml version>
git tag -a v0.1.2 -m "e2sp 0.1.2"
git push origin v0.1.2
```

The workflow then, in order: refuses any ref that is not a tag; fails if the tag does not match the `Cargo.toml` version; re-runs fmt / clippy / tests on the tagged commit; builds an uncached release binary per architecture; uploads the archives plus `SHA256SUMS.txt` to a **draft** release; signs [build provenance](https://docs.github.com/en/actions/security-guides/using-artifact-attestations-to-establish-provenance-for-builds) for each archive; and only then publishes the release. A tag suffixed with a hyphen (`v0.2.0-rc.1`) is published as a prerelease—the rule that the tag equals `v<Cargo.toml version>` still holds, so set `version = "0.2.0-rc.1"` in `Cargo.toml` for those.

Each release archive contains the `e2sp` binary, `README.md` and `LICENSE`, and needs Ubuntu 24.04 (glibc 2.39) or newer. Consumers can verify a download with:

```bash
sha256sum -c SHA256SUMS.txt
gh attestation verify e2sp-<version>-<target>.tar.gz --repo wp-media/e2e-site-spawner
```

Because the release is assembled as a draft, any failure before the final step leaves an unpublished draft rather than a broken public release: fix the cause and re-run the workflow, or use `workflow_dispatch` against the existing tag (the entry appears once this file is on `develop`).

## Troubleshooting

- **"ELEVATED PRIVILEGES REQUIRED"** – rerun the command with `sudo` (or as root). The CLI prints the exact command to copy/paste.
- **`acme.sh` missing** – install it from <https://github.com/acmesh-official/acme.sh> as root / sudo or omit `--ssl`. And make sure create a symlink to be accesible globaly by all users, so, `sudo acme.sh..` work. You can do it with: `sudo ln -sf "/root/acme.sh" /usr/local/bin/acme.sh`
- **Nginx validation failures** – inspect `nginx -t` output. The tool cancels the operation if validation fails before or after file changes.
- **Database errors** – ensure the MySQL root user can create databases without a password or update `src/constants.rs` to match your environment.

## License

Distributed under the MIT License. See `LICENSE` for more information.

## Author

Sandy Figueroa: [Github](https://github.com/sandyfzu)

## Reference documentation

- [Rust Book](https://doc.rust-lang.org/book/)
- [Clap](https://docs.rs/clap/latest/clap/)
- [Internal QA LNMP guide](https://www.notion.so/wpmedia/LNMP-WordPress-site-on-Nginx-137b1ef929d14b029a940567f0605a4c)

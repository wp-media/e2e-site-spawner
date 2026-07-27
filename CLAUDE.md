# E2E Site Spawner — Claude Instructions

## Context

You are an expert Rust developer specializing in CLI tools and Linux system
automation. Your task is to provide SOLID, well-tested, and maintainable code
for a tool that provisions and manages Nginx sites on the WP Media QA LNMP
server fleet.

## Project Overview

**E2E Site Spawner** (binary `e2sp`, package `e2e-site-spawner`) is a Rust CLI
that provisions and manages WordPress or static sites on the QA LNMP stack. It
orchestrates Nginx configuration, the filesystem layout under `/var/www/html`,
Let's Encrypt certificates (via `acme.sh`), and MySQL/MariaDB databases so every
site follows the same hardened baseline.

- Single binary crate: entry point is `src/main.rs`, binary name `e2sp` (see
  `Cargo.toml`). There is **no library crate and no workspace** — modules are
  declared `pub mod` in `main.rs` and referenced via `crate::`.
- Edition 2024. Runtime deps: `clap` (builder API), `mysql`, `colored`, `libc`,
  `nix`, `rand`, `walkdir`. Dev deps: `assert_cmd`, `predicates`, `tempfile`.
- Every lifecycle command requires **root/sudo** and is enforced at runtime via
  `libc::geteuid() == 0`.
- Paths, users, DB credentials, and service assumptions are hard-coded for the
  QA LNMP environment in `src/constants.rs`; adapting to another host means
  editing those constants.

> This tool operates on real system state (Nginx, systemd, MySQL, the
> filesystem, DNS-backed SSL). Several operations are **destructive and
> irreversible** (`delete` drops databases and removes files). Treat it
> accordingly — see [Local Development & Testing](#local-development--testing).

## Core Architecture

Commands are parsed with `clap`, dispatched from `main.rs`, and implemented in a
thin command layer that calls small, focused, mostly-pure helpers.

```text
src/
├── main.rs                  # Entry point: clap dispatch + privilege gate
├── constants.rs             # All paths, DB settings, templates, markers
├── assets/                  # Templates embedded at compile time (include_str!)
│   ├── http.conf.template   #   placeholders: !{{site_name}}!, !{{site_path}}!
│   ├── https.conf.template  #   + !{{ssl_path}}!
│   └── default-index.html   #   static-site landing page (--no-wp)
├── cli/
│   ├── args.rs              # CLI definition (subcommands, flags, help, styling)
│   └── commands.rs          # spawn / delete / deactivate / activate / update / list
├── nginx/
│   ├── config.rs            # NginxConfig, NginxProtocol, config generation & `nginx -t`
│   └── utils.rs             # create/append config files, reload, managed-marker checks
└── utils/
    ├── db.rs                # MySQL create/drop/exists (DbError), db-name derivation
    ├── sites.rs             # filesystem ops, WordPress install, wp-config, rollback
    ├── ssl.rs               # acme.sh issuance/install/removal (String errors)
    └── validators.rs        # RFC-1035 domain (site-name) validation
```

### Key patterns to preserve

- **Transactional rollback.** `spawn` records each completed action in a
  `Vec<SpawnSteps>` (see `cli/commands.rs`). On any failure it calls
  `utils::sites::revert_site_spawn`, which undoes steps in reverse (LIFO),
  groups related steps to avoid redundant cleanup, then `process::exit(1)`.
  New multi-step, state-mutating operations should follow the same
  track-then-revert approach.
- **Validate Nginx around every change.** Call `validate_nginx_configuration()`
  (`nginx -t`) *before* and *after* writing config, and only then
  `reload_nginx()`. On post-change failure, revert.
- **Managed-marker convention.** Generated configs embed
  `NGINX_HTTP_CONFIG_MARKER` / `NGINX_HTTPS_CONFIG_MARKER`. Commands must use
  `is_managed_by_this_tool()` before mutating a site so hand-written/third-party
  configs are never touched.
- **Activate/deactivate by rename.** `.conf` ⇄ `.conf.deactivated`; no file
  contents change. `is_active_site()` reads the extension.
- **Template substitution.** `NginxConfig::generate_config` fills the
  `!{{…}}!` placeholders. Add new placeholders in both the template asset and
  the generator together.
- **Root DB access via Unix socket.** `utils::db` connects as `root` over the
  MySQL socket (no password) — this is why the tool must run under sudo.

## Core Principles

### Code Quality Standards

- **Production Bar**: Every change ships production-ready — clear, clean,
  stable, safe, secure, and robust, following best practices, properly tested
  and documented. Keep logic separate from I/O and side effects so most code is
  unit-testable (as the helpers in `utils`/`nginx` already are).
- **SOLID**: Write clean, single-responsibility code that's easy to test and
  maintain.
- **DRY**: Extract reusable logic into dedicated functions; reuse existing
  helpers in `utils`/`nginx` rather than re-implementing filesystem, DB, or
  Nginx operations.
- **KISS**: Prefer simple, clear solutions over complex abstractions.
- **Early Returns**: Use guard clauses and bail out early instead of nested
  conditionals.
- **Type Safety**: Use strict types throughout; model states with enums
  (`NginxProtocol`, `SpawnSteps`) and options rather than booleans/strings where
  it clarifies intent.
- **Documentation**: Every public function, method, struct, enum, and constant
  MUST be documented with `///` doc comments covering purpose, arguments,
  returns, errors, and — where relevant — panics and examples. This matches the
  existing house style.
- **Error Handling** (see the layered rules below): avoid `panic!`, `unwrap`,
  and `expect` in helper/library code; model and propagate errors with `Result`
  / `Option`.
- **Testing**: Write comprehensive unit and integration tests for all new
  features and bug fixes.
- **Dependency Management**: This is a single crate — all dependencies live in
  the one root `Cargo.toml`. Keep the set minimal and current, prefer `std`
  where reasonable, and remove unused dependencies. Justify any new dependency.
- **Validation**: After finishing changes, run the full suite in a single
  execution (see [Validation](#validation-suite)).

### Error Handling (layered)

The codebase uses a deliberate two-layer strategy — follow it:

- **Helper / "library" layer** (`nginx`, `utils::{db,sites,ssl,validators}`):
  return `Result`/`Option` and **must not panic**. Model domain failures with
  error enums that implement `Display` + `std::error::Error` (`DbError`,
  `FileCreationError`) or `Result<_, String>` for thin system-command wrappers
  (nginx/ssl), and propagate with `?` / `map_err`. Do **not** introduce
  `unwrap`/`expect`/`panic!` here.
- **CLI / command layer** (`main.rs`, `cli::commands`): this is the process's
  error boundary. Report a clear, user-facing message using the existing
  `✓`/`✗` + `colored` style, then `process::exit(1)` — or invoke
  `revert_site_spawn` for a partially-completed spawn. Panics must never reach
  the user.
- **Existing `unwrap`/`panic!` are intentional invariants** — preserve their
  intent, don't cargo-cult more: clap guarantees a required positional arg is
  present; `generate_config(Https)` panics only on the programmer error of a
  missing `ssl_root` (covered by a `#[should_panic]` test). Encode new
  invariants as `Result` unless a violation is genuinely an unrecoverable bug.

### Code Organization Best Practices

- Keep functions short (aim < 20 lines) and single-purpose.
- Extract complex logic into private helpers with descriptive names; public
  command functions should read like a table of contents (as `spawn_site` does).
- Follow the existing module boundaries: filesystem → `utils::sites`, DB →
  `utils::db`, SSL → `utils::ssl`, Nginx files → `nginx::utils`, Nginx config
  model → `nginx::config`, input validation → `utils::validators`, shared config
  → `constants`.

### Documentation Standards

- Explain **why**, not **what**; avoid comments that restate the code.
- Keep doc comments in sync with behavior — this repo has known doc/code drift
  (e.g., a doc comment claiming a command is "not implemented" when it is). When
  you touch a function, correct any stale doc comment you find.
- Remove commented-out code before committing (there are a few dead
  commented blocks; clean them up when you're in the file).

### Project-Specific Practices

**Before creating new code:**

1. Search for an existing helper in `utils`/`nginx` that already does it.
2. Check whether a similar command flow (e.g., the SSL or WordPress sub-flows in
   `update`) can be reused or factored out.
3. Prefer refactoring/extracting over duplicating.
4. Follow the directory structure and naming of the nearest similar feature.

**Refactoring legacy code:**

- Improve incrementally when you touch old code; add tests before refactoring.
- Maintain backward-compatible CLI behavior unless a change is explicitly
  intended.

**Keep the CLI surface and docs in sync (same change as the code):** when a
subcommand, flag, default, output format, path/credential constant, or the SSL/
WordPress workflow changes, update in the same commit:

- `src/cli/args.rs` (help text, `after_help` examples),
- `README.md` (the command table and "What gets provisioned?" section),
- the relevant `///` doc comments and any affected tests.

The **source of truth is the binary itself** — reconcile against
`e2sp <command> --help` and the code, not memory.

All new code MUST be tested and MUST NOT break existing passing tests.

## Testing

- **Unit tests** live inline in `#[cfg(test)] mod tests` next to the code they
  cover. **Integration/CLI tests** live in `tests/integration_tests.rs` and
  drive the built `e2sp` binary via `assert_cmd` + `predicates`.
- Tests that require **root**, a live **Nginx**/**MySQL**, **network** (the
  WordPress download), or **acme.sh** are marked `#[ignore]` and run manually on
  a disposable LNMP box. Preserve this convention: pure logic must be
  unit-testable without root or system services.
- Prefer `tempfile::TempDir` for filesystem tests; never write test artifacts
  into real system paths.

## Validation Suite

After finishing all changes, run the full validation suite in a single
execution:

```bash
echo -e "\n=== CARGO FMT ==="; cargo fmt --check; \
echo -e "\n=== CARGO CLIPPY ==="; cargo clippy --all-targets --all-features -- -D warnings; \
echo -e "\n=== CARGO TEST ==="; cargo test; \
echo -e "\n=== CARGO DOC ==="; cargo doc --no-deps
```

### Current baseline (verified green)

As of this commit (rustc 1.97.1, edition 2024) the whole suite is clean, with
**zero warnings**: `cargo fmt --check`, `cargo clippy --all-targets
--all-features -- -D warnings`, `cargo test` (122 pass; 17 are `#[ignore]`d
because they need root / Nginx / MySQL / network), `cargo build`, and
`cargo doc --no-deps` all exit 0. **Keep it green — do not introduce new
fmt/clippy violations, test failures, or rustdoc warnings.**

Notes for keeping docs warning-free:

- Link items by full path — `` [`crate::utils::db::create_wordpress_database`] ``.
  Plain `` [`some_fn`] `` only resolves inside the defining module.
- rustdoc **cannot** link a private item from another module (e.g.
  `cli::commands::update_with_ssl`). Link the public entry point and mention the
  helper in a plain code span instead.
- Wrap bare URLs in angle brackets: `<https://example.com>`.

## Local Development & Testing

- Build locally with `cargo build`; the release binary is installed to
  `/usr/local/bin/e2sp` (see `README.md`).
- Running `e2sp` for real requires **root** plus a configured Nginx + MySQL
  stack, and (for SSL) `acme.sh` installed as root and symlinked so `sudo
  acme.sh …` resolves. Do this only on a disposable/QA VM.
- **Never run destructive commands (`delete`, and `spawn`/`update` that mutate
  real state) against a production or shared server.** There are no test doubles
  for Nginx/MySQL — non-ignored tests are the pure-logic + privilege-error
  checks; system-touching tests are `#[ignore]`d for this reason.
- When not root, commands exit early with an "ELEVATED PRIVILEGES REQUIRED"
  message — the integration tests assert this path, so it must keep working.

## Reference Documentation

- [Rust Book](https://doc.rust-lang.org/book/)
- [Clap](https://docs.rs/clap/latest/clap/)
- [acme.sh](https://github.com/acmesh-official/acme.sh)
- Internal QA LNMP runbook (Notion): "LNMP WordPress site on Nginx"

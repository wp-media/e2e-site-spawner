# E2E Site Spawner

## Overview

The `E2E Site Spawner` is a command-line interface (CLI) tool designed to manage sites on the QA LNMP server. It provides commands for creating and deleting sites, along with options for SSL and WordPress integration.

## Installation

To install the `E2E Site Spawner`, ensure you have Rust and Cargo installed on your system. You can install Rust by following the instructions at [rust-lang.org](https://www.rust-lang.org/tools/install).

Once Rust is installed, clone the repository and install the tool:

```bash
git clone <repository-url>
cd e2e-site-spawner
cargo install --path .
```

This command will:

- Build the project in release mode (optimized)
- Install the `e2sp` binary to `~/.cargo/bin/`
- Make it available globally (assuming `~/.cargo/bin` is in your PATH)

### Verify installation

After installation, verify the tool is available:

```bash
e2sp --version
```

### Uninstalling

To uninstall the tool:

```bash
cargo uninstall e2e-site-spawner
```

## Usage

The CLI tool can be executed from the command line. Below are the available commands and their usage:

### Commands

- **spawn**
  - Creates a new site.
  - **Arguments:**
    - `site_name`: The name of the site to create.
  - **Options:**
    - `--ssl`: Enable SSL for the site.
    - `--no-wp`: Create the site without WordPress.
- **delete**
  - Deletes an existing site.
  - **Arguments:**
    - `site_name`: The name of the site to delete.

## Technologies

- [Rust Documentation](https://doc.rust-lang.org/book/)
- [Clap (Command Line Argument Parser)](https://docs.rs/clap/latest/clap/)
- [Rust Testing Documentation](https://doc.rust-lang.org/book/ch11-00-testing.html)

## IMPORTANT

By the moment, this is prepared to work only in our [QA LNMP server](https://www.notion.so/wpmedia/LNMP-WordPress-site-on-Nginx-137b1ef929d14b029a940567f0605a4c)

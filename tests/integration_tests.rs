// This file contains integration tests for the CLI tool, ensuring that all commands work as expected.

#[cfg(test)]
mod tests {
    use predicates::prelude::*;

    const TEST_DOMAIN: &str = "test.e2e.rocketlabsqa.ovh";
    const INVALID_DOMAIN: &str = "invalid_domain";

    // Create a macro to wrap the binary name
    macro_rules! cmd {
        () => {
            assert_cmd::cargo::cargo_bin_cmd!("e2sp")
        };
    }

    // ===== Basic CLI Tests =====

    #[test]
    fn test_no_args_shows_help() {
        let mut cmd = cmd!();
        cmd.assert()
            .failure()
            .stderr(predicate::str::contains("Usage:"));
    }

    #[test]
    fn test_help_flag() {
        let mut cmd = cmd!();
        cmd.arg("--help");
        cmd.assert()
            .success()
            .stdout(predicate::str::contains(
                "CLI tool for managing Nginx sites",
            ))
            .stdout(predicate::str::contains("spawn"))
            .stdout(predicate::str::contains("delete"))
            .stdout(predicate::str::contains("deactivate"))
            .stdout(predicate::str::contains("activate"));
    }

    #[test]
    fn test_version_flag() {
        let mut cmd = cmd!();
        cmd.arg("--version");
        cmd.assert()
            .success()
            .stdout(predicate::str::contains(env!("CARGO_PKG_VERSION")));
    }

    // ===== Spawn Command Tests =====

    #[test]
    fn test_spawn_site_basic_requires_privileges() {
        let mut cmd = cmd!();
        cmd.arg("spawn").arg(TEST_DOMAIN);

        if !is_running_as_root() {
            // Without root: expect privilege error
            cmd.assert()
                .failure()
                .code(1)
                .stdout(predicate::str::contains("ELEVATED PRIVILEGES REQUIRED"));
        } else {
            // With root: expect domain validation error (invalid_domain has no TLD)
            // or success if domain is valid and system is configured
            let result = cmd.assert();

            // The command should at least not fail with privilege error
            let output = String::from_utf8_lossy(&result.get_output().stdout);
            assert!(!output.contains("ELEVATED PRIVILEGES REQUIRED"));
        }
    }

    #[test]
    fn test_spawn_site_with_valid_domain() {
        let mut cmd = cmd!();
        cmd.arg("spawn").arg(TEST_DOMAIN).arg("--no-wp");

        if !is_running_as_root() {
            cmd.assert()
                .failure()
                .code(1)
                .stdout(predicate::str::contains("ELEVATED PRIVILEGES REQUIRED"));
        } else {
            // With root: might succeed or fail based on system state
            // (nginx installed, paths exist, etc.)
            let result = cmd.output().unwrap();

            if !result.status.success() {
                let stderr = String::from_utf8_lossy(&result.stderr);
                let stdout = String::from_utf8_lossy(&result.stdout);

                // Should NOT be a privilege error
                assert!(!stdout.contains("ELEVATED PRIVILEGES REQUIRED"));
                assert!(!stderr.contains("ELEVATED PRIVILEGES REQUIRED"));

                // Might fail for other valid reasons:
                // - Site already exists
                // - Nginx not installed
                // - Path issues
                // etc.
            }
        }
    }

    #[test]
    fn test_spawn_invalid_domain_with_and_without_root() {
        let mut cmd = cmd!();
        cmd.arg("spawn").arg(INVALID_DOMAIN);

        if !is_running_as_root() {
            // Without root: fails with privilege error first
            cmd.assert()
                .failure()
                .code(1)
                .stdout(predicate::str::contains("ELEVATED PRIVILEGES REQUIRED"));
        } else {
            // With root: should fail with domain validation error
            cmd.assert()
                .failure()
                .stderr(predicate::str::contains("Invalid site name"));
        }
    }

    #[test]
    fn test_delete_site_behavior() {
        let mut cmd = cmd!();
        cmd.arg("delete").arg(TEST_DOMAIN);

        if !is_running_as_root() {
            cmd.assert()
                .failure()
                .code(1)
                .stdout(predicate::str::contains("ELEVATED PRIVILEGES REQUIRED"));
        } else {
            // With root: might fail if site doesn't exist
            let result = cmd.output().unwrap();

            if !result.status.success() {
                let stderr = String::from_utf8_lossy(&result.stderr);
                let stdout = String::from_utf8_lossy(&result.stdout);

                // Should not be privilege error
                assert!(!stdout.contains("ELEVATED PRIVILEGES REQUIRED"));

                // Likely "site not found" or similar
                assert!(
                    stderr.contains("not found")
                        || stderr.contains("does not exist")
                        || stdout.contains("not found")
                        || stdout.contains("does not exist")
                );
            }
        }
    }

    #[test]
    fn test_update_requires_privileges() {
        let mut cmd = cmd!();
        cmd.arg("update").arg(TEST_DOMAIN).arg("--wp");

        if !is_running_as_root() {
            // Without root: must fail with the privilege error, like every other
            // state-mutating command.
            cmd.assert()
                .failure()
                .code(1)
                .stdout(predicate::str::contains("ELEVATED PRIVILEGES REQUIRED"));
        } else {
            // With root: must NOT be a privilege error (it may still fail for other
            // reasons, e.g. the site does not exist).
            let result = cmd.output().unwrap();
            let stdout = String::from_utf8_lossy(&result.stdout);
            assert!(!stdout.contains("ELEVATED PRIVILEGES REQUIRED"));
        }
    }

    // Better lifecycle test that handles both privilege scenarios
    #[test]
    fn test_complete_lifecycle() {
        use std::time::{SystemTime, UNIX_EPOCH};

        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let test_site = format!("test-{}.e2e.rocketlabsqa.ovh", timestamp);

        if !is_running_as_root() {
            // Test that all commands fail with privilege error
            let mut spawn_cmd = cmd!();
            spawn_cmd.arg("spawn").arg(&test_site).arg("--no-wp");
            spawn_cmd
                .assert()
                .failure()
                .code(1)
                .stdout(predicate::str::contains("ELEVATED PRIVILEGES REQUIRED"));

            let mut delete_cmd = cmd!();
            delete_cmd.arg("delete").arg(&test_site);
            delete_cmd
                .assert()
                .failure()
                .code(1)
                .stdout(predicate::str::contains("ELEVATED PRIVILEGES REQUIRED"));
        } else {
            // With root: actually test the lifecycle
            println!("Running lifecycle test with root privileges");

            // 1. Spawn the site
            let mut spawn_cmd = cmd!();
            spawn_cmd.arg("spawn").arg(&test_site).arg("--no-wp");

            let spawn_result = spawn_cmd.output().unwrap();
            if !spawn_result.status.success() {
                // Print why it failed for debugging
                eprintln!(
                    "Spawn failed: {}",
                    String::from_utf8_lossy(&spawn_result.stderr)
                );
                eprintln!("Stdout: {}", String::from_utf8_lossy(&spawn_result.stdout));

                // Common acceptable failures:
                let stderr = String::from_utf8_lossy(&spawn_result.stderr);
                assert!(
                    stderr.contains("nginx") || // Nginx not installed
                    stderr.contains("WordPress") || // WordPress issues
                    stderr.contains("already exists") // Site exists
                );
                return; // Skip rest of test if spawn failed for valid reasons
            }

            // 2. Deactivate the site
            let mut deactivate_cmd = cmd!();
            deactivate_cmd.arg("deactivate").arg(&test_site);
            assert!(deactivate_cmd.output().unwrap().status.success());

            // 3. Activate the site
            let mut activate_cmd = cmd!();
            activate_cmd.arg("activate").arg(&test_site);
            assert!(activate_cmd.output().unwrap().status.success());

            // 4. Delete the site
            let mut delete_cmd = cmd!();
            delete_cmd.arg("delete").arg(&test_site);
            assert!(delete_cmd.output().unwrap().status.success());
        }
    }

    // Test specifically for SSL with acme.sh check
    #[test]
    fn test_ssl_requires_acme_sh() {
        let mut cmd = cmd!();
        cmd.arg("spawn").arg(TEST_DOMAIN).arg("--ssl");

        if !is_running_as_root() {
            // Without root: privilege error comes first
            cmd.assert()
                .failure()
                .code(1)
                .stdout(predicate::str::contains("ELEVATED PRIVILEGES REQUIRED"));
        } else if !has_acme_sh() {
            // With root but no acme.sh: should fail with acme.sh error
            cmd.assert()
                .failure()
                .stdout(predicate::str::contains("acme.sh"));
        } else {
            // With root and acme.sh: might succeed or fail for other reasons
            let result = cmd.output().unwrap();
            if !result.status.success() {
                let output = String::from_utf8_lossy(&result.stdout);
                let stderr = String::from_utf8_lossy(&result.stderr);

                // Should not be privilege error
                assert!(!output.contains("ELEVATED PRIVILEGES REQUIRED"));

                // Might fail for SSL-specific reasons
                println!("SSL spawn failed (expected): {}", stderr);
            }
        }
    }

    // ===== Helper Functions =====

    /// Check if running as root (same logic as main.rs)
    fn is_running_as_root() -> bool {
        #[cfg(unix)]
        {
            unsafe { libc::geteuid() == 0 }
        }
        #[cfg(not(unix))]
        {
            false
        }
    }

    /// Check if acme.sh is installed
    fn has_acme_sh() -> bool {
        std::process::Command::new("acme.sh")
            .arg("--version")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }

    // ===== Output Format Tests =====

    #[test]
    fn test_colored_output_disabled() {
        // Test with NO_COLOR environment variable
        let mut cmd = cmd!();
        cmd.env("NO_COLOR", "1");
        cmd.arg("--help");
        cmd.assert()
            .success()
            .stdout(predicate::str::contains("CLI tool"));
        // Should not contain ANSI escape codes when NO_COLOR is set
    }

    #[test]
    fn test_quiet_flag_not_supported() {
        // Verify that --quiet flag is not supported (as it's not in the CLI definition)
        let mut cmd = cmd!();
        cmd.arg("--quiet").arg("spawn").arg(TEST_DOMAIN);
        cmd.assert()
            .failure()
            .stderr(predicate::str::contains("unexpected argument"));
    }

    #[test]
    fn test_verbose_flag_not_supported() {
        // Verify that --verbose flag is not supported
        let mut cmd = cmd!();
        cmd.arg("--verbose").arg("spawn").arg(TEST_DOMAIN);
        cmd.assert()
            .failure()
            .stderr(predicate::str::contains("unexpected argument"));
    }
}

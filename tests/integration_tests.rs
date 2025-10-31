// This file contains integration tests for the CLI tool, ensuring that all commands work as expected.

#[cfg(test)]
mod tests {
    use predicates::prelude::*;

    const TEST_DOMAIN: &str = "test.e2e.rocketlabsqa.ovh";

    // Create a macro to wrap the binary name
    macro_rules! cmd {
        () => {
            assert_cmd::cargo::cargo_bin_cmd!("e2sp")
        };
    }

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
            .stdout(predicate::str::contains("CLI tool for managing Nginx sites"))
            .stdout(predicate::str::contains("spawn"))
            .stdout(predicate::str::contains("delete"));
    }

    #[test]
    fn test_version_flag() {
        let mut cmd = cmd!();
        cmd.arg("--version");
        cmd.assert()
            .success()
            .stdout(predicate::str::contains(env!("CARGO_PKG_VERSION")))
            .stdout(predicate::str::contains("Sandy Figueroa"));
    }

    // Spawn command tests
    #[test]
    fn test_spawn_site_basic() {
        let mut cmd = cmd!();
        cmd.arg("spawn")
            .arg(TEST_DOMAIN);
        cmd.assert()
            .success()
            .stdout(predicate::str::contains("Preparing to create site"))
            .stdout(predicate::str::contains(TEST_DOMAIN));
    }

    #[test]
    fn test_spawn_site_with_ssl() {
        let mut cmd = cmd!();
        cmd.arg("spawn")
            .arg(TEST_DOMAIN)
            .arg("--ssl");
        cmd.assert()
            .success()
            .stdout(predicate::str::contains("Preparing to create site"))
            .stdout(predicate::str::contains("SSL will be enabled"))
            .stdout(predicate::str::contains(TEST_DOMAIN));
    }

    #[test]
    fn test_spawn_site_no_wp() {
        let mut cmd = cmd!();
        cmd.arg("spawn")
            .arg(TEST_DOMAIN)
            .arg("--no-wp");
        cmd.assert()
            .success()
            .stdout(predicate::str::contains("Preparing to create site"))
            .stdout(predicate::str::contains("WordPress will not be installed"))
            .stdout(predicate::str::contains(TEST_DOMAIN));
    }

    #[test]
    fn test_spawn_site_no_wp_with_ssl() {
        let mut cmd = cmd!();
        cmd.arg("spawn")
            .arg(TEST_DOMAIN)
            .arg("--no-wp")
            .arg("--ssl");
        cmd.assert()
            .success()
            .stdout(predicate::str::contains("Preparing to create site"))
            .stdout(predicate::str::contains("SSL will be enabled"))
            .stdout(predicate::str::contains("WordPress will not be installed"))
            .stdout(predicate::str::contains(TEST_DOMAIN));
    }

    #[test]
    fn test_spawn_missing_site_name() {
        let mut cmd = cmd!();
        cmd.arg("spawn");
        cmd.assert()
            .failure()
            .stderr(predicate::str::contains("required arguments were not provided"));
    }

    #[test]
    fn test_spawn_help() {
        let mut cmd = cmd!();
        cmd.arg("spawn")
            .arg("--help");
        cmd.assert()
            .success()
            .stdout(predicate::str::contains("Creates a new site with Nginx configuration"))
            .stdout(predicate::str::contains("EXAMPLES:"))
            .stdout(predicate::str::contains("--ssl"))
            .stdout(predicate::str::contains("--no-wp"));
    }

    // Delete command tests
    #[test]
    fn test_delete_site() {
        let mut cmd = cmd!();
        cmd.arg("delete")
            .arg(TEST_DOMAIN);
        cmd.assert()
            .success()
            .stdout(predicate::str::contains("Preparing to delete site"))
            .stdout(predicate::str::contains(TEST_DOMAIN));
    }

    #[test]
    fn test_delete_missing_site_name() {
        let mut cmd = cmd!();
        cmd.arg("delete");
        cmd.assert()
            .failure()
            .stderr(predicate::str::contains("required arguments were not provided"));
    }

    #[test]
    fn test_delete_help() {
        let mut cmd = cmd!();
        cmd.arg("delete")
            .arg("--help");
        cmd.assert()
            .success()
            .stdout(predicate::str::contains("Completely removes a site"))
            .stdout(predicate::str::contains("EXAMPLES:"));
    }

    // Invalid command tests
    #[test]
    fn test_invalid_command() {
        let mut cmd = cmd!();
        cmd.arg("invalid-command");
        cmd.assert()
            .failure()
            .stderr(predicate::str::contains("unrecognized subcommand"));
    }

    #[test]
    fn test_invalid_flag() {
        let mut cmd = cmd!();
        cmd.arg("spawn")
            .arg(TEST_DOMAIN)
            .arg("--invalid-flag");
        cmd.assert()
            .failure()
            .stderr(predicate::str::contains("unexpected argument"));
    }

    // Test for commented out commands (these should fail until implemented)
    #[test]
    #[ignore = "Command not yet implemented"]
    fn test_deactivate_command() {
        let mut cmd = cmd!();
        cmd.arg("deactivate")
            .arg(TEST_DOMAIN);
        cmd.assert()
            .failure()
            .stderr(predicate::str::contains("unrecognized subcommand"));
    }

    #[test]
    #[ignore = "Command not yet implemented"]
    fn test_activate_command() {
        let mut cmd = cmd!();
        cmd.arg("activate")
            .arg(TEST_DOMAIN);
        cmd.assert()
            .failure()
            .stderr(predicate::str::contains("unrecognized subcommand"));
    }

    #[test]
    #[ignore = "Command not yet implemented"]
    fn test_update_command() {
        let mut cmd = cmd!();
        cmd.arg("update")
            .arg(TEST_DOMAIN)
            .arg("--wp");
        cmd.assert()
            .failure()
            .stderr(predicate::str::contains("unrecognized subcommand"));
    }
}
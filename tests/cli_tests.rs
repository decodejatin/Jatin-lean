use assert_cmd::Command;
use predicates::prelude::*;
use tempfile::tempdir;

fn cmd() -> Command {
    Command::cargo_bin("jatin-lean").unwrap()
}

// When no node_modules exists, should exit with error and show helpful message

fn test_node_scan_no_node_modules_shows_error() {
    let dir = tempdir().unwrap();

    cmd()
        .args(["node", "scan", dir.path().to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("No node_modules found"));
}

// Should suggest running npm install

fn test_node_scan_suggests_npm_install() {
    let dir = tempdir().unwrap();

    cmd()
        .args(["node", "scan", dir.path().to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("npm install"));
}

// Should work when node_modules directory exists

fn test_node_scan_with_node_modules_succeeds() {
    let dir = tempdir().unwrap();
    std::fs::create_dir(dir.path().join("node_modules")).unwrap();

    cmd()
        .args(["node", "scan", dir.path().to_str().unwrap()])
        .assert()
        .success();
}

// Invalid subcommand should fail

fn test_invalid_subcommand_fails() {
    cmd()
        .arg("nonexistent-command")
        .assert()
        .failure();
}

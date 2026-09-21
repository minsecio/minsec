use serde_json::Value;
use std::path::PathBuf;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

fn temp_config() -> PathBuf {
    static COUNTER: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let unique = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
    let sequence = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let directory = std::env::temp_dir().join(format!("minsec-cli-{}-{unique}-{sequence}", std::process::id()));
    std::fs::create_dir_all(directory.join("conf.d")).unwrap();
    std::fs::create_dir_all(directory.join("filters")).unwrap();
    directory
}

fn minsec() -> Command {
    Command::new(env!("CARGO_BIN_EXE_minsec"))
}

#[test]
fn json_inspect_reports_schema_and_discovery() {
    let directory = temp_config();
    std::fs::write(
        directory.join("filters/custom.toml"),
        "name = \"custom\"\npatterns = [\"failed from <HOST>\"]\n",
    )
    .unwrap();
    let output = minsec()
        .args(["--config-dir", directory.to_str().unwrap(), "--json", "inspect"])
        .output()
        .unwrap();
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    let json: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(json["schema_version"], 1);
    assert_eq!(json["ok"], true);
    assert!(json["filters"]
        .as_array()
        .unwrap()
        .iter()
        .any(|filter| filter["name"] == "custom" && filter["enabled"] == false));
    std::fs::remove_dir_all(directory).unwrap();
}

#[test]
fn human_inspect_shows_sources_and_allow_list() {
    let directory = temp_config();
    std::fs::write(
        directory.join("minsec.toml"),
        "[defaults]\nallow = [\"10.0.0.0/8\"]\n[filters.custom]\nenabled = true\n",
    )
    .unwrap();
    std::fs::write(
        directory.join("filters/custom.toml"),
        "name = \"custom\"\nfiles = [\"/nonexistent/minsec-cli.log\"]\npatterns = [\"failed from <HOST>\"]\n",
    )
    .unwrap();
    let output = minsec()
        .args(["--config-dir", directory.to_str().unwrap(), "inspect"])
        .output()
        .unwrap();
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("allow: 10.0.0.0/8\n  always: loopback"), "{stdout}");
    assert!(stdout.contains("enabled filters (1 of "), "{stdout}");
    assert!(stdout.contains("  custom "), "{stdout}");
    assert!(stdout.contains("(filters/custom.toml)"), "{stdout}");
    assert!(
        stdout.contains("files: /nonexistent/minsec-cli.log (absent)"),
        "{stdout}"
    );
    assert!(stdout.contains("disabled: apache-auth"), "{stdout}");
    assert!(stdout.lines().count() <= 30, "{stdout}");
    std::fs::remove_dir_all(directory).unwrap();
}

#[test]
fn json_check_all_reports_success_and_errors() {
    let directory = temp_config();
    let custom = directory.join("filters/custom.toml");
    std::fs::write(&custom, "name = \"custom\"\npatterns = [\"failed from <HOST>\"]\n").unwrap();
    let success = minsec()
        .args(["--config-dir", directory.to_str().unwrap(), "--json", "check", "--all"])
        .output()
        .unwrap();
    assert!(success.status.success());
    let success_json: Value = serde_json::from_slice(&success.stdout).unwrap();
    assert_eq!(success_json["ok"], true);
    assert!(success_json["checked_filters"]
        .as_array()
        .unwrap()
        .iter()
        .any(|filter| filter == "custom"));

    std::fs::write(&custom, "name = \"custom\"\npatterns = [\"no address capture\"]\n").unwrap();
    let failure = minsec()
        .args(["--config-dir", directory.to_str().unwrap(), "--json", "check", "--all"])
        .output()
        .unwrap();
    assert!(!failure.status.success());
    let failure_json: Value = serde_json::from_slice(&failure.stdout).unwrap();
    assert_eq!(failure_json["ok"], false);
    assert!(failure_json["errors"]
        .as_array()
        .unwrap()
        .iter()
        .any(|error| error["filter"] == "custom"));
    std::fs::remove_dir_all(directory).unwrap();
}

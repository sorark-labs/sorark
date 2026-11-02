use sorark_wasm::encode_soroban_wasm_with_specs;
use std::path::PathBuf;
use std::process::Command;
use stellar_xdr::{
    ScSpecEntry, ScSpecTypeDef, ScSpecUdtStructFieldV0, ScSpecUdtStructV0, StringM, VecM,
};

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf()
}

fn sorark_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_sorark"))
}

#[test]
fn cli_lint_catches_all_hazards_in_vulnerable_vault_example() {
    let example_dir = workspace_root().join("examples/vulnerable-vault");
    let output = Command::new(sorark_bin())
        .args(["lint", example_dir.to_str().unwrap()])
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(1));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("ARK-STOR-001"), "stdout: {stdout}");
    assert!(stdout.contains("ARK-STOR-002"), "stdout: {stdout}");
    assert!(stdout.contains("ARK-STOR-003"), "stdout: {stdout}");
    assert!(stdout.contains("ARK-STOR-004"), "stdout: {stdout}");
    assert!(stdout.contains("ARK-UPG-001"), "stdout: {stdout}");
}

#[test]
fn cli_lint_min_severity_filters_lower_severities() {
    let example_dir = workspace_root().join("examples/vulnerable-vault");

    // 1. Without --min-severity error, Warning ARK-STOR-002 is present
    let unfiltered = Command::new(sorark_bin())
        .args(["lint", example_dir.to_str().unwrap()])
        .output()
        .unwrap();
    let stdout_unfiltered = String::from_utf8_lossy(&unfiltered.stdout);
    assert!(stdout_unfiltered.contains("ARK-STOR-002"));

    // 2. With --min-severity error, Warning ARK-STOR-002 is filtered out
    // and only Error-level diagnostics (ARK-STOR-001, ARK-STOR-003, ARK-STOR-004, ARK-UPG-001) remain
    let filtered = Command::new(sorark_bin())
        .args([
            "lint",
            example_dir.to_str().unwrap(),
            "--min-severity",
            "error",
        ])
        .output()
        .unwrap();

    assert_eq!(filtered.status.code(), Some(1));
    let stdout = String::from_utf8_lossy(&filtered.stdout);
    assert!(stdout.contains("ARK-STOR-001"), "stdout: {stdout}");
    assert!(
        !stdout.contains("ARK-STOR-002"),
        "stdout should not contain Warning ARK-STOR-002: {stdout}"
    );
    assert!(stdout.contains("ARK-STOR-003"), "stdout: {stdout}");
    assert!(stdout.contains("ARK-STOR-004"), "stdout: {stdout}");
    assert!(stdout.contains("ARK-UPG-001"), "stdout: {stdout}");
    assert!(
        stdout.contains("0 warning(s)"),
        "warning count should be 0: {stdout}"
    );
}

#[test]
fn cli_lint_min_severity_json_format() {
    let example_dir = workspace_root().join("examples/vulnerable-vault");
    let output = Command::new(sorark_bin())
        .args([
            "lint",
            example_dir.to_str().unwrap(),
            "--format",
            "json",
            "--min-severity",
            "error",
        ])
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(1));
    let parsed: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let diags = parsed["diagnostics"].as_array().unwrap();
    assert!(!diags.is_empty());
    for d in diags {
        assert_eq!(d["severity"], "error");
    }
    assert_eq!(parsed["summary"]["warnings"], 0);
}

#[test]
fn cli_lint_passes_cleanly_on_upgrade_v1_example() {
    let example_dir = workspace_root().join("examples/upgrade-v1");
    let output = Command::new(sorark_bin())
        .args(["--deny-warnings", "lint", example_dir.to_str().unwrap()])
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(output.status.code(), Some(0), "stdout: {stdout}");
    assert!(
        stdout.contains("0 error(s), 0 warning(s)"),
        "stdout: {stdout}"
    );
}

#[test]
fn cli_diff_catches_storage_and_abi_breakages_between_v1_and_v2_examples() {
    let v1_dir = workspace_root().join("examples/upgrade-v1");
    let v2_dir = workspace_root().join("examples/upgrade-v2-broken");

    let output = Command::new(sorark_bin())
        .args([
            "diff",
            "--old",
            v1_dir.to_str().unwrap(),
            "--new",
            v2_dir.to_str().unwrap(),
        ])
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(output.status.code(), Some(1), "stdout: {stdout}");
    assert!(stdout.contains("ARK-DIFF-001"), "stdout: {stdout}");
    assert!(stdout.contains("ARK-DIFF-002"), "stdout: {stdout}");
    assert!(stdout.contains("ARK-DIFF-003"), "stdout: {stdout}");
    assert!(stdout.contains("ARK-DIFF-004"), "stdout: {stdout}");
}

#[test]
fn cli_diff_min_severity_filters_warning_diagnostics() {
    let v1_dir = workspace_root().join("examples/upgrade-v1");
    let v2_dir = workspace_root().join("examples/upgrade-v2-broken");

    // Diff without filter contains errors (ARK-DIFF-001, ARK-DIFF-002) and warnings (ARK-DIFF-003, ARK-DIFF-004)
    let unfiltered = Command::new(sorark_bin())
        .args([
            "diff",
            "--old",
            v1_dir.to_str().unwrap(),
            "--new",
            v2_dir.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    let stdout_unfiltered = String::from_utf8_lossy(&unfiltered.stdout);
    assert!(stdout_unfiltered.contains("ARK-DIFF-003"));
    assert!(stdout_unfiltered.contains("ARK-DIFF-004"));

    // Diff with --min-severity error excludes warnings ARK-DIFF-003 and ARK-DIFF-004
    let filtered = Command::new(sorark_bin())
        .args([
            "diff",
            "--old",
            v1_dir.to_str().unwrap(),
            "--new",
            v2_dir.to_str().unwrap(),
            "--min-severity",
            "error",
        ])
        .output()
        .unwrap();

    assert_eq!(filtered.status.code(), Some(1));
    let stdout = String::from_utf8_lossy(&filtered.stdout);
    assert!(stdout.contains("ARK-DIFF-001"), "stdout: {stdout}");
    assert!(stdout.contains("ARK-DIFF-002"), "stdout: {stdout}");
    assert!(
        !stdout.contains("ARK-DIFF-003"),
        "stdout should not contain Warning ARK-DIFF-003: {stdout}"
    );
    assert!(
        !stdout.contains("ARK-DIFF-004"),
        "stdout should not contain Warning ARK-DIFF-004: {stdout}"
    );
    assert!(
        stdout.contains("0 warning(s)"),
        "warning count should be 0: {stdout}"
    );
}

#[test]
fn cli_sarif_and_wasm_binary_diff_work_end_to_end() {
    let tmp = tempfile::tempdir().unwrap();
    let v1_wasm_path = tmp.path().join("v1.wasm");
    let v2_wasm_path = tmp.path().join("v2.wasm");

    let v1_struct = ScSpecEntry::UdtStructV0(ScSpecUdtStructV0 {
        doc: StringM::default(),
        lib: StringM::default(),
        name: StringM::try_from("Position").unwrap(),
        fields: VecM::try_from(vec![ScSpecUdtStructFieldV0 {
            doc: StringM::default(),
            name: StringM::try_from("shares").unwrap(),
            type_: ScSpecTypeDef::I128,
        }])
        .unwrap(),
    });

    let v2_struct = ScSpecEntry::UdtStructV0(ScSpecUdtStructV0 {
        doc: StringM::default(),
        lib: StringM::default(),
        name: StringM::try_from("Position").unwrap(),
        fields: VecM::try_from(vec![ScSpecUdtStructFieldV0 {
            doc: StringM::default(),
            name: StringM::try_from("shares").unwrap(),
            type_: ScSpecTypeDef::U64,
        }])
        .unwrap(),
    });

    std::fs::write(
        &v1_wasm_path,
        encode_soroban_wasm_with_specs(22, &[v1_struct]).unwrap(),
    )
    .unwrap();
    std::fs::write(
        &v2_wasm_path,
        encode_soroban_wasm_with_specs(22, &[v2_struct]).unwrap(),
    )
    .unwrap();

    // 1. Inspect v1.wasm
    let inspect_out = Command::new(sorark_bin())
        .args(["inspect", v1_wasm_path.to_str().unwrap()])
        .output()
        .unwrap();
    assert_eq!(inspect_out.status.code(), Some(0));
    let inspect_text = String::from_utf8_lossy(&inspect_out.stdout);
    assert!(
        inspect_text.contains("Protocol 22"),
        "inspect: {inspect_text}"
    );
    assert!(
        inspect_text.contains("struct Position"),
        "inspect: {inspect_text}"
    );

    // 2. Diff v1.wasm vs v2.wasm in SARIF format
    let diff_out = Command::new(sorark_bin())
        .args([
            "diff",
            "--old",
            v1_wasm_path.to_str().unwrap(),
            "--new",
            v2_wasm_path.to_str().unwrap(),
            "--format",
            "sarif",
        ])
        .output()
        .unwrap();
    assert_eq!(diff_out.status.code(), Some(1));
    let sarif_json: serde_json::Value = serde_json::from_slice(&diff_out.stdout).unwrap();
    assert_eq!(sarif_json["version"], "2.1.0");
    assert_eq!(
        sarif_json["runs"][0]["results"][0]["ruleId"],
        "ARK-DIFF-001"
    );
}

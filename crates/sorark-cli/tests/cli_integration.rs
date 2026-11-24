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

#[test]
fn cli_supports_min_severity_filter_github_format_and_rule_explain() {
    let example_dir = workspace_root().join("examples/vulnerable-vault");

    // 1. `--min-severity error` filters out warning ARK-STOR-002
    let min_sev_out = Command::new(sorark_bin())
        .args([
            "lint",
            example_dir.to_str().unwrap(),
            "--min-severity",
            "error",
        ])
        .output()
        .unwrap();
    assert_eq!(min_sev_out.status.code(), Some(1));
    let min_sev_stdout = String::from_utf8_lossy(&min_sev_out.stdout);
    assert!(min_sev_stdout.contains("ARK-STOR-001"));
    assert!(
        !min_sev_stdout.contains("ARK-STOR-002"),
        "Expected warning ARK-STOR-002 to be filtered out: {min_sev_stdout}"
    );

    // 2. `--format github` emits GitHub Actions workflow commands
    let gh_out = Command::new(sorark_bin())
        .args(["lint", example_dir.to_str().unwrap(), "--format", "github"])
        .output()
        .unwrap();
    let gh_stdout = String::from_utf8_lossy(&gh_out.stdout);
    assert!(
        gh_stdout.contains("::error file="),
        "Expected ::error workflow command, got: {gh_stdout}"
    );
    assert!(
        gh_stdout.contains("ARK-STOR-001"),
        "Expected ARK-STOR-001 in github output, got: {gh_stdout}"
    );

    // 3. `sorark rules --explain ARK-STOR-005` prints vulnerable and remediated examples
    let explain_out = Command::new(sorark_bin())
        .args(["rules", "--explain", "ARK-STOR-005"])
        .output()
        .unwrap();
    assert_eq!(explain_out.status.code(), Some(0));
    let explain_stdout = String::from_utf8_lossy(&explain_out.stdout);
    assert!(explain_stdout.contains("ARK-STOR-005"));
    assert!(explain_stdout.contains("Vulnerable Example:"));
    assert!(explain_stdout.contains("Remediated Example:"));

    // 4. `sorark lint --sep41` flags missing SEP-41 token interface entrypoints on a non-token contract
    let sep41_out = Command::new(sorark_bin())
        .args([
            "lint",
            workspace_root()
                .join("examples/upgrade-v1")
                .to_str()
                .unwrap(),
            "--sep41",
        ])
        .output()
        .unwrap();
    assert_eq!(sep41_out.status.code(), Some(1));
    let sep41_stdout = String::from_utf8_lossy(&sep41_out.stdout);
    assert!(
        sep41_stdout.contains("ARK-SEP-041"),
        "Expected ARK-SEP-041 diagnostics, got: {sep41_stdout}"
    );
}

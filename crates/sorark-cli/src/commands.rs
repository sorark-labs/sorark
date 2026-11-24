//! Execution handlers for each `sorark` CLI subcommand (`lint`, `diff`, `inspect`, `rules`, `init`).

use crate::cli::{Cli, Commands};
use crate::format::{
    OutputFormat, render_diagnostics, render_rule_catalog, render_rule_explanation,
    render_wasm_inspection,
};
use anyhow::{Context, Result, bail};
use sorark_ast::scan_rust_path;
use sorark_diff::compare_contract_modules;
use sorark_ir::{
    ContractModule, Diagnostic, Severity, SorarkConfig, builtin_rule_catalog,
    check_sep41_conformance, find_rule_descriptor,
};
use sorark_wasm::inspect_wasm_file;
use std::fmt::Write as _;
use std::path::Path;
use std::process::{Command, ExitCode};

/// Options passed to `sorark lint`.
struct LintOptions<'a> {
    path: &'a Path,
    format: OutputFormat,
    rule_filter: Option<&'a str>,
    min_severity: Option<Severity>,
    verify_sep41: bool,
    suggest_patch: bool,
}

/// Options passed to `sorark diff`.
struct DiffOptions<'a> {
    old: Option<&'a Path>,
    new: Option<&'a Path>,
    old_rev: Option<&'a str>,
    new_rev: Option<&'a str>,
    repo_path: &'a Path,
    format: OutputFormat,
    min_severity: Option<Severity>,
}

/// Dispatches the parsed [`Cli`] arguments to the selected subcommand handler.
pub fn execute(cli: Cli) -> Result<ExitCode> {
    let mut config = load_config(cli.config.as_deref())?;
    if cli.deny_warnings {
        config.fail_on_warnings = true;
    }

    match cli.command {
        Commands::Lint {
            path,
            format,
            rule,
            min_severity,
            sep41,
            suggest_patch,
        } => run_lint(
            &LintOptions {
                path: &path,
                format,
                rule_filter: rule.as_deref(),
                min_severity,
                verify_sep41: sep41,
                suggest_patch,
            },
            &config,
        ),
        Commands::Diff {
            old,
            new,
            old_rev,
            new_rev,
            path,
            format,
            min_severity,
        } => run_diff(
            &DiffOptions {
                old: old.as_deref(),
                new: new.as_deref(),
                old_rev: old_rev.as_deref(),
                new_rev: new_rev.as_deref(),
                repo_path: &path,
                format,
                min_severity,
            },
            &config,
        ),
        Commands::Inspect { wasm, format } => run_inspect(&wasm, format, &config),
        Commands::Rules { format, explain } => run_rules(format, explain.as_deref()),
        Commands::Init { output, force } => run_init(&output, force),
    }
}

/// Executes `sorark lint` against either a compiled `.wasm` file or a Rust source path.
fn run_lint(opts: &LintOptions<'_>, config: &SorarkConfig) -> Result<ExitCode> {
    let (module, mut diagnostics) = if is_wasm_path(opts.path) {
        let report = inspect_wasm_file(opts.path, config)?;
        (report.module, report.diagnostics)
    } else {
        let report = scan_rust_path(opts.path, config)?;
        (report.context.module, report.diagnostics)
    };

    if opts.verify_sep41 {
        diagnostics.extend(check_sep41_conformance(&module, config));
    }

    if let Some(filter) = opts.rule_filter {
        diagnostics.retain(|d| d.rule_id.eq_ignore_ascii_case(filter));
    }
    if let Some(min_sev) = opts.min_severity {
        diagnostics.retain(|d| d.severity >= min_sev);
    }

    let rendered = render_diagnostics(&diagnostics, opts.format)?;
    print!("{rendered}");

    if opts.suggest_patch {
        let patch = generate_suggested_ttl_patches(&diagnostics);
        if !patch.is_empty() {
            print!("\n{patch}");
        }
    }

    Ok(exit_code_for_diagnostics(
        &diagnostics,
        config.fail_on_warnings,
    ))
}

/// Executes `sorark diff` between a baseline (`--old` or `--old-rev`) and candidate (`--new` or `--new-rev`) contract.
fn run_diff(opts: &DiffOptions<'_>, config: &SorarkConfig) -> Result<ExitCode> {
    let (old_module, new_module) = match (opts.old, opts.new, opts.old_rev, opts.new_rev) {
        (Some(old_path), Some(new_path), None, None) => {
            let old_mod = load_contract_module(old_path, config).with_context(|| {
                format!(
                    "Failed to load baseline (--old) contract `{}`",
                    old_path.display()
                )
            })?;
            let new_mod = load_contract_module(new_path, config).with_context(|| {
                format!(
                    "Failed to load candidate (--new) contract `{}`",
                    new_path.display()
                )
            })?;
            (old_mod, new_mod)
        }
        (None, None, Some(old_rev), Some(new_rev)) => {
            let old_mod = load_contract_module_from_git_rev(opts.repo_path, old_rev, config)
                .with_context(|| {
                    format!("Failed to load baseline (--old-rev `{old_rev}`) from git")
                })?;
            let new_mod = load_contract_module_from_git_rev(opts.repo_path, new_rev, config)
                .with_context(|| {
                    format!("Failed to load candidate (--new-rev `{new_rev}`) from git")
                })?;
            (old_mod, new_mod)
        }
        _ => {
            bail!(
                "Specify either `--old <PATH> --new <PATH>` or `--old-rev <GIT_REF> --new-rev <GIT_REF> [--path <DIR>]`."
            );
        }
    };

    let mut diff_report = compare_contract_modules(&old_module, &new_module, config);
    if let Some(min_sev) = opts.min_severity {
        diff_report.diagnostics.retain(|d| d.severity >= min_sev);
    }

    let rendered = render_diagnostics(&diff_report.diagnostics, opts.format)?;
    print!("{rendered}");
    Ok(exit_code_for_diagnostics(
        &diff_report.diagnostics,
        config.fail_on_warnings,
    ))
}

/// Extracts `.rs` files from a Git revision (`git ls-tree` + `git show`) into a temporary workspace
/// and parses them into a [`ContractModule`].
fn load_contract_module_from_git_rev(
    repo_path: &Path,
    rev: &str,
    config: &SorarkConfig,
) -> Result<ContractModule> {
    let ls_out = Command::new("git")
        .current_dir(repo_path)
        .args(["ls-tree", "-r", "--name-only", rev])
        .output()
        .context("Failed to invoke `git ls-tree`")?;

    if !ls_out.status.success() {
        bail!(
            "`git ls-tree -r --name-only {rev}` failed: {}",
            String::from_utf8_lossy(&ls_out.stderr).trim()
        );
    }

    let tmp_dir = tempfile::tempdir().context("Failed to create temporary git extraction dir")?;
    let listing = String::from_utf8_lossy(&ls_out.stdout);
    let mut extracted_count = 0usize;

    for rel_file in listing.lines().filter(|l| l.ends_with(".rs")) {
        let spec = format!("{rev}:{rel_file}");
        let show_out = Command::new("git")
            .current_dir(repo_path)
            .args(["show", &spec])
            .output()
            .with_context(|| format!("Failed to invoke `git show {spec}`"))?;

        if !show_out.status.success() {
            bail!(
                "`git show {spec}` failed: {}",
                String::from_utf8_lossy(&show_out.stderr).trim()
            );
        }

        let dest = tmp_dir.path().join(rel_file);
        if let Some(parent) = dest.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&dest, &show_out.stdout)?;
        extracted_count += 1;
    }

    if extracted_count == 0 {
        bail!("Git revision `{rev}` contains no `.rs` source files");
    }

    let mut report = scan_rust_path(tmp_dir.path(), config)?;
    report.context.module.name = rev.to_string();
    Ok(report.context.module)
}

/// Generates unified diff auto-remediation suggestions for `ARK-STOR-002` (missing `extend_ttl`) findings.
fn generate_suggested_ttl_patches(diagnostics: &[Diagnostic]) -> String {
    let mut out = String::new();
    for d in diagnostics {
        if d.rule_id != "ARK-STOR-002" {
            continue;
        }
        let Some(span) = &d.span else {
            continue;
        };
        let snippet = span.snippet.as_deref().unwrap_or("");
        let suggested_call = if snippet.contains(".instance()") {
            "env.storage().instance().extend_ttl(17_280, 518_400);".to_string()
        } else {
            let key_arg = extract_first_arg_from_set_snippet(snippet).unwrap_or("&key");
            format!("env.storage().persistent().extend_ttl({key_arg}, 17_280, 518_400);")
        };

        let _ = writeln!(out, "--- a/{}", span.file);
        let _ = writeln!(out, "+++ b/{}", span.file);
        let _ = writeln!(out, "@@ -{},1 +{},2 @@", span.line, span.line);
        let _ = writeln!(out, " {snippet}");
        let _ = writeln!(out, "+{suggested_call}");
    }
    out
}

/// Extracts the first argument (`&key`) from a `.set(&key, &val)` or `.update(&key, ...)` source line snippet.
fn extract_first_arg_from_set_snippet(snippet: &str) -> Option<&str> {
    let marker_pos = snippet.find(".set(").or_else(|| snippet.find(".update("))?;
    let after_open = &snippet[marker_pos..];
    let open_paren = after_open.find('(')?;
    let args_slice = &after_open[open_paren + 1..];
    let comma = args_slice.find(',')?;
    Some(args_slice[..comma].trim())
}

/// Executes `sorark inspect` on a compiled `.wasm` binary.
fn run_inspect(wasm: &Path, format: OutputFormat, config: &SorarkConfig) -> Result<ExitCode> {
    let report = inspect_wasm_file(wasm, config)?;
    let rendered = render_wasm_inspection(&report, format)?;
    print!("{rendered}");
    Ok(exit_code_for_diagnostics(
        &report.diagnostics,
        config.fail_on_warnings,
    ))
}

/// Executes `sorark rules` to print the built-in SORARK rule catalog or explain a single rule.
fn run_rules(format: OutputFormat, explain_rule_id: Option<&str>) -> Result<ExitCode> {
    if let Some(rule_id) = explain_rule_id {
        let Some(rule) = find_rule_descriptor(rule_id) else {
            bail!(
                "Unknown SORARK rule ID `{rule_id}`. Run `sorark rules` to see all available rule IDs."
            );
        };
        let rendered = render_rule_explanation(&rule, format)?;
        print!("{rendered}");
        return Ok(ExitCode::SUCCESS);
    }

    let catalog = builtin_rule_catalog();
    let rendered = render_rule_catalog(&catalog, format)?;
    print!("{rendered}");
    Ok(ExitCode::SUCCESS)
}

/// Executes `sorark init` to generate a documented `sorark.toml` configuration file.
fn run_init(output: &Path, force: bool) -> Result<ExitCode> {
    if output.exists() && !force {
        bail!(
            "Configuration file `{}` already exists. Pass `--force` to overwrite it.",
            output.display()
        );
    }
    std::fs::write(output, SorarkConfig::default_toml_template())
        .with_context(|| format!("Failed to write `{}`", output.display()))?;
    println!("Created SORARK configuration at `{}`", output.display());
    Ok(ExitCode::SUCCESS)
}

/// Loads `sorark.toml` from `explicit_path`, or from `./sorark.toml` if present,
/// falling back to [`SorarkConfig::default`].
fn load_config(explicit_path: Option<&Path>) -> Result<SorarkConfig> {
    if let Some(path) = explicit_path {
        return Ok(SorarkConfig::from_file(path)?);
    }
    let default_path = Path::new("sorark.toml");
    if default_path.exists() {
        return Ok(SorarkConfig::from_file(default_path)?);
    }
    Ok(SorarkConfig::default())
}

/// Returns `true` if `path` points to a `.wasm` file on disk.
fn is_wasm_path(path: &Path) -> bool {
    path.is_file() && path.extension().and_then(|s| s.to_str()) == Some("wasm")
}

/// Loads a [`ContractModule`] from either a compiled `.wasm` binary or a Rust source path.
fn load_contract_module(path: &Path, config: &SorarkConfig) -> Result<ContractModule> {
    if is_wasm_path(path) {
        let report = inspect_wasm_file(path, config)?;
        Ok(report.module)
    } else {
        let report = scan_rust_path(path, config)?;
        Ok(report.context.module)
    }
}

/// Computes the process [`ExitCode`] (`0` when clean, `1` when blocking diagnostics exist).
fn exit_code_for_diagnostics(diagnostics: &[Diagnostic], fail_on_warnings: bool) -> ExitCode {
    let has_failure = diagnostics.iter().any(|d| {
        d.severity == Severity::Error || (fail_on_warnings && d.severity == Severity::Warning)
    });
    if has_failure {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    }
}

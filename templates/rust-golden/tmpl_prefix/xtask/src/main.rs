//! Workspace automation tasks (`cargo xtask <subcommand>`).

use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::ffi::OsString;
use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, ExitStatus};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Layer {
    Foundation,
    Domain,
    Adapters,
    Apps,
}

impl Layer {
    fn from_member_dir(member_dir: &str) -> Option<Self> {
        match member_dir.trim_matches('/').split('/').next()? {
            "foundation" => Some(Self::Foundation),
            "domain" => Some(Self::Domain),
            "adapters" => Some(Self::Adapters),
            "apps" => Some(Self::Apps),
            _ => None,
        }
    }

    const fn as_str(self) -> &'static str {
        match self {
            Self::Foundation => "foundation",
            Self::Domain => "domain",
            Self::Adapters => "adapters",
            Self::Apps => "apps",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CrateSpec {
    name: String,
    member_dir: String,
    dependencies: Vec<String>,
}

fn check_layer_rules(specs: &[CrateSpec]) -> Result<(), Vec<String>> {
    let mut errors = Vec::new();
    let mut crate_layers: BTreeMap<&str, Layer> = BTreeMap::new();

    for spec in specs {
        if spec.member_dir == "xtask" || spec.name == "xtask" {
            continue;
        }
        match Layer::from_member_dir(&spec.member_dir) {
            Some(layer) => {
                crate_layers.insert(&spec.name, layer);
            }
            None => errors.push(format!(
                "crate `{}` in `{}` does not belong to a known layer directory (expected foundation, domain, adapters, or apps)",
                spec.name, spec.member_dir
            )),
        }
    }

    for spec in specs {
        let Some(&layer) = crate_layers.get(spec.name.as_str()) else {
            continue;
        };
        for dep in &spec.dependencies {
            if let Some(&dep_layer) = crate_layers.get(dep.as_str())
                && dep_layer >= layer
            {
                errors.push(format!(
                    "layer violation: crate `{}` (layer `{}`) cannot depend on `{}` (layer `{}`; allowed: strictly lower layers than `{}`)",
                    spec.name,
                    layer.as_str(),
                    dep,
                    dep_layer.as_str(),
                    layer.as_str()
                ));
            }
        }
    }

    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}

#[derive(Deserialize)]
struct WorkspaceManifest {
    workspace: Option<WorkspaceSection>,
}

#[derive(Default, Deserialize)]
struct WorkspaceSection {
    #[serde(default)]
    members: Vec<String>,
    #[serde(default)]
    exclude: Vec<String>,
    #[serde(default)]
    dependencies: BTreeMap<String, DependencyEntry>,
}

#[derive(Default, Deserialize)]
struct DependencyTables {
    #[serde(default)]
    dependencies: BTreeMap<String, DependencyEntry>,
    #[serde(default, rename = "dev-dependencies")]
    dev_dependencies: BTreeMap<String, DependencyEntry>,
    #[serde(default, rename = "build-dependencies")]
    build_dependencies: BTreeMap<String, DependencyEntry>,
}

impl DependencyTables {
    fn iter(&self) -> impl Iterator<Item = (&String, &DependencyEntry)> {
        self.dependencies
            .iter()
            .chain(&self.dev_dependencies)
            .chain(&self.build_dependencies)
    }
}

#[derive(Deserialize)]
struct MemberManifest {
    package: PackageSection,
    #[serde(flatten)]
    deps: DependencyTables,
    #[serde(default)]
    target: BTreeMap<String, DependencyTables>,
}

#[derive(Deserialize)]
struct PackageSection {
    name: String,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum DependencyEntry {
    Simple(String),
    Detailed(DependencyDetail),
}

#[derive(Deserialize)]
struct DependencyDetail {
    package: Option<String>,
    #[serde(default)]
    workspace: bool,
}

impl DependencyEntry {
    fn direct_name<'a>(&'a self, key: &'a str) -> &'a str {
        match self {
            Self::Simple(_version) => key,
            Self::Detailed(d) => d.package.as_deref().unwrap_or(key),
        }
    }

    fn resolved_name<'a>(&'a self, key: &'a str, ws_deps: &'a BTreeMap<String, Self>) -> &'a str {
        match self {
            Self::Detailed(d) if d.workspace => {
                ws_deps.get(key).map_or(key, |ws| ws.direct_name(key))
            }
            _ => self.direct_name(key),
        }
    }
}

#[derive(Debug)]
struct XtaskError {
    message: String,
    code: u8,
}

impl XtaskError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            code: 1,
        }
    }
}

impl From<String> for XtaskError {
    fn from(message: String) -> Self {
        Self::new(message)
    }
}

fn exit_code_from_status(status: ExitStatus) -> u8 {
    status
        .code()
        .and_then(|c| u8::try_from(c).ok())
        .filter(|&c| c != 0)
        .unwrap_or(1)
}

fn workspace_root() -> Result<PathBuf, String> {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .map(Path::to_path_buf)
        .ok_or_else(|| "failed to locate workspace root from CARGO_MANIFEST_DIR".to_owned())
}

fn run_cargo(root: &Path, args: &[&str]) -> Result<(), XtaskError> {
    let cargo = env::var("CARGO").unwrap_or_else(|_| "cargo".to_owned());
    let joined = args.join(" ");
    println!("+ {cargo} {joined}");
    let status = Command::new(&cargo)
        .current_dir(root)
        .args(args)
        .status()
        .map_err(|e| XtaskError::new(format!("failed to execute `{cargo} {joined}`: {e}")))?;
    if status.success() {
        Ok(())
    } else {
        Err(XtaskError {
            message: format!("command `{cargo} {joined}` exited with status {status}"),
            code: exit_code_from_status(status),
        })
    }
}

fn has_glob_chars(s: &str) -> bool {
    s.contains(['*', '?', '[', ']'])
}

fn normalize_rel_path(s: &str) -> &str {
    s.trim_start_matches("./").trim_end_matches('/')
}

fn resolve_workspace_members(
    root: &Path,
    members: &[String],
    exclude: &[String],
) -> Result<Vec<String>, String> {
    let excluded: BTreeSet<&str> = exclude.iter().map(|s| normalize_rel_path(s)).collect();
    let mut resolved = BTreeSet::new();

    for raw in members {
        let entry = normalize_rel_path(raw);
        if let Some(prefix) = entry.strip_suffix("/*").map(normalize_rel_path) {
            if prefix.is_empty() || has_glob_chars(prefix) {
                return Err(format!(
                    "unsupported glob pattern `{raw}` in `[workspace].members`"
                ));
            }
            let dir_path = root.join(prefix);
            let entries = fs::read_dir(&dir_path)
                .map_err(|e| format!("failed to read `{}`: {e}", dir_path.display()))?;
            for entry in entries {
                let entry =
                    entry.map_err(|e| format!("failed to read `{}`: {e}", dir_path.display()))?;
                if entry.path().join("Cargo.toml").is_file() {
                    let file_name = entry.file_name();
                    let name = file_name.to_str().ok_or_else(|| {
                        format!("non-UTF-8 directory name under `{}`", dir_path.display())
                    })?;
                    let rel = format!("{prefix}/{name}");
                    if !excluded.contains(rel.as_str()) {
                        resolved.insert(rel);
                    }
                }
            }
        } else if has_glob_chars(entry) {
            return Err(format!(
                "unsupported glob pattern `{raw}` in `[workspace].members`"
            ));
        } else if !excluded.contains(entry) {
            resolved.insert(entry.to_owned());
        }
    }

    Ok(resolved.into_iter().collect())
}

fn read_toml<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<T, String> {
    let text = fs::read_to_string(path)
        .map_err(|e| format!("failed to read `{}`: {e}", path.display()))?;
    toml::from_str(&text).map_err(|e| format!("failed to parse `{}`: {e}", path.display()))
}

fn load_workspace_specs(root: &Path) -> Result<Vec<CrateSpec>, String> {
    let root_path = root.join("Cargo.toml");
    let root_manifest: WorkspaceManifest = read_toml(&root_path)?;
    let ws = root_manifest
        .workspace
        .ok_or_else(|| format!("missing `[workspace]` table in `{}`", root_path.display()))?;
    let members = resolve_workspace_members(root, &ws.members, &ws.exclude)?;

    members
        .into_iter()
        .map(|member_dir| {
            let manifest: MemberManifest = read_toml(&root.join(&member_dir).join("Cargo.toml"))?;
            let dependencies = manifest
                .deps
                .iter()
                .chain(manifest.target.values().flat_map(DependencyTables::iter))
                .map(|(k, v)| v.resolved_name(k, &ws.dependencies).to_owned())
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect();
            Ok(CrateSpec {
                name: manifest.package.name,
                member_dir,
                dependencies,
            })
        })
        .collect()
}

fn cmd_layers(root: &Path) -> Result<(), String> {
    let specs = load_workspace_specs(root)?;
    check_layer_rules(&specs).map_err(|v| v.join("\n"))?;
    println!(
        "layer check passed ({} workspace members verified)",
        specs.len()
    );
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum CliCommand {
    Ci,
    Fmt,
    Layers,
    BumpMsrv(String),
}

fn validate_msrv_version(ver: &str) -> Result<String, XtaskError> {
    let parts: Vec<&str> = ver.split('.').collect();
    if (parts.len() != 2 && parts.len() != 3)
        || parts
            .iter()
            .any(|p| p.is_empty() || !p.bytes().all(|b| b.is_ascii_digit()))
    {
        return Err(XtaskError::new(format!(
            "invalid MSRV version `{ver}` (expected `\\d+\\.\\d+(\\.\\d+)?`, e.g. `1.88` or `1.88.0`)"
        )));
    }
    if parts.len() == 2 {
        Ok(format!("{}.{}.0", parts[0], parts[1]))
    } else {
        Ok(ver.to_owned())
    }
}

fn rewrite_cargo_toml_msrv(text: &str, ver: &str) -> Result<String, String> {
    let mut out = String::with_capacity(text.len() + 16);
    let mut in_ws_pkg = false;
    let mut replaced = false;
    for line in text.split_inclusive('\n') {
        let trimmed = line.trim();
        if trimmed.starts_with('[') && trimmed.ends_with(']') {
            in_ws_pkg = trimmed == "[workspace.package]";
        } else if in_ws_pkg && !replaced {
            let no_comment = trimmed.split('#').next().unwrap_or("").trim();
            if let Some(rest) = no_comment.strip_prefix("rust-version")
                && rest.trim_start().starts_with('=')
            {
                let ending = if line.ends_with("\r\n") {
                    "\r\n"
                } else if line.ends_with('\n') {
                    "\n"
                } else {
                    ""
                };
                let _ = write!(out, "rust-version = \"{ver}\"{ending}");
                replaced = true;
                continue;
            }
        }
        out.push_str(line);
    }
    if replaced {
        Ok(out)
    } else {
        Err(
            "could not find `rust-version = \"...\"` under `[workspace.package]` in `Cargo.toml`"
                .to_owned(),
        )
    }
}

fn rewrite_clippy_toml_msrv(text: &str, full_ver: &str) -> String {
    let mut out = String::with_capacity(text.len() + 24);
    let mut replaced = false;
    for line in text.split_inclusive('\n') {
        let trimmed = line.trim();
        let no_comment = trimmed.split('#').next().unwrap_or("").trim();
        if !replaced
            && let Some(rest) = no_comment.strip_prefix("msrv")
            && rest.trim_start().starts_with('=')
        {
            let ending = if line.ends_with("\r\n") {
                "\r\n"
            } else if line.ends_with('\n') {
                "\n"
            } else {
                ""
            };
            let _ = write!(out, "msrv = \"{full_ver}\"{ending}");
            replaced = true;
            continue;
        }
        out.push_str(line);
    }
    if !replaced {
        out = format!("msrv = \"{full_ver}\"\n{out}");
    }
    out
}

fn rewrite_ci_yml_msrv(text: &str, ver: &str) -> Result<String, String> {
    let mut out = String::with_capacity(text.len() + 32);
    let mut replaced_toolchain = false;
    let mut replaced_run = false;

    for line in text.split_inclusive('\n') {
        let ending = if line.ends_with("\r\n") {
            "\r\n"
        } else if line.ends_with('\n') {
            "\n"
        } else {
            ""
        };
        let body = line.trim_end_matches(['\r', '\n']);

        if let Some(idx) = body.find("name: MSRV (")
            && let Some(end_paren) = body[idx..].find(')')
        {
            let prefix = &body[..idx + "name: MSRV (".len()];
            let suffix = &body[idx + end_paren..];
            let _ = write!(out, "{prefix}{ver}{suffix}{ending}");
            continue;
        }

        if let Some(idx) = body.find("dtolnay/rust-toolchain@") {
            let prefix = &body[..idx + "dtolnay/rust-toolchain@".len()];
            let _ = write!(out, "{prefix}{ver}{ending}");
            replaced_toolchain = true;
            continue;
        }

        if let Some(idx) = body.find("cargo +") {
            let after_plus = &body[idx + "cargo +".len()..];
            if let Some(space_idx) = after_plus.find(' ') {
                let prefix = &body[..idx + "cargo +".len()];
                let suffix = &after_plus[space_idx..];
                let _ = write!(out, "{prefix}{ver}{suffix}{ending}");
                replaced_run = true;
                continue;
            }
        }

        out.push_str(line);
    }

    if replaced_toolchain && replaced_run {
        Ok(out)
    } else {
        Err("could not update MSRV job in `.github/workflows/ci.yml`".to_owned())
    }
}

fn default_msrv_check_runner(root: &Path, ver: &str) -> Result<(), XtaskError> {
    let plus_tc = format!("+{ver}");
    println!("+ rustup run {ver} cargo --version");
    let probe = Command::new("rustup")
        .current_dir(root)
        .args(["run", ver, "cargo", "--version"])
        .output();

    if let Ok(out) = probe
        && !out.status.success()
    {
        let stderr = String::from_utf8_lossy(&out.stderr);
        let stdout = String::from_utf8_lossy(&out.stdout);
        let combined = format!("{stderr}\n{stdout}");
        if combined.contains("is not installed") || combined.contains("toolchain") {
            let install_msg = format!(
                "missing Rust toolchain `{ver}`; install it with: `rustup toolchain install {ver}`"
            );
            println!("{install_msg}");
            return Err(XtaskError {
                message: install_msg,
                code: exit_code_from_status(out.status),
            });
        }
    }

    let args = [
        plus_tc.as_str(),
        "check",
        "--workspace",
        "--all-targets",
        "--locked",
    ];
    let joined = args.join(" ");
    println!("+ cargo {joined}");
    let status = Command::new("cargo")
        .current_dir(root)
        .env_remove("CARGO")
        .env_remove("RUSTC")
        .args(args)
        .status()
        .map_err(|e| {
            XtaskError::new(format!(
                "failed to execute `cargo {joined}`: {e} (install toolchain with `rustup toolchain install {ver}`)"
            ))
        })?;

    if status.success() {
        Ok(())
    } else {
        Err(XtaskError {
            message: format!("command `cargo {joined}` exited with status {status}"),
            code: exit_code_from_status(status),
        })
    }
}

fn cmd_bump_msrv_with<F>(root: &Path, ver: &str, runner: F) -> Result<(), XtaskError>
where
    F: FnOnce(&Path, &str) -> Result<(), XtaskError>,
{
    let full_ver = validate_msrv_version(ver)?;
    let cargo_path = root.join("Cargo.toml");
    let clippy_path = root.join("clippy.toml");
    let ci_path = root.join(".github/workflows/ci.yml");

    let orig_cargo = fs::read_to_string(&cargo_path)
        .map_err(|e| XtaskError::new(format!("failed to read `{}`: {e}", cargo_path.display())))?;
    let orig_clippy = fs::read_to_string(&clippy_path)
        .map_err(|e| XtaskError::new(format!("failed to read `{}`: {e}", clippy_path.display())))?;
    let orig_ci = fs::read_to_string(&ci_path)
        .map_err(|e| XtaskError::new(format!("failed to read `{}`: {e}", ci_path.display())))?;

    let new_cargo = rewrite_cargo_toml_msrv(&orig_cargo, ver).map_err(XtaskError::new)?;
    let new_clippy = rewrite_clippy_toml_msrv(&orig_clippy, &full_ver);
    let new_ci = rewrite_ci_yml_msrv(&orig_ci, ver).map_err(XtaskError::new)?;

    let write_all = || -> Result<(), String> {
        fs::write(&cargo_path, &new_cargo)
            .map_err(|e| format!("failed to write `{}`: {e}", cargo_path.display()))?;
        fs::write(&clippy_path, &new_clippy)
            .map_err(|e| format!("failed to write `{}`: {e}", clippy_path.display()))?;
        fs::write(&ci_path, &new_ci)
            .map_err(|e| format!("failed to write `{}`: {e}", ci_path.display()))?;
        Ok(())
    };

    let rollback = || {
        let _ = fs::write(&cargo_path, &orig_cargo);
        let _ = fs::write(&clippy_path, &orig_clippy);
        let _ = fs::write(&ci_path, &orig_ci);
    };

    if let Err(err) = write_all() {
        rollback();
        return Err(XtaskError::new(err));
    }

    match runner(root, ver) {
        Ok(()) => {
            println!("MSRV bumped to {ver} (clippy msrv = {full_ver})");
            Ok(())
        }
        Err(err) => {
            rollback();
            Err(err)
        }
    }
}

fn parse_cli_args<I: IntoIterator<Item = OsString>>(args: I) -> Result<CliCommand, XtaskError> {
    let args: Vec<String> = args
        .into_iter()
        .map(|a| {
            a.into_string().map_err(|bad| {
                XtaskError::new(format!(
                    "invalid non-UTF-8 argument `{}`",
                    bad.to_string_lossy()
                ))
            })
        })
        .collect::<Result<_, _>>()?;
    match args.as_slice() {
        [] => Err(XtaskError::new(
            "missing xtask subcommand (expected: `ci`, `fmt`, `layers`, or `bump-msrv <ver>`)",
        )),
        [sub] => match sub.as_str() {
            "ci" => Ok(CliCommand::Ci),
            "fmt" => Ok(CliCommand::Fmt),
            "layers" => Ok(CliCommand::Layers),
            "bump-msrv" => Err(XtaskError::new(
                "missing version argument for `bump-msrv` (usage: `cargo xtask bump-msrv <ver>`)",
            )),
            other => Err(XtaskError::new(format!(
                "unknown xtask subcommand `{other}` (expected: `ci`, `fmt`, `layers`, or `bump-msrv <ver>`)"
            ))),
        },
        [sub, ver] if sub == "bump-msrv" => {
            validate_msrv_version(ver)?;
            Ok(CliCommand::BumpMsrv(ver.clone()))
        }
        [_, extra, ..] => Err(XtaskError::new(format!(
            "unexpected extra argument `{extra}`"
        ))),
    }
}

fn run() -> Result<(), XtaskError> {
    let root = workspace_root()?;
    match parse_cli_args(env::args_os().skip(1))? {
        CliCommand::Ci => {
            run_cargo(&root, &["fmt", "--all", "--", "--check"])?;
            run_cargo(
                &root,
                &[
                    "clippy",
                    "--workspace",
                    "--all-targets",
                    "--locked",
                    "--",
                    "-D",
                    "warnings",
                ],
            )?;
            run_cargo(&root, &["test", "--workspace", "--locked"])?;
            Ok(cmd_layers(&root)?)
        }
        CliCommand::Fmt => run_cargo(&root, &["fmt", "--all"]),
        CliCommand::Layers => Ok(cmd_layers(&root)?),
        CliCommand::BumpMsrv(ver) => cmd_bump_msrv_with(&root, &ver, default_msrv_check_runner),
    }
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("error: {}", err.message);
            ExitCode::from(err.code)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    const FOUNDATION: &str =
        // Package name after scaffold substitution.
        "tmpl-prefix-foundation";
    const DOMAIN: &str = "tmpl-prefix-domain";
    const ADAPTERS: &str =
        // Package name after scaffold substitution.
        "tmpl-prefix-adapters";
    const CLI: &str = "tmpl-prefix-cli";

    fn spec(name: &str, member_dir: &str, deps: &[&str]) -> CrateSpec {
        CrateSpec {
            name: name.to_owned(),
            member_dir: member_dir.to_owned(),
            dependencies: deps.iter().map(|s| (*s).to_owned()).collect(),
        }
    }

    fn sample_workspace(extra_found: &[&str], extra_dom: &[&str]) -> Vec<CrateSpec> {
        let mut dom_deps = vec![FOUNDATION];
        dom_deps.extend_from_slice(extra_dom);
        vec![
            spec(FOUNDATION, "foundation", extra_found),
            spec(DOMAIN, "domain", &dom_deps),
            spec(ADAPTERS, "adapters", &[FOUNDATION, DOMAIN]),
            spec(CLI, "apps/cli", &[FOUNDATION, DOMAIN, ADAPTERS]),
        ]
    }

    struct TempWorkspace {
        root: PathBuf,
    }

    impl TempWorkspace {
        fn new(label: &str) -> Self {
            static COUNTER: AtomicUsize = AtomicUsize::new(0);
            let id = COUNTER.fetch_add(1, Ordering::Relaxed);
            let root = env::temp_dir().join(format!(
                "xtask-layer-test-{label}-{}-{id}",
                std::process::id()
            ));
            let _ = fs::remove_dir_all(&root);
            fs::create_dir_all(&root).unwrap();
            Self { root }
        }

        fn write(&self, rel: &str, contents: &str) {
            let path = self.root.join(rel);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, contents).unwrap();
        }

        fn pkg(&self, dir: &str, name: &str, extra_toml: &str) {
            self.write(
                &format!("{dir}/Cargo.toml"),
                &format!("[package]\nname = \"{name}\"\nversion = \"0.1.0\"\n{extra_toml}\n"),
            );
        }
    }

    impl Drop for TempWorkspace {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    #[test]
    fn valid_layered_workspace_passes() {
        assert!(check_layer_rules(&sample_workspace(&[], &[])).is_ok());
    }

    #[test]
    fn foundation_depending_on_domain_fails() {
        let errs = check_layer_rules(&sample_workspace(&[DOMAIN], &[])).unwrap_err();
        assert_eq!(errs.len(), 1);
        assert!(errs[0].contains(FOUNDATION) && errs[0].contains(DOMAIN));
    }

    #[test]
    fn domain_depending_on_adapters_or_apps_fails() {
        let errs = check_layer_rules(&sample_workspace(&[], &[ADAPTERS, CLI])).unwrap_err();
        assert_eq!(errs.len(), 2);
        assert!(errs.iter().any(|e| e.contains(ADAPTERS)));
        assert!(errs.iter().any(|e| e.contains(CLI)));
    }

    #[test]
    fn real_workspace_manifest_passes_layer_rules() {
        let specs = load_workspace_specs(&workspace_root().unwrap()).unwrap();
        assert!(check_layer_rules(&specs).is_ok());
    }

    #[test]
    fn target_cfg_forbidden_dependency_is_detected() {
        let ws = TempWorkspace::new("target-cfg");
        ws.write(
            "Cargo.toml",
            "[workspace]\nmembers = [\"foundation\", \"domain\"]\n",
        );
        ws.pkg(
            "foundation",
            "my-foundation",
            "[target.'cfg(unix)'.dev-dependencies]\nmy-domain = { path = \"../domain\" }",
        );
        ws.pkg("domain", "my-domain", "");

        let errs = check_layer_rules(&load_workspace_specs(&ws.root).unwrap()).unwrap_err();
        assert_eq!(errs.len(), 1);
        assert!(errs[0].contains("my-foundation") && errs[0].contains("my-domain"));
    }

    #[test]
    fn workspace_dependency_rename_violation_is_detected() {
        let ws = TempWorkspace::new("ws-dep-rename");
        ws.write(
            "Cargo.toml",
            "[workspace]\nmembers = [\"foundation\", \"domain\", \"adapters\"]\n\
             [workspace.dependencies]\n\
             alias = { path = \"domain\", package = \"real-domain-pkg\" }\n",
        );
        ws.pkg(
            "foundation",
            "real-foundation-pkg",
            "[dependencies]\nalias = { workspace = true }",
        );
        ws.pkg(
            "domain",
            "real-domain-pkg",
            "[dependencies]\nlocal-adapters-alias = { path = \"../adapters\", package = \"real-adapters-pkg\" }",
        );
        ws.pkg("adapters", "real-adapters-pkg", "");

        let specs = load_workspace_specs(&ws.root).unwrap();
        let errs = check_layer_rules(&specs).unwrap_err();
        assert_eq!(errs.len(), 2);
        assert!(
            errs.iter()
                .any(|e| e.contains("real-foundation-pkg") && e.contains("real-domain-pkg"))
        );
        assert!(
            errs.iter()
                .any(|e| e.contains("real-domain-pkg") && e.contains("real-adapters-pkg"))
        );

        let ws_deps = BTreeMap::from([(
            "alias".to_owned(),
            DependencyEntry::Detailed(DependencyDetail {
                package: Some("real-domain-pkg".to_owned()),
                workspace: false,
            }),
        )]);
        let inherited = DependencyEntry::Detailed(DependencyDetail {
            package: Some("ignored".to_owned()),
            workspace: true,
        });
        assert_eq!(
            inherited.resolved_name("alias", &ws_deps),
            "real-domain-pkg"
        );
    }

    #[test]
    fn workspace_member_globs_and_exclude_are_resolved() {
        let ws = TempWorkspace::new("member-globs");
        ws.write(
            "Cargo.toml",
            "[workspace]\nmembers = [\"foundation\", \"domain/*\", \"apps/*\"]\nexclude = [\"apps/ignored\"]\n",
        );
        ws.pkg("foundation", "glob-foundation", "");
        ws.pkg(
            "domain/billing",
            "glob-domain-billing",
            "[dependencies]\nglob-cli = { path = \"../../apps/cli\" }",
        );
        ws.write("domain/notes/README.md", "not a crate");
        ws.pkg("apps/cli", "glob-cli", "");
        ws.pkg("apps/ignored", "glob-ignored", "");

        let specs = load_workspace_specs(&ws.root).unwrap();
        assert_eq!(specs.len(), 3);
        assert!(!specs.iter().any(|s| s.name == "glob-ignored"));

        let errs = check_layer_rules(&specs).unwrap_err();
        assert_eq!(errs.len(), 1);
        assert!(errs[0].contains("glob-domain-billing") && errs[0].contains("glob-cli"));

        ws.write("Cargo.toml", "[workspace]\nmembers = [\"apps/**\"]\n");
        assert!(load_workspace_specs(&ws.root).unwrap_err().contains("glob"));
    }

    #[test]
    fn non_utf8_args_and_child_exit_codes_are_handled() {
        #[cfg(unix)]
        {
            use std::os::unix::ffi::OsStringExt;
            use std::os::unix::process::ExitStatusExt;

            let err = parse_cli_args([OsString::from_vec(vec![0xff, 0xfe])]).unwrap_err();
            assert_eq!(err.code, 1);
            assert!(err.message.contains("UTF-8"));
            assert_eq!(exit_code_from_status(ExitStatus::from_raw(101 << 8)), 101);
            assert_eq!(exit_code_from_status(ExitStatus::from_raw(15)), 1);
        }
    }

    #[test]
    fn parse_cli_args_and_validate_msrv_versions() {
        assert_eq!(
            parse_cli_args([OsString::from("ci")]).unwrap(),
            CliCommand::Ci
        );
        assert_eq!(
            parse_cli_args([OsString::from("fmt")]).unwrap(),
            CliCommand::Fmt
        );
        assert_eq!(
            parse_cli_args([OsString::from("layers")]).unwrap(),
            CliCommand::Layers
        );
        assert_eq!(
            parse_cli_args([OsString::from("bump-msrv"), OsString::from("1.88")]).unwrap(),
            CliCommand::BumpMsrv("1.88".to_owned())
        );
        assert_eq!(
            parse_cli_args([OsString::from("bump-msrv"), OsString::from("1.89.1")]).unwrap(),
            CliCommand::BumpMsrv("1.89.1".to_owned())
        );
        assert!(parse_cli_args([OsString::from("bump-msrv")]).is_err());
        assert!(parse_cli_args([OsString::from("bump-msrv"), OsString::from("stable")]).is_err());
        assert!(parse_cli_args([OsString::from("bump-msrv"), OsString::from("1")]).is_err());
        assert!(parse_cli_args([OsString::from("bump-msrv"), OsString::from("1.88.0.1")]).is_err());
        assert!(
            parse_cli_args([
                OsString::from("bump-msrv"),
                OsString::from("1.88"),
                OsString::from("extra"),
            ])
            .is_err()
        );
    }

    #[test]
    fn bump_msrv_updates_all_three_files_and_rolls_back_on_failure() {
        let ws = TempWorkspace::new("bump-msrv");
        let orig_cargo = "[workspace]\nmembers = [\"foundation\"]\n\n[workspace.package]\nversion = \"0.1.0\"\nedition = \"2024\"\nrust-version = \"1.88\"\n";
        let orig_clippy = "msrv = \"1.88.0\"\nallow-unwrap-in-tests = true\n";
        let orig_ci = "jobs:\n  msrv:\n    name: MSRV (1.88)\n    steps:\n      - uses: dtolnay/rust-toolchain@1.88\n      - run: cargo +1.88 check --workspace --all-targets --locked\n";
        ws.write("Cargo.toml", orig_cargo);
        ws.write("clippy.toml", orig_clippy);
        ws.write(".github/workflows/ci.yml", orig_ci);

        // 1. Failure rolls back all three files to byte-for-byte original contents
        let err = cmd_bump_msrv_with(&ws.root, "1.90", |_root, ver| {
            Err(XtaskError::new(format!(
                "missing Rust toolchain `{ver}`; install it with: `rustup toolchain install {ver}`"
            )))
        })
        .unwrap_err();
        assert!(err.message.contains("rustup toolchain install 1.90"));
        assert_eq!(
            fs::read_to_string(ws.root.join("Cargo.toml")).unwrap(),
            orig_cargo
        );
        assert_eq!(
            fs::read_to_string(ws.root.join("clippy.toml")).unwrap(),
            orig_clippy
        );
        assert_eq!(
            fs::read_to_string(ws.root.join(".github/workflows/ci.yml")).unwrap(),
            orig_ci
        );

        // 2. Success keeps the updated versions across all three files
        cmd_bump_msrv_with(&ws.root, "1.90", |root, ver| {
            assert_eq!(ver, "1.90");
            assert!(
                fs::read_to_string(root.join("Cargo.toml"))
                    .unwrap()
                    .contains("rust-version = \"1.90\"")
            );
            Ok(())
        })
        .unwrap();
        assert!(
            fs::read_to_string(ws.root.join("Cargo.toml"))
                .unwrap()
                .contains("rust-version = \"1.90\"")
        );
        assert!(
            fs::read_to_string(ws.root.join("clippy.toml"))
                .unwrap()
                .contains("msrv = \"1.90.0\"")
        );
        let updated_ci = fs::read_to_string(ws.root.join(".github/workflows/ci.yml")).unwrap();
        assert!(updated_ci.contains("name: MSRV (1.90)"));
        assert!(updated_ci.contains("dtolnay/rust-toolchain@1.90"));
        assert!(updated_ci.contains("cargo +1.90 check --workspace --all-targets --locked"));
    }
}

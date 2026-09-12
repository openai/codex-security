// Test-only launcher: Node's Windows startup has already replaced lone surrogates.
#[cfg(not(windows))]
fn main() {}

#[cfg(windows)]
fn main() -> std::io::Result<()> {
    use std::{
        env,
        ffi::OsString,
        fs, io,
        os::windows::{ffi::OsStringExt, fs::OpenOptionsExt},
        path::{Path, PathBuf},
        process::Command,
    };

    fn raw(prefix: &str, unit: u16) -> OsString {
        OsString::from_wide(&prefix.encode_utf16().chain([unit]).collect::<Vec<_>>())
    }

    fn run(node: OsString, script: OsString, root: &Path) -> io::Result<()> {
        let cwd = root.join(raw("cwd-", 0xd800));
        fs::create_dir(&cwd)?;
        let replacement = root.join("cwd-\u{fffd}");
        fs::create_dir(&replacement)?;
        fs::write(replacement.join("sentinel"), "replacement cwd untouched")?;
        let names = [
            raw("high-", 0xd800),
            raw("high-", 0xfffd),
            raw("low-", 0xdc80),
            raw("low-", 0xfffd),
            raw("tail-", 0xdfff),
            raw("tail-", 0xfffd),
            OsString::from("unicode-🔐-東京"),
        ];
        for (index, name) in names.iter().enumerate() {
            fs::write(cwd.join(name), format!("sentinel-{index}"))?;
        }
        std::os::windows::fs::symlink_file(&names[0], cwd.join("relative-link"))?;
        std::os::windows::fs::symlink_file(raw("missing-", 0xdfff), cwd.join("missing-link"))?;
        std::os::windows::fs::symlink_file(
            Path::new("..").join(raw("missing-", 0xdfff)),
            cwd.join("missing-parent-link"),
        )?;
        std::os::windows::fs::symlink_file("loop-link", cwd.join("loop-link"))?;
        fs::write(cwd.join("missing-tail"), "ordinary sibling")?;
        std::os::windows::fs::symlink_file("missing-tail.", cwd.join("dot-target-link"))?;
        std::os::windows::fs::symlink_file("missing-tail ", cwd.join("space-target-link"))?;
        fs::create_dir(cwd.join("empty"))?;
        fs::create_dir(cwd.join(raw("directory-", 0xdc80)))?;
        std::os::windows::fs::symlink_file(&names[0], cwd.join("file-link"))?;
        std::os::windows::fs::symlink_dir("empty", cwd.join("directory-link"))?;
        std::os::windows::fs::symlink_dir(
            raw("missing-", 0xdfff),
            cwd.join("dangling-directory-link"),
        )?;
        let locked = cwd.join(raw("locked-", 0xdfff));
        fs::write(&locked, "directory enumeration does not open this file")?;
        fs::write(root.join(raw("parent-", 0xd800)), "parent sentinel")?;
        let verbatim = fs::canonicalize(&cwd)?;
        for (name, contents) in [
            ("trailing", "ordinary dot sibling"),
            ("trailing.", "literal dot file"),
            ("space", "ordinary space sibling"),
            ("space ", "literal space file"),
        ] {
            fs::write(verbatim.join(name), contents)?;
        }
        let arguments = [
            raw("arg-high-", 0xd800),
            raw("arg-low-", 0xdc80),
            raw("arg-tail-", 0xdfff),
            OsString::from("replacement-\u{fffd}"),
            OsString::from("Unicode 🔐 東京"),
            OsString::from(""),
            OsString::from("space and\ttab"),
            OsString::from("quoted \"value\" and trailing\\"),
            OsString::from("backslash\\\"quote"),
        ];
        let guard = fs::OpenOptions::new()
            .read(true)
            .share_mode(0)
            .open(&locked)?;
        let status = Command::new(node)
            .arg(script)
            .arg("wide-worker")
            .arg(root)
            .args(arguments)
            .current_dir(&cwd)
            .env("CODEX_SECURITY_WIDE_VALUE", raw("value-", 0xd800))
            .env("CODEX_SECURITY_WIDE_EMPTY", "")
            .env_remove("CODEX_SECURITY_WIDE_ABSENT")
            .env(raw("CODEX_SECURITY_WIDE_NAME_", 0xdfff), "wide name value")
            .env("CODEX_SECURITY_WIDE_LONG", "x".repeat(1024))
            .env("USERPROFILE", &cwd)
            .status()?;
        if !status.success() {
            return Err(io::Error::other("Wide Windows child proof failed"));
        }
        drop(guard);
        if fs::read(replacement.join("sentinel"))? != b"replacement cwd untouched" {
            return Err(io::Error::other("Replacement cwd was changed"));
        }
        Ok(())
    }

    fn policy_proof(node: OsString, script: OsString, root: &Path) -> io::Result<()> {
        let cwds = [raw("cwd-", 0xd800), raw("cwd-", 0xfffd)];
        let repos = [raw("İrepo-", 0xdc80), raw("İrepo-", 0xfffd)];
        let scopes = [raw("scope-", 0xdfff), raw("scope-", 0xfffd)];
        let replacement_output = raw("out-", 0xfffd);
        let mut sentinels = Vec::new();
        for (ci, cwd) in cwds.iter().enumerate() {
            for (ri, repo) in repos.iter().enumerate() {
                let directory = root.join(cwd).join(repo);
                fs::create_dir_all(&directory)?;
                fs::write(
                    directory.join("SECURITY.md"),
                    if ci == 0 && ri == 0 {
                        "root raw\n"
                    } else {
                        "replacement policy\n"
                    },
                )?;
                let sentinel = directory.join(&replacement_output);
                fs::write(&sentinel, "output sentinel")?;
                sentinels.push(sentinel);
                for (si, scope) in scopes.iter().enumerate() {
                    fs::create_dir(directory.join(scope))?;
                    fs::write(
                        directory.join(scope).join("SECURITY.md"),
                        if ci == 0 && ri == 0 && si == 0 {
                            "scope raw\n"
                        } else {
                            "replacement policy\n"
                        },
                    )?;
                }
            }
        }
        let repo = root.join(&cwds[0]).join(&repos[0]);
        let output_name = raw("out-", 0xdfff);
        let output = repo.join(&output_name);
        let invoke = |args: &[PathBuf]| {
            Command::new(&node)
                .arg(&script)
                .args(["--helper", "resolve-security-md"])
                .args(args)
                .current_dir(&repo)
                .env("USERPROFILE", &repo)
                .output()
        };
        for (repo_arg, scope_arg, output_arg) in [
            (repo.clone(), PathBuf::from(&scopes[0]), output.clone()),
            (
                PathBuf::from("~"),
                PathBuf::from("~").join(&scopes[0]),
                PathBuf::from(&output_name),
            ),
            (
                PathBuf::from("."),
                PathBuf::from(&scopes[0]),
                PathBuf::from(&output_name),
            ),
        ] {
            let child = invoke(&[
                "--repo".into(),
                repo_arg,
                "--scope".into(),
                scope_arg,
                "--out".into(),
                output_arg,
            ])?;
            if !child.status.success() || !child.stdout.is_empty() || !child.stderr.is_empty() {
                return Err(io::Error::other(format!(
                    "Windows policy helper execution failed ({}): {}",
                    child.status,
                    String::from_utf8_lossy(&child.stderr),
                )));
            }
            let expected = concat!(
                "## SECURITY.md source: \"SECURITY.md\"\r\n\r\nroot raw\r\n\r\n",
                "## SECURITY.md source: \"scope-\\udfff/SECURITY.md\"\r\n\r\nscope raw\r\n",
            );
            if fs::read(&output)? != expected.as_bytes() {
                return Err(io::Error::other(
                    "Windows policy helper selected the wrong path",
                ));
            }
            fs::remove_file(&output)?;
        }
        let listing = invoke(&["--repo".into(), "~".into(), "--list".into()])?;
        let expected =
            b"[\"SECURITY.md\", \"scope-\\udfff/SECURITY.md\", \"scope-\\ufffd/SECURITY.md\"]\n";
        if !listing.status.success() || !listing.stderr.is_empty() || listing.stdout != expected {
            return Err(io::Error::other(
                "Windows policy helper lost directory names",
            ));
        }
        for sentinel in sentinels {
            if fs::read(sentinel)? != b"output sentinel" {
                return Err(io::Error::other(
                    "Windows policy helper changed a replacement output",
                ));
            }
        }
        let identity_root = root.join("İroot");
        let sibling = root.join("i\u{307}root");
        fs::create_dir(&identity_root)?;
        fs::create_dir(&sibling)?;
        let sibling_policy = sibling.join("SECURITY.md");
        fs::write(&sibling_policy, "sibling policy\n")?;
        for scope in [&sibling, &identity_root] {
            if scope == &identity_root {
                std::os::windows::fs::symlink_file(
                    &sibling_policy,
                    identity_root.join("SECURITY.md"),
                )?;
            }
            let result = invoke(&[
                "--repo".into(),
                identity_root.clone(),
                "--scope".into(),
                scope.clone(),
                "--out".into(),
                "-".into(),
            ])?;
            if result.status.code() != Some(2)
                || !result.stdout.is_empty()
                || !String::from_utf8_lossy(&result.stderr).contains("outside the scan root")
            {
                return Err(io::Error::other(
                    "Windows policy helper did not preserve directory identity",
                ));
            }
        }
        let input_name = raw("input-", 0xd800);
        let scope_name = raw("scope-files-", 0xdc80);
        fs::write(repo.join("source.py"), "source line\n")?;
        fs::write(repo.join(&scope_name), "source.py\ndeleted.py\n")?;
        fs::write(repo.join(raw("scope-files-", 0xfffd)), "wrong.py\n")?;
        fs::write(
            repo.join(raw("input-", 0xfffd)),
            "invalid replacement input",
        )?;
        fs::write(
            repo.join(&input_name),
            concat!(
                "{\"cwe_ids\":[\"CWE-89\"],\"locations\":[{\"path\":\"source.py\",",
                "\"start_line\":1,\"role\":\"entrypoint\"}],\"summary\":\"wide paths\",",
                "\"evidence\":\"source evidence\"}\n",
            ),
        )?;
        let output_link = "i\u{0307}.jsonl";
        std::os::windows::fs::symlink_file(&output_name, repo.join(output_link))?;
        std::os::windows::fs::symlink_file(output_link, repo.join("İ.jsonl"))?;
        let expected = concat!(
            "{\"candidate_id\":\"candidate-a69fa65a28ed4e55\",\"cwe_ids\":[\"CWE-89\"],",
            "\"evidence\":\"source evidence\",\"locations\":[{\"end_line\":1,",
            "\"path\":\"source.py\",\"role\":\"entrypoint\",\"start_line\":1}],",
            "\"summary\":\"wide paths\"}\r\n",
        );
        let candidate = |repo_arg: &Path, input: &Path, scope: &Path, output: &Path| {
            Command::new(&node)
                .arg(&script)
                .args(["--helper", "normalize-candidates", "--repo-root"])
                .arg(repo_arg)
                .arg("--input")
                .arg(input)
                .arg("--in-scope-files")
                .arg(scope)
                .arg("--out")
                .arg(output)
                .arg("--allow-missing-in-scope")
                .current_dir(&repo)
                .env("USERPROFILE", &repo)
                .output()
        };
        for (index, prefix) in [repo.clone(), PathBuf::from("~"), PathBuf::from(".")]
            .into_iter()
            .enumerate()
        {
            if index == 0 {
                fs::write(&output, "previous output")?;
            }
            let child = candidate(
                &prefix,
                &prefix.join(&input_name),
                &prefix.join(&scope_name),
                &prefix.join(if index == 0 {
                    output_name.clone()
                } else {
                    OsString::from("İ.jsonl")
                }),
            )?;
            if !child.status.success()
                || !child.stderr.is_empty()
                || fs::read(&output)? != expected.as_bytes()
            {
                return Err(io::Error::other(format!(
                    "Wide candidate helper failed: {}",
                    String::from_utf8_lossy(&child.stderr)
                )));
            }
            fs::remove_file(&output)?;
        }
        fs::create_dir(repo.join("blocked-output"))?;
        let child = candidate(
            Path::new("."),
            Path::new(&input_name),
            Path::new(&scope_name),
            Path::new("blocked-output"),
        )?;
        if child.status.code() != Some(2) || !repo.join("blocked-output").is_dir() {
            return Err(io::Error::other(
                "Candidate replacement failure was not preserved",
            ));
        }
        for entry in fs::read_dir(&repo)? {
            if entry?
                .file_name()
                .to_string_lossy()
                .starts_with(".blocked-output.")
            {
                return Err(io::Error::other(
                    "Candidate temporary output was not removed",
                ));
            }
        }
        for cwd in &cwds {
            for repository in &repos {
                if fs::read(root.join(cwd).join(repository).join(&replacement_output))?
                    != b"output sentinel"
                {
                    return Err(io::Error::other(
                        "Candidate helper changed a replacement output",
                    ));
                }
            }
        }
        let assessment_name = raw("assessment-", 0xd800);
        let assessment_path = repo.join(&assessment_name);
        let replacement_assessment = repo.join(raw("assessment-", 0xfffd));
        let assessment = r#"{
            "schemaVersion":1,
            "patch":{"repository":"example/project","sourceType":"patch_file","base":"base","head":"head","changedFiles":["src/example.ts"],"sha256":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"},
            "recommendation":"no_op","workflowLabel":"no_op",
            "impact":{"rating":"low","rationale":"No active path changes."},
            "regressionLikelihood":{"rating":"low","rationale":"No live effect."},
            "regressionProtection":{"rating":"strong","rationale":"Fixture validated.","exactHeadChecksPassed":true},
            "recoverability":{"rating":"easy","rationale":"Local change."},
            "confidence":{"rating":"high","rationale":"Known fixture."},
            "applicability":{"status":"no_live_effect","rationale":"Synthetic input."},
            "statusQuoRisk":{"rating":"low","rationale":"No live effect."},
            "autoMergeExclusions":[],"affectedRuntimeRoots":[],"materialBoundaries":[],
            "validation":[{"name":"fixture","status":"passed","protects":"Validator input."}],
            "unknowns":[],"evidencePlan":[]
        }"#;
        fs::write(&assessment_path, assessment)?;
        fs::write(&replacement_assessment, "replacement assessment sentinel")?;
        for input in [assessment_path.clone(), PathBuf::from(&assessment_name)] {
            let child = Command::new(&node)
                .arg(&script)
                .args(["--helper", "validate-patch-risk-assessment"])
                .arg(input)
                .current_dir(&repo)
                .output()?;
            if !child.status.success() || !child.stdout.is_empty() || !child.stderr.is_empty() {
                return Err(io::Error::other(format!(
                    "Wide assessment helper failed: {}",
                    String::from_utf8_lossy(&child.stderr)
                )));
            }
        }
        if fs::read(&assessment_path)? != assessment.as_bytes()
            || fs::read(&replacement_assessment)? != b"replacement assessment sentinel"
        {
            return Err(io::Error::other("Assessment validation changed its input"));
        }
        let worklist_dir = raw("worklist-", 0xdc80);
        let worklist_output = repo.join(&worklist_dir).join(&output_name);
        let worklist_sentinel = repo
            .join(raw("worklist-", 0xfffd))
            .join(&replacement_output);
        fs::create_dir_all(worklist_sentinel.parent().unwrap())?;
        fs::write(&worklist_sentinel, "worklist output sentinel")?;
        for (command, input_flag, row) in [
            (
                "copy-deep-review-input",
                "--rank-input",
                "{\"path\":\"source.py\",\"area\":\"src\",\"preview\":\"source line\"}\n",
            ),
            (
                "select-deep-review-input",
                "--rank-output",
                "{\"path\":\"source.py\",\"area\":\"src\",\"score\":5,\"include\":true,\"reason\":\"source line\"}\n",
            ),
        ] {
            fs::write(repo.join(&input_name), row)?;
            for prefix in [repo.clone(), PathBuf::from("~"), PathBuf::from(".")] {
                let child = Command::new(&node)
                    .arg(&script)
                    .args(["--helper", command, input_flag])
                    .arg(prefix.join(&input_name))
                    .arg("--out")
                    .arg(prefix.join(&worklist_dir).join(&output_name))
                    .current_dir(&repo)
                    .env("USERPROFILE", &repo)
                    .output()?;
                if !child.status.success()
                    || !child.stderr.is_empty()
                    || fs::read(&worklist_output)? != b"{\"path\":\"source.py\",\"area\":\"src\"}\r\n"
                {
                    return Err(io::Error::other(format!(
                        "Wide deep-review helper failed: {}",
                        String::from_utf8_lossy(&child.stderr)
                    )));
                }
                fs::remove_file(&worklist_output)?;
            }
        }
        if fs::read(&worklist_sentinel)? != b"worklist output sentinel"
            || fs::read(repo.join(raw("input-", 0xfffd)))? != b"invalid replacement input"
        {
            return Err(io::Error::other(
                "Deep-review helper changed a replacement path",
            ));
        }
        println!("{{\"policyHelperRawPaths\":true,\"candidateHelperRawPaths\":true,\"assessmentHelperRawPaths\":true,\"deepReviewHelperRawPaths\":true,\"directoryIdentity\":true}}");
        Ok(())
    }

    let mut args = env::args_os().skip(1);
    let node = args.next().expect("Node executable path");
    let script = args.next().expect("Windows wide proof script");
    let root = PathBuf::from(args.next().expect("Proof fixture directory")).join("wide-İprocess");
    fs::create_dir(&root)?;
    let result = if args.next().is_some_and(|argument| argument == "policy") {
        policy_proof(node, script, &root)
    } else {
        run(node, script, &root)
    };
    let cleanup = fs::remove_dir_all(&root);
    result?;
    cleanup
}

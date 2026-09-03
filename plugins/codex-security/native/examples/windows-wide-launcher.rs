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
        let repos = [raw("repo-", 0xdc80), raw("repo-", 0xfffd)];
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
        println!("{{\"policyHelperRawPaths\":true}}");
        Ok(())
    }

    let mut args = env::args_os().skip(1);
    let node = args.next().expect("Node executable path");
    let script = args.next().expect("Windows wide proof script");
    let root = PathBuf::from(args.next().expect("Proof fixture directory")).join("wide-process");
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

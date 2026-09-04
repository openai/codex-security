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
        fs::write(
            replacement.join("high-\u{fffd}"),
            "core replacement sentinel",
        )?;
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

    let mut args = env::args_os().skip(1);
    let node = args.next().expect("Node executable path");
    let script = args.next().expect("Windows wide proof script");
    let root = PathBuf::from(args.next().expect("Proof fixture directory")).join("wide-process");
    fs::create_dir(&root)?;
    let result = run(node, script, &root);
    let cleanup = fs::remove_dir_all(&root);
    result?;
    cleanup
}

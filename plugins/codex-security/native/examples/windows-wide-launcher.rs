// Test-only launcher: Node's Windows startup has already replaced lone surrogates.
#[cfg(not(windows))]
fn main() {}

#[cfg(windows)]
fn main() -> std::io::Result<()> {
    use std::{
        env,
        ffi::OsString,
        fs, io,
        mem::size_of,
        os::windows::ffi::{OsStrExt, OsStringExt},
        path::{Path, PathBuf},
        process::Command,
        ptr::null_mut,
    };
    use windows_sys::Win32::Security::*;

    fn raw(prefix: &str, unit: u16) -> OsString {
        OsString::from_wide(&prefix.encode_utf16().chain([unit]).collect::<Vec<_>>())
    }

    fn deny_file_access(path: &Path, operation: impl FnOnce() -> io::Result<()>) -> io::Result<()> {
        let path = path
            .as_os_str()
            .encode_wide()
            .chain([0])
            .collect::<Vec<_>>();
        let mut length = 0;
        unsafe {
            GetFileSecurityW(
                path.as_ptr(),
                DACL_SECURITY_INFORMATION,
                null_mut(),
                0,
                &mut length,
            )
        };
        if length == 0 {
            return Err(io::Error::last_os_error());
        }
        let mut saved = vec![0_usize; (length as usize).div_ceil(size_of::<usize>())];
        let mut control = 0;
        let mut revision = 0;
        if unsafe {
            GetFileSecurityW(
                path.as_ptr(),
                DACL_SECURITY_INFORMATION,
                saved.as_mut_ptr().cast(),
                length,
                &mut length,
            ) == 0
                || GetSecurityDescriptorControl(
                    saved.as_mut_ptr().cast(),
                    &mut control,
                    &mut revision,
                ) == 0
        } {
            return Err(io::Error::last_os_error());
        }
        let mut acl = ACL::default();
        let mut descriptor = SECURITY_DESCRIPTOR::default();
        let descriptor = (&mut descriptor as *mut SECURITY_DESCRIPTOR).cast();
        if unsafe {
            InitializeAcl(&mut acl, size_of::<ACL>() as u32, ACL_REVISION) == 0
                || InitializeSecurityDescriptor(descriptor, 1) == 0
                || SetSecurityDescriptorDacl(descriptor, 1, &acl, 0) == 0
                || SetFileSecurityW(
                    path.as_ptr(),
                    DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                    descriptor,
                ) == 0
        } {
            return Err(io::Error::last_os_error());
        }
        let result = operation();
        let protection = if control & SE_DACL_PROTECTED != 0 {
            PROTECTED_DACL_SECURITY_INFORMATION
        } else {
            UNPROTECTED_DACL_SECURITY_INFORMATION
        };
        // Restore the owned fixture's original DACL even if the child proof fails.
        if unsafe {
            SetFileSecurityW(
                path.as_ptr(),
                DACL_SECURITY_INFORMATION | protection,
                saved.as_mut_ptr().cast(),
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        result
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
        let denied = cwd.join(raw("denied-", 0xdfff));
        fs::write(&denied, "directory enumeration does not open this file")?;
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
        deny_file_access(&denied, || {
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
            Ok(())
        })?;
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

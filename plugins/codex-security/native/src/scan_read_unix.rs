use napi::bindgen_prelude::Buffer;
use std::{
    ffi::{CString, OsStr},
    fs::{self, File, Metadata},
    io::{self, Read},
    mem::MaybeUninit,
    os::{
        fd::{AsRawFd, FromRawFd, RawFd},
        unix::{ffi::OsStrExt, fs::MetadataExt},
    },
    path::PathBuf,
};

// These descriptors anchor named lookups and metadata checks without listing the directory.
#[cfg(target_os = "linux")]
const DIRECTORY_ACCESS: i32 = libc::O_PATH;
#[cfg(not(target_os = "linux"))]
const DIRECTORY_ACCESS: i32 = libc::O_RDONLY;

pub(crate) struct ScanReadRootBackend {
    path: PathBuf,
    directory: Option<File>,
}

pub(crate) struct ScanReadFileBackend {
    file: File,
}

fn failure(context: &str, error: impl std::fmt::Display) -> napi::Error {
    napi::Error::from_reason(format!("{context}: {error}"))
}

fn same_file(left: &Metadata, right: &Metadata) -> bool {
    left.dev() == right.dev() && left.ino() == right.ino()
}

fn open_at(parent: RawFd, path: &OsStr, flags: i32) -> io::Result<File> {
    let path = CString::new(path.as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "Path contains a NUL byte"))?;
    let descriptor = unsafe { libc::openat(parent, path.as_ptr(), flags | libc::O_CLOEXEC) };
    if descriptor < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { File::from_raw_fd(descriptor) })
}

// Retry a deep lookup from the held root when keeping every ancestor open exhausted
// the process descriptor limit. openat2 enforces the boundary and rejects symlinks
// throughout the parent path in a single kernel lookup.
#[cfg(target_os = "linux")]
fn open_beneath_root(root: &File, relative_path: &str) -> Result<File, OpenError> {
    let (parent_path, name) = relative_path
        .rsplit_once('/')
        .unwrap_or((".", relative_path));
    let parent_path = CString::new(parent_path).map_err(|error| OpenError::Parent(error.into()))?;
    // The kernel requires unused and future open_how fields to be zero.
    let mut how: libc::open_how = unsafe { std::mem::zeroed() };
    how.flags = (libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC) as u64;
    how.resolve = libc::RESOLVE_BENEATH | libc::RESOLVE_NO_SYMLINKS;
    let open_parent = || -> io::Result<File> {
        let descriptor = unsafe {
            libc::syscall(
                libc::SYS_openat2,
                root.as_raw_fd(),
                parent_path.as_ptr(),
                &how,
                std::mem::size_of_val(&how),
            )
        };
        if descriptor < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(unsafe { File::from_raw_fd(descriptor as RawFd) })
    };

    let parent = open_parent().map_err(OpenError::Parent)?;
    let file = open_at(
        parent.as_raw_fd(),
        OsStr::new(name),
        libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK,
    )
    .map_err(OpenError::Leaf)?;
    let verify = || {
        if !same_file(&parent.metadata()?, &open_parent()?.metadata()?) {
            return Err(io::Error::other("Scan path changed while opening the file"));
        }
        verify_components(&parent, &[name], &[], &file)
    };
    verify().map_err(OpenError::Verify)?;
    Ok(file)
}

// Check the names against their held descriptors before returning the opened file.
fn verify_components(
    root: &File,
    parts: &[&str],
    directories: &[File],
    file: &File,
) -> io::Result<()> {
    let mut parent = root;
    for (part, held) in parts.iter().zip(directories.iter().chain([file])) {
        let name = CString::new(*part)?;
        let mut named = MaybeUninit::uninit();
        let status = unsafe {
            libc::fstatat(
                parent.as_raw_fd(),
                name.as_ptr(),
                named.as_mut_ptr(),
                libc::AT_SYMLINK_NOFOLLOW,
            )
        };
        if status != 0 {
            return Err(io::Error::last_os_error());
        }
        let named = unsafe { named.assume_init() };
        let held_metadata = held.metadata()?;
        // dev_t and ino_t vary between Unix targets.
        #[allow(clippy::unnecessary_cast)]
        if named.st_dev as u64 != held_metadata.dev() || named.st_ino as u64 != held_metadata.ino()
        {
            return Err(io::Error::other("Scan path changed while opening the file"));
        }
        parent = held;
    }
    Ok(())
}

#[derive(Debug)]
enum OpenError {
    Parent(io::Error),
    Leaf(io::Error),
    Verify(io::Error),
}

fn open_by_components(root: &File, parts: &[&str]) -> Result<File, OpenError> {
    let mut directories = Vec::new();
    let mut parent = root.as_raw_fd();
    for part in &parts[..parts.len() - 1] {
        let directory = open_at(
            parent,
            OsStr::new(part),
            DIRECTORY_ACCESS | libc::O_DIRECTORY | libc::O_NOFOLLOW,
        )
        .map_err(OpenError::Parent)?;
        parent = directory.as_raw_fd();
        directories.push(directory);
    }
    let file = open_at(
        parent,
        OsStr::new(parts[parts.len() - 1]),
        libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK,
    )
    .map_err(OpenError::Leaf)?;
    verify_components(root, parts, &directories, &file).map_err(OpenError::Verify)?;
    Ok(file)
}

fn open_relative_file(root: &File, parts: &[&str]) -> Result<File, OpenError> {
    let result = open_by_components(root, parts);
    #[cfg(target_os = "linux")]
    if matches!(
        &result,
        Err(OpenError::Parent(error) | OpenError::Leaf(error))
            if error.raw_os_error() == Some(libc::EMFILE)
    ) {
        // The unsuccessful walk has released its descriptors. Preserve its error
        // when the kernel or sandbox cannot perform the bounded lookup.
        let retry = open_beneath_root(root, &parts.join("/"));
        if !matches!(
            &retry,
            Err(OpenError::Parent(error))
                if matches!(error.raw_os_error(), Some(libc::ENOSYS | libc::EPERM | libc::ENAMETOOLONG))
        ) {
            return retry;
        }
    }
    result
}

impl ScanReadRootBackend {
    pub(crate) fn open(path: Buffer) -> napi::Result<Self> {
        let path = PathBuf::from(OsStr::from_bytes(path.as_ref()));
        let observed = fs::symlink_metadata(&path)
            .map_err(|error| failure("Cannot inspect scan directory", error))?;
        if !observed.is_dir() || !path.is_absolute() {
            return Err(napi::Error::from_reason(
                "Scan directory must be an existing non-symlink absolute directory",
            ));
        }
        let canonical = fs::canonicalize(&path)
            .map_err(|error| failure("Cannot resolve scan directory", error))?;
        if canonical != path {
            return Err(napi::Error::from_reason(
                "Scan directory must be a canonical non-symlink directory",
            ));
        }
        let directory = open_at(
            libc::AT_FDCWD,
            path.as_os_str(),
            DIRECTORY_ACCESS | libc::O_DIRECTORY | libc::O_NOFOLLOW,
        )
        .map_err(|error| failure("Cannot open scan directory", error))?;
        let opened = directory
            .metadata()
            .map_err(|error| failure("Cannot inspect opened scan directory", error))?;
        if !same_file(&observed, &opened) {
            return Err(napi::Error::from_reason(
                "Scan directory changed while opening",
            ));
        }
        let root = Self {
            path,
            directory: Some(directory),
        };
        root.verify()?;
        Ok(root)
    }

    pub(crate) fn open_file(
        &self,
        env: napi::Env,
        relative_path: &str,
    ) -> napi::Result<Option<ScanReadFileBackend>> {
        self.verify()?;
        let parts = relative_path.split('/').collect::<Vec<_>>();
        if parts.is_empty()
            || parts
                .iter()
                .any(|part| part.is_empty() || matches!(*part, "." | ".."))
            || relative_path.contains(['\\', '\0'])
        {
            return Err(napi::Error::from_reason(
                "Expected a safe scan-relative POSIX path",
            ));
        }
        let root = self
            .directory
            .as_ref()
            .ok_or_else(|| napi::Error::from_reason("Scan directory is closed"))?;
        let file = match open_relative_file(root, &parts) {
            Ok(file) => file,
            Err(OpenError::Parent(error) | OpenError::Leaf(error))
                if error.kind() == io::ErrorKind::NotFound =>
            {
                return Ok(None)
            }
            Err(OpenError::Parent(error)) => {
                return Err(failure("Cannot open scan file parent", error))
            }
            Err(OpenError::Leaf(error)) if error.raw_os_error() == Some(libc::EACCES) => {
                return Err(crate::scan_read::access_denied(env, error));
            }
            Err(OpenError::Leaf(error)) => return Err(failure("Cannot open scan file", error)),
            Err(OpenError::Verify(error)) => {
                return Err(failure("Cannot verify opened scan file", error))
            }
        };
        if !file
            .metadata()
            .map_err(|error| failure("Cannot inspect scan file", error))?
            .is_file()
        {
            return Err(napi::Error::from_reason(
                "Expected a regular non-symlink scan file",
            ));
        }
        self.verify()?;
        Ok(Some(ScanReadFileBackend { file }))
    }

    pub(crate) fn verify(&self) -> napi::Result<()> {
        let directory = self
            .directory
            .as_ref()
            .ok_or_else(|| napi::Error::from_reason("Scan directory is closed"))?;
        let current = fs::symlink_metadata(&self.path)
            .map_err(|error| failure("Scan directory changed while reading", error))?;
        let held = directory
            .metadata()
            .map_err(|error| failure("Cannot inspect held scan directory", error))?;
        let canonical = fs::canonicalize(&self.path)
            .map_err(|error| failure("Scan directory changed while reading", error))?;
        if !current.is_dir() || !same_file(&current, &held) || canonical != self.path {
            return Err(napi::Error::from_reason(
                "Scan directory changed while reading",
            ));
        }
        Ok(())
    }

    pub(crate) fn close(&mut self) {
        self.directory = None;
    }
}

impl ScanReadFileBackend {
    pub(crate) fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        self.file.read(buffer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "linux")]
    #[test]
    fn reads_deep_artifacts_with_a_low_descriptor_limit() -> io::Result<()> {
        use std::{os::unix::process::CommandExt, process::Command};

        const CHILD_ROOT: &str = "CODEX_SECURITY_TEST_FD_LIMIT_ROOT";
        let mut parts = vec!["tier"; 48];
        parts.push("receipt");
        if let Some(path) = std::env::var_os(CHILD_ROOT) {
            let root = File::open(path)?;
            assert!(matches!(
                open_by_components(&root, &parts),
                Err(OpenError::Parent(error) | OpenError::Leaf(error))
                    if error.raw_os_error() == Some(libc::EMFILE)
            ));
            let mut file = open_relative_file(&root, &parts).unwrap();
            let mut value = String::new();
            file.read_to_string(&mut value)?;
            assert_eq!(value, "sealed");
            *parts.last_mut().unwrap() = "missing";
            assert!(matches!(
                open_relative_file(&root, &parts),
                Err(OpenError::Leaf(error)) if error.kind() == io::ErrorKind::NotFound
            ));
            parts.pop();
            parts.extend(["link", "receipt"]);
            assert!(open_relative_file(&root, &parts).is_err());
            return Ok(());
        }

        let fixture =
            std::env::temp_dir().join(format!("codex-security-fd-limit-{}", std::process::id()));
        fs::create_dir(&fixture)?;
        let result = (|| {
            let scan = fixture.join("scan");
            let path = scan.join(parts.join("/"));
            let parent = path.parent().unwrap();
            fs::create_dir_all(parent)?;
            fs::write(&path, "sealed")?;
            fs::write(fixture.join("receipt"), "outside")?;
            std::os::unix::fs::symlink(&fixture, parent.join("link"))?;
            let root = File::open(&scan)?;
            // Older kernels and sandboxes can disable openat2 entirely.
            match open_beneath_root(&root, &parts.join("/")) {
                Err(OpenError::Parent(error))
                    if matches!(error.raw_os_error(), Some(libc::ENOSYS | libc::EPERM)) =>
                {
                    return Ok(())
                }
                other => drop(other.unwrap()),
            }
            let mut child = Command::new(std::env::current_exe()?);
            child.args([
                "--exact",
                "scan_read_unix::tests::reads_deep_artifacts_with_a_low_descriptor_limit",
            ]);
            child.env(CHILD_ROOT, scan);
            // Only the isolated test child receives the lower process limit.
            unsafe {
                child.pre_exec(|| {
                    let limit = libc::rlimit {
                        rlim_cur: 32,
                        rlim_max: 32,
                    };
                    if libc::setrlimit(libc::RLIMIT_NOFILE, &limit) != 0 {
                        return Err(io::Error::last_os_error());
                    }
                    Ok(())
                });
            }
            let output = child.output()?;
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stdout)
            );
            Ok(())
        })();
        fs::remove_dir_all(fixture)?;
        result
    }

    #[test]
    fn verifies_every_opened_component_including_the_leaf() -> io::Result<()> {
        let scan =
            std::env::temp_dir().join(format!("scan-read-components-{}", std::process::id()));
        fs::create_dir(&scan)?;
        let artifacts = scan.join("artifacts");
        let moved = scan.join("moved");
        fs::create_dir(&artifacts)?;
        fs::write(artifacts.join("receipt"), "original")?;
        let root = File::open(&scan)?;
        let directories = [File::open(&artifacts)?];
        let file = File::open(artifacts.join("receipt"))?;
        let verify = || verify_components(&root, &["artifacts", "receipt"], &directories, &file);
        verify()?;

        fs::rename(&artifacts, &moved)?;
        fs::create_dir(&artifacts)?;
        fs::hard_link(moved.join("receipt"), artifacts.join("receipt"))?;
        assert!(verify().is_err());

        fs::remove_dir_all(&artifacts)?;
        fs::rename(&moved, &artifacts)?;
        fs::rename(artifacts.join("receipt"), artifacts.join("original"))?;
        fs::write(artifacts.join("receipt"), "replacement")?;
        assert!(verify().is_err());

        fs::remove_dir_all(scan)
    }
}

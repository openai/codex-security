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
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW,
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
        let mut directories = Vec::new();
        let mut parent = root.as_raw_fd();
        for part in &parts[..parts.len() - 1] {
            let directory = match open_at(
                parent,
                OsStr::new(part),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW,
            ) {
                Ok(directory) => directory,
                Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
                Err(error) => return Err(failure("Cannot open scan file parent", error)),
            };
            parent = directory.as_raw_fd();
            directories.push(directory);
        }
        let file = match open_at(
            parent,
            OsStr::new(parts[parts.len() - 1]),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK,
        ) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) if error.raw_os_error() == Some(libc::EACCES) => {
                return Err(crate::scan_read::access_denied(env, error))
            }
            Err(error) => return Err(failure("Cannot open scan file", error)),
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
        verify_components(root, &parts, &directories, &file)
            .map_err(|error| failure("Cannot verify opened scan file", error))?;
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

use napi::bindgen_prelude::Buffer;
use std::{
    ffi::{CString, OsStr},
    fs::{self, File, Metadata},
    io::{self, Read},
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
        let mut directory = self
            .directory
            .as_ref()
            .ok_or_else(|| napi::Error::from_reason("Scan directory is closed"))?
            .try_clone()
            .map_err(|error| failure("Cannot hold scan directory", error))?;
        for part in &parts[..parts.len() - 1] {
            directory = match open_at(
                directory.as_raw_fd(),
                OsStr::new(part),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW,
            ) {
                Ok(directory) => directory,
                Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
                Err(error) => return Err(failure("Cannot open scan file parent", error)),
            };
        }
        let file = match open_at(
            directory.as_raw_fd(),
            OsStr::new(parts[parts.len() - 1]),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK,
        ) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
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

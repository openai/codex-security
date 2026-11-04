use napi::bindgen_prelude::Buffer;
use std::{
    ffi::OsString,
    fs::File,
    io::{self, Read},
    mem::size_of,
    os::windows::{
        ffi::{OsStrExt, OsStringExt},
        io::{AsRawHandle, FromRawHandle},
    },
    path::{Path, PathBuf},
    ptr::{null, null_mut},
    sync::Arc,
};
use windows_sys::Win32::{
    Foundation::{ERROR_FILE_NOT_FOUND, ERROR_PATH_NOT_FOUND, INVALID_HANDLE_VALUE},
    Globalization::{CompareStringOrdinal, CSTR_EQUAL},
    Storage::FileSystem::{
        CreateFileW, FileBasicInfo, GetFileInformationByHandleEx, GetFileType,
        GetFinalPathNameByHandleW, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT,
        FILE_BASIC_INFO, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
        FILE_GENERIC_READ, FILE_READ_ATTRIBUTES, FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_TRAVERSE,
        FILE_TYPE_DISK, OPEN_EXISTING,
    },
};

struct HeldDirectory {
    file: File,
    path: PathBuf,
}

impl HeldDirectory {
    fn verify(&self) -> io::Result<()> {
        verify_directory(&self.file, &self.path)
    }
}

struct RootHandles {
    path: PathBuf,
    directories: Vec<HeldDirectory>,
}

impl RootHandles {
    fn verify(&self) -> io::Result<()> {
        for directory in &self.directories {
            directory.verify()?;
        }
        Ok(())
    }
}

pub(crate) struct ScanReadRootBackend {
    root: Option<Arc<RootHandles>>,
}

pub(crate) struct ScanReadFileBackend {
    file: File,
    // A file remains anchored even if its caller closes the root first.
    _root: Arc<RootHandles>,
    _directories: Vec<File>,
}

impl ScanReadRootBackend {
    pub(crate) fn open(path: Buffer) -> napi::Result<Self> {
        let path = decode_path(path)?;
        let path = std::path::absolute(path).map_err(native_error)?;
        let mut directories = Vec::new();
        // Fix each ancestor in place before opening a child through its path.
        for ancestor in path.ancestors().collect::<Vec<_>>().into_iter().rev() {
            let file = open_file(ancestor, true)
                .map_err(native_error)?
                .ok_or_else(|| native_error(io::Error::from(io::ErrorKind::NotFound)))?;
            verify_directory(&file, ancestor).map_err(native_error)?;
            directories.push(HeldDirectory {
                file,
                path: ancestor.to_path_buf(),
            });
        }
        let root = Arc::new(RootHandles { path, directories });
        root.verify().map_err(native_error)?;
        Ok(Self { root: Some(root) })
    }

    pub(crate) fn open_file(
        &self,
        env: napi::Env,
        relative_path: &str,
    ) -> napi::Result<Option<ScanReadFileBackend>> {
        let root = self.root()?;
        let parts = relative_parts(relative_path)?;
        root.verify().map_err(native_error)?;
        let mut path = root.path.clone();
        let mut directories = Vec::new();
        for component in &parts[..parts.len() - 1] {
            path.push(component);
            let Some(file) = open_file(&path, true).map_err(native_error)? else {
                return Ok(None);
            };
            verify_directory(&file, &path).map_err(native_error)?;
            directories.push(file);
        }
        path.push(parts[parts.len() - 1]);
        let Some(file) = open_file(&path, false).map_err(|error| {
            if error.raw_os_error()
                == Some(windows_sys::Win32::Foundation::ERROR_ACCESS_DENIED as i32)
            {
                crate::scan_read::access_denied(env, error)
            } else {
                native_error(error)
            }
        })?
        else {
            return Ok(None);
        };
        verify_regular_file(&file, &path).map_err(native_error)?;
        Ok(Some(ScanReadFileBackend {
            file,
            _root: Arc::clone(root),
            _directories: directories,
        }))
    }

    pub(crate) fn verify(&self) -> napi::Result<()> {
        self.root()?.verify().map_err(native_error)
    }

    pub(crate) fn close(&mut self) {
        self.root.take();
    }

    fn root(&self) -> napi::Result<&Arc<RootHandles>> {
        self.root
            .as_ref()
            .ok_or_else(|| napi::Error::from_reason("Scan read root is closed"))
    }
}

impl ScanReadFileBackend {
    pub(crate) fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        self.file.read(buffer)
    }
}

fn native_error(error: io::Error) -> napi::Error {
    napi::Error::from_reason(error.to_string())
}

fn invalid_path(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

fn decode_path(bytes: Buffer) -> napi::Result<PathBuf> {
    if !bytes.len().is_multiple_of(2) {
        return Err(native_error(invalid_path(
            "Path must contain whole UTF-16LE code units",
        )));
    }
    let units = bytes
        .chunks_exact(2)
        .map(|part| u16::from_le_bytes([part[0], part[1]]))
        .collect::<Vec<_>>();
    if units.contains(&0) {
        return Err(native_error(invalid_path("Path contains a NUL code unit")));
    }
    Ok(PathBuf::from(OsString::from_wide(&units)))
}

fn relative_parts(value: &str) -> napi::Result<Vec<&str>> {
    let parts = value.split('/').collect::<Vec<_>>();
    for part in &parts {
        let device = part.split('.').next().unwrap_or_default().to_uppercase();
        let reserved = matches!(
            device.as_str(),
            "AUX" | "CON" | "CONIN$" | "CONOUT$" | "NUL" | "PRN"
        ) || ["COM", "LPT"].iter().any(|prefix| {
            device.strip_prefix(prefix).is_some_and(|suffix| {
                suffix.chars().count() == 1
                    && suffix
                        .chars()
                        .all(|ch| matches!(ch, '1'..='9' | '¹' | '²' | '³'))
            })
        });
        if part.is_empty()
            || matches!(*part, "." | "..")
            || part.ends_with([' ', '.'])
            || part
                .chars()
                .any(|ch| ch < ' ' || matches!(ch, '\\' | '<' | '>' | ':' | '"' | '|' | '?' | '*'))
            || reserved
        {
            return Err(native_error(invalid_path(
                "Expected a safe scan-relative POSIX path",
            )));
        }
    }
    Ok(parts)
}

fn extended_path(path: &Path) -> Vec<u16> {
    let units = path.as_os_str().encode_wide().collect::<Vec<_>>();
    let (prefix, tail) = if units.starts_with(&[92, 92, 63, 92]) {
        ("", units.as_slice())
    } else if units.starts_with(&[92, 92]) {
        (r"\\?\UNC\", &units[2..])
    } else {
        (r"\\?\", units.as_slice())
    };
    prefix
        .encode_utf16()
        .chain(tail.iter().copied())
        .chain([0])
        .collect()
}

fn open_file(path: &Path, directory: bool) -> io::Result<Option<File>> {
    let path = extended_path(path);
    let handle = unsafe {
        CreateFileW(
            path.as_ptr(),
            if directory {
                // Attribute-only handles do not participate in share-access checks.
                FILE_READ_ATTRIBUTES | FILE_TRAVERSE
            } else {
                FILE_GENERIC_READ
            },
            if directory {
                FILE_SHARE_READ | FILE_SHARE_WRITE
            } else {
                FILE_SHARE_READ
            },
            null(),
            OPEN_EXISTING,
            FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS,
            null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        let error = io::Error::last_os_error();
        return if matches!(
            error.raw_os_error().map(|code| code as u32),
            Some(ERROR_FILE_NOT_FOUND | ERROR_PATH_NOT_FOUND)
        ) {
            Ok(None)
        } else {
            Err(error)
        };
    }
    Ok(Some(unsafe { File::from_raw_handle(handle) }))
}

fn attributes(file: &File) -> io::Result<u32> {
    let mut info = FILE_BASIC_INFO::default();
    if unsafe {
        GetFileInformationByHandleEx(
            file.as_raw_handle(),
            FileBasicInfo,
            (&mut info as *mut FILE_BASIC_INFO).cast(),
            size_of::<FILE_BASIC_INFO>() as u32,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(info.FileAttributes)
}

fn verify_directory(file: &File, path: &Path) -> io::Result<()> {
    let attributes = attributes(file)?;
    if attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 || attributes & FILE_ATTRIBUTE_DIRECTORY == 0
    {
        return Err(invalid_path(
            "Expected a canonical non-reparse scan directory",
        ));
    }
    verify_path(file, path)
}

fn verify_regular_file(file: &File, path: &Path) -> io::Result<()> {
    let attributes = attributes(file)?;
    if attributes & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DIRECTORY) != 0
        || unsafe { GetFileType(file.as_raw_handle()) } != FILE_TYPE_DISK
    {
        return Err(invalid_path("Expected a regular non-reparse scan file"));
    }
    verify_path(file, path)
}

fn final_path(file: &File) -> io::Result<Vec<u16>> {
    let length = unsafe { GetFinalPathNameByHandleW(file.as_raw_handle(), null_mut(), 0, 0) };
    if length == 0 {
        return Err(io::Error::last_os_error());
    }
    let mut path = vec![0; length as usize + 1];
    let written = unsafe {
        GetFinalPathNameByHandleW(
            file.as_raw_handle(),
            path.as_mut_ptr(),
            path.len() as u32,
            0,
        )
    };
    if written == 0 {
        return Err(io::Error::last_os_error());
    }
    if written as usize >= path.len() {
        return Err(invalid_path("Scan path changed while reading"));
    }
    path.truncate(written as usize);
    Ok(path)
}

fn normalized_path(mut units: Vec<u16>) -> Vec<u16> {
    if units.starts_with(&[92, 92, 63, 92, 85, 78, 67, 92]) {
        units.splice(..8, [92, 92]);
    } else if units.starts_with(&[92, 92, 63, 92]) {
        units.drain(..4);
    }
    for unit in &mut units {
        if *unit == b'/' as u16 {
            *unit = b'\\' as u16;
        }
    }
    while units.last() == Some(&(b'\\' as u16)) {
        units.pop();
    }
    units
}

fn verify_path(file: &File, expected: &Path) -> io::Result<()> {
    let actual = normalized_path(final_path(file)?);
    let expected = normalized_path(expected.as_os_str().encode_wide().collect());
    let equal = unsafe {
        CompareStringOrdinal(
            actual.as_ptr(),
            actual.len() as i32,
            expected.as_ptr(),
            expected.len() as i32,
            1,
        )
    };
    if equal == 0 {
        return Err(io::Error::last_os_error());
    }
    if equal != CSTR_EQUAL {
        return Err(invalid_path(
            "Opened file resolved outside its verified scan path",
        ));
    }
    Ok(())
}

use napi::bindgen_prelude::{BigInt, Buffer};
use napi_derive::napi;
use std::{
    ffi::OsString,
    fs::{File, TryLockError},
    io::{self, Read, Seek, SeekFrom, Write},
    mem::{offset_of, size_of, MaybeUninit},
    os::windows::{
        ffi::{OsStrExt, OsStringExt},
        io::{AsRawHandle, FromRawHandle},
    },
    path::Path,
    ptr::{copy_nonoverlapping, null, null_mut},
};
use windows_sys::Win32::{
    Foundation::{
        GetLastError, SetLastError, ERROR_FILE_NOT_FOUND, ERROR_INVALID_HANDLE,
        ERROR_INVALID_PARAMETER, ERROR_LOCK_VIOLATION, ERROR_NO_MORE_FILES,
        ERROR_PATH_NOT_FOUND, HANDLE, INVALID_HANDLE_VALUE,
    },
    Storage::FileSystem::*,
};

fn invalid(message: &str) -> napi::Error {
    napi::Error::new(napi::Status::InvalidArg, message)
}

fn status(success: i32) -> u32 {
    if success == 0 {
        unsafe { GetLastError() }
    } else {
        0
    }
}

fn io_error(error: io::Error) -> u32 {
    error.raw_os_error().unwrap() as u32
}

fn io_status(result: io::Result<()>) -> u32 {
    result.map_or_else(io_error, |()| 0)
}

fn io_count(result: io::Result<usize>) -> WindowsResult {
    match result {
        Ok(value) => WindowsResult {
            error: 0,
            value: value as u32,
        },
        Err(error) => WindowsResult {
            error: io_error(error),
            value: 0,
        },
    }
}

fn wide_path(bytes: Buffer) -> napi::Result<Vec<u16>> {
    if !bytes.len().is_multiple_of(2) {
        return Err(invalid("Path must contain whole UTF-16LE code units"));
    }
    let mut path = bytes
        .chunks_exact(2)
        .map(|part| u16::from_le_bytes([part[0], part[1]]))
        .collect::<Vec<_>>();
    if path.contains(&0) {
        return Err(invalid("Path contains a NUL code unit"));
    }
    path.push(0);
    Ok(path)
}

fn wide_bytes(units: impl IntoIterator<Item = u16>) -> Buffer {
    units
        .into_iter()
        .flat_map(u16::to_le_bytes)
        .collect::<Vec<_>>()
        .into()
}

fn os_string(bytes: Buffer) -> napi::Result<OsString> {
    let path = wide_path(bytes)?;
    Ok(OsString::from_wide(&path[..path.len() - 1]))
}

#[napi(object)]
pub struct BufferResult {
    pub error: u32,
    pub value: Buffer,
}

#[napi(object)]
pub struct DirectoryResult {
    pub error: u32,
    pub value: Vec<Buffer>,
}

#[napi(object)]
pub struct DirectoryEntry {
    pub name: Buffer,
    pub is_directory: bool,
    pub is_symbolic_link: bool,
}

#[napi(object)]
pub struct DirectoryEntriesResult {
    pub error: u32,
    pub value: Vec<DirectoryEntry>,
}

#[napi]
pub fn windows_arguments() -> Vec<Buffer> {
    std::env::args_os()
        .map(|argument| wide_bytes(argument.encode_wide()))
        .collect()
}

#[napi]
pub fn windows_environment(name: Buffer) -> napi::Result<Option<Buffer>> {
    Ok(std::env::var_os(os_string(name)?).map(|value| wide_bytes(value.encode_wide())))
}

#[napi]
pub fn windows_absolute_path(path: Buffer) -> napi::Result<BufferResult> {
    let path = wide_path(path)?;
    let mut absolute = vec![0_u16; 256];
    loop {
        let capacity = u32::try_from(absolute.len())
            .map_err(|_| invalid("Absolute path exceeds the Win32 buffer size"))?;
        let length =
            unsafe { GetFullPathNameW(path.as_ptr(), capacity, absolute.as_mut_ptr(), null_mut()) };
        if length == 0 {
            return Ok(BufferResult {
                error: unsafe { GetLastError() },
                value: Vec::new().into(),
            });
        }
        if length < capacity {
            return Ok(BufferResult {
                error: 0,
                value: wide_bytes(absolute[..length as usize].iter().copied()),
            });
        }
        absolute.resize(length as usize + 1, 0);
    }
}

#[napi]
pub fn windows_directory_names(path: Buffer) -> napi::Result<DirectoryResult> {
    let result = windows_directory_entries(path)?;
    Ok(DirectoryResult {
        error: result.error,
        value: result.value.into_iter().map(|entry| entry.name).collect(),
    })
}

#[napi]
pub fn windows_directory_entries(path: Buffer) -> napi::Result<DirectoryEntriesResult> {
    let path = os_string(path)?;
    let failure = |error| DirectoryEntriesResult {
        error,
        value: Vec::new(),
    };
    if path.is_empty() {
        return Ok(failure(ERROR_PATH_NOT_FOUND));
    }
    let pattern = Path::new(&path).join("*");
    let pattern = directory_search_path(wide_bytes(pattern.as_os_str().encode_wide()))?;
    if pattern.error != 0 {
        return Ok(failure(pattern.error));
    }
    let pattern = wide_path(pattern.value)?;
    let mut data = WIN32_FIND_DATAW::default();
    let handle = unsafe { FindFirstFileW(pattern.as_ptr(), &mut data) };
    if handle == INVALID_HANDLE_VALUE {
        let error = unsafe { GetLastError() };
        // Like read_dir, a successful empty search is an empty iterator.
        return Ok(failure(if error == ERROR_FILE_NOT_FOUND {
            0
        } else {
            error
        }));
    }
    struct FindHandle(HANDLE);
    impl Drop for FindHandle {
        fn drop(&mut self) {
            unsafe { FindClose(self.0) };
        }
    }
    let handle = FindHandle(handle);
    let mut value = Vec::new();
    loop {
        let end = data.cFileName.iter().position(|unit| *unit == 0).unwrap();
        let name = &data.cFileName[..end];
        if name != [b'.' as u16] && name != [b'.' as u16, b'.' as u16] {
            value.push(DirectoryEntry {
                name: wide_bytes(name.iter().copied()),
                is_directory: data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0,
                is_symbolic_link: data.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
                    && data.dwReserved0 == 0xa000000c,
            });
        }
        if unsafe { FindNextFileW(handle.0, &mut data) } == 0 {
            let error = unsafe { GetLastError() };
            return Ok(if error == ERROR_NO_MORE_FILES {
                DirectoryEntriesResult { error: 0, value }
            } else {
                failure(error)
            });
        }
    }
}

fn directory_search_path(path: Buffer) -> napi::Result<BufferResult> {
    const SEP: u16 = b'\\' as u16;
    const ALT: u16 = b'/' as u16;
    const COLON: u16 = b':' as u16;
    const DOT: u16 = b'.' as u16;
    const QUERY: u16 = b'?' as u16;
    let units = wide_path(path.to_vec().into())?;
    let verbatim =
        units.starts_with(&[SEP, SEP, QUERY, SEP]) || units.starts_with(&[SEP, QUERY, QUERY, SEP]);
    let short_absolute = units.len() < 248
        && (matches!(units.as_slice(), [drive, COLON, SEP | ALT, ..] if ![SEP, ALT].contains(drive))
            || matches!(units.as_slice(), [SEP | ALT, SEP | ALT, ..]));
    if verbatim || short_absolute {
        return Ok(BufferResult {
            error: 0,
            value: path,
        });
    }
    // Match read_dir's conversion of relative and long search paths to verbatim paths.
    let absolute = windows_absolute_path(path)?;
    if absolute.error != 0 {
        return Ok(absolute);
    }
    let units = wide_path(absolute.value)?;
    let units = &units[..units.len() - 1];
    let (prefix, rest): (&[u16], &[u16]) = match units {
        [_, COLON, SEP, ..] => (&[SEP, SEP, QUERY, SEP], units),
        [SEP, SEP, DOT, SEP, rest @ ..] => (&[SEP, SEP, QUERY, SEP], rest),
        [SEP, SEP, QUERY, SEP, ..] | [SEP, QUERY, QUERY, SEP, ..] => (&[], units),
        [SEP, SEP, rest @ ..] => (
            &[
                SEP,
                SEP,
                QUERY,
                SEP,
                b'U' as u16,
                b'N' as u16,
                b'C' as u16,
                SEP,
            ],
            rest,
        ),
        _ => (&[], units),
    };
    Ok(BufferResult {
        error: 0,
        value: wide_bytes(prefix.iter().chain(rest).copied()),
    })
}

fn io_range(buffer: &Buffer, offset: f64, length: f64) -> napi::Result<(usize, u32)> {
    if !offset.is_finite()
        || !length.is_finite()
        || offset.fract() != 0.0
        || length.fract() != 0.0
        || offset < 0.0
        || length < 0.0
        || length > u32::MAX as f64
        || offset + length > buffer.len() as f64
    {
        return Err(invalid("I/O range must fit the buffer and a Win32 DWORD"));
    }
    Ok((offset as usize, length as u32))
}

#[napi]
pub struct WindowsHandle {
    file: Option<File>,
}

impl WindowsHandle {
    fn file(&self) -> io::Result<&File> {
        self.file
            .as_ref()
            .ok_or_else(|| io::Error::from_raw_os_error(ERROR_INVALID_HANDLE as i32))
    }

    fn raw(&self) -> HANDLE {
        self.file
            .as_ref()
            .map_or(INVALID_HANDLE_VALUE, AsRawHandle::as_raw_handle)
    }
}

#[napi(object, object_from_js = false)]
pub struct OpenResult {
    pub error: u32,
    pub handle: Option<WindowsHandle>,
}

#[napi(object)]
pub struct WindowsResult {
    pub error: u32,
    pub value: u32,
}

#[napi(object)]
pub struct AttributesResult {
    pub error: u32,
    pub attributes: u32,
    pub reparse_tag: u32,
}

#[napi(object)]
pub struct IdentityResult {
    pub error: u32,
    pub volume: String,
    pub file_id: Buffer,
}

#[napi(object)]
pub struct PositionResult {
    pub error: u32,
    pub value: String,
}

#[napi(object)]
pub struct PathResult {
    pub error: u32,
    pub path: Buffer,
}

#[napi]
pub fn open_windows_file(
    path: Buffer,
    access: u32,
    share: u32,
    disposition: u32,
    flags: u32,
) -> napi::Result<OpenResult> {
    // Pending overlapped I/O could retain pointers after these synchronous calls return.
    if flags & FILE_FLAG_OVERLAPPED != 0 {
        return Err(invalid("Overlapped handles are not supported"));
    }
    let path = wide_path(path)?;
    let handle = unsafe {
        CreateFileW(
            path.as_ptr(),
            access,
            share,
            null(),
            disposition,
            flags,
            null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Ok(OpenResult {
            error: unsafe { GetLastError() },
            handle: None,
        });
    }
    Ok(OpenResult {
        error: 0,
        handle: Some(WindowsHandle {
            file: Some(unsafe { File::from_raw_handle(handle) }),
        }),
    })
}

#[napi]
pub fn create_windows_directory(path: Buffer) -> napi::Result<u32> {
    let path = wide_path(path)?;
    Ok(status(unsafe { CreateDirectoryW(path.as_ptr(), null()) }))
}

#[napi]
impl WindowsHandle {
    #[napi]
    pub fn close(&mut self) -> u32 {
        drop(self.file.take());
        0
    }

    #[napi]
    pub fn attributes(&self) -> AttributesResult {
        let mut info = FILE_ATTRIBUTE_TAG_INFO::default();
        let error = status(unsafe {
            GetFileInformationByHandleEx(
                self.raw(),
                FileAttributeTagInfo,
                (&mut info as *mut FILE_ATTRIBUTE_TAG_INFO).cast(),
                size_of::<FILE_ATTRIBUTE_TAG_INFO>() as u32,
            )
        });
        AttributesResult {
            error,
            attributes: info.FileAttributes,
            reparse_tag: info.ReparseTag,
        }
    }

    #[napi]
    pub fn identity(&self) -> IdentityResult {
        let mut info = FILE_ID_INFO::default();
        let error = status(unsafe {
            GetFileInformationByHandleEx(
                self.raw(),
                FileIdInfo,
                (&mut info as *mut FILE_ID_INFO).cast(),
                size_of::<FILE_ID_INFO>() as u32,
            )
        });
        IdentityResult {
            error,
            volume: info.VolumeSerialNumber.to_string(),
            file_id: info.FileId.Identifier.to_vec().into(),
        }
    }

    #[napi]
    pub fn file_type(&self) -> WindowsResult {
        unsafe { SetLastError(0) };
        let value = unsafe { GetFileType(self.raw()) };
        WindowsResult {
            error: if value == FILE_TYPE_UNKNOWN {
                unsafe { GetLastError() }
            } else {
                0
            },
            value,
        }
    }

    #[napi]
    pub fn final_path(&self, flags: u32) -> napi::Result<PathResult> {
        let mut path = vec![0_u16; 256];
        loop {
            let capacity = u32::try_from(path.len())
                .map_err(|_| invalid("Final path exceeds the Win32 buffer size"))?;
            let length = unsafe {
                GetFinalPathNameByHandleW(self.raw(), path.as_mut_ptr(), capacity, flags)
            };
            if length == 0 {
                return Ok(PathResult {
                    error: unsafe { GetLastError() },
                    path: Vec::new().into(),
                });
            }
            if length < capacity {
                return Ok(PathResult {
                    error: 0,
                    path: path[..length as usize]
                        .iter()
                        .flat_map(|unit| unit.to_le_bytes())
                        .collect::<Vec<_>>()
                        .into(),
                });
            }
            path.resize(length as usize + 1, 0);
        }
    }

    #[napi]
    pub fn read(
        &self,
        mut buffer: Buffer,
        offset: f64,
        length: f64,
    ) -> napi::Result<WindowsResult> {
        let (offset, length) = io_range(&buffer, offset, length)?;
        Ok(io_count(self.file().and_then(|mut file| {
            file.read(&mut buffer[offset..offset + length as usize])
        })))
    }

    #[napi]
    pub fn write(&self, buffer: Buffer, offset: f64, length: f64) -> napi::Result<WindowsResult> {
        let (offset, length) = io_range(&buffer, offset, length)?;
        Ok(io_count(self.file().and_then(|mut file| {
            file.write(&buffer[offset..offset + length as usize])
        })))
    }

    #[napi]
    pub fn seek(&self, distance: BigInt, origin: u32) -> napi::Result<PositionResult> {
        let (distance, lossless) = distance.get_i64();
        if !lossless {
            return Err(invalid("Seek offset must fit a signed 64-bit integer"));
        }
        let result = self.file().and_then(|mut file| {
            let position = match origin {
                FILE_BEGIN => SeekFrom::Start(distance as u64),
                FILE_CURRENT => SeekFrom::Current(distance),
                FILE_END => SeekFrom::End(distance),
                _ => return Err(io::Error::from_raw_os_error(ERROR_INVALID_PARAMETER as i32)),
            };
            file.seek(position)
        });
        Ok(match result {
            Ok(value) => PositionResult {
                error: 0,
                value: (value as i64).to_string(),
            },
            Err(error) => PositionResult {
                error: io_error(error),
                value: "0".to_owned(),
            },
        })
    }

    #[napi]
    pub fn size(&self) -> PositionResult {
        let mut value = 0;
        let error = status(unsafe { GetFileSizeEx(self.raw(), &mut value) });
        PositionResult {
            error,
            value: value.to_string(),
        }
    }

    #[napi]
    pub fn set_end_of_file(&self) -> u32 {
        io_status(self.file().and_then(|mut file| {
            let position = file.stream_position()?;
            file.set_len(position)
        }))
    }

    #[napi]
    pub fn flush(&self) -> u32 {
        io_status(self.file().and_then(File::sync_all))
    }

    #[napi]
    pub fn rename(&self, destination: Buffer, replace: bool) -> napi::Result<u32> {
        let path = wide_path(destination)?;
        let name_bytes = (path.len() - 1) * size_of::<u16>();
        let size = offset_of!(FILE_RENAME_INFO, FileName)
            .checked_add(name_bytes + size_of::<u16>())
            .ok_or_else(|| invalid("Rename path exceeds the Win32 buffer size"))?
            .max(size_of::<FILE_RENAME_INFO>());
        let size_u32 = u32::try_from(size)
            .map_err(|_| invalid("Rename path exceeds the Win32 buffer size"))?;
        // Allocate with the generated structure's alignment, including its variable tail.
        let mut storage = vec![
            MaybeUninit::<FILE_RENAME_INFO>::zeroed();
            size.div_ceil(size_of::<FILE_RENAME_INFO>())
        ];
        let info = storage.as_mut_ptr().cast::<FILE_RENAME_INFO>();
        unsafe {
            (*info).Anonymous.ReplaceIfExists = replace;
            (*info).RootDirectory = null_mut();
            (*info).FileNameLength = name_bytes as u32;
            copy_nonoverlapping(
                path.as_ptr(),
                info.cast::<u8>()
                    .add(offset_of!(FILE_RENAME_INFO, FileName))
                    .cast::<u16>(),
                path.len(),
            );
        }
        Ok(status(unsafe {
            SetFileInformationByHandle(self.raw(), FileRenameInfo, info.cast(), size_u32)
        }))
    }

    #[napi]
    pub fn set_disposition(&self, delete: bool) -> u32 {
        let info = FILE_DISPOSITION_INFO { DeleteFile: delete };
        status(unsafe {
            SetFileInformationByHandle(
                self.raw(),
                FileDispositionInfo,
                (&info as *const FILE_DISPOSITION_INFO).cast(),
                size_of::<FILE_DISPOSITION_INFO>() as u32,
            )
        })
    }

    #[napi]
    pub fn lock(&self, nonblocking: bool) -> u32 {
        io_status(self.file().and_then(|file| {
            if nonblocking {
                file.try_lock().map_err(|error| match error {
                    TryLockError::WouldBlock => {
                        io::Error::from_raw_os_error(ERROR_LOCK_VIOLATION as i32)
                    }
                    TryLockError::Error(error) => error,
                })
            } else {
                file.lock()
            }
        }))
    }

    #[napi]
    pub fn unlock(&self) -> u32 {
        io_status(self.file().and_then(File::unlock))
    }
}

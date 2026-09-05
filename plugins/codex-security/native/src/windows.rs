use napi::bindgen_prelude::{BigInt, Buffer};
use napi_derive::napi;
use std::{
    ffi::OsString,
    fs::{self, File, TryLockError},
    io::{self, Read, Seek, SeekFrom, Write},
    mem::{offset_of, size_of, MaybeUninit},
    os::windows::{
        ffi::{OsStrExt, OsStringExt},
        fs::FileTypeExt,
        io::{AsRawHandle, FromRawHandle},
    },
    ptr::{copy_nonoverlapping, null, null_mut},
};
use windows_sys::Win32::{
    Foundation::{
        GetLastError, SetLastError, ERROR_INVALID_HANDLE, ERROR_INVALID_PARAMETER,
        ERROR_LOCK_VIOLATION, HANDLE, INVALID_HANDLE_VALUE,
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
    let path = os_string(path)?;
    if path.is_empty() {
        // Rust rejects empty paths before Win32; retain the native error contract.
        let mut value = [0_u16; 256];
        let error = unsafe {
            GetFullPathNameW([0_u16].as_ptr(), 256, value.as_mut_ptr(), null_mut());
            GetLastError()
        };
        return Ok(BufferResult {
            error,
            value: Vec::new().into(),
        });
    }
    match std::path::absolute(path) {
        Ok(value) => Ok(BufferResult {
            error: 0,
            value: wide_bytes(value.as_os_str().encode_wide()),
        }),
        Err(error) => Ok(BufferResult {
            error: error
                .raw_os_error()
                .ok_or_else(|| invalid(&error.to_string()))? as u32,
            value: Vec::new().into(),
        }),
    }
}

#[napi]
pub fn windows_directory_entries(path: Buffer) -> napi::Result<DirectoryEntriesResult> {
    let path = os_string(path)?;
    let entries = || -> io::Result<Vec<DirectoryEntry>> {
        fs::read_dir(path)?
            .map(|entry| {
                let entry = entry?;
                let kind = entry.file_type()?;
                Ok(DirectoryEntry {
                    name: wide_bytes(entry.file_name().encode_wide()),
                    is_directory: kind.is_dir() || kind.is_symlink_dir(),
                    is_symbolic_link: kind.is_symlink(),
                })
            })
            .collect()
    };
    match entries() {
        Ok(value) => Ok(DirectoryEntriesResult { error: 0, value }),
        Err(error) => Ok(DirectoryEntriesResult {
            error: error
                .raw_os_error()
                .ok_or_else(|| invalid(&error.to_string()))? as u32,
            value: Vec::new(),
        }),
    }
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

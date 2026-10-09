use napi::bindgen_prelude::Buffer;
use napi_derive::napi;
use std::{
    ffi::{CStr, OsStr, OsString},
    fs::{self, File},
    io::{self, Read, Write},
    mem::{offset_of, size_of, MaybeUninit},
    os::windows::{
        ffi::{OsStrExt, OsStringExt},
        fs::FileTypeExt,
        io::{AsRawHandle, FromRawHandle, OwnedHandle},
    },
    ptr::{copy_nonoverlapping, null, null_mut},
};
use windows_sys::Win32::{
    Foundation::{
        GetLastError, LocalFree, SetLastError, ERROR_INVALID_HANDLE, HANDLE, INVALID_HANDLE_VALUE,
    },
    Security::{
        Authorization::{
            ConvertSidToStringSidA, ConvertStringSecurityDescriptorToSecurityDescriptorW,
            SDDL_REVISION_1,
        },
        GetTokenInformation, TokenUser, SECURITY_ATTRIBUTES, SECURITY_MAX_SID_SIZE, TOKEN_QUERY,
        TOKEN_USER,
    },
    Storage::FileSystem::*,
    System::Threading::{GetCurrentProcess, OpenProcessToken},
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

#[napi(object)]
pub struct WindowsEnvironmentValue {
    pub name: Buffer,
    pub value: Buffer,
}

#[napi(object)]
pub struct WindowsProcessResult {
    pub error: u32,
    pub message: Option<String>,
    pub status: i32,
}

fn windows_command_line(executable: &OsStr, arguments: &[OsString]) -> Vec<u16> {
    let mut line = vec![b'"' as u16];
    line.extend(executable.encode_wide());
    line.push(b'"' as u16);
    for argument in arguments {
        line.push(b' ' as u16);
        let quote = argument.is_empty()
            || argument
                .as_encoded_bytes()
                .iter()
                .any(|byte| matches!(byte, b' ' | b'\t'));
        if quote {
            line.push(b'"' as u16);
        }
        let mut slashes = 0;
        for unit in argument.encode_wide() {
            if unit == b'\\' as u16 {
                slashes += 1;
                continue;
            }
            line.extend(std::iter::repeat_n(
                b'\\' as u16,
                if unit == b'"' as u16 {
                    slashes * 2 + 1
                } else {
                    slashes
                },
            ));
            line.push(unit);
            slashes = 0;
        }
        line.extend(std::iter::repeat_n(
            b'\\' as u16,
            if quote { slashes * 2 } else { slashes },
        ));
        if quote {
            line.push(b'"' as u16);
        }
    }
    line.push(0);
    line
}

fn windows_application_path(executable: &OsStr) -> io::Result<Vec<u16>> {
    use windows_sys::Win32::Foundation::MAX_PATH;

    let namespaced = |path: &OsStr| {
        let bytes = path.as_encoded_bytes();
        bytes.starts_with(br"\\?\") || bytes.starts_with(br"\\.\") || bytes.starts_with(br"\??\")
    };
    let terminated = |path: &OsStr| path.encode_wide().chain([0]).collect::<Vec<_>>();
    if namespaced(executable) {
        return Ok(terminated(executable));
    }
    // Resolve lexically, without canonicalizing the selected file or changing argv.
    let absolute = std::path::absolute(executable)?;
    if namespaced(absolute.as_os_str()) {
        return Ok(terminated(absolute.as_os_str()));
    }
    let units = absolute.as_os_str().encode_wide().collect::<Vec<_>>();
    if units.len() < MAX_PATH as usize {
        return Ok(terminated(executable));
    }
    // CreateProcessW needs a namespace for an ordinary long application path.
    let (prefix, tail) = if units.starts_with(&[b'\\' as u16; 2]) {
        (r"\\?\UNC\", &units[2..])
    } else {
        (r"\\?\", units.as_slice())
    };
    Ok(prefix
        .encode_utf16()
        .chain(tail.iter().copied())
        .chain([0])
        .collect())
}

fn run_exact_com_process(executable: &OsStr, arguments: &[OsString]) -> io::Result<i32> {
    use windows_sys::Win32::{
        Foundation::{DuplicateHandle, DUPLICATE_SAME_ACCESS, WAIT_OBJECT_0},
        System::Threading::{
            CreateProcessW, GetExitCodeProcess, WaitForSingleObject, CREATE_UNICODE_ENVIRONMENT,
            INFINITE, PROCESS_INFORMATION, STARTF_USESTDHANDLES, STARTUPINFOW,
        },
    };

    fn duplicate(handle: HANDLE) -> io::Result<Option<OwnedHandle>> {
        if handle.is_null() || handle == INVALID_HANDLE_VALUE {
            return Ok(None);
        }
        let process = unsafe { GetCurrentProcess() };
        let mut inherited = null_mut();
        if unsafe {
            DuplicateHandle(
                process,
                handle,
                process,
                &mut inherited,
                0,
                1,
                DUPLICATE_SAME_ACCESS,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(Some(unsafe { OwnedHandle::from_raw_handle(inherited) }))
    }

    let application = windows_application_path(executable)?;
    let handles = [
        duplicate(io::stdin().as_raw_handle())?,
        duplicate(io::stdout().as_raw_handle())?,
        duplicate(io::stderr().as_raw_handle())?,
    ];
    let mut startup: STARTUPINFOW = unsafe { std::mem::zeroed() };
    startup.cb = size_of::<STARTUPINFOW>() as u32;
    startup.dwFlags = STARTF_USESTDHANDLES;
    startup.hStdInput = handles[0]
        .as_ref()
        .map_or(null_mut(), AsRawHandle::as_raw_handle);
    startup.hStdOutput = handles[1]
        .as_ref()
        .map_or(null_mut(), AsRawHandle::as_raw_handle);
    startup.hStdError = handles[2]
        .as_ref()
        .map_or(null_mut(), AsRawHandle::as_raw_handle);
    let mut process: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };
    let mut command_line = windows_command_line(executable, arguments);
    if unsafe {
        CreateProcessW(
            application.as_ptr(),
            command_line.as_mut_ptr(),
            null(),
            null(),
            1,
            CREATE_UNICODE_ENVIRONMENT,
            null(),
            null(),
            &startup,
            &mut process,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    let child = unsafe { OwnedHandle::from_raw_handle(process.hProcess) };
    drop(unsafe { OwnedHandle::from_raw_handle(process.hThread) });
    drop(handles);
    if unsafe { WaitForSingleObject(child.as_raw_handle(), INFINITE) } != WAIT_OBJECT_0 {
        return Err(io::Error::last_os_error());
    }
    let mut exit_code = 0;
    if unsafe { GetExitCodeProcess(child.as_raw_handle(), &mut exit_code) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(exit_code as i32)
}

/// Run only inside the Node subprocess shim: blocking here keeps pipe ownership in that process.
#[napi]
pub fn run_windows_process(
    executable: Buffer,
    arguments: Vec<Buffer>,
    cwd: Option<Buffer>,
    environment: Option<Vec<WindowsEnvironmentValue>>,
) -> napi::Result<WindowsProcessResult> {
    use std::process::{Command, Stdio};

    let executable = os_string(executable)?;
    let arguments = arguments
        .into_iter()
        .map(os_string)
        .collect::<napi::Result<Vec<_>>>()?;
    let cwd = cwd.map(os_string).transpose()?;
    let environment = environment
        .unwrap_or_default()
        .into_iter()
        .map(|entry| Ok((os_string(entry.name)?, os_string(entry.value)?)))
        .collect::<napi::Result<Vec<_>>>()?;
    fn run(
        mut executable: OsString,
        arguments: Vec<OsString>,
        cwd: Option<OsString>,
        environment: Vec<(OsString, OsString)>,
    ) -> io::Result<i32> {
        use std::path::Path;
        use windows_sys::Win32::System::Environment::{
            NeedCurrentDirectoryForExePathW, SetEnvironmentVariableW,
        };
        use windows_sys::Win32::System::JobObjects::{
            AssignProcessToJobObject, CreateJobObjectW, JobObjectExtendedLimitInformation,
            SetInformationJobObject, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
            JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
        };
        // Restore target settings inside the one-command shim after Node startup.
        // Lookup must use the exact environment, including Rust's parent-PATH fallback.
        for (name, value) in environment {
            let name = name.encode_wide().chain([0]).collect::<Vec<_>>();
            let value = value.encode_wide().chain([0]).collect::<Vec<_>>();
            if unsafe { SetEnvironmentVariableW(name.as_ptr(), value.as_ptr()) } == 0 {
                return Err(io::Error::last_os_error());
            }
        }
        // The private shim runs one command. Resolve relative executables and PATH
        // entries from the target directory without changing the caller's cwd.
        if let Some(directory) = cwd {
            std::env::set_current_dir(directory)?;
        }
        // Rust searches PATH but omits Node's current-directory lookup for bare names.
        if Path::new(&executable).file_name() == Some(executable.as_os_str())
            && unsafe { NeedCurrentDirectoryForExePathW([0_u16].as_ptr()) } != 0
        {
            let bytes = executable.as_encoded_bytes();
            let has_extension = bytes
                .iter()
                .position(|&byte| byte == b'.')
                .is_some_and(|index| index + 1 < bytes.len());
            let mut candidates = Vec::new();
            if has_extension {
                candidates.push(executable.clone());
            }
            for extension in ["com", "exe"] {
                let mut candidate = executable.clone();
                if bytes.last() != Some(&b'.') {
                    candidate.push(".");
                }
                candidate.push(extension);
                candidates.push(candidate);
            }
            if let Some(candidate) = candidates
                .into_iter()
                .find(|path| Path::new(path).is_file())
            {
                executable = std::env::current_dir()?.join(candidate).into_os_string();
            }
        }
        let raw_job = unsafe { CreateJobObjectW(null(), null()) };
        if raw_job.is_null() {
            return Err(io::Error::last_os_error());
        }
        let job = unsafe { OwnedHandle::from_raw_handle(raw_job) };
        let mut limits: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { std::mem::zeroed() };
        limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        if unsafe {
            SetInformationJobObject(
                job.as_raw_handle(),
                JobObjectExtendedLimitInformation,
                &limits as *const _ as *const _,
                size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        if unsafe { AssignProcessToJobObject(job.as_raw_handle(), GetCurrentProcess()) } == 0 {
            return Err(io::Error::last_os_error());
        }
        // This function runs once in the private shim. Keep its job handle until
        // process exit, so descendants inherit membership before they can run.
        // Closing the handle on return would terminate the shim before reporting status.
        std::mem::forget(job);
        // Rust otherwise prefers a sibling .com.exe over an explicitly selected .com.
        let path = Path::new(&executable);
        let bytes = executable.as_encoded_bytes();
        if path.file_name() != Some(executable.as_os_str())
            && bytes[bytes.len().saturating_sub(4)..].eq_ignore_ascii_case(b".com")
        {
            return run_exact_com_process(&executable, &arguments);
        }
        let mut command = Command::new(executable);
        // Explicit PATH is searched before the shim's executable and system directories.
        if let Some(path) = std::env::var_os("PATH") {
            command.env("PATH", path);
        }
        command.args(arguments);
        Ok(command
            .stdin(Stdio::inherit())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .status()?
            .code()
            .unwrap_or(1))
    }
    match run(executable, arguments, cwd, environment) {
        Ok(status) => Ok(WindowsProcessResult {
            error: 0,
            message: None,
            status,
        }),
        Err(error) => Ok(WindowsProcessResult {
            error: error.raw_os_error().unwrap_or(1) as u32,
            message: Some(error.to_string()),
            status: 127,
        }),
    }
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
        // The public Rust path API rejects empty input before reaching Win32.
        let mut value = [0_u16; 256];
        let error = unsafe {
            SetLastError(0);
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
pub fn create_windows_directories(path: Buffer) -> napi::Result<u32> {
    Ok(io_status(fs::create_dir_all(os_string(path)?)))
}

#[napi]
pub fn create_private_windows_directory(path: Buffer) -> napi::Result<u32> {
    let path = wide_path(path)?;
    let mut token = null_mut();
    let error = status(unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) });
    if error != 0 {
        return Ok(error);
    }
    let token = unsafe { OwnedHandle::from_raw_handle(token) };
    // TOKEN_USER is followed by the SID; use Windows' defined maximum SID size.
    #[repr(C)]
    struct TokenUserBuffer {
        user: TOKEN_USER,
        sid: [u8; SECURITY_MAX_SID_SIZE as usize],
    }
    let mut user = TokenUserBuffer {
        user: TOKEN_USER::default(),
        sid: [0; SECURITY_MAX_SID_SIZE as usize],
    };
    let mut length = 0;
    let error = status(unsafe {
        GetTokenInformation(
            token.as_raw_handle(),
            TokenUser,
            (&mut user as *mut TokenUserBuffer).cast(),
            size_of::<TokenUserBuffer>() as u32,
            &mut length,
        )
    });
    if error != 0 {
        return Ok(error);
    }
    let mut sid = null_mut();
    let error = status(unsafe { ConvertSidToStringSidA(user.user.User.Sid, &mut sid) });
    if error != 0 {
        return Ok(error);
    }
    let descriptor = format!(
        "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;{})",
        unsafe { CStr::from_ptr(sid.cast()) }.to_str().unwrap()
    );
    unsafe { LocalFree(sid.cast()) };
    let mut attributes = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        ..Default::default()
    };
    // Match the credential-home policy: current user, SYSTEM and administrators.
    let descriptor = descriptor.encode_utf16().chain(Some(0)).collect::<Vec<_>>();
    let error = status(unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            descriptor.as_ptr(),
            SDDL_REVISION_1,
            &mut attributes.lpSecurityDescriptor,
            null_mut(),
        )
    });
    if error != 0 {
        return Ok(error);
    }
    let error = status(unsafe { CreateDirectoryW(path.as_ptr(), &attributes) });
    unsafe { LocalFree(attributes.lpSecurityDescriptor) };
    Ok(error)
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
                    path: wide_bytes(path[..length as usize].iter().copied()),
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
}

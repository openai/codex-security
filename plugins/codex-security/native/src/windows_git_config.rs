use napi::bindgen_prelude::Buffer;
use napi_derive::napi;
use std::cell::UnsafeCell;
use std::ffi::c_void;
use std::io;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::ptr::{null, null_mut};
use std::sync::{Arc, Mutex};
use windows_sys::Wdk::Storage::FileSystem::{
    FilePipeLocalInformation, NtQueryInformationFile, FILE_PIPE_LISTENING_STATE,
    FILE_PIPE_LOCAL_INFORMATION,
};
use windows_sys::Win32::Foundation::{
    DuplicateHandle, GetLastError, ERROR_BROKEN_PIPE, ERROR_IO_PENDING, ERROR_NO_DATA,
    ERROR_PIPE_CONNECTED, ERROR_PIPE_NOT_CONNECTED, HANDLE, INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;
use windows_sys::Win32::Storage::FileSystem::{
    FlushFileBuffers, WriteFile, FILE_FLAG_FIRST_PIPE_INSTANCE, FILE_FLAG_OVERLAPPED,
    PIPE_ACCESS_OUTBOUND,
};
use windows_sys::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, IsProcessInJob,
};
use windows_sys::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, GetNamedPipeClientProcessId,
    PIPE_REJECT_REMOTE_CLIENTS,
};
use windows_sys::Win32::System::SystemServices::JOB_OBJECT_QUERY;
use windows_sys::Win32::System::Threading::{
    CallbackMayRunLong, CloseThreadpoolWait, CreateEventW, CreateThreadpoolWait, GetCurrentProcess,
    OpenProcess, ResetEvent, SetEvent, SetThreadpoolWait, PROCESS_QUERY_LIMITED_INFORMATION,
    PTP_CALLBACK_INSTANCE, PTP_WAIT,
};
use windows_sys::Win32::System::IO::{GetOverlappedResult, IO_STATUS_BLOCK, OVERLAPPED};

#[napi]
pub fn windows_git_coordinator_sid() -> napi::Result<String> {
    crate::windows::current_user_sid().map_err(win_error)
}

fn win_error(code: u32) -> napi::Error {
    error(io::Error::from_raw_os_error(code as i32))
}

fn error(error: io::Error) -> napi::Error {
    napi::Error::from_reason(format!("Cannot serve Git configuration: {error}"))
}

fn git_job() -> Result<OwnedHandle, u32> {
    // OWNER RIGHTS suppresses the shared account's implicit WRITE_DAC. The
    // creator can attach the bridge, then retain only JOB_OBJECT_QUERY (0x4).
    crate::windows::with_security_descriptor("D:P(A;;0x4;;;OW)", |security| unsafe {
        let attributes = SECURITY_ATTRIBUTES {
            nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: security,
            bInheritHandle: 0,
        };
        let job = CreateJobObjectW(&attributes, null());
        if job.is_null() {
            return Err(GetLastError());
        }
        let job = OwnedHandle::from_raw_handle(job);
        let process = GetCurrentProcess();
        let mut query = null_mut();
        if AssignProcessToJobObject(job.as_raw_handle(), process) == 0
            || DuplicateHandle(
                process,
                job.as_raw_handle(),
                process,
                &mut query,
                JOB_OBJECT_QUERY,
                0,
                0,
            ) == 0
        {
            return Err(GetLastError());
        }
        Ok(OwnedHandle::from_raw_handle(query))
    })
}

// The Git bridge creates an anonymous job before spawning its command. Git, hooks,
// and nested invocations all inherit membership. Windows reports the client PID.
fn is_git_client(pipe: HANDLE, job: HANDLE) -> bool {
    let mut pid = 0;
    if unsafe { GetNamedPipeClientProcessId(pipe, &mut pid) } == 0 {
        return false;
    }
    let client = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    if client.is_null() {
        return false;
    }
    let client = unsafe { OwnedHandle::from_raw_handle(client) };
    let mut member = 0;
    unsafe { IsProcessInJob(client.as_raw_handle(), job, &mut member) != 0 && member != 0 }
}

struct Config {
    pipes: Vec<OwnedHandle>,
    failure: Mutex<Option<io::Error>>,
    bytes: Vec<u8>,
    job: Arc<OwnedHandle>,
}

impl Config {
    fn check_spare(&self, rearmed: Option<usize>) -> io::Result<()> {
        for (slot, pipe) in self.pipes.iter().enumerate() {
            if Some(slot) == rearmed {
                continue;
            }
            let mut info = FILE_PIPE_LOCAL_INFORMATION::default();
            let mut status = IO_STATUS_BLOCK::default();
            let result = unsafe {
                NtQueryInformationFile(
                    pipe.as_raw_handle(),
                    &mut status,
                    (&raw mut info).cast(),
                    size_of_val(&info) as u32,
                    FilePipeLocalInformation,
                )
            };
            if result != 0 {
                return Err(io::Error::other(format!(
                    "cannot inspect listener (NTSTATUS {result:#x})"
                )));
            }
            if info.NamedPipeState == FILE_PIPE_LISTENING_STATE {
                return Ok(());
            }
        }
        Err(io::Error::other(
            "concurrent readers exhausted the pipe listeners",
        ))
    }
}

static CONFIGS: Mutex<Vec<Arc<Config>>> = Mutex::new(Vec::new());

#[napi]
pub fn check_windows_git_configs() -> napi::Result<()> {
    for config in CONFIGS.lock().unwrap().iter() {
        let failure = config.failure.lock().unwrap();
        if let Some(reason) = &*failure {
            return Err(error(io::Error::other(reason.to_string())));
        }
        config.check_spare(None).map_err(error)?;
    }
    Ok(())
}

struct Listener {
    config: Arc<Config>,
    slot: usize,
    event: OwnedHandle,
    operation: UnsafeCell<OVERLAPPED>,
}

impl Listener {
    fn pipe(&self) -> HANDLE {
        self.config.pipes[self.slot].as_raw_handle()
    }

    fn start(config: Arc<Config>, slot: usize) -> io::Result<()> {
        let event = unsafe { CreateEventW(null(), 1, 0, null()) };
        if event.is_null() {
            return Err(io::Error::last_os_error());
        }
        let listener = Box::new(Self {
            config,
            slot,
            event: unsafe { OwnedHandle::from_raw_handle(event) },
            operation: UnsafeCell::new(OVERLAPPED::default()),
        });
        // The short-lived Git bridge owns each reserved pipe until process exit.
        // Its address must stay fixed while a connect or callback is outstanding.
        let context = Box::into_raw(listener);
        let wait = unsafe { CreateThreadpoolWait(Some(Self::accept), context.cast(), null()) };
        let result = if wait == 0 {
            Err(io::Error::last_os_error())
        } else {
            unsafe { (*context).listen(wait) }
        };
        if result.is_err() {
            // listen only returns an error before registering its wait.
            if wait != 0 {
                unsafe { CloseThreadpoolWait(wait) };
            }
            drop(unsafe { Box::from_raw(context) });
        }
        result
    }

    // Only called after the previous operation has completed.
    unsafe fn operation(&self) -> *mut OVERLAPPED {
        let operation = self.operation.get();
        unsafe {
            operation.write(OVERLAPPED {
                hEvent: self.event.as_raw_handle(),
                ..OVERLAPPED::default()
            });
        }
        operation
    }

    // Only the installer or the previous callback arms this one-shot wait.
    // Neither touches the operation again after publishing the wait.
    unsafe fn listen(&self, wait: PTP_WAIT) -> io::Result<()> {
        let event = self.event.as_raw_handle();
        unsafe {
            if ResetEvent(event) == 0 {
                return Err(io::Error::last_os_error());
            }
            let ready = if ConnectNamedPipe(self.pipe(), self.operation()) == 0 {
                match GetLastError() {
                    ERROR_IO_PENDING => false,
                    ERROR_PIPE_CONNECTED | ERROR_NO_DATA => true,
                    code => return Err(io::Error::from_raw_os_error(code as i32)),
                }
            } else {
                true
            };
            if ready && SetEvent(event) == 0 {
                return Err(io::Error::last_os_error());
            }
            SetThreadpoolWait(wait, event, null());
        }
        Ok(())
    }

    fn send(&self) -> io::Result<()> {
        let pipe = self.pipe();
        let mut remaining = &self.config.bytes[..];
        while !remaining.is_empty() {
            let mut written = 0;
            unsafe {
                let operation = self.operation();
                if WriteFile(
                    pipe,
                    remaining.as_ptr(),
                    remaining.len().min(u32::MAX as usize) as u32,
                    null_mut(),
                    operation,
                ) == 0
                    && GetLastError() != ERROR_IO_PENDING
                {
                    return Err(io::Error::last_os_error());
                }
                if GetOverlappedResult(pipe, operation, &mut written, 1) == 0 {
                    return Err(io::Error::last_os_error());
                }
                if written == 0 {
                    return Err(io::ErrorKind::WriteZero.into());
                }
            }
            remaining = &remaining[written as usize..];
        }
        if unsafe { FlushFileBuffers(pipe) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    unsafe extern "system" fn accept(
        instance: PTP_CALLBACK_INSTANCE,
        context: *mut c_void,
        wait: PTP_WAIT,
        _: u32,
    ) {
        let listener = unsafe { &*context.cast::<Self>() };
        let pipe = listener.pipe();
        if is_git_client(pipe, listener.config.job.as_raw_handle()) {
            unsafe { CallbackMayRunLong(instance) };
            if let Err(error) = listener.send() {
                // Git closes its access probes before reading any data.
                if !matches!(
                    error.raw_os_error().map(|code| code as u32),
                    Some(ERROR_BROKEN_PIPE | ERROR_NO_DATA | ERROR_PIPE_NOT_CONNECTED)
                ) {
                    listener.config.failure.lock().unwrap().get_or_insert(error);
                }
            }
        }
        // Only rearming can restore a consumed listener. Serialize rearms
        // and require another slot still listening *after* each rearm. This
        // proves continuous coverage even if Git ignores a busy-pipe error.
        // The bridge checks the final interval after the child exits.
        let mut failure = listener.config.failure.lock().unwrap();
        unsafe { DisconnectNamedPipe(pipe) };
        if let Err(error) = unsafe { listener.listen(wait) }
            .and_then(|()| listener.config.check_spare(Some(listener.slot)))
        {
            failure.get_or_insert(error);
        }
    }
}

#[napi]
pub fn serve_windows_git_configs(
    prefix: String,
    files: Vec<Buffer>,
    coordinator: String,
) -> napi::Result<bool> {
    if windows_git_coordinator_sid()? == coordinator {
        return Ok(false);
    }
    let job = Arc::new(git_job().map_err(win_error)?);
    let prefix = prefix.replace('/', "\\");
    for (index, bytes) in files.into_iter().enumerate() {
        let name: Vec<_> = format!("{prefix}{index}")
            .encode_utf16()
            .chain([0])
            .collect();
        // Reserve every slot before exposing any name. Keeping all server handles
        // open prevents another process from supplying a competing instance.
        const INSTANCES: u32 = 32;
        let mut pipes = Vec::new();
        for instance in 0..INSTANCES {
            let first = if instance == 0 {
                FILE_FLAG_FIRST_PIPE_INSTANCE
            } else {
                0
            };
            let pipe = unsafe {
                CreateNamedPipeW(
                    name.as_ptr(),
                    PIPE_ACCESS_OUTBOUND | FILE_FLAG_OVERLAPPED | first,
                    PIPE_REJECT_REMOTE_CLIENTS,
                    INSTANCES,
                    0,
                    0,
                    0,
                    null(),
                )
            };
            if pipe == INVALID_HANDLE_VALUE {
                return Err(error(io::Error::last_os_error()));
            }
            pipes.push(unsafe { OwnedHandle::from_raw_handle(pipe) });
        }
        let config = Arc::new(Config {
            pipes,
            failure: Mutex::new(None),
            bytes: bytes.to_vec(),
            job: Arc::clone(&job),
        });
        for slot in 0..config.pipes.len() {
            Listener::start(Arc::clone(&config), slot).map_err(error)?;
        }
        CONFIGS.lock().unwrap().push(config);
    }
    Ok(true)
}

use napi::bindgen_prelude::Buffer;
use napi_derive::napi;
use std::{
    ffi::{CStr, CString},
    io,
};

#[napi(object)]
pub struct SyscallResult {
    pub value: i32,
    pub errno: i32,
}

fn result(value: i32) -> SyscallResult {
    SyscallResult {
        value,
        errno: if value < 0 {
            io::Error::last_os_error().raw_os_error().unwrap()
        } else {
            0
        },
    }
}

fn retry_eintr(mut operation: impl FnMut() -> i32) -> SyscallResult {
    loop {
        let value = result(operation());
        if value.errno != libc::EINTR {
            return value;
        }
    }
}

fn path(value: Buffer) -> napi::Result<CString> {
    CString::new(value.as_ref()).map_err(|_| napi::Error::from_reason("Path contains a NUL byte"))
}

#[napi]
pub fn open_at(directory: i32, name: Buffer, flags: i32, mode: u32) -> napi::Result<SyscallResult> {
    let name = path(name)?;
    let mode = mode as libc::mode_t;
    // macOS mode_t is u16 and needs C integer promotion in this variadic call.
    #[cfg(target_os = "macos")]
    let mode = libc::c_int::from(mode);
    Ok(retry_eintr(|| unsafe {
        libc::openat(directory, name.as_ptr(), flags | libc::O_CLOEXEC, mode)
    }))
}

#[napi]
pub fn make_directory_at(directory: i32, name: Buffer, mode: u32) -> napi::Result<SyscallResult> {
    let name = path(name)?;
    Ok(result(unsafe {
        libc::mkdirat(directory, name.as_ptr(), mode as libc::mode_t)
    }))
}

#[napi]
pub fn rename_at(
    old_directory: i32,
    old_name: Buffer,
    new_directory: i32,
    new_name: Buffer,
) -> napi::Result<SyscallResult> {
    let old_name = path(old_name)?;
    let new_name = path(new_name)?;
    Ok(result(unsafe {
        libc::renameat(
            old_directory,
            old_name.as_ptr(),
            new_directory,
            new_name.as_ptr(),
        )
    }))
}

#[napi]
pub fn unlink_at(directory: i32, name: Buffer) -> napi::Result<SyscallResult> {
    let name = path(name)?;
    Ok(result(unsafe {
        libc::unlinkat(directory, name.as_ptr(), 0)
    }))
}

#[napi]
pub fn duplicate(descriptor: i32) -> SyscallResult {
    result(unsafe { libc::fcntl(descriptor, libc::F_DUPFD_CLOEXEC, 0) })
}

#[napi]
pub fn file_lock(descriptor: i32, unlock: bool, nonblocking: bool) -> SyscallResult {
    let flags = if unlock {
        libc::LOCK_UN
    } else {
        libc::LOCK_EX | if nonblocking { libc::LOCK_NB } else { 0 }
    };
    retry_eintr(|| unsafe { libc::flock(descriptor, flags) })
}

#[napi(object)]
pub struct MetadataResult {
    pub errno: i32,
    pub mode: u32,
    pub device: String,
    pub inode: String,
}

#[napi]
// libc stat field widths differ between Linux and macOS.
#[allow(clippy::unnecessary_cast)]
pub fn stat_at(directory: i32, name: Buffer) -> napi::Result<MetadataResult> {
    let name = path(name)?;
    let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
    let code = unsafe {
        libc::fstatat(
            directory,
            name.as_ptr(),
            stat.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if code < 0 {
        return Ok(MetadataResult {
            errno: io::Error::last_os_error().raw_os_error().unwrap(),
            mode: 0,
            device: String::new(),
            inode: String::new(),
        });
    }
    let stat = unsafe { stat.assume_init() };
    Ok(MetadataResult {
        errno: 0,
        mode: stat.st_mode as u32,
        device: (stat.st_dev as u64).to_string(),
        inode: stat.st_ino.to_string(),
    })
}

#[napi(object)]
pub struct ReadLinkResult {
    pub errno: i32,
    pub value: Buffer,
}

#[napi]
pub fn read_link_at(directory: i32, name: Buffer) -> napi::Result<ReadLinkResult> {
    let name = path(name)?;
    let mut buffer = vec![0_u8; 256];
    loop {
        let length = unsafe {
            libc::readlinkat(
                directory,
                name.as_ptr(),
                buffer.as_mut_ptr().cast(),
                buffer.len(),
            )
        };
        if length < 0 {
            return Ok(ReadLinkResult {
                errno: io::Error::last_os_error().raw_os_error().unwrap(),
                value: Vec::new().into(),
            });
        }
        if (length as usize) < buffer.len() {
            buffer.truncate(length as usize);
            return Ok(ReadLinkResult {
                errno: 0,
                value: buffer.into(),
            });
        }
        buffer.resize(buffer.len() * 2, 0);
    }
}

#[napi(object, use_nullable = true)]
pub struct UserHomeResult {
    pub errno: i32,
    pub value: Option<Buffer>,
}

#[napi]
pub fn user_home(username: Buffer) -> napi::Result<UserHomeResult> {
    let username = path(username)?;
    let mut buffer = vec![0_u8; 1024];
    loop {
        let mut entry = std::mem::MaybeUninit::<libc::passwd>::uninit();
        let mut found = std::ptr::null_mut();
        let code = unsafe {
            libc::getpwnam_r(
                username.as_ptr(),
                entry.as_mut_ptr(),
                buffer.as_mut_ptr().cast(),
                buffer.len(),
                &mut found,
            )
        };
        if code == libc::ERANGE {
            buffer.resize(buffer.len() * 2, 0);
            continue;
        }
        let value = if code == 0 && !found.is_null() {
            Some(
                unsafe { CStr::from_ptr((*found).pw_dir) }
                    .to_bytes()
                    .to_vec()
                    .into(),
            )
        } else {
            None
        };
        return Ok(UserHomeResult { errno: code, value });
    }
}

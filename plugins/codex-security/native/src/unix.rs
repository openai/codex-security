use napi::bindgen_prelude::Buffer;
use napi_derive::napi;
use std::{
    ffi::{CStr, CString, OsStr},
    fs, io,
    os::unix::ffi::OsStrExt,
    path::Path,
};

#[napi(object)]
pub struct DirectoryEntry {
    pub name: Buffer,
    pub is_directory: bool,
    pub is_symbolic_link: bool,
    pub errno: i32,
}

#[napi(object)]
pub struct DirectoryResult {
    pub value: Vec<DirectoryEntry>,
    pub errno: i32,
}

#[napi]
pub fn directory_entries(name: Buffer, with_types: bool) -> napi::Result<DirectoryResult> {
    let name = CString::new(name.as_ref())
        .map_err(|_| napi::Error::from_reason("Path contains a NUL byte"))?;
    let entries = fs::read_dir(Path::new(OsStr::from_bytes(name.to_bytes()))).and_then(|entries| {
        entries
            .map(|entry| {
                let entry = entry?;
                let mut value = DirectoryEntry {
                    name: entry.file_name().as_bytes().to_vec().into(),
                    is_directory: false,
                    is_symbolic_link: false,
                    errno: 0,
                };
                if with_types {
                    match entry.file_type() {
                        Ok(kind) => {
                            value.is_directory = kind.is_dir();
                            value.is_symbolic_link = kind.is_symlink();
                        }
                        Err(error) => value.errno = error.raw_os_error().unwrap(),
                    }
                }
                Ok(value)
            })
            .collect::<io::Result<Vec<_>>>()
    });
    Ok(match entries {
        Ok(value) => DirectoryResult { value, errno: 0 },
        Err(error) => DirectoryResult {
            value: Vec::new(),
            errno: error.raw_os_error().unwrap(),
        },
    })
}

#[napi(object, use_nullable = true)]
pub struct UserHomeResult {
    pub errno: i32,
    pub value: Option<Buffer>,
}

#[napi]
pub fn user_home(username: Buffer) -> napi::Result<UserHomeResult> {
    let username = CString::new(username.as_ref())
        .map_err(|_| napi::Error::from_reason("Username contains a NUL byte"))?;
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

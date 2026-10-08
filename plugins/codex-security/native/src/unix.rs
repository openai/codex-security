use napi::bindgen_prelude::Buffer;
use napi_derive::napi;
use std::ffi::{CStr, CString};

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

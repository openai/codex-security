use napi::bindgen_prelude::Buffer;
use napi_derive::napi;

#[cfg(unix)]
use crate::scan_read_unix::{ScanReadFileBackend, ScanReadRootBackend};
#[cfg(windows)]
use crate::scan_read_windows::{ScanReadFileBackend, ScanReadRootBackend};

pub(super) fn access_denied(env: napi::Env, error: std::io::Error) -> napi::Error {
    let error = napi::Error::new("EACCES", error.to_string());
    napi::JsError::from(error).into_unknown(env).into()
}

#[napi]
pub struct ScanReadRoot {
    backend: ScanReadRootBackend,
}

#[napi]
pub struct ScanReadFile {
    backend: Option<ScanReadFileBackend>,
}

#[napi]
pub fn open_scan_read_root(path: Buffer) -> napi::Result<ScanReadRoot> {
    Ok(ScanReadRoot {
        backend: ScanReadRootBackend::open(path)?,
    })
}

#[napi]
impl ScanReadRoot {
    #[napi]
    pub fn open_file(
        &self,
        env: napi::Env,
        relative_path: String,
    ) -> napi::Result<Option<ScanReadFile>> {
        Ok(self
            .backend
            .open_file(env, &relative_path)?
            .map(|backend| ScanReadFile {
                backend: Some(backend),
            }))
    }

    #[napi]
    pub fn verify(&self) -> napi::Result<()> {
        self.backend.verify()
    }

    #[napi]
    pub fn close(&mut self) {
        self.backend.close();
    }
}

#[napi]
impl ScanReadFile {
    #[napi]
    pub fn read(&mut self, size: f64) -> napi::Result<Buffer> {
        if !size.is_finite() || size <= 0.0 || size.fract() != 0.0 || size > u32::MAX as f64 {
            return Err(napi::Error::new(
                napi::Status::InvalidArg,
                "Read size must be a positive buffer length",
            ));
        }
        let backend = self
            .backend
            .as_mut()
            .ok_or_else(|| napi::Error::from_reason("Scan file is closed"))?;
        let mut buffer = vec![0; size as usize];
        let count = backend
            .read(&mut buffer)
            .map_err(|error| napi::Error::from_reason(format!("Cannot read scan file: {error}")))?;
        buffer.truncate(count);
        Ok(buffer.into())
    }

    #[napi]
    pub fn close(&mut self) {
        self.backend = None;
    }
}

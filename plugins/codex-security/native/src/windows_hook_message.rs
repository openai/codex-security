use crate::{
    scan_read_windows::ScanReadRootBackend,
    windows::{current_user_sid, os_string, set_disposition, with_private_directory_security},
    windows_output::relative_directory,
};
use napi::bindgen_prelude::Buffer;
use napi_derive::napi;
use std::{
    ffi::OsStr,
    fs::{self, File, OpenOptions},
    io::{self, Read},
    os::windows::{fs::OpenOptionsExt, io::AsRawHandle},
    path::{Path, PathBuf},
};
use windows_sys::Win32::Storage::FileSystem::{
    GetFileInformationByHandle, GetFileType, BY_HANDLE_FILE_INFORMATION, DELETE,
    FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS,
    FILE_FLAG_OPEN_REPARSE_POINT, FILE_GENERIC_WRITE, FILE_SHARE_READ, FILE_SHARE_WRITE,
    FILE_TYPE_DISK,
};

fn win_error(code: u32) -> napi::Error {
    io::Error::from_raw_os_error(code as i32).into()
}

fn guard(directory: &Path, additional_access: u32) -> io::Result<File> {
    // Sharing excludes delete. NTFS will not turn a nonempty directory into a junction.
    OpenOptions::new()
        .write(true)
        .access_mode(FILE_GENERIC_WRITE | additional_access)
        .create_new(true)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
        .open(directory.join(".guard"))
}

struct Stage {
    // The outer path stays canonical while remove_dir_all opens its child.
    _ancestors: ScanReadRootBackend,
    outer_path: PathBuf,
    outer: File,
    outer_guard: Option<File>,
    message: Option<File>,
    message_guard: Option<File>,
}

impl Stage {
    fn remove(mut self) -> napi::Result<()> {
        if let Some(message) = self.message.take() {
            drop(self.message_guard.take());
            drop(message);
            // Windows std opens the child without following its reparse point, then
            // enumerates and deletes descendants relative to held directory handles.
            fs::remove_dir_all(self.outer_path.join("message"))?;
        }
        if let Some(guard) = self.outer_guard.take() {
            let error = set_disposition(guard.as_raw_handle(), true);
            if error != 0 {
                return Err(win_error(error));
            }
            drop(guard);
        }
        // Mark only the originally created, now empty carrier for removal.
        let error = set_disposition(self.outer.as_raw_handle(), true);
        if error != 0 {
            return Err(win_error(error));
        }
        Ok(())
    }
}

#[napi]
pub struct WindowsHookMessageStage {
    stage: Option<Stage>,
}

#[napi]
impl WindowsHookMessageStage {
    #[napi(getter)]
    pub fn coordinator(&self) -> napi::Result<String> {
        current_user_sid().map_err(win_error)
    }

    #[napi]
    pub fn close(&mut self) -> napi::Result<()> {
        self.stage.take().map_or(Ok(()), Stage::remove)
    }
}

impl Drop for WindowsHookMessageStage {
    fn drop(&mut self) {
        let _ = self.close();
    }
}

#[napi]
pub fn create_windows_hook_message_stage(path: Buffer) -> napi::Result<WindowsHookMessageStage> {
    let path = PathBuf::from(os_string(path)?);
    let parent = path
        .parent()
        .filter(|parent| parent.is_absolute())
        .ok_or_else(|| {
            napi::Error::from_reason("Expected a new absolute hook message directory")
        })?;
    let name = path
        .file_name()
        .ok_or_else(|| napi::Error::from_reason("Expected a hook message directory name"))?;
    let ancestors = ScanReadRootBackend::open_path(parent)?;
    let parent = ancestors.directory()?;
    let sid = current_user_sid().map_err(win_error)?;
    // FILE_CREATE returns the newly-created carrier already pinned, with its
    // private DACL in place before any sandbox can observe it.
    let outer = with_private_directory_security(&sid, |security| {
        relative_directory(parent, name, Some(security), DELETE)
    })
    .map_err(win_error)?;
    let mut stage = Stage {
        _ancestors: ancestors,
        outer_path: path,
        outer,
        outer_guard: None,
        message: None,
        message_guard: None,
    };
    let setup = (|| -> napi::Result<()> {
        stage.outer_guard = Some(guard(&stage.outer_path, DELETE)?);
        stage.message = Some(
            with_private_directory_security(&sid, |security| {
                relative_directory(&stage.outer, OsStr::new("message"), Some(security), 0)
            })
            .map_err(win_error)?,
        );
        stage.message_guard = Some(guard(&stage.outer_path.join("message"), 0)?);
        Ok(())
    })();
    if let Err(error) = setup {
        stage.remove()?;
        return Err(error);
    }
    Ok(WindowsHookMessageStage { stage: Some(stage) })
}

fn message_version(file: &File) -> napi::Result<(u64, u64)> {
    let raw = file.as_raw_handle();
    let mut info = BY_HANDLE_FILE_INFORMATION::default();
    if unsafe { GetFileInformationByHandle(raw, &mut info) } == 0 {
        return Err(io::Error::last_os_error().into());
    }
    if info.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT) != 0
        || info.nNumberOfLinks != 1
        || unsafe { GetFileType(raw) } != FILE_TYPE_DISK
    {
        return Err(napi::Error::from_reason(
            "The commit-message hook requires a regular, unlinked COMMIT_EDITMSG.",
        ));
    }
    Ok((
        u64::from(info.nFileSizeHigh) << 32 | u64::from(info.nFileSizeLow),
        u64::from(info.ftLastWriteTime.dwHighDateTime) << 32
            | u64::from(info.ftLastWriteTime.dwLowDateTime),
    ))
}

// The trusted coordinator holds all ancestors for this sandboxed reader.
#[napi]
pub fn read_windows_hook_message(path: Buffer) -> napi::Result<Buffer> {
    let path = PathBuf::from(os_string(path)?);
    if !path.is_absolute() || path.file_name() != Some(OsStr::new("COMMIT_EDITMSG")) {
        return Err(napi::Error::from_reason(
            "Expected the staged COMMIT_EDITMSG.",
        ));
    }
    let mut file = OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS)
        .open(path)?;
    let version = message_version(&file)?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;
    if version != message_version(&file)? || version.0 != bytes.len() as u64 {
        return Err(napi::Error::from_reason(
            "The hook's private commit-message file changed while reading it.",
        ));
    }
    Ok(bytes.into())
}

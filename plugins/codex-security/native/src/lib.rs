mod scan_read;
#[cfg(unix)]
mod scan_read_unix;
#[cfg(windows)]
mod scan_read_windows;
#[cfg(unix)]
mod unix;
#[cfg(windows)]
mod windows;
#[cfg(windows)]
mod windows_git_config;
#[cfg(windows)]
mod windows_hook_message;
#[cfg(windows)]
mod windows_output;

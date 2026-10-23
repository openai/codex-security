mod scan_read;
#[cfg(unix)]
mod scan_read_unix;
#[cfg(windows)]
mod scan_read_windows;
#[cfg(unix)]
mod unix;
#[cfg(windows)]
mod windows;

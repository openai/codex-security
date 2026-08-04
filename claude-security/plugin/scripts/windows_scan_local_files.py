"""Secure scan-local file operations for Windows.

Windows does not implement Python's descriptor-relative ``dir_fd`` APIs or
``O_NOFOLLOW``.  This module provides the three operations needed by the scan
finalizer without falling back to check-then-use path validation.

The implementation opens every directory with ``FILE_FLAG_OPEN_REPARSE_POINT``
and rejects all reparse points, including junctions.  Directory handles remain
open without ``FILE_SHARE_DELETE`` for the full operation, which prevents an
already-validated ancestor from being renamed or replaced during a read,
write, or delete.  Writes rename the exact temporary-file handle into place so
an attacker cannot substitute another file at the temporary name.

Importing this module is safe on non-Windows hosts.  Its public operations
raise ``WindowsScanLocalFileError`` when called anywhere other than Windows.
"""

from __future__ import annotations

import argparse
import contextlib
import ctypes
import errno
import importlib
import ntpath
import os
import secrets
from collections.abc import Iterator
from ctypes import wintypes
from pathlib import Path, PurePosixPath

_msvcrt = importlib.import_module("msvcrt") if os.name == "nt" else None


class WindowsScanLocalFileError(OSError):
    """Raised when a scan-local operation cannot be completed securely."""


# CreateFile access and sharing flags.
_DELETE = 0x00010000
_FILE_READ_ATTRIBUTES = 0x00000080
_GENERIC_READ = 0x80000000
_GENERIC_WRITE = 0x40000000
_FILE_SHARE_READ = 0x00000001
_FILE_SHARE_WRITE = 0x00000002
_FILE_SHARE_DELETE = 0x00000004

# CreateFile dispositions, attributes, and flags.
_CREATE_NEW = 1
_OPEN_EXISTING = 3
_FILE_ATTRIBUTE_DIRECTORY = 0x00000010
_FILE_ATTRIBUTE_NORMAL = 0x00000080
_FILE_ATTRIBUTE_REPARSE_POINT = 0x00000400
_FILE_FLAG_BACKUP_SEMANTICS = 0x02000000
_FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000

# GetFileInformationByHandleEx / SetFileInformationByHandle classes.
_FILE_RENAME_INFO_CLASS = 3
_FILE_DISPOSITION_INFO_CLASS = 4
_FILE_ATTRIBUTE_TAG_INFO_CLASS = 9

_FILE_TYPE_DISK = 0x0001
_FILE_NAME_OPENED = 0x00000008
_ERROR_FILE_NOT_FOUND = 2
_ERROR_PATH_NOT_FOUND = 3
_ERROR_FILE_EXISTS = 80
_ERROR_ALREADY_EXISTS = 183
_MISSING_ERRORS = {_ERROR_FILE_NOT_FOUND, _ERROR_PATH_NOT_FOUND}
_COLLISION_ERRORS = {_ERROR_FILE_EXISTS, _ERROR_ALREADY_EXISTS}
_INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value
_MAX_WRITE_CHUNK = 1024 * 1024

_INVALID_COMPONENT_CHARACTERS = frozenset('<>:"|?*')
_RESERVED_DEVICE_NAMES = {
    "AUX",
    "CON",
    "CONIN$",
    "CONOUT$",
    "NUL",
    "PRN",
    *(f"COM{number}" for number in range(1, 10)),
    *(f"LPT{number}" for number in range(1, 10)),
    *(f"COM{number}" for number in "¹²³"),
    *(f"LPT{number}" for number in "¹²³"),
}


class _FileAttributeTagInfo(ctypes.Structure):
    _fields_ = [
        ("FileAttributes", wintypes.DWORD),
        ("ReparseTag", wintypes.DWORD),
    ]


class _FileDispositionInfo(ctypes.Structure):
    _fields_ = [("DeleteFile", wintypes.BOOLEAN)]


class _FileRenameInfo(ctypes.Structure):
    # The first field is a union.  FileRenameInfo interprets its low byte as
    # ReplaceIfExists; representing the union as DWORD also provides the
    # correct alignment for RootDirectory on 32-bit and 64-bit Windows.
    _fields_ = [
        ("FlagsOrReplaceIfExists", wintypes.DWORD),
        ("RootDirectory", wintypes.HANDLE),
        ("FileNameLength", wintypes.DWORD),
        ("FileName", wintypes.WCHAR * 1),
    ]


class _OwnedHandle:
    """Own a Win32 HANDLE and close it exactly once."""

    def __init__(self, value: int) -> None:
        self.value: int | None = value

    def close(self) -> None:
        if self.value is not None:
            _close_handle(self.value)
            self.value = None

    def detach(self) -> int:
        if self.value is None:
            raise RuntimeError("handle is already closed")
        value = self.value
        self.value = None
        return value

    def __enter__(self) -> _OwnedHandle:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()


if os.name == "nt":
    _kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

    _CreateFileW = _kernel32.CreateFileW
    _CreateFileW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    ]
    _CreateFileW.restype = wintypes.HANDLE

    _CreateDirectoryW = _kernel32.CreateDirectoryW
    _CreateDirectoryW.argtypes = [wintypes.LPCWSTR, wintypes.LPVOID]
    _CreateDirectoryW.restype = wintypes.BOOL

    _CloseHandle = _kernel32.CloseHandle
    _CloseHandle.argtypes = [wintypes.HANDLE]
    _CloseHandle.restype = wintypes.BOOL

    _GetFileInformationByHandleEx = _kernel32.GetFileInformationByHandleEx
    _GetFileInformationByHandleEx.argtypes = [
        wintypes.HANDLE,
        ctypes.c_int,
        wintypes.LPVOID,
        wintypes.DWORD,
    ]
    _GetFileInformationByHandleEx.restype = wintypes.BOOL

    _GetFileType = _kernel32.GetFileType
    _GetFileType.argtypes = [wintypes.HANDLE]
    _GetFileType.restype = wintypes.DWORD

    _GetFinalPathNameByHandleW = _kernel32.GetFinalPathNameByHandleW
    _GetFinalPathNameByHandleW.argtypes = [
        wintypes.HANDLE,
        wintypes.LPWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
    ]
    _GetFinalPathNameByHandleW.restype = wintypes.DWORD

    _SetFileInformationByHandle = _kernel32.SetFileInformationByHandle
    _SetFileInformationByHandle.argtypes = [
        wintypes.HANDLE,
        ctypes.c_int,
        wintypes.LPVOID,
        wintypes.DWORD,
    ]
    _SetFileInformationByHandle.restype = wintypes.BOOL

    _WriteFile = _kernel32.WriteFile
    _WriteFile.argtypes = [
        wintypes.HANDLE,
        wintypes.LPCVOID,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
        wintypes.LPVOID,
    ]
    _WriteFile.restype = wintypes.BOOL

    _FlushFileBuffers = _kernel32.FlushFileBuffers
    _FlushFileBuffers.argtypes = [wintypes.HANDLE]
    _FlushFileBuffers.restype = wintypes.BOOL
else:
    _kernel32 = None


def _require_windows() -> None:
    if _kernel32 is None:
        raise WindowsScanLocalFileError(
            errno.ENOSYS,
            "secure Windows scan-local file operations require Windows",
        )


def _raise_last_error(operation: str, path: Path | None = None) -> None:
    error = ctypes.get_last_error()
    detail = ctypes.FormatError(error).strip()
    target = f" for {path}" if path is not None else ""
    raise WindowsScanLocalFileError(error, f"{operation}{target}: {detail}", str(path or ""))


def _invalid_path(path: Path | str, reason: str) -> WindowsScanLocalFileError:
    return WindowsScanLocalFileError(errno.EINVAL, reason, str(path))


def _validated_parts(relative_path: str) -> tuple[str, ...]:
    """Validate a POSIX contract path against Windows filesystem aliases."""

    path = PurePosixPath(relative_path)
    normalized = path.as_posix()
    if (
        not relative_path
        or normalized == "."
        or path.is_absolute()
        or ".." in path.parts
        or "\\" in relative_path
        or "\0" in relative_path
    ):
        raise _invalid_path(relative_path, "expected a safe scan-relative POSIX path")

    for component in path.parts:
        if (
            any(character in _INVALID_COMPONENT_CHARACTERS for character in component)
            or any(ord(character) < 32 for character in component)
            or component.endswith((" ", "."))
        ):
            raise _invalid_path(relative_path, "path contains a Windows-unsafe component")
        device_name = component.split(".", 1)[0].upper()
        if device_name in _RESERVED_DEVICE_NAMES:
            raise _invalid_path(relative_path, "path contains a reserved Windows device name")
    return path.parts


def _extended_path(path: Path) -> str:
    """Return a Win32 extended-length path so long scan paths remain usable."""

    value = str(path)
    if value.startswith("\\\\?\\"):
        return value
    if value.startswith("\\\\"):
        return "\\\\?\\UNC\\" + value[2:]
    return "\\\\?\\" + value


def _normalized_windows_path(path: Path | str) -> str:
    value = str(path)
    if value.startswith("\\\\?\\UNC\\"):
        value = "\\\\" + value[8:]
    elif value.startswith("\\\\?\\"):
        value = value[4:]
    return ntpath.normcase(ntpath.normpath(value))


def _close_handle(handle: int) -> None:
    _require_windows()
    if not _CloseHandle(handle):
        _raise_last_error("CloseHandle")


def _create_file(
    path: Path,
    *,
    access: int,
    share: int,
    disposition: int,
    flags: int,
    missing_ok: bool = False,
) -> _OwnedHandle | None:
    _require_windows()
    handle = _CreateFileW(
        _extended_path(path),
        access,
        share,
        None,
        disposition,
        flags,
        None,
    )
    if handle == _INVALID_HANDLE_VALUE:
        error = ctypes.get_last_error()
        if missing_ok and error in _MISSING_ERRORS:
            return None
        _raise_last_error("CreateFileW", path)
    return _OwnedHandle(int(handle))


def _attributes(handle: int) -> _FileAttributeTagInfo:
    info = _FileAttributeTagInfo()
    if not _GetFileInformationByHandleEx(
        handle,
        _FILE_ATTRIBUTE_TAG_INFO_CLASS,
        ctypes.byref(info),
        ctypes.sizeof(info),
    ):
        _raise_last_error("GetFileInformationByHandleEx")
    return info


def _final_path(handle: int, *, opened_name: bool = False) -> str:
    flags = _FILE_NAME_OPENED if opened_name else 0
    size = _GetFinalPathNameByHandleW(handle, None, 0, flags)
    if size == 0:
        _raise_last_error("GetFinalPathNameByHandleW")
    buffer = ctypes.create_unicode_buffer(size + 1)
    written = _GetFinalPathNameByHandleW(handle, buffer, len(buffer), flags)
    if written == 0 or written >= len(buffer):
        _raise_last_error("GetFinalPathNameByHandleW")
    return buffer.value


def _verify_handle_path(handle: int, expected_path: Path, *, opened_name: bool = False) -> None:
    actual = _normalized_windows_path(_final_path(handle, opened_name=opened_name))
    expected = _normalized_windows_path(expected_path)
    if actual != expected:
        raise _invalid_path(expected_path, "opened file resolved outside its verified scan path")


def _verify_directory(handle: int, expected_path: Path) -> None:
    info = _attributes(handle)
    if info.FileAttributes & _FILE_ATTRIBUTE_REPARSE_POINT:
        raise _invalid_path(expected_path, "scan-local directories must not be reparse points")
    if not info.FileAttributes & _FILE_ATTRIBUTE_DIRECTORY:
        raise _invalid_path(expected_path, "expected a scan-local directory")
    _verify_handle_path(handle, expected_path)


def _verify_regular_file(handle: int, expected_path: Path) -> None:
    info = _attributes(handle)
    if info.FileAttributes & _FILE_ATTRIBUTE_REPARSE_POINT:
        raise _invalid_path(expected_path, "scan-local files must not be reparse points")
    if info.FileAttributes & _FILE_ATTRIBUTE_DIRECTORY or _GetFileType(handle) != _FILE_TYPE_DISK:
        raise _invalid_path(expected_path, "expected a regular scan-local file")
    _verify_handle_path(handle, expected_path)


def _canonical_scan_directory(scan_dir: Path) -> tuple[Path, tuple[int, int]]:
    absolute = Path(scan_dir).absolute()
    try:
        expected = absolute.lstat()
        canonical = absolute.resolve(strict=True)
    except OSError as exc:
        raise _invalid_path(scan_dir, "expected an existing scan directory") from exc
    if _normalized_windows_path(absolute) != _normalized_windows_path(canonical):
        raise _invalid_path(scan_dir, "scan directory must be canonical and non-reparse")
    return canonical, (expected.st_dev, expected.st_ino)


def _open_directory(path: Path, *, missing_ok: bool = False) -> _OwnedHandle | None:
    handle = _create_file(
        path,
        access=_FILE_READ_ATTRIBUTES,
        share=_FILE_SHARE_READ | _FILE_SHARE_WRITE,
        disposition=_OPEN_EXISTING,
        flags=_FILE_FLAG_BACKUP_SEMANTICS | _FILE_FLAG_OPEN_REPARSE_POINT,
        missing_ok=missing_ok,
    )
    if handle is not None:
        try:
            assert handle.value is not None
            _verify_directory(handle.value, path)
        except BaseException:
            handle.close()
            raise
    return handle


def _create_directory(path: Path) -> None:
    if _CreateDirectoryW(_extended_path(path), None):
        return
    error = ctypes.get_last_error()
    if error not in _COLLISION_ERRORS:
        _raise_last_error("CreateDirectoryW", path)


@contextlib.contextmanager
def _locked_parent(
    scan_dir: Path,
    relative_path: str,
    *,
    create: bool,
) -> Iterator[tuple[Path, str]]:
    """Hold non-deletable handles for every directory in the absolute target path."""

    _require_windows()
    parts = _validated_parts(relative_path)
    root_path, expected_root_identity = _canonical_scan_directory(scan_dir)
    handles: list[_OwnedHandle] = []
    try:
        # Absolute-path Win32 calls remain safe only while every ancestor is
        # fixed in place. Otherwise an attacker could rename an ancestor of the
        # scan root and substitute a different tree at the stored path.
        for directory_path in (*reversed(root_path.parents), root_path):
            directory_handle = _open_directory(directory_path)
            assert directory_handle is not None
            handles.append(directory_handle)
        current_root = root_path.lstat()
        if (current_root.st_dev, current_root.st_ino) != expected_root_identity:
            raise _invalid_path(scan_dir, "scan directory changed while it was being opened")
        current_path = root_path
        for component in parts[:-1]:
            current_path /= component
            child_handle = _open_directory(current_path, missing_ok=create)
            if child_handle is None:
                _create_directory(current_path)
                child_handle = _open_directory(current_path)
                assert child_handle is not None
            handles.append(child_handle)
        yield current_path, parts[-1]
    finally:
        for handle in reversed(handles):
            handle.close()


def open_read_fd(scan_dir: Path, relative_path: str, context: str) -> int:
    """Open a verified regular file and return an owned binary read descriptor."""

    try:
        with _locked_parent(scan_dir, relative_path, create=False) as (parent_path, leaf_name):
            path = parent_path / leaf_name
            handle = _create_file(
                path,
                access=_GENERIC_READ | _FILE_READ_ATTRIBUTES,
                # Denying write/delete sharing keeps the opened contents stable.
                share=_FILE_SHARE_READ,
                disposition=_OPEN_EXISTING,
                flags=_FILE_FLAG_OPEN_REPARSE_POINT,
            )
            assert handle is not None and handle.value is not None
            try:
                _verify_regular_file(handle.value, path)
                raw_handle = handle.detach()
                try:
                    assert _msvcrt is not None
                    return _msvcrt.open_osfhandle(raw_handle, os.O_RDONLY | os.O_BINARY)
                except BaseException:
                    _close_handle(raw_handle)
                    raise
            finally:
                handle.close()
    except WindowsScanLocalFileError as exc:
        raise WindowsScanLocalFileError(
            exc.errno,
            f"{context}: {exc.strerror}",
            exc.filename,
        ) from exc


def _write_all(handle: int, payload: bytes) -> None:
    view = memoryview(payload)
    offset = 0
    while offset < len(view):
        chunk = bytes(view[offset : offset + _MAX_WRITE_CHUNK])
        buffer = ctypes.create_string_buffer(chunk, len(chunk))
        written = wintypes.DWORD()
        if not _WriteFile(handle, buffer, len(chunk), ctypes.byref(written), None):
            _raise_last_error("WriteFile")
        if written.value == 0:
            raise WindowsScanLocalFileError(errno.EIO, "WriteFile made no progress")
        offset += written.value
    if not _FlushFileBuffers(handle):
        _raise_last_error("FlushFileBuffers")


def _rename_handle(handle: int, destination_path: Path) -> None:
    encoded_name = _extended_path(destination_path).encode("utf-16-le")
    file_name_offset = _FileRenameInfo.FileName.offset
    buffer_size = max(
        ctypes.sizeof(_FileRenameInfo),
        file_name_offset + len(encoded_name) + ctypes.sizeof(wintypes.WCHAR),
    )
    buffer = ctypes.create_string_buffer(buffer_size)
    info = ctypes.cast(buffer, ctypes.POINTER(_FileRenameInfo)).contents
    info.FlagsOrReplaceIfExists = 1
    # The fully qualified destination uses a null RootDirectory. Verified
    # directory handles remain open to prevent ancestor replacement.
    info.RootDirectory = None
    info.FileNameLength = len(encoded_name)
    ctypes.memmove(ctypes.addressof(buffer) + file_name_offset, encoded_name, len(encoded_name))
    if not _SetFileInformationByHandle(
        handle,
        _FILE_RENAME_INFO_CLASS,
        buffer,
        buffer_size,
    ):
        _raise_last_error("SetFileInformationByHandle(FileRenameInfo)")


def _mark_handle_for_deletion(handle: int) -> None:
    info = _FileDispositionInfo(True)
    if not _SetFileInformationByHandle(
        handle,
        _FILE_DISPOSITION_INFO_CLASS,
        ctypes.byref(info),
        ctypes.sizeof(info),
    ):
        _raise_last_error("SetFileInformationByHandle(FileDispositionInfo)")


def _validate_existing_output(path: Path) -> None:
    handle = _create_file(
        path,
        access=_FILE_READ_ATTRIBUTES,
        share=_FILE_SHARE_READ | _FILE_SHARE_WRITE | _FILE_SHARE_DELETE,
        disposition=_OPEN_EXISTING,
        flags=_FILE_FLAG_OPEN_REPARSE_POINT | _FILE_FLAG_BACKUP_SEMANTICS,
        missing_ok=True,
    )
    if handle is None:
        return
    with handle:
        assert handle.value is not None
        _verify_regular_file(handle.value, path)


def atomic_write(scan_dir: Path, relative_path: str, payload: bytes) -> None:
    """Atomically replace a scan-local regular file with ``payload``."""

    with _locked_parent(scan_dir, relative_path, create=True) as (parent_path, leaf_name):
        destination_path = parent_path / leaf_name
        _validate_existing_output(destination_path)

        temp_handle: _OwnedHandle | None = None
        temp_path: Path | None = None
        for _ in range(16):
            temp_path = parent_path / f".{leaf_name}.{secrets.token_hex(8)}.tmp"
            try:
                temp_handle = _create_file(
                    temp_path,
                    access=_GENERIC_WRITE | _DELETE | _FILE_READ_ATTRIBUTES,
                    share=0,
                    disposition=_CREATE_NEW,
                    flags=_FILE_ATTRIBUTE_NORMAL,
                )
            except WindowsScanLocalFileError as exc:
                if exc.errno in _COLLISION_ERRORS:
                    continue
                raise
            break
        if temp_handle is None or temp_path is None:
            raise WindowsScanLocalFileError(errno.EEXIST, "could not allocate a unique temp file")

        with temp_handle:
            assert temp_handle.value is not None
            try:
                _verify_regular_file(temp_handle.value, temp_path)
                _write_all(temp_handle.value, payload)
                _rename_handle(temp_handle.value, destination_path)
                _verify_regular_file(temp_handle.value, destination_path)
            except BaseException:
                # Deleting by handle removes the exact temp/output file and cannot
                # be redirected through a swapped path or reparse point.
                try:
                    _mark_handle_for_deletion(temp_handle.value)
                except OSError:
                    pass
                raise


def unlink_if_exists(scan_dir: Path, relative_path: str) -> None:
    """Delete a scan-local regular file or reparse-point leaf without following it."""

    with _locked_parent(scan_dir, relative_path, create=False) as (parent_path, leaf_name):
        path = parent_path / leaf_name
        handle = _create_file(
            path,
            access=_DELETE | _FILE_READ_ATTRIBUTES,
            # Deny delete sharing so an existing delete-capable handle makes
            # cleanup fail instead of moving the verified object before delete.
            share=_FILE_SHARE_READ | _FILE_SHARE_WRITE,
            disposition=_OPEN_EXISTING,
            flags=_FILE_FLAG_OPEN_REPARSE_POINT | _FILE_FLAG_BACKUP_SEMANTICS,
            missing_ok=True,
        )
        if handle is None:
            return
        with handle:
            assert handle.value is not None
            info = _attributes(handle.value)
            is_reparse_point = bool(info.FileAttributes & _FILE_ATTRIBUTE_REPARSE_POINT)
            is_directory = bool(info.FileAttributes & _FILE_ATTRIBUTE_DIRECTORY)
            if is_directory and not is_reparse_point:
                raise _invalid_path(path, "scan-local cleanup target must not be a directory")
            _verify_handle_path(handle.value, path, opened_name=is_reparse_point)
            _mark_handle_for_deletion(handle.value)


def main() -> None:
    argparse.ArgumentParser(description=__doc__).parse_args()


if __name__ == "__main__":
    main()

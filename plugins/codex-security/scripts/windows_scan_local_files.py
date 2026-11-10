"""Secure scan-local file operations for Windows.

Windows does not implement Python's descriptor-relative ``dir_fd`` APIs or
``O_NOFOLLOW``.  This module provides the three operations needed by the scan
finalizer without falling back to check-then-use path validation.

Scan-local reads, writes, and deletes open every directory with
``FILE_FLAG_OPEN_REPARSE_POINT`` and reject all reparse points, including junctions.
Directory handles remain open without ``FILE_SHARE_DELETE`` for the full
operation, which prevents an
already-validated ancestor from being renamed or replaced during a read,
write, or delete.  Writes rename the exact temporary-file handle into place so
an attacker cannot substitute another file at the temporary name.

The snapshot helper copies junction metadata without opening the link target.

Importing this module and comparing streams work on every platform. Filesystem
operations raise ``WindowsScanLocalFileError`` outside Windows.
"""

from __future__ import annotations

import argparse
import contextlib
import ctypes
import ctypes.wintypes as wintypes
import errno
import functools
import importlib
import ntpath
import os
import secrets
import struct
from collections.abc import Callable, Iterator
from pathlib import Path, PurePosixPath
from typing import BinaryIO

_msvcrt = importlib.import_module("msvcrt") if os.name == "nt" else None


class WindowsScanLocalFileError(OSError):
    """Raised when a scan-local operation cannot be completed securely."""


class WindowsScanLocalPathError(WindowsScanLocalFileError):
    """Raised when a scan-local path fails an integrity check."""


# CreateFile access and sharing flags.
_DRIVE_FIXED = 3
_DELETE = 0x00010000
_FILE_ADD_SUBDIRECTORY = 0x00000004
_FILE_DELETE_CHILD = 0x00000040
_CHANGE_ACL = 0x000C0000  # WRITE_DAC | WRITE_OWNER
_SET_REPARSE_POINT = 0x00000102  # FILE_WRITE_ATTRIBUTES | FILE_WRITE_DATA
_OUTPUT_RIGHTS = (
    _DELETE | _FILE_ADD_SUBDIRECTORY | _FILE_DELETE_CHILD | _CHANGE_ACL | _SET_REPARSE_POINT
)
_FILE_TRAVERSE = 0x00000020
_FILE_READ_ATTRIBUTES = 0x00000080
_READ_CONTROL = 0x00020000
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
_ERROR_ACCESS_DENIED = 5
_ERROR_SHARING_VIOLATION = 32
_ERROR_LOCK_VIOLATION = 33
_ERROR_FILE_EXISTS = 80
_ERROR_INSUFFICIENT_BUFFER = 122
_ERROR_ALREADY_EXISTS = 183
_ERROR_DIRECTORY = 267
_OWNER_SECURITY_INFORMATION = 0x00000001
_DACL_SECURITY_INFORMATION = 0x00000004
_MISSING_ERRORS = {_ERROR_FILE_NOT_FOUND, _ERROR_PATH_NOT_FOUND}
_COLLISION_ERRORS = {_ERROR_FILE_EXISTS, _ERROR_ALREADY_EXISTS}
_INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value
_MAX_COMPARE_CHUNK = 64 * 1024
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


class _FileBasicInfo(ctypes.Structure):
    _fields_ = [
        ("CreationTime", ctypes.c_int64),
        ("LastAccessTime", ctypes.c_int64),
        ("LastWriteTime", ctypes.c_int64),
        ("ChangeTime", ctypes.c_int64),
        ("FileAttributes", wintypes.DWORD),
    ]


class _FileAttributeTagInfo(ctypes.Structure):
    _fields_ = [
        ("FileAttributes", wintypes.DWORD),
        ("ReparseTag", wintypes.DWORD),
    ]


class _SecurityAttributes(ctypes.Structure):
    _fields_ = [
        ("length", wintypes.DWORD),
        ("descriptor", wintypes.LPVOID),
        ("inherit", wintypes.BOOL),
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
    _advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    _ntdll = ctypes.WinDLL("ntdll")

    _GetFileSecurityW = _advapi32.GetFileSecurityW
    _GetFileSecurityW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
    ]
    _GetFileSecurityW.restype = wintypes.BOOL

    _GetDriveTypeW = _kernel32.GetDriveTypeW
    _GetDriveTypeW.argtypes = [wintypes.LPCWSTR]
    _GetDriveTypeW.restype = wintypes.UINT

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

    _ReOpenFile = _kernel32.ReOpenFile
    _ReOpenFile.argtypes = [wintypes.HANDLE, wintypes.DWORD, wintypes.DWORD, wintypes.DWORD]
    _ReOpenFile.restype = wintypes.HANDLE

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

    _DeviceIoControl = _kernel32.DeviceIoControl
    _DeviceIoControl.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
        wintypes.LPVOID,
    ]
    _DeviceIoControl.restype = wintypes.BOOL

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


def _invalid_path(path: Path | str, reason: str) -> WindowsScanLocalPathError:
    return WindowsScanLocalPathError(errno.EINVAL, reason, str(path))


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


def copy_directory_junction(source: Path, destination: Path) -> None:
    """Copy raw junction data to an empty directory without opening the link target."""
    # MAXIMUM_REPARSE_DATA_BUFFER_SIZE, including the reparse data header.
    data = ctypes.create_string_buffer(16 * 1024)
    size = wintypes.DWORD()
    for path, write in ((source, False), (destination, True)):
        handle = _create_file(
            path,
            access=_GENERIC_WRITE if write else _FILE_READ_ATTRIBUTES,
            share=_FILE_SHARE_READ | _FILE_SHARE_WRITE,
            disposition=_OPEN_EXISTING,
            flags=_FILE_FLAG_BACKUP_SEMANTICS | _FILE_FLAG_OPEN_REPARSE_POINT,
        )
        assert handle is not None
        with handle:
            if not _DeviceIoControl(
                handle.value,
                0x000900A4 if write else 0x000900A8,  # FSCTL_SET/GET_REPARSE_POINT.
                data if write else None,
                size.value if write else 0,
                None if write else data,
                0 if write else len(data),
                ctypes.byref(size),
                None,
            ):
                _raise_last_error("Copy directory junction", path)


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
        if exc.errno not in {errno.ENOENT, errno.ENOTDIR, errno.ELOOP}:
            raise
        raise _invalid_path(scan_dir, "expected an existing scan directory") from exc
    if _normalized_windows_path(absolute) != _normalized_windows_path(canonical):
        raise _invalid_path(scan_dir, "scan directory must be canonical and non-reparse")
    return canonical, (expected.st_dev, expected.st_ino)


def _open_directory(
    path: Path,
    *,
    missing_ok: bool = False,
    missing_is_path_error: bool = True,
    movable: bool = False,
) -> _OwnedHandle | None:
    try:
        handle = _create_file(
            path,
            # Attribute-only handles do not participate in Win32 sharing checks.
            access=_FILE_READ_ATTRIBUTES | (0 if movable else _FILE_TRAVERSE),
            share=_FILE_SHARE_READ | _FILE_SHARE_WRITE | (_FILE_SHARE_DELETE if movable else 0),
            disposition=_OPEN_EXISTING,
            flags=_FILE_FLAG_BACKUP_SEMANTICS | _FILE_FLAG_OPEN_REPARSE_POINT,
            missing_ok=missing_ok,
        )
    except WindowsScanLocalFileError as exc:
        if exc.errno != _ERROR_DIRECTORY and not (
            missing_is_path_error and exc.errno in _MISSING_ERRORS
        ):
            raise
        raise _invalid_path(path, f"could not open scan-local directory: {exc}") from exc
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


def _directory_security_descriptor(source: Path, information: int) -> ctypes.Array:
    source_path = _extended_path(source)
    size = wintypes.DWORD()
    _GetFileSecurityW(source_path, information, None, 0, ctypes.byref(size))
    if ctypes.get_last_error() != _ERROR_INSUFFICIENT_BUFFER:
        _raise_last_error("GetFileSecurityW", source)
    descriptor = ctypes.create_string_buffer(size.value)
    if not _GetFileSecurityW(source_path, information, descriptor, size.value, ctypes.byref(size)):
        _raise_last_error("GetFileSecurityW", source)
    return descriptor


def _sid_text(sid: wintypes.LPVOID) -> str:
    value = wintypes.LPWSTR()
    if not _advapi32.ConvertSidToStringSidW(sid, ctypes.byref(value)):
        _raise_last_error("ConvertSidToStringSidW")
    try:
        return value.value
    finally:
        _kernel32.LocalFree(value)


@functools.cache
def _current_user_sid() -> str:
    token = wintypes.HANDLE(-4)  # GetCurrentProcessToken pseudo-handle.
    size = wintypes.DWORD()
    _advapi32.GetTokenInformation(token, 1, None, 0, ctypes.byref(size))
    if ctypes.get_last_error() != _ERROR_INSUFFICIENT_BUFFER:
        _raise_last_error("GetTokenInformation")
    user = ctypes.create_string_buffer(size.value)
    if not _advapi32.GetTokenInformation(token, 1, user, size, ctypes.byref(size)):
        _raise_last_error("GetTokenInformation")
    return _sid_text(wintypes.LPVOID.from_buffer(user))


def _output_directory_grants(handle: int, path: Path) -> int:
    """Inspect the descriptor of the opened directory, even if its pathname changes."""
    owner, acl, descriptor = wintypes.LPVOID(), wintypes.LPVOID(), wintypes.LPVOID()
    status = _advapi32.GetSecurityInfo(
        wintypes.HANDLE(handle),
        1,
        _OWNER_SECURITY_INFORMATION | _DACL_SECURITY_INFORMATION,
        ctypes.byref(owner),
        None,
        ctypes.byref(acl),
        None,
        ctypes.byref(descriptor),
    )
    if status:
        raise ctypes.WinError(status)
    try:
        trusted = {
            _current_user_sid(),
            "S-1-5-18",
            "S-1-5-32-544",  # Current user, SYSTEM, Administrators.
            "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464",  # TrustedInstaller.
        }
        if _sid_text(owner) not in trusted:
            raise _invalid_path(path, "Scan output directory must have a trusted owner.")
        return _output_dacl_grants(acl, trusted, path)
    finally:
        _kernel32.LocalFree(descriptor)


def _authenticated_account(sid: wintypes.LPVOID, trustee: str) -> bool:
    # The Guest account can have its own SID without Authenticated Users membership.
    if not trustee.startswith("S-1-5-21-") or trustee.endswith("-501"):
        return False
    name_size, domain_size, sid_type = (ctypes.pointer(wintypes.DWORD()) for _ in range(3))
    lookup = _advapi32.LookupAccountSidW
    lookup(None, sid, None, name_size, None, domain_size, sid_type)
    if ctypes.get_last_error() != _ERROR_INSUFFICIENT_BUFFER:
        return False
    name = ctypes.create_unicode_buffer(name_size.contents.value)
    domain = ctypes.create_unicode_buffer(domain_size.contents.value)
    found = lookup(None, sid, name, name_size, domain, domain_size, sid_type)
    return bool(found) and sid_type.contents.value == 1  # SidTypeUser


def _output_dacl_grants(acl: wintypes.LPVOID, trusted: set[str], path: Path) -> int:
    if not acl.value:  # A NULL DACL grants full access.
        return _OUTPUT_RIGHTS
    # Read ACEs in DACL order. A deny masks future grants for its trustee.
    denied: dict[str, int] = {}
    granted = 0
    for index in range(wintypes.WORD.from_address(acl.value + 4).value):  # ACL.AceCount
        ace = wintypes.LPVOID()
        if not _advapi32.GetAce(acl, index, ctypes.byref(ace)):
            _raise_last_error("GetAce", path)
        kind, flags, size = struct.unpack("<BBH", ctypes.string_at(ace, 4))
        if flags & 8 or kind in {10, 12}:  # INHERIT_ONLY or conditional deny.
            continue
        entry = ctypes.string_at(ace, size)
        mask = struct.unpack_from("<I", entry, 4)[0]
        if mask & 0x10000000:  # GENERIC_ALL
            mask |= _OUTPUT_RIGHTS
        if mask & _GENERIC_WRITE:
            mask |= _FILE_ADD_SUBDIRECTORY | _SET_REPARSE_POINT
        mask &= _OUTPUT_RIGHTS
        if not mask:
            continue
        offset = 8  # ACE_HEADER and ACCESS_MASK precede the trustee SID.
        if kind in {5, 6, 11}:
            object_flags = struct.unpack_from("<I", entry, offset)[0]
            offset += 4 + 16 * (object_flags & 3).bit_count()
            if kind == 6 and object_flags & 1:
                continue  # This deny is scoped to a particular object type.
        elif kind not in {0, 1, 9}:
            raise _invalid_path(path, "Unable to evaluate scan output directory permissions.")
        if len(entry) < offset + 8 or len(entry) < offset + 8 + 4 * entry[offset + 1]:
            raise _invalid_path(path, "Invalid scan output directory trustee.")
        sid = wintypes.LPVOID(ace.value + offset)
        trustee = _sid_text(sid)
        if trustee in trusted or trustee == "S-1-3-4":  # OWNER RIGHTS applies to the checked owner.
            continue
        if kind in {1, 6}:
            denied[trustee] = denied.get(trustee, 0) | mask
        else:
            blocked = denied.get(trustee, 0) | denied.get("S-1-1-0", 0)
            authenticated = denied.get("S-1-5-11", 0)
            if mask & authenticated and _authenticated_account(sid, trustee):
                blocked |= authenticated
            granted |= mask & ~blocked
    if granted & _CHANGE_ACL:
        granted |= _OUTPUT_RIGHTS
    return granted


def _require_stable_output(path: Path, parent_grants: int, child_grants: int = 0) -> None:
    can_remove = parent_grants & _FILE_DELETE_CHILD or child_grants & _DELETE
    can_replace = parent_grants & (_FILE_ADD_SUBDIRECTORY | _SET_REPARSE_POINT)
    if can_remove and can_replace:
        raise _invalid_path(path, "Scan output directory can be replaced by another user.")


@contextlib.contextmanager
def _checked_output_directory(path: Path) -> Iterator[tuple[int, int]]:
    """Hold the checked canonical chain and expose its final directory handle and grants."""
    parent_grants = 0
    parent = None
    with contextlib.ExitStack() as pins:
        for directory in (*reversed(path.parents), path):
            if parent is None:
                handle = _create_file(
                    directory,
                    access=_FILE_TRAVERSE | _FILE_READ_ATTRIBUTES | _READ_CONTROL,
                    share=_FILE_SHARE_READ | _FILE_SHARE_WRITE,
                    disposition=_OPEN_EXISTING,
                    flags=_FILE_FLAG_BACKUP_SEMANTICS | _FILE_FLAG_OPEN_REPARSE_POINT,
                )
                assert handle is not None
            else:
                error, child = _relative_output_directory(parent, directory.name)
                if error:
                    raise WindowsScanLocalPathError(
                        error, ctypes.FormatError(error), str(directory)
                    )
                handle = _OwnedHandle(child)
            pins.enter_context(handle)
            assert handle.value is not None
            _verify_directory(handle.value, directory)
            grants = _output_directory_grants(handle.value, directory)
            _require_stable_output(directory, parent_grants, grants)
            parent, parent_grants = handle.value, grants
        yield parent, parent_grants


def require_windows_output_path(path: Path, *, writable_output: bool = False) -> None:
    with _checked_output_directory(path) as (_, grants):
        if writable_output and grants & _SET_REPARSE_POINT:
            raise _invalid_path(
                path, "Another user can turn the output directory into a reparse point when empty."
            )


class _UnicodeString(ctypes.Structure):
    _fields_ = [
        ("length", wintypes.USHORT),
        ("capacity", wintypes.USHORT),
        ("text", wintypes.LPWSTR),
    ]


class _ObjectAttributes(ctypes.Structure):
    _fields_ = [
        ("length", wintypes.ULONG),
        ("root", wintypes.HANDLE),
        ("name", ctypes.POINTER(_UnicodeString)),
        ("attributes", wintypes.ULONG),
        ("security", wintypes.LPVOID),
        ("qos", wintypes.LPVOID),
    ]


def _relative_output_directory(
    parent: int, basename: str, descriptor=None
) -> tuple[int, int | None]:
    """Open or create one component relative to its checked parent without reparsing it."""
    size = len(basename.encode("utf-16-le", errors="surrogatepass"))
    if size >= 1 << 16:  # UNICODE_STRING.Length is a byte count in a USHORT.
        return 206, None
    name = _UnicodeString(size, size, basename)
    attributes = _ObjectAttributes(
        ctypes.sizeof(_ObjectAttributes),
        parent,
        ctypes.pointer(name),
        0x40 | 0x1000,  # OBJ_CASE_INSENSITIVE | OBJ_DONT_REPARSE
        descriptor,
        None,
    )
    handle = wintypes.HANDLE()
    io_status = (ctypes.c_void_p * 2)()  # IO_STATUS_BLOCK
    status = _ntdll.NtCreateFile(
        ctypes.byref(handle),
        _FILE_TRAVERSE | _FILE_READ_ATTRIBUTES | _READ_CONTROL | 0x100000,
        ctypes.byref(attributes),
        ctypes.byref(io_status),
        None,
        _FILE_ATTRIBUTE_NORMAL,
        _FILE_SHARE_READ | _FILE_SHARE_WRITE,
        1 if descriptor is None else 2,  # FILE_OPEN or FILE_CREATE
        0x200021,  # FILE_OPEN_REPARSE_POINT | FILE_SYNCHRONOUS_IO_NONALERT | FILE_DIRECTORY_FILE
        None,
        0,
    )
    return (_ntdll.RtlNtStatusToDosError(status), None) if status < 0 else (0, handle.value)


def create_windows_output_directory(path: Path, descriptor: wintypes.LPVOID) -> int:
    with _checked_output_directory(path.parent) as (parent, grants):
        _require_stable_output(path, grants)
        error, handle = _relative_output_directory(parent, path.name, descriptor)
        if not error:
            _close_handle(handle)
        return error


def create_private_directory(path: Path, *, exist_ok: bool, scan_output: bool) -> Path:
    """Create one Windows directory with a protected inheritable DACL."""
    _require_windows()
    # Older supported Python releases ignore mkdir's 0700 mode on Windows.
    # Apply the same owner/SYSTEM/Administrators policy at creation so a
    # writable parent never becomes an inheritance window.
    volume = ctypes.create_unicode_buffer(32768)
    flags = wintypes.DWORD()
    if not _kernel32.GetVolumePathNameW(str(path.parent.resolve()), volume, len(volume)):
        raise ctypes.WinError(ctypes.get_last_error())
    if not _kernel32.GetVolumeInformationW(
        volume, None, 0, None, None, ctypes.byref(flags), None, 0
    ):
        raise ctypes.WinError(ctypes.get_last_error())
    if not flags.value & 0x8:  # FILE_PERSISTENT_ACLS
        raise ValueError("Select a directory on a Windows volume that supports ACLs.")

    sid = _current_user_sid()
    owner = "" if exist_ok else f"O:{sid}"
    dacl = f"{owner}D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;{sid})"

    descriptor = wintypes.LPVOID()
    if not _advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW(
        dacl, 1, ctypes.byref(descriptor), None
    ):
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        if scan_output:
            error = create_windows_output_directory(path, descriptor)
        else:
            attributes = _SecurityAttributes(ctypes.sizeof(_SecurityAttributes), descriptor, False)
            error = (
                0
                if _CreateDirectoryW(str(path), ctypes.byref(attributes))
                else ctypes.get_last_error()
            )
        if not error:
            return path if exist_ok else verify_private_scan_root(path, descriptor)
        if exist_ok and error == 183 and path.is_dir():  # ERROR_ALREADY_EXISTS
            if scan_output:
                require_windows_output_path(path)
            return path
        raise ctypes.WinError(error)
    finally:
        _kernel32.LocalFree(descriptor)


def create_directory_with_same_dacl(path: Path, source: Path) -> None:
    """Create an archive replacement with the original directory's DACL."""
    _require_windows()
    descriptor = _directory_security_descriptor(source, _DACL_SECURITY_INFORMATION)
    error = create_windows_output_directory(path, ctypes.cast(descriptor, wintypes.LPVOID))
    if error:
        raise WindowsScanLocalFileError(error, ctypes.FormatError(error), str(path))


@contextlib.contextmanager
def _locked_parent(
    scan_dir: Path,
    relative_path: str,
    *,
    create: bool,
    missing_is_path_error: bool = True,
    expected_root_identity: tuple[int, int] | None = None,
) -> Iterator[tuple[Path, str]]:
    """Hold non-deletable handles for every directory in the absolute target path."""

    _require_windows()
    parts = _validated_parts(relative_path)
    root_path, observed_root_identity = _canonical_scan_directory(scan_dir)
    if expected_root_identity is not None and observed_root_identity != expected_root_identity:
        raise _invalid_path(scan_dir, "scan directory changed after artifact restoration setup")
    handles: list[_OwnedHandle] = []
    try:
        # Absolute-path Win32 calls remain safe only while every ancestor is
        # fixed in place. Otherwise an attacker could rename an ancestor of the
        # scan root and substitute a different tree at the stored path.
        for directory_path in (*reversed(root_path.parents), root_path):
            directory_handle = _open_directory(directory_path)
            assert directory_handle is not None
            handles.append(directory_handle)
        try:
            current_root = root_path.lstat()
        except OSError as exc:
            if exc.errno not in {errno.ENOENT, errno.ENOTDIR, errno.ELOOP}:
                raise
            raise _invalid_path(
                scan_dir, f"scan directory changed while it was being opened: {exc}"
            ) from exc
        current_root_identity = (current_root.st_dev, current_root.st_ino)
        if current_root_identity != observed_root_identity or (
            expected_root_identity is not None and current_root_identity != expected_root_identity
        ):
            raise _invalid_path(scan_dir, "scan directory changed while it was being opened")
        current_path = root_path
        for component in parts[:-1]:
            current_path /= component
            child_handle = _open_directory(
                current_path, missing_ok=create, missing_is_path_error=missing_is_path_error
            )
            if child_handle is None:
                _create_directory(current_path)
                child_handle = _open_directory(current_path)
                assert child_handle is not None
            handles.append(child_handle)
        yield current_path, parts[-1]
    finally:
        for handle in reversed(handles):
            handle.close()


def _generated_directory_policy(descriptor: object) -> tuple[str, bool, frozenset[str]]:
    # Let Windows normalize SID aliases, access masks and inheritance flags in
    # both descriptors. ACE order is immaterial for our three allow grants.
    sddl = wintypes.LPWSTR()
    if not _advapi32.ConvertSecurityDescriptorToStringSecurityDescriptorW(
        descriptor,
        1,
        _OWNER_SECURITY_INFORMATION | _DACL_SECURITY_INFORMATION,
        ctypes.byref(sddl),
        None,
    ):
        _raise_last_error("ConvertSecurityDescriptorToStringSecurityDescriptorW")
    try:
        owner, _, dacl = sddl.value.partition("D:")
        flags, _, entries = dacl.partition("(")
        return owner, "P" in flags, frozenset(entries.removesuffix(")").split(")("))
    finally:
        _kernel32.LocalFree(sddl)


def verify_private_scan_root(scan_dir: Path, expected_descriptor: object) -> Path:
    """Verify the new directory's owner and protected grants while the path is pinned."""
    with _locked_parent(scan_dir, ".security", create=False) as (root_path, _):
        actual = _directory_security_descriptor(
            root_path, _OWNER_SECURITY_INFORMATION | _DACL_SECURITY_INFORMATION
        )
        if _generated_directory_policy(actual) != _generated_directory_policy(expected_descriptor):
            raise _invalid_path(scan_dir, "new scan directory lacks its private owner or DACL")
        return root_path


def scan_root_identity(scan_dir: Path) -> tuple[Path, tuple[int, int]]:
    """Return a canonical scan root and its identity while holding it fixed."""

    with _locked_parent(scan_dir, ".identity", create=False) as (root_path, _):
        metadata = root_path.lstat()
        return root_path, (metadata.st_dev, metadata.st_ino)


@contextlib.contextmanager
def pinned_root_git_marker(
    cwd: Path, metadata: Path, *, work_tree: Path | None = None
) -> Iterator[Path | None]:
    """Return a short explicit worktree marker while its cwd and Git metadata are pinned."""
    if work_tree is None:
        work_tree = cwd
    if (
        not cwd.is_absolute()
        or not metadata.is_absolute()
        or len(cwd.drive) != 2
        or len(metadata.drive) != 2
        or len(work_tree.parts) < 2
        or cwd.parts[: len(work_tree.parts)] != work_tree.parts
        or len(metadata.parts) < 2
        or _GetDriveTypeW(cwd.anchor) != _DRIVE_FIXED
        or _GetDriveTypeW(metadata.anchor) != _DRIVE_FIXED
    ):
        yield None
        return
    marker = None
    with contextlib.ExitStack() as pins:
        try:
            for path in (cwd, metadata):
                _validated_parts(PurePosixPath(*path.parts[1:]).as_posix())
                # Pin each literal ancestor before opening the next component. Never resolve
                # a repository-controlled reparse point to find the directory to be pinned.
                for directory in (*reversed(path.parents), path):
                    handle = _open_directory(directory)
                    assert handle is not None
                    pins.enter_context(handle)
                assert handle.value is not None
                if _final_path(handle.value) != _extended_path(path):
                    raise ValueError("the selected Git directory spelling is not canonical")
            root_marker = work_tree / ".git"
            reference = Path(os.path.relpath(root_marker, cwd))
            if str(root_marker) != str(metadata):
                # The literal canonical root is already pinned before opening its regular file.
                fd, leaf = open_read_fd_with_path(work_tree, ".git", "Git metadata pointer")
                pointer = pins.enter_context(os.fdopen(fd, "rb"))
                if leaf != ".git":
                    raise ValueError("the root marker name does not match .git")
                expected = f"gitdir: {metadata}".encode("utf-8")
                value = pointer.read(len(expected) + 3).removesuffix(b"\n").removesuffix(b"\r")
                if value.replace(b"/", b"\\") != expected:
                    raise ValueError("the root marker does not name the selected Git directory")
                # A deep scope can make the relative spelling longer than the gitfile itself.
                if len(os.fsencode(root_marker)) < len(os.fsencode(reference)):
                    reference = root_marker
            marker = reference
        except (OSError, ValueError):
            pins.close()
        yield marker


def open_read_fd(scan_dir: Path, relative_path: str, context: str) -> int:
    """Open a verified regular file and return an owned binary read descriptor."""

    return open_read_fd_with_path(scan_dir, relative_path, context)[0]


def open_read_fd_with_path(scan_dir: Path, relative_path: str, context: str) -> tuple[int, str]:
    """Return an owned read descriptor and the scan-relative path with the file's actual leaf name.

    Verify the regular file while holding its parent directories. The caller must
    close the returned descriptor.
    """

    try:
        with _locked_parent(scan_dir, relative_path, create=False, missing_is_path_error=False) as (
            parent_path,
            leaf_name,
        ):
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
            with handle:
                _verify_regular_file(handle.value, path)
                filename = Path(_final_path(handle.value)).name
                resolved_path = PurePosixPath(relative_path).with_name(filename).as_posix()
                raw_handle = handle.detach()
                try:
                    assert _msvcrt is not None
                    descriptor = _msvcrt.open_osfhandle(raw_handle, os.O_RDONLY | os.O_BINARY)
                    return descriptor, resolved_path
                except BaseException:
                    _close_handle(raw_handle)
                    raise
    except WindowsScanLocalFileError as exc:
        raise WindowsScanLocalFileError(
            exc.errno,
            f"{context}: {exc.strerror}",
            exc.filename,
        ) from exc


def file_change_time(descriptor: int) -> int:
    """Return the filesystem change time. Python's Windows st_ctime is creation time."""
    assert _msvcrt is not None
    info = _FileBasicInfo()
    if not _GetFileInformationByHandleEx(
        _msvcrt.get_osfhandle(descriptor), 0, ctypes.byref(info), ctypes.sizeof(info)
    ):
        _raise_last_error("GetFileInformationByHandleEx(FileBasicInfo)")
    return info.ChangeTime


def stream_matches_payload(stream: BinaryIO, payload: bytes) -> bool:
    """Compare bytes from the current stream position to payload, requiring EOF after the final byte."""
    offset = 0
    while offset < len(payload):
        chunk = stream.read(min(_MAX_COMPARE_CHUNK, len(payload) - offset))
        if not chunk or chunk != payload[offset : offset + len(chunk)]:
            return False
        offset += len(chunk)
    return stream.read(1) == b""


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


def _rename_handle(handle: int, destination_path: Path, replace_existing: bool) -> None:
    encoded_name = _extended_path(destination_path).encode("utf-16-le")
    file_name_offset = _FileRenameInfo.FileName.offset
    buffer_size = max(
        ctypes.sizeof(_FileRenameInfo),
        file_name_offset + len(encoded_name) + ctypes.sizeof(wintypes.WCHAR),
    )
    buffer = ctypes.create_string_buffer(buffer_size)
    info = ctypes.cast(buffer, ctypes.POINTER(_FileRenameInfo)).contents
    info.FlagsOrReplaceIfExists = int(replace_existing)
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
        if not replace_existing and ctypes.get_last_error() in _COLLISION_ERRORS:
            raise FileExistsError(errno.EEXIST, os.strerror(errno.EEXIST), str(destination_path))
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


def _validate_existing_output(path: Path) -> bool:
    handle = _create_file(
        path,
        access=_FILE_READ_ATTRIBUTES,
        share=_FILE_SHARE_READ | _FILE_SHARE_WRITE | _FILE_SHARE_DELETE,
        disposition=_OPEN_EXISTING,
        flags=_FILE_FLAG_OPEN_REPARSE_POINT | _FILE_FLAG_BACKUP_SEMANTICS,
        missing_ok=True,
    )
    if handle is None:
        return False
    with handle:
        assert handle.value is not None
        _verify_regular_file(handle.value, path)
    return True


def _existing_output_matches(path: Path, payload: bytes) -> bool:
    try:
        handle = _create_file(
            path,
            access=_GENERIC_READ | _FILE_READ_ATTRIBUTES,
            # Deny write and delete sharing while comparing the opened contents.
            share=_FILE_SHARE_READ,
            disposition=_OPEN_EXISTING,
            flags=_FILE_FLAG_OPEN_REPARSE_POINT | _FILE_FLAG_BACKUP_SEMANTICS,
            missing_ok=True,
        )
    except WindowsScanLocalFileError as exc:
        if exc.errno in {
            _ERROR_ACCESS_DENIED,
            _ERROR_SHARING_VIOLATION,
            _ERROR_LOCK_VIOLATION,
        }:
            return False
        raise
    if handle is None:
        return False
    with handle:
        assert handle.value is not None
        _verify_regular_file(handle.value, path)
        raw_handle = handle.detach()
        try:
            assert _msvcrt is not None
            descriptor = _msvcrt.open_osfhandle(raw_handle, os.O_RDONLY | os.O_BINARY)
        except BaseException:
            _close_handle(raw_handle)
            raise
        try:
            with os.fdopen(descriptor, "rb") as stream:
                if os.fstat(stream.fileno()).st_size != len(payload):
                    return False
                return stream_matches_payload(stream, payload)
        except OSError:
            return False


@contextlib.contextmanager
def _written_temp(destination: Path, payload: bytes) -> Iterator[tuple[Path, _OwnedHandle]]:
    for _ in range(16):
        path = destination.with_name(f".{destination.name}.{secrets.token_hex(8)}.tmp")
        try:
            handle = _create_file(
                path,
                access=_GENERIC_WRITE | _DELETE | _FILE_READ_ATTRIBUTES,
                share=0,
                disposition=_CREATE_NEW,
                flags=_FILE_ATTRIBUTE_NORMAL,
            )
        except WindowsScanLocalFileError as exc:
            if exc.errno in _COLLISION_ERRORS:
                continue
            raise
        assert handle is not None and handle.value is not None
        with handle:
            try:
                _verify_regular_file(handle.value, path)
                _write_all(handle.value, payload)
                yield path, handle
            except BaseException:
                if handle.value is not None:
                    with contextlib.suppress(OSError):
                        _mark_handle_for_deletion(handle.value)
                raise
        return
    raise WindowsScanLocalFileError(errno.EEXIST, "could not allocate a unique temp file")


def _stage_metadata(
    handle: _OwnedHandle, *, close_writer: bool = False
) -> tuple[os.stat_result, int]:
    # Windows can update LastWriteTime on last writer close. Observe the same
    # file across that close, independently of whatever is now at the name.
    assert handle.value is not None and _msvcrt is not None
    raw = _ReOpenFile(
        handle.value,
        _FILE_READ_ATTRIBUTES,
        _FILE_SHARE_READ | _FILE_SHARE_WRITE | _FILE_SHARE_DELETE,
        0,
    )
    if raw is None or raw == _INVALID_HANDLE_VALUE:
        _raise_last_error("ReOpenFile")
    with _OwnedHandle(raw) as observer:
        descriptor = _msvcrt.open_osfhandle(raw, os.O_RDONLY | os.O_BINARY)
        observer.detach()
        try:
            if close_writer:
                handle.close()
            try:
                return os.fstat(descriptor), file_change_time(descriptor)
            except BaseException:
                if close_writer:
                    # The observer still identifies the staged file after the writer closed.
                    cleanup = _ReOpenFile(
                        raw, _DELETE, _FILE_SHARE_READ | _FILE_SHARE_WRITE | _FILE_SHARE_DELETE, 0
                    )
                    if cleanup and cleanup != _INVALID_HANDLE_VALUE:
                        with _OwnedHandle(cleanup), contextlib.suppress(OSError):
                            _mark_handle_for_deletion(cleanup)
                raise
        finally:
            os.close(descriptor)


@contextlib.contextmanager
def stage_write(
    scan_dir: Path,
    relative_path: str,
    payload: bytes,
    *,
    expected_root_identity: tuple[int, int] | None = None,
    replace_existing: bool = False,
) -> Iterator[Callable[..., tuple[os.stat_result, int]]]:
    """Flush a patch and keep only a movable handle to its root across admission."""
    if expected_root_identity is None:
        root = scan_dir.lstat()
        expected_root_identity = (root.st_dev, root.st_ino)
    with _locked_parent(
        scan_dir, relative_path, create=True, expected_root_identity=expected_root_identity
    ) as (parent, leaf):
        destination = parent / leaf
        if _validate_existing_output(destination) and not replace_existing:
            raise FileExistsError(errno.EEXIST, os.strerror(errno.EEXIST), str(destination))
        root_handle = _open_directory(scan_dir, movable=True)
        assert root_handle is not None
        try:
            with _written_temp(destination, payload) as (temp, writer):
                staged, change_time = _stage_metadata(writer, close_writer=True)
        except BaseException:
            root_handle.close()
            raise

    location = scan_dir
    published = False

    @contextlib.contextmanager
    def open_stage() -> Iterator[tuple[_OwnedHandle, Path]]:
        with _locked_parent(
            location, relative_path, create=False, expected_root_identity=expected_root_identity
        ) as (parent, leaf):
            path = parent / temp.name
            handle = _create_file(
                path,
                access=_DELETE | _FILE_READ_ATTRIBUTES,
                share=0,
                disposition=_OPEN_EXISTING,
                flags=_FILE_FLAG_OPEN_REPARSE_POINT | _FILE_FLAG_BACKUP_SEMANTICS,
            )
            assert handle is not None and handle.value is not None
            with handle:
                _verify_regular_file(handle.value, path)
                current, changed = _stage_metadata(handle)
                if not (
                    os.path.samestat(staged, current)
                    and staged.st_size == current.st_size
                    and staged.st_mtime_ns == current.st_mtime_ns
                    and change_time == changed
                ):
                    raise _invalid_path(path, "staged patch changed before publication")
                yield handle, parent / leaf

    def publish(directory: Path | None = None) -> tuple[os.stat_result, int]:
        nonlocal location, published
        if directory is not None:
            location = directory
        with open_stage() as (handle, destination):
            assert handle.value is not None
            _rename_handle(handle.value, destination, replace_existing)
            published = True
            _verify_regular_file(handle.value, destination)
            return _stage_metadata(handle)

    with root_handle:
        try:
            yield publish
        finally:
            if not published:
                # A different workbench database may own the archive move.
                assert root_handle.value is not None
                with contextlib.suppress(OSError):
                    location = Path(_final_path(root_handle.value))
                    while True:
                        try:
                            with open_stage() as (handle, _):
                                assert handle.value is not None
                                _mark_handle_for_deletion(handle.value)
                            break
                        except OSError:
                            # A move can land between locating the root and fixing its parents.
                            moved_to = Path(_final_path(root_handle.value))
                            if moved_to == location:
                                break
                            location = moved_to


def atomic_write(
    scan_dir: Path,
    relative_path: str,
    payload: bytes,
    *,
    expected_root_identity: tuple[int, int] | None = None,
    replace_existing: bool = True,
) -> None:
    """Atomically publish ``payload`` to a scan-local regular file."""
    with _locked_parent(
        scan_dir, relative_path, create=True, expected_root_identity=expected_root_identity
    ) as (parent, leaf):
        destination = parent / leaf
        if _validate_existing_output(destination) and not replace_existing:
            raise FileExistsError(errno.EEXIST, os.strerror(errno.EEXIST), str(destination))
        if (
            replace_existing
            and expected_root_identity is not None
            and _existing_output_matches(destination, payload)
        ):
            return
        with _written_temp(destination, payload) as (_, handle):
            assert handle.value is not None
            _rename_handle(handle.value, destination, replace_existing)
            _verify_regular_file(handle.value, destination)


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


if __name__ == "__main__":
    argparse.ArgumentParser(description=__doc__).parse_args()

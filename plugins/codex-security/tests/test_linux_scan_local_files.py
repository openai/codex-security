"""Exercise the Linux syscall fallback for exclusive scan-local file publication."""

import ctypes
import os
import sys
import sysconfig
from types import SimpleNamespace

import pytest
from workbench_test_support import load_script


@pytest.mark.skipif(
    sys.platform != "linux"
    or (sysconfig.get_config_var("MULTIARCH") or "").partition("-")[0] not in {"x86_64", "aarch64"}
    or ctypes.sizeof(ctypes.c_void_p) != 8,
    reason="requires a supported 64-bit Linux syscall ABI",
)
def test_exclusive_rename_without_a_libc_wrapper(tmp_path, monkeypatch):
    writer = load_script("posix_scan_local_files")
    libc = SimpleNamespace(syscall=ctypes.CDLL(None, use_errno=True).syscall)
    monkeypatch.setattr(ctypes, "CDLL", lambda *args, **kwargs: libc)
    staged = tmp_path / "staged"
    target = tmp_path / "résumé.patch"
    staged.write_bytes(b"first")
    original = staged.stat()
    parent_fd = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        writer._rename_exclusive(parent_fd, staged.name, target.name)
        assert os.path.samestat(target.stat(), original)
        staged.write_bytes(b"second")
        with pytest.raises(FileExistsError):
            writer._rename_exclusive(parent_fd, staged.name, target.name)
    finally:
        os.close(parent_fd)
    assert target.read_bytes() == b"first"
    assert staged.read_bytes() == b"second"

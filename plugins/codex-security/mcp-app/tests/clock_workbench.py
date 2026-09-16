"""Control the workbench clock while retaining its real commands and database writes."""

import errno
import os
import runpy
import sys
from pathlib import Path

source = Path(sys.argv[1])
sys.argv = [str(source), *sys.argv[2:]]
sys.path.insert(0, str(source.parent))
api = runpy.run_path(str(source), run_name="test_workbench")
instant = os.environ["TEST_WORKBENCH_NOW"]
api["main"].__globals__["now"] = lambda: instant
if os.environ.get("TEST_WORKBENCH_RECEIPT_IO_FAILURE"):
    if os.name == "nt":
        from finalize_scan_contract import _windows_scan_local_files

        backend = _windows_scan_local_files()
        original_replace = backend._rename_handle
    else:
        original_replace = os.replace

    def replace(source, destination, *args, **kwargs):
        if str(destination).endswith(".accepted.json"):
            raise OSError(errno.ENOSPC, "Synthetic receipt I/O failure", destination)
        return original_replace(source, destination, *args, **kwargs)

    if os.name == "nt":
        backend._rename_handle = replace
    else:
        os.replace = replace
api["main"]()

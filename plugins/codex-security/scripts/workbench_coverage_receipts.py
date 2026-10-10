"""Resolve accepted worker receipt references without changing their ownership."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from finalize_scan_contract import ContractError, open_scan_local_file_descriptor


def resolve_coverage_receipts(
    scan_dir: Path, item: dict[str, Any], worker: Any, relative: str
) -> Any:
    refs = item.get("receiptRefs", [])
    if not isinstance(refs, list):
        return refs
    directory = Path(relative).parent
    if directory.name == "checkpoints":
        directory = directory.parent
    output = Path(worker["artifact_dir"]).relative_to(scan_dir)
    worker_prefix = (output.parent if output.name == "output" else output).as_posix() + "/"
    active_prefix = output.as_posix() + "/"
    if directory != output:
        refs = [
            f"{directory.as_posix()}/{Path(ref).as_posix()[len(active_prefix) :]}"
            if isinstance(ref, str) and Path(ref).as_posix().startswith(active_prefix)
            else ref
            for ref in refs
        ]

    def scan_receipt(ref: str) -> bool:
        try:
            descriptor = open_scan_local_file_descriptor(scan_dir, ref, "coverage receipt")
        except (ContractError, OSError):
            return False
        os.close(descriptor)
        return True

    def qualified_receipt(ref: Any) -> Any:
        if not isinstance(ref, str):
            return ref
        ref = Path(ref).as_posix()
        provenance = item.get("provenance")
        inherited_scan_refs = (
            provenance.get("scanReceiptRefs", []) if isinstance(provenance, dict) else []
        )
        if ref.startswith(worker_prefix) or (
            isinstance(inherited_scan_refs, list) and ref in inherited_scan_refs
        ):
            return ref
        local_ref = Path(f"{directory}/{ref}").as_posix()
        return local_ref if scan_receipt(local_ref) or not scan_receipt(ref) else ref

    return [qualified_receipt(ref) for ref in refs]

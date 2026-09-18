"""Select trusted review guidance from the existing scan's filename inventory."""

from __future__ import annotations

import json
from pathlib import Path

from generate_in_scope_files import committed_changed_paths
from generate_rank_input import git_changed_paths, path_is_diff_excluded, repo_scope_paths


def rust_scan_guidance(
    repository: Path,
    scopes: list[str],
    *,
    plugin_root: Path,
    diff_target: dict[str, str] | None = None,
) -> str:
    """Return the Rust supplement only when the selected scope includes Rust source."""
    repository = repository.expanduser().resolve()
    if diff_target is None:
        has_rust = any(
            Path(path).suffix.lower() == ".rs" for path in repo_scope_paths(repository, scopes)
        )
    else:
        base, head = diff_target["baseRevision"], diff_target["headRevision"]
        revisions = diff_target["kind"] != "working_tree"
        changed = (
            committed_changed_paths(repository, base, head)
            if revisions
            else git_changed_paths(repository, base, head, "local-patch")
        )
        has_rust = any(
            path.suffix.lower() == ".rs"
            and not path_is_diff_excluded(path.relative_to(repository))
            and (revisions or status == "D" or (path.is_file() and not path.is_symlink()))
            for path, status in changed
        )
    if not has_rust:
        return ""

    skill = plugin_root / "skills" / "unsafe-rust-review" / "SKILL.md"
    return (
        f"Rust review supplement: Read {json.dumps(str(skill))} and its referenced upstream "
        "method, and apply their soundness checks to Rust evidence during the full security "
        "audit. Continue all "
        "other vulnerability checks, including application logic and trust boundaries. Pass "
        "this skill path to the relevant baseline reviewers, investigators, and diff discovery "
        "and validation reviewers; explicitly authorize this supplied methodology even when "
        "their normal instructions prohibit other skills. Supply and authorize reading the "
        "available local dependency and standard-library source/documentation paths as "
        "supporting evidence for the selected target. The scan owner prepares missing sources "
        "and tools under existing host permissions and attempts useful Miri or sanitizer "
        "reproductions for concrete "
        "candidates in its authorized execution workspace. Source-review subagents remain "
        "source-only and offline, returning candidates and proposed reproductions. Keep the "
        "existing target, execution permissions, validation ownership, and reporting format. "
        "Do not start another scan or produce a second set of reports."
    )

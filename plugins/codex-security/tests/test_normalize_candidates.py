from __future__ import annotations

import json
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "normalize_candidates.py"


def write_jsonl(path: Path, rows: list[dict[str, object]]) -> None:
    path.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")


def location(path: str, line: int, role: str) -> dict[str, object]:
    return {"path": path, "start_line": line, "role": role}


def candidate(
    locations: list[dict[str, object]],
    *,
    cwes: list[str] | None = None,
    summary: str = "Request input reaches an unsafe operation",
    evidence: str = "The input is passed to the operation without a check",
    context: str | None = None,
    instance: str | None = None,
) -> dict[str, object]:
    row: dict[str, object] = {
        "cwe_ids": ["CWE-89"] if cwes is None else cwes,
        "locations": locations,
        "summary": summary,
        "evidence": evidence,
    }
    if context is not None:
        row["context"] = context
    if instance is not None:
        row["instance"] = instance
    return row


def setup_repo(tmp_path: Path) -> tuple[Path, Path]:
    repo = tmp_path / "repo"
    for path in ("app/routes.py", "app/query.py", "app/export.py", "helpers/shared.py"):
        source = repo / path
        source.parent.mkdir(parents=True, exist_ok=True)
        source.write_text("one\ntwo\nthree\nfour\nfive\n", encoding="utf-8")
    scope = tmp_path / "in_scope_files.txt"
    scope.write_text("app/routes.py\napp/query.py\napp/export.py\n", encoding="utf-8")
    return repo, scope


def run_combiner(
    tmp_path: Path,
    inputs: list[list[dict[str, object]]],
    *,
    repo: Path | None = None,
    scope: Path | None = None,
    output_name: str = "combined.jsonl",
    allow_missing: bool = False,
) -> tuple[subprocess.CompletedProcess[str], Path]:
    if repo is None or scope is None:
        repo, scope = setup_repo(tmp_path)
    sources: list[Path] = []
    for index, rows in enumerate(inputs):
        source = tmp_path / f"candidates-{index}.jsonl"
        write_jsonl(source, rows)
        sources.append(source)
    output = tmp_path / output_name
    result = subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "--input",
            *(str(source) for source in sources),
            "--out",
            str(output),
            "--repo-root",
            str(repo),
            "--in-scope-files",
            str(scope),
            *(["--allow-missing-in-scope"] if allow_missing else []),
        ],
        capture_output=True,
        text=True,
    )
    return result, output


def read_jsonl(path: Path) -> list[dict[str, object]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").split("\n") if line]


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX-only literal file names")
@pytest.mark.parametrize(
    "relative",
    [
        "app/ leading.py",
        "app/trailing .py",
        "app/ .py",
        "app/   .py",
        "app/carriage\rname.py",
        "app/trailing-carriage.py\r",
        "app/vertical\vname.py",
        "app/form\fname.py",
        "app/next\u0085name.py",
        "app/line\u2028name.py",
        "app/paragraph\u2029name.py",
    ],
)
def test_scope_preserves_literal_posix_inventory_paths(tmp_path: Path, relative: str) -> None:
    repo, scope = setup_repo(tmp_path)
    source = repo / relative
    source.write_text("one\ntwo\n", encoding="utf-8")
    scope.write_bytes((relative + "\n").encode("utf-8"))

    result, output = run_combiner(
        tmp_path,
        [[candidate([location(relative, 1, "entrypoint")])]],
        repo=repo,
        scope=scope,
    )

    assert result.returncode == 0, result.stderr
    assert read_jsonl(output)[0]["locations"][0]["path"] == relative


def test_scope_accepts_crlf_inventory_on_every_platform(tmp_path: Path) -> None:
    repo, scope = setup_repo(tmp_path)
    scope.write_bytes(b"\r\napp/routes.py\r\napp/query.py\r\n")

    result, output = run_combiner(
        tmp_path,
        [[candidate([location("app/routes.py", 1, "entrypoint")])]],
        repo=repo,
        scope=scope,
    )

    assert result.returncode == 0, result.stderr
    assert read_jsonl(output)[0]["locations"][0]["path"] == "app/routes.py"


def test_diff_scope_accepts_deleted_files_without_weakening_candidate_locations(
    tmp_path: Path,
) -> None:
    repo, scope = setup_repo(tmp_path)
    scope.write_text("app/deleted_guard.py\napp/routes.py\n", encoding="utf-8")

    rejected, _ = run_combiner(
        tmp_path,
        [[candidate([location("app/routes.py", 1, "entrypoint")])]],
        repo=repo,
        scope=scope,
    )
    assert rejected.returncode == 2
    assert "in-scope file row 1" in rejected.stderr

    accepted, output = run_combiner(
        tmp_path,
        [[candidate([location("app/routes.py", 1, "entrypoint")])]],
        repo=repo,
        scope=scope,
        allow_missing=True,
    )
    assert accepted.returncode == 0, accepted.stderr
    assert read_jsonl(output)[0]["locations"][0]["path"] == "app/routes.py"

    missing_candidate, _ = run_combiner(
        tmp_path,
        [[candidate([location("app/deleted_guard.py", 1, "root_control")])]],
        repo=repo,
        scope=scope,
        output_name="missing-candidate.jsonl",
        allow_missing=True,
    )
    assert missing_candidate.returncode == 2
    assert "deleted_guard.py" in missing_candidate.stderr


def test_diff_scope_rejects_deleted_path_outside_repository(tmp_path: Path) -> None:
    repo, scope = setup_repo(tmp_path)
    scope.write_text("../deleted_guard.py\napp/routes.py\n", encoding="utf-8")

    result, output = run_combiner(
        tmp_path,
        [[candidate([location("app/routes.py", 1, "entrypoint")])]],
        repo=repo,
        scope=scope,
        allow_missing=True,
    )

    assert result.returncode == 2
    assert "in-scope file row 1" in result.stderr
    assert not output.exists()


@pytest.mark.parametrize(
    "inventory",
    [
        b"app/routes.py\r\napp/query.py\n",
        b"app/routes.py\r\napp/query.py",
    ],
)
def test_scope_accepts_mixed_and_unterminated_crlf_inventories(
    tmp_path: Path, inventory: bytes
) -> None:
    repo, scope = setup_repo(tmp_path)
    scope.write_bytes(inventory)

    result, output = run_combiner(
        tmp_path,
        [[candidate([location("app/routes.py", 1, "entrypoint")])]],
        repo=repo,
        scope=scope,
    )

    assert result.returncode == 0, result.stderr
    assert read_jsonl(output)[0]["locations"][0]["path"] == "app/routes.py"


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX-only literal file names")
def test_crlf_scope_preserves_paths_when_carriage_return_names_also_exist(
    tmp_path: Path,
) -> None:
    repo, scope = setup_repo(tmp_path)
    (repo / "app/routes.py\r").write_text("one\ntwo\n", encoding="utf-8")
    scope.write_bytes(b"app/routes.py\r\napp/query.py\r\n")

    result, output = run_combiner(
        tmp_path,
        [[candidate([location("app/routes.py", 1, "entrypoint")])]],
        repo=repo,
        scope=scope,
    )

    assert result.returncode == 0, result.stderr
    assert read_jsonl(output)[0]["locations"][0]["path"] == "app/routes.py"


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX-only literal file names")
@pytest.mark.parametrize("candidate_path", ["app/routes.py", "app/routes.py\r"])
def test_lf_scope_preserves_separately_listed_carriage_return_collisions(
    tmp_path: Path, candidate_path: str
) -> None:
    repo, scope = setup_repo(tmp_path)
    for relative in ("app/routes.py\r", "app/query.py\r"):
        (repo / relative).write_text("one\ntwo\n", encoding="utf-8")
    scope.write_bytes(b"app/query.py\napp/query.py\r\napp/routes.py\napp/routes.py\r\n")

    result, output = run_combiner(
        tmp_path,
        [[candidate([location(candidate_path, 1, "entrypoint")])]],
        repo=repo,
        scope=scope,
    )

    assert result.returncode == 0, result.stderr
    assert read_jsonl(output)[0]["locations"][0]["path"] == candidate_path


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX-only literal file names")
def test_scope_preserves_unterminated_final_carriage_return_filename(
    tmp_path: Path,
) -> None:
    repo, scope = setup_repo(tmp_path)
    relative = "app/routes.py\r"
    (repo / relative).write_text("one\ntwo\n", encoding="utf-8")
    scope.write_bytes(b"app/query.py\r\napp/routes.py\r")

    result, output = run_combiner(
        tmp_path,
        [[candidate([location(relative, 1, "entrypoint")])]],
        repo=repo,
        scope=scope,
    )

    assert result.returncode == 0, result.stderr
    assert read_jsonl(output)[0]["locations"][0]["path"] == relative


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX-only literal file names")
@pytest.mark.parametrize(
    "relative",
    ["app/literal\\name.py", "app/C:foo.py", " ", "   "],
)
def test_candidate_rejects_paths_incompatible_with_scan_contract(
    tmp_path: Path, relative: str
) -> None:
    repo, scope = setup_repo(tmp_path)
    source = repo / relative
    source.write_text("one\ntwo\n", encoding="utf-8")
    scope.write_bytes((relative + "\n").encode("utf-8"))

    result, output = run_combiner(
        tmp_path,
        [[candidate([location(relative, 1, "entrypoint")])]],
        repo=repo,
        scope=scope,
    )

    assert result.returncode == 2
    assert "safe repository-relative POSIX path" in result.stderr
    assert not output.exists()


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX-only literal file names")
@pytest.mark.parametrize("candidate_path", ["app/routes.py", "app/routes.py\r"])
def test_mixed_scope_rejects_colliding_carriage_return_file_names(
    tmp_path: Path, candidate_path: str
) -> None:
    repo, scope = setup_repo(tmp_path)
    (repo / "app/routes.py\r").write_text("one\ntwo\n", encoding="utf-8")
    scope.write_bytes(b"app/routes.py\r\napp/query.py\n")

    result, output = run_combiner(
        tmp_path,
        [[candidate([location(candidate_path, 1, "entrypoint")])]],
        repo=repo,
        scope=scope,
    )

    assert result.returncode == 2
    assert "ambiguous carriage-return paths" in result.stderr
    assert not output.exists()


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX-only literal file names")
def test_lf_scope_uses_independent_literal_carriage_return_evidence(
    tmp_path: Path,
) -> None:
    repo, scope = setup_repo(tmp_path)
    relative = "app/routes.py\r"
    evidence = "app/literal-evidence.py\r"
    for path in (relative, evidence):
        (repo / path).write_text("one\ntwo\n", encoding="utf-8")
    scope.write_bytes(b"app/routes.py\r\napp/literal-evidence.py\r\napp/query.py\n")

    result, output = run_combiner(
        tmp_path,
        [[candidate([location(relative, 1, "entrypoint")])]],
        repo=repo,
        scope=scope,
    )

    assert result.returncode == 0, result.stderr
    assert read_jsonl(output)[0]["locations"][0]["path"] == relative


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX-only literal file names")
def test_scope_rejects_indistinguishable_carriage_return_inventories(
    tmp_path: Path,
) -> None:
    repo, scope = setup_repo(tmp_path)
    for relative in ("app/routes.py\r", "app/query.py\r"):
        (repo / relative).write_text("one\ntwo\n", encoding="utf-8")
    scope.write_bytes(b"app/routes.py\r\napp/query.py\r\n")

    result, output = run_combiner(
        tmp_path,
        [[candidate([location("app/routes.py", 1, "entrypoint")])]],
        repo=repo,
        scope=scope,
    )

    assert result.returncode == 2
    assert "ambiguous carriage-return paths" in result.stderr
    assert not output.exists()


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX-only literal file names")
def test_crlf_blank_line_disambiguates_colliding_carriage_return_paths(
    tmp_path: Path,
) -> None:
    repo, scope = setup_repo(tmp_path)
    for relative in ("app/routes.py\r", "app/query.py\r"):
        (repo / relative).write_text("one\ntwo\n", encoding="utf-8")
    scope.write_bytes(b"\r\napp/routes.py\r\napp/query.py\r\n")

    result, output = run_combiner(
        tmp_path,
        [[candidate([location("app/routes.py", 1, "entrypoint")])]],
        repo=repo,
        scope=scope,
    )

    assert result.returncode == 0, result.stderr
    assert read_jsonl(output)[0]["locations"][0]["path"] == "app/routes.py"


@pytest.mark.skipif(sys.platform != "win32", reason="Windows-native file paths")
def test_windows_scope_normalizes_native_separators(tmp_path: Path) -> None:
    repo, scope = setup_repo(tmp_path)
    scope.write_bytes(b"app\\routes.py\r\n")

    result, output = run_combiner(
        tmp_path,
        [[candidate([location("app\\routes.py", 2, "entrypoint")])]],
        repo=repo,
        scope=scope,
    )

    assert result.returncode == 0, result.stderr
    assert read_jsonl(output)[0]["locations"][0]["path"] == "app/routes.py"


@pytest.mark.skipif(sys.platform != "win32", reason="Windows-native drive paths")
def test_windows_candidates_reject_drive_qualified_paths(tmp_path: Path) -> None:
    result, output = run_combiner(
        tmp_path,
        [[candidate([location("C:routes.py", 1, "entrypoint")])]],
    )

    assert result.returncode == 2
    assert "repository-relative path without traversal" in result.stderr
    assert not output.exists()


def test_matching_code_paths_combine_even_when_the_prose_differs(
    tmp_path: Path,
) -> None:
    first = candidate(
        [
            location("app/query.py", 4, "sink"),
            location("app/routes.py", 2, "entrypoint"),
            location("app/query.py", 3, "root_control"),
        ],
        cwes=["cwe-089", "CWE-89"],
        summary="The request id reaches an interpolated query",
        evidence="The query uses an f-string",
        context="Intentional training application",
    )
    second = candidate(
        [
            location("app/query.py", 3, "root_control"),
            location("app/routes.py", 2, "entrypoint"),
            location("app/query.py", 4, "sink"),
            location("app/query.py", 4, "sink"),
        ],
        summary="SQL injection is reachable from the request",
        evidence="The id is inserted directly into SQL",
        context="Runs only on localhost",
    )

    result, output = run_combiner(tmp_path, [[first], [second]])

    assert result.returncode == 0, result.stderr
    rows = read_jsonl(output)
    assert len(rows) == 1
    assert rows[0]["candidate_id"].startswith("candidate-")
    assert rows[0]["cwe_ids"] == ["CWE-89"]
    assert rows[0]["locations"] == [
        {"path": "app/routes.py", "start_line": 2, "end_line": 2, "role": "entrypoint"},
        {
            "path": "app/query.py",
            "start_line": 3,
            "end_line": 3,
            "role": "root_control",
        },
        {"path": "app/query.py", "start_line": 4, "end_line": 4, "role": "sink"},
    ]
    assert rows[0]["summary"] == (
        "SQL injection is reachable from the request\nThe request id reaches an interpolated query"
    )
    assert rows[0]["evidence"] == "The id is inserted directly into SQL\nThe query uses an f-string"
    assert rows[0]["context"] == "Intentional training application\nRuns only on localhost"


@pytest.mark.parametrize(
    "first_locations,second_locations",
    [
        (
            [
                location("app/routes.py", 2, "entrypoint"),
                location("helpers/shared.py", 3, "root_control"),
                location("app/query.py", 4, "sink"),
            ],
            [
                location("app/routes.py", 2, "entrypoint"),
                location("helpers/shared.py", 3, "root_control"),
                location("app/export.py", 4, "sink"),
            ],
        ),
        (
            [
                location("app/routes.py", 2, "entrypoint"),
                location("helpers/shared.py", 3, "root_control"),
                location("app/query.py", 4, "sink"),
            ],
            [
                location("app/export.py", 2, "entrypoint"),
                location("helpers/shared.py", 3, "root_control"),
                location("app/query.py", 4, "sink"),
            ],
        ),
    ],
)
def test_different_reachable_paths_remain_separate(
    tmp_path: Path,
    first_locations: list[dict[str, object]],
    second_locations: list[dict[str, object]],
) -> None:
    result, output = run_combiner(
        tmp_path,
        [[candidate(first_locations), candidate(second_locations)]],
    )

    assert result.returncode == 0, result.stderr
    rows = read_jsonl(output)
    assert len(rows) == 2
    assert rows[0]["candidate_id"] != rows[1]["candidate_id"]


def test_separate_bugs_at_the_same_locations_can_use_an_instance_label(
    tmp_path: Path,
) -> None:
    locations = [
        location("app/routes.py", 2, "entrypoint"),
        location("app/query.py", 4, "sink"),
    ]
    first = candidate(locations, instance="id parameter")
    second = candidate(locations, instance="sort parameter")

    result, output = run_combiner(tmp_path, [[first, second]])

    assert result.returncode == 0, result.stderr
    rows = read_jsonl(output)
    assert len(rows) == 2
    assert {row["instance"] for row in rows} == {"id parameter", "sort parameter"}
    assert rows[0]["candidate_id"] != rows[1]["candidate_id"]


def test_output_is_stable_when_input_and_row_order_changes(tmp_path: Path) -> None:
    duplicate_one = candidate(
        [
            location("app/routes.py", 2, "entrypoint"),
            location("app/query.py", 4, "sink"),
        ],
        summary="Request id reaches SQL",
        evidence="The query interpolates id",
    )
    duplicate_two = candidate(
        [
            location("app/query.py", 4, "sink"),
            location("app/routes.py", 2, "entrypoint"),
        ],
        summary="SQL is built from request input",
        evidence="The id is part of the query string",
    )
    separate = candidate(
        [
            location("app/export.py", 2, "entrypoint"),
            location("app/export.py", 4, "sink"),
        ],
        cwes=["CWE-22"],
        summary="The export path is unsafe",
        evidence="The path is joined without a containment check",
    )

    first, first_output = run_combiner(
        tmp_path,
        [[duplicate_one, separate], [duplicate_two]],
        output_name="first.jsonl",
    )
    second, second_output = run_combiner(
        tmp_path,
        [[duplicate_two], [separate, duplicate_one]],
        output_name="second.jsonl",
    )

    assert first.returncode == 0, first.stderr
    assert second.returncode == 0, second.stderr
    assert first_output.read_bytes() == second_output.read_bytes()


def test_combined_output_can_be_combined_again_without_changing_it(
    tmp_path: Path,
) -> None:
    repo, scope = setup_repo(tmp_path)
    locations = [
        location("app/routes.py", 2, "entrypoint"),
        location("app/query.py", 4, "sink"),
    ]
    first, first_output = run_combiner(
        tmp_path,
        [
            [
                candidate(locations, evidence="First trace"),
                candidate(locations, evidence="Second trace"),
            ]
        ],
        repo=repo,
        scope=scope,
        output_name="first.jsonl",
    )
    second_output = tmp_path / "second.jsonl"
    second = subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "--input",
            str(first_output),
            "--out",
            str(second_output),
            "--repo-root",
            str(repo),
            "--in-scope-files",
            str(scope),
        ],
        capture_output=True,
        text=True,
    )

    assert first.returncode == 0, first.stderr
    assert second.returncode == 0, second.stderr
    assert first_output.read_bytes() == second_output.read_bytes()


def test_multiline_candidate_text_keeps_its_original_order(tmp_path: Path) -> None:
    summary = "Z: attacker reaches the route.\nA: the route then reaches the sink."
    evidence = "Z: read the request.\nA: pass it into the query."
    context = "Z: enabled in the demo.\nA: runs only on localhost."
    row = candidate(
        [location("app/routes.py", 2, "entrypoint")],
        summary=summary,
        evidence=evidence,
        context=context,
    )

    result, output = run_combiner(tmp_path, [[row]])

    assert result.returncode == 0, result.stderr
    combined = read_jsonl(output)[0]
    assert combined["summary"] == summary
    assert combined["evidence"] == evidence
    assert combined["context"] == context


def test_unknown_cwe_and_supporting_location_outside_scope_are_allowed(
    tmp_path: Path,
) -> None:
    row = candidate(
        [
            location("app/routes.py", 2, "entrypoint"),
            location("helpers/shared.py", 3, "root_control"),
        ],
        cwes=[],
    )

    result, output = run_combiner(tmp_path, [[row]])

    assert result.returncode == 0, result.stderr
    assert read_jsonl(output)[0]["cwe_ids"] == []


@pytest.mark.parametrize(
    ("change", "message"),
    [
        (lambda row: row.pop("cwe_ids"), "cwe_ids: expected an array"),
        (
            lambda row: row.update(cwe_ids=["SQL injection"]),
            "cwe_ids: unsupported value",
        ),
        (lambda row: row.update(locations=[]), "locations: expected a non-empty array"),
        (
            lambda row: row["locations"][0].update(path="app/missing.py"),
            "missing.py",
        ),
        (
            lambda row: row["locations"][0].update(path="../outside.py"),
            "repository-relative path without traversal",
        ),
        (
            lambda row: row["locations"][0].update(start_line=6),
            "line range 6-6 exceeds app/routes.py:5",
        ),
        (
            lambda row: row["locations"][0].update(end_line=1),
            "greater than or equal",
        ),
        (
            lambda row: row["locations"][0].update(role="rootControl"),
            "role: unsupported value",
        ),
        (
            lambda row: row["locations"][0].update(line=2),
            "locations: unsupported fields line",
        ),
        (
            lambda row: row.update(technically_validated=True),
            "unsupported fields technically_validated",
        ),
        (
            lambda row: row.update(disposition="reportable"),
            "unsupported fields disposition",
        ),
    ],
)
def test_invalid_candidates_fail_with_the_input_row(
    tmp_path: Path, change: Callable[[dict[str, object]], object], message: str
) -> None:
    valid = candidate([location("app/routes.py", 2, "entrypoint")])
    invalid = candidate([location("app/routes.py", 2, "entrypoint")])
    change(invalid)

    result, output = run_combiner(tmp_path, [[valid, invalid]])

    assert result.returncode == 2
    assert "candidates-0.jsonl row 2:" in result.stderr
    assert message in result.stderr
    assert not output.exists()


def test_candidate_with_no_in_scope_location_fails(tmp_path: Path) -> None:
    row = candidate([location("helpers/shared.py", 3, "root_control")])

    result, output = run_combiner(tmp_path, [[row]])

    assert result.returncode == 2
    assert "expected at least one in-scope file" in result.stderr
    assert not output.exists()


def test_malformed_json_does_not_replace_an_existing_output(tmp_path: Path) -> None:
    repo, scope = setup_repo(tmp_path)
    source = tmp_path / "candidates.jsonl"
    source.write_text(
        json.dumps(candidate([location("app/routes.py", 2, "entrypoint")])) + "\nnot-json\n",
        encoding="utf-8",
    )
    output = tmp_path / "combined.jsonl"
    output.write_text("previous output\n", encoding="utf-8")

    result = subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "--input",
            str(source),
            "--out",
            str(output),
            "--repo-root",
            str(repo),
            "--in-scope-files",
            str(scope),
        ],
        capture_output=True,
        text=True,
    )

    assert result.returncode == 2
    assert "candidates.jsonl row 2:" in result.stderr
    assert output.read_text(encoding="utf-8") == "previous output\n"


def test_empty_candidate_input_produces_an_empty_ledger(tmp_path: Path) -> None:
    result, output = run_combiner(tmp_path, [[]])

    assert result.returncode == 0, result.stderr
    assert output.read_text(encoding="utf-8") == ""


def test_output_cannot_replace_the_in_scope_file_list(tmp_path: Path) -> None:
    repo, scope = setup_repo(tmp_path)
    source = tmp_path / "candidates.jsonl"
    write_jsonl(source, [candidate([location("app/routes.py", 2, "entrypoint")])])
    original_scope = scope.read_text(encoding="utf-8")

    result = subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "--input",
            str(source),
            "--out",
            str(scope),
            "--repo-root",
            str(repo),
            "--in-scope-files",
            str(scope),
        ],
        capture_output=True,
        text=True,
    )

    assert result.returncode == 2
    assert "--out: must not replace --in-scope-files" in result.stderr
    assert scope.read_text(encoding="utf-8") == original_scope

"""Cover source selection and failures at the AWS CLI boundary."""

import json
import runpy
import subprocess
import sys
from pathlib import Path

import pytest

SCRIPT = (
    Path(__file__).resolve().parents[1] / "skills/publish-findings/scripts/collect_continuum.py"
)
main = runpy.run_path(str(SCRIPT))["main"]


@pytest.fixture
def invoke(monkeypatch):
    def run(scope, *responses):
        replies = iter(responses)
        calls = []

        def aws(command):
            calls.append(command)
            reply = next(replies)
            if isinstance(reply, Exception):
                raise reply
            return json.dumps(reply).encode()

        monkeypatch.setattr(subprocess, "check_output", aws)
        monkeypatch.setattr(
            sys, "argv", [str(SCRIPT), "--environment-id", "env", "--finding-id", "f", *scope]
        )
        return main(), calls

    return run


def patch(source=None):
    return {
        "body": {
            "patch": {
                "patch": "example\n",
                "sizeBytes": 8,
                "patchSha256": "13550350a8681c84c861aac2e5b440161c2b33a3e4f302ac680ca5b686de48de",
                **({"repositoryName": source} if source else {}),
            }
        }
    }


def test_collects_only_selected_repository_on_duplicate_issue(invoke, capsys):
    finding = {"duplicateOfIssueId": "original"}
    status, calls = invoke(
        ["--repository-name", "api"],
        finding,
        {"items": [{"artifactId": "two"}, {"artifactId": "one"}]},
        patch("api"),
        patch("web"),
    )
    assert status == 0
    assert [call[2] for call in calls] == [
        "get-code-finding",
        "list-code-issue-artifacts",
        "get-code-issue-artifact",
        "get-code-issue-artifact",
    ]
    for call in calls:
        assert call[3:5] == ["--environment-id", "env"]
    assert calls[0][5:7] == ["--finding-id", "f"]
    assert calls[1][5:9] == ["--issue-id", "original", "--artifact-type", "PATCH"]
    assert [call[5:9] for call in calls[2:]] == [
        ["--issue-id", "original", "--artifact-id", "one"],
        ["--issue-id", "original", "--artifact-id", "two"],
    ]
    assert json.loads(capsys.readouterr().out) == {
        "finding": finding,
        "patches": [{"artifactId": "one", **patch("api")["body"]["patch"]}],
    }


def test_unnamed_patch_does_not_block_matching_patches(invoke, capsys):
    finding = {"createdIssueId": "issue"}
    status, _ = invoke(
        ["--repository-name", "api"],
        finding,
        {"items": [{"artifactId": "one"}, {"artifactId": "two"}]},
        patch(),
        patch("api"),
    )
    output = capsys.readouterr()
    assert status == 0
    assert "Skipped Continuum patch one" in output.err
    assert json.loads(output.out) == {
        "finding": finding,
        "patches": [{"artifactId": "two", **patch("api")["body"]["patch"]}],
    }


@pytest.mark.parametrize(
    ("finding", "replies"),
    [
        ({"findingId": "f"}, []),
        ({"createdIssueId": "issue"}, [{"items": [{"artifactId": "one"}]}, patch("web")]),
    ],
)
def test_no_eligible_patch_preserves_native_finding(invoke, capsys, finding, replies):
    status, _ = invoke(["--repository-name", "api"], finding, *replies)
    assert status == 0
    assert json.loads(capsys.readouterr().out) == finding


def test_failure_after_first_patch_emits_no_partial_report(invoke, capsys):
    status, _ = invoke(
        ["--single-repository"],
        {"createdIssueId": "issue"},
        {"items": [{"artifactId": "one"}, {"artifactId": "two"}]},
        patch(),
        subprocess.CalledProcessError(254, ["aws"]),
    )
    assert status == 254
    assert not capsys.readouterr().out

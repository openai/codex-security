from __future__ import annotations

import json
import runpy
from pathlib import Path

FINDING_PREVIEW_SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "finding_preview.py"


def test_nested_attack_path_stays_within_its_preview_budget() -> None:
    preview = runpy.run_path(str(FINDING_PREVIEW_SCRIPT))
    attack_path = {
        f"branch-{branch}": {f"node-{node}": "\n😀" * 40 for node in range(3)}
        for branch in range(3)
    }

    bounded = preview["bounded_finding_details"]({"attackPath": attack_path})["attackPath"]

    assert bounded["branch-0"]["node-0"] == "\n😀" * 40
    assert len(json.dumps(bounded, separators=(",", ":")).encode()) <= 4_000
    assert attack_path["branch-2"]["node-2"] == "\n😀" * 40


def test_bounded_finding_details_normalizes_scalar_attack_path_assessments() -> None:
    preview = runpy.run_path(str(FINDING_PREVIEW_SCRIPT))
    scalar_finding = {
        "attackPath": {
            "impact": "Native memory corruption is possible.",
            "likelihood": "medium",
        }
    }

    bounded = preview["bounded_finding_details"](scalar_finding)

    assert bounded["attackPath"]["impact"] == {"rationale": "Native memory corruption is possible."}
    assert bounded["attackPath"]["likelihood"] == {"level": "medium"}
    assert scalar_finding == {
        "attackPath": {
            "impact": "Native memory corruption is possible.",
            "likelihood": "medium",
        }
    }

    structured_finding = {
        "attackPath": {
            "impact": {"level": "high", "why": "The extraction target is writable."},
            "likelihood": None,
        }
    }
    structured = preview["bounded_finding_details"](structured_finding)

    assert structured["attackPath"]["impact"] == structured_finding["attackPath"]["impact"]
    assert structured["attackPath"]["likelihood"] is None

    missing = preview["bounded_finding_details"]({"attackPath": {"summary": "An upload is read."}})

    assert "impact" not in missing["attackPath"]
    assert "likelihood" not in missing["attackPath"]


def test_bounded_finding_details_merges_root_cause_aliases() -> None:
    preview = runpy.run_path(str(FINDING_PREVIEW_SCRIPT))
    original = {
        "rootCause": {"code": "SELECT * FROM users"},
        "root_cause": {
            "code": "os.system(user_input)",
            "evidence_refs": ["legacy-source"],
            "language": "python",
            "summary": "The destination is not contained.",
        },
    }

    bounded = preview["bounded_finding_details"](original)

    assert bounded["rootCause"] == {
        "code": "SELECT * FROM users",
        "evidenceRefs": ["legacy-source"],
        "summary": "The destination is not contained.",
    }
    assert "root_cause" not in bounded
    assert original["root_cause"]["language"] == "python"


def test_bounded_finding_details_ignores_malformed_root_cause_alias() -> None:
    preview = runpy.run_path(str(FINDING_PREVIEW_SCRIPT))
    original = {
        "rootCause": {"summary": 42},
        "root_cause": {
            "summary": "The valid legacy root cause.",
            "evidence_refs": ["legacy-source"],
        },
        "code_evidence": [{"id": "legacy-source", "code": "legacy_source()"}],
    }

    bounded = preview["bounded_finding_details"](original)

    assert bounded["rootCause"] == {
        "evidenceRefs": ["legacy-source"],
        "summary": "The valid legacy root cause.",
    }
    assert bounded["code_evidence"] == [{"id": "legacy-source", "code": "legacy_source()"}]


def test_bounded_finding_details_strips_invalid_legacy_evidence_fields() -> None:
    preview = runpy.run_path(str(FINDING_PREVIEW_SCRIPT))
    original = {
        "code_evidence": [
            {
                "id": "legacy-source",
                "code": "dangerous_call()",
                "startLine": 0,
                "endLine": "12",
                "label": 7,
                "role": {"kind": "sink"},
            }
        ]
    }

    bounded = preview["bounded_finding_details"](original)

    assert bounded["code_evidence"] == [{"id": "legacy-source", "code": "dangerous_call()"}]
    assert original["code_evidence"][0]["startLine"] == 0
    assert original["code_evidence"][0]["endLine"] == "12"


def test_bounded_finding_details_reserves_core_sections() -> None:
    preview = runpy.run_path(str(FINDING_PREVIEW_SCRIPT))
    bounded = preview["bounded_finding_details"](
        {
            "attackPath": {
                "blindspots": ["x" * 20_000],
                "summary": "The upload reaches the archive write. " + "x" * 20_000,
                "reachability": "Authenticated uploaders can trigger extraction.",
                "preconditions": ["Automatic extraction is enabled."],
                "evidenceRefs": ["evidence-0"],
            },
            "codeEvidence": [
                {
                    "id": f"evidence-{index}",
                    "label": "Long source excerpt",
                    "path": "src/archive.py",
                    "startLine": 40,
                    "role": "user_input" if index == 0 else "propagation",
                    "code": "\\\\\n😀" * 5_000,
                    "explanation": "The write precedes the containment check.",
                }
                for index in range(10)
            ],
            "rootCause": {
                "code": "x" * 20_000,
                "summary": "Containment is checked after the write. " + "x" * 20_000,
                "evidenceRefs": ["evidence-0"],
            },
            "validation": {
                "evidence": ["x" * 20_000],
                "summary": "The traversal was reproduced. " + "x" * 20_000,
                "method": "focused extraction test",
                "evidenceRefs": ["evidence-0"],
                "futureMetadata": "x" * 20_000,
                "counterEvidence": ["Known mitigations remain unverified."],
            },
            "writeup": {
                "reportPath": "findings/archive-traversal/archive-traversal.md",
                "untrustedExtra": "x" * 20_000,
            },
            "evidenceExcerpt": "x" * 20_000,
        }
    )

    assert bounded["rootCause"]["summary"].startswith("Containment is checked after the write.")
    assert bounded["rootCause"]["evidenceRefs"] == ["evidence-0"]
    assert bounded["validation"]["summary"].startswith("The traversal was reproduced.")
    assert bounded["validation"]["method"] == "focused extraction test"
    assert bounded["validation"]["evidenceRefs"] == ["evidence-0"]
    assert bounded["validation"]["counterEvidence"] == ["Known mitigations remain unverified."]
    assert bounded["attackPath"]["summary"].startswith("The upload reaches the archive write.")
    assert bounded["attackPath"]["reachability"] == (
        "Authenticated uploaders can trigger extraction."
    )
    assert bounded["attackPath"]["preconditions"] == ["Automatic extraction is enabled."]
    assert bounded["attackPath"]["evidenceRefs"] == ["evidence-0"]
    assert bounded["writeup"] == {"reportPath": "findings/archive-traversal/archive-traversal.md"}
    assert len(bounded["codeEvidence"]) == preview["FINDING_CODE_EVIDENCE_LIMIT"]
    assert bounded["codeEvidence"][0]["role"] == "user_input"
    assert all(
        len(json.dumps(item["code"], separators=(",", ":")).encode("utf-8"))
        <= preview["FINDING_CODE_EVIDENCE_SNIPPET_BYTES"]
        for item in bounded["codeEvidence"]
    )
    assert (
        len(json.dumps(bounded, separators=(",", ":")).encode("utf-8"))
        <= preview["FINDING_DETAILS_PREVIEW_BYTES"]
    )


def test_bounded_finding_details_keeps_guidance_and_both_evidence_aliases() -> None:
    preview = runpy.run_path(str(FINDING_PREVIEW_SCRIPT))

    bounded = preview["bounded_finding_details"](
        {
            "codeEvidence": [
                {"id": "canonical", "code": "canonical_source()"},
            ],
            "code_evidence": [
                {"id": "legacy", "code": "legacy_source()"},
            ],
            "preventiveControls": ["Centralize archive path validation."],
            "remediationTests": ["Reject traversal archive entries."],
            "rootCause": {"summary": "The destination path is not contained."},
        }
    )

    assert [item["id"] for item in bounded["codeEvidence"]] == ["canonical", "legacy"]
    assert "code_evidence" not in bounded
    assert bounded["preventiveControls"] == ["Centralize archive path validation."]
    assert bounded["remediationTests"] == ["Reject traversal archive entries."]


def test_bounded_finding_details_deduplicates_evidence_before_limiting() -> None:
    preview = runpy.run_path(str(FINDING_PREVIEW_SCRIPT))

    bounded = preview["bounded_finding_details"](
        {
            "codeEvidence": [
                {"id": "shared", "code": "canonical_shared()"},
                {"id": "shared", "code": "duplicate_shared()"},
                {"id": "canonical-two", "code": "canonical_two()"},
                {"id": "canonical-three", "code": "canonical_three()"},
            ],
            "code_evidence": [
                {"id": "shared", "code": "legacy_shared()"},
                {"id": "legacy-four", "code": "legacy_four()"},
                {"id": "legacy-five", "code": "legacy_five()"},
            ],
        }
    )

    assert [item["id"] for item in bounded["codeEvidence"]] == [
        "shared",
        "canonical-two",
        "canonical-three",
        "legacy-four",
    ]
    assert bounded["codeEvidence"][0]["code"] == "canonical_shared()"


def test_bounded_finding_details_filters_malformed_evidence_before_limiting() -> None:
    preview = runpy.run_path(str(FINDING_PREVIEW_SCRIPT))

    bounded = preview["bounded_finding_details"](
        {
            "code_evidence": [
                None,
                "junk",
                {},
                {"id": "empty", "code": ""},
                {"id": "valid", "code": "valid_source()"},
            ]
        }
    )

    assert bounded["code_evidence"] == [{"id": "valid", "code": "valid_source()"}]

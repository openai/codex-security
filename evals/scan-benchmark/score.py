"""Score canonical scan artifacts against versioned, synthetic expectations."""

import argparse
import hashlib
import json
from pathlib import Path

from jsonschema import Draft202012Validator, ValidationError

ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent


def read(path):
    return json.loads(path.read_text(encoding="utf-8"))


def validate(document, schema):
    Draft202012Validator(schema).validate(document)


def overlap(actual, expected):
    return (
        actual["path"].replace("\\", "/").removeprefix("./") == expected["path"]
        and actual["startLine"] <= expected["endLine"]
        and actual.get("endLine", actual["startLine"]) >= expected["startLine"]
    )


def matches(finding, expectation, *, quality=True):
    if not set(finding["taxonomy"]["cwe"]) & set(expectation["cwe"]):
        return False
    if not all(
        any(overlap(location, region) for location in finding["locations"])
        for region in expectation["regions"]
    ):
        return False
    if not quality:
        return True
    return finding["severity"]["level"] in expectation["severity"] and all(
        any(overlap(evidence, region) for evidence in finding.get("codeEvidence", []))
        for region in expectation.get("evidenceRegions", [])
    )


def assignment(findings, expectations):
    """Maximum one-to-one matching; broad findings cannot inflate recall."""
    owners = {}

    def assign(expected_index, seen):
        for finding_index, finding in enumerate(findings):
            if finding_index in seen or not matches(finding, expectations[expected_index]):
                continue
            seen.add(finding_index)
            if finding_index not in owners or assign(owners[finding_index], seen):
                owners[finding_index] = expected_index
                return True
        return False

    # Required expectations take priority over optional ones.
    for index in range(len(expectations)):
        assign(index, set())
    return owners


def score(expected, findings, coverage, candidates=None):
    positives = [e for e in expected["findings"] if e["presence"] == "required"]
    required_count = len(positives)
    positives += [e for e in expected["findings"] if e["presence"] == "optional"]
    absent = [e for e in expected["findings"] if e["presence"] == "absent"]
    prohibited = {
        i
        for i, finding in enumerate(findings)
        if any(matches(finding, e, quality=False) for e in absent)
    }
    eligible = [(i, finding) for i, finding in enumerate(findings) if i not in prohibited]
    owned = assignment([finding for _, finding in eligible], positives)
    matched = set(owned.values())
    duplicates = []
    unexpected = list(prohibited)
    allowance = {i: e.get("allowedDuplicates", 0) for i, e in enumerate(positives)}
    for index, (original_index, finding) in enumerate(eligible):
        if index in owned:
            continue
        groups = [i for i in matched if matches(finding, positives[i])]
        if groups:
            duplicates.append(original_index)
            available = next((i for i in groups if allowance[i] > 0), None)
            if available is not None:
                allowance[available] -= 1
            else:
                unexpected.append(original_index)
        else:
            unexpected.append(original_index)
    missing = [positives[i]["id"] for i in range(required_count) if i not in matched]
    complete = coverage["completeness"] == "complete" and coverage["mode"] == expected["mode"]
    result = {
        "caseId": expected["caseId"],
        "required": required_count,
        "matchedRequired": required_count - len(missing),
        "recall": (required_count - len(missing)) / required_count if required_count else 1.0,
        "missing": missing,
        "unexpected": [findings[i]["findingId"] for i in sorted(unexpected)],
        "absentViolations": [findings[i]["findingId"] for i in sorted(prohibited)],
        "duplicates": [findings[i]["findingId"] for i in sorted(duplicates)],
        "duplicateRate": len(duplicates) / len(findings) if findings else 0.0,
        "coverageComplete": complete,
        "passed": not missing and not unexpected and complete,
        "validationSurvival": None,
    }
    if candidates is not None:
        discovered = set(assignment(candidates, positives).values()) & set(range(required_count))
        surviving = discovered & matched
        result["validationSurvival"] = {
            "discoveredRequired": len(discovered),
            "survivingRequired": len(surviving),
            "rate": len(surviving) / len(discovered) if discovered else None,
        }
    return result


def run(results_dir, baseline=None):
    schema = read(HERE / "expected.schema.json")
    schemas = ROOT / "plugins/codex-security/schemas"
    findings_schema = read(schemas / "findings.schema.json")
    coverage_schema = read(schemas / "coverage.schema.json")
    cases = []
    corpus_hash = hashlib.sha256((HERE / "expected.schema.json").read_bytes())
    for case in sorted((HERE / "cases").iterdir()):
        expected = read(case / "expected.json")
        for source in sorted(case.rglob("*")):
            if source.is_file() and "__pycache__" not in source.parts:
                corpus_hash.update(source.relative_to(HERE).as_posix().encode())
                corpus_hash.update(b"\0" + source.read_bytes() + b"\0")
        validate(expected, schema)
        ids = [item["id"] for item in expected["findings"]]
        if len(set(ids)) != len(ids):
            raise ValueError(f"{case.name}: duplicate expectation IDs")
        for item in expected["findings"]:
            for region in item["regions"] + item.get("evidenceRegions", []):
                if region["startLine"] > region["endLine"]:
                    raise ValueError(f"{case.name}: reversed source range")
        directory = results_dir / expected["caseId"]
        document = read(directory / "findings.json")
        coverage = read(directory / "coverage.json")
        validate(document, findings_schema)
        validate(coverage, coverage_schema)
        if document["scanId"] != coverage["scanId"]:
            raise ValueError(f"{case.name}: findings and coverage scanId differ")
        candidates_path = directory / "candidates.json"
        candidates = None
        if candidates_path.exists():
            candidate_document = read(candidates_path)
            validate(candidate_document, findings_schema)
            if candidate_document["scanId"] != document["scanId"]:
                raise ValueError(f"{case.name}: candidates scanId differs")
            candidates = candidate_document["findings"]
        cases.append(score(expected, document["findings"], coverage, candidates))
    regressions = []
    if baseline is not None:
        if baseline["corpusVersion"] != 1 or baseline["corpusDigest"] != corpus_hash.hexdigest():
            raise ValueError("baseline corpus version or contents differ")
        previous = {case["caseId"]: case for case in baseline["cases"]}
        if set(previous) != {case["caseId"] for case in cases}:
            raise ValueError("baseline case set differs")
        for case in cases:
            old = previous[case["caseId"]]
            if (
                case["recall"] < old["recall"]
                or len(case["unexpected"]) > len(old["unexpected"])
                or case["duplicateRate"] > old["duplicateRate"]
                or (old["coverageComplete"] and not case["coverageComplete"])
            ):
                regressions.append(case["caseId"])
    required = sum(case["required"] for case in cases)
    return {
        "corpusVersion": 1,
        "corpusDigest": corpus_hash.hexdigest(),
        "cases": cases,
        "recall": sum(case["matchedRequired"] for case in cases) / required if required else 1.0,
        "unexpectedCount": sum(len(case["unexpected"]) for case in cases),
        "regressions": regressions,
        "passed": all(case["passed"] for case in cases) and not regressions,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("results", type=Path)
    parser.add_argument("--baseline", type=Path)
    args = parser.parse_args()
    try:
        report = run(args.results, read(args.baseline) if args.baseline else None)
    except (OSError, ValueError, KeyError, TypeError, ValidationError) as error:
        parser.exit(2, f"benchmark input error: {error}\n")
    print(json.dumps(report, indent=2))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())

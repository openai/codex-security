"""Image patch evidence binds the selected advisory to a comparable pair of images."""

import hashlib
import json
import subprocess
import sys
from copy import deepcopy

import pytest
from workbench_test_support import load_script

image_evidence = load_script("image_patch_evidence")

pytestmark = pytest.mark.cross_platform


def reports(package_type="apk"):
    descriptor = {"version": "1", "configuration": {"search": {"scope": "squashed"}}}
    package = {
        "name": "example",
        "type": package_type,
        "version": "1",
        "purl": f"pkg:{package_type}/vendor/example@1",
    }
    metadata = {"manifestDigest": "sha256:" + "a" * 64, "os": "linux", "architecture": "amd64"}
    sbom = {
        "descriptor": {**descriptor, "name": "syft"},
        "source": {"type": "image", "metadata": metadata},
        "artifacts": [package],
    }
    scan = {
        "descriptor": {
            **descriptor,
            "name": "grype",
            "db": {
                "status": {
                    "built": "2099-01-01T00:00:00Z",
                    "schemaVersion": "1",
                    "from": "db",
                    "valid": True,
                },
                "providers": {"example": {"input": "synthetic"}},
            },
        },
        "source": {"type": "image", "target": metadata},
        "matches": [
            {
                "artifact": package,
                "relatedVulnerabilities": [{"id": "alias"}],
                "vulnerability": {
                    "id": "test-advisory",
                    "fix": {"state": "fixed", "versions": ["2"]},
                },
            }
        ],
    }
    after, scanned = deepcopy((sbom, scan))
    after["source"]["metadata"]["manifestDigest"] = "sha256:" + "b" * 64
    after["artifacts"][0]["version"] = "2"
    after["artifacts"][0]["purl"] = f"pkg:{package_type}/vendor/example@2"
    scanned["matches"] = []
    return sbom, scan, after, scanned


def run(inputs, package_type="apk", advisory="test-advisory"):
    return image_evidence.compare(*inputs, advisory, "example", package_type)


@pytest.mark.parametrize("advisory", ["test-advisory", "alias"])
def test_installed_fix_and_disappeared_match(advisory):
    result = run(reports(), advisory=advisory)
    assert result["scanner_evidence"] == "reported_fix_present"
    assert result["before"]["total_matches"] == 1
    assert result["after"]["distinct_advisories"] == 0
    assert result["deployment"] == "unverified"


@pytest.mark.parametrize(
    "case", ["missing package", "namespace", "unlisted version", "suppressed", "still active"]
)
def test_no_false_closure(case):
    items = reports()
    _, scan, after, scanned = items
    if case == "missing package":
        after["artifacts"] = []
    elif case == "namespace":
        after["artifacts"][0]["purl"] = "pkg:apk/other/example@2"
    elif case == "unlisted version":
        after["artifacts"][0]["version"] = "3"
    elif case == "suppressed":
        scanned["ignoredMatches"] = scan["matches"]
    else:
        scanned["matches"] = scan["matches"]
    expected = "still_reported" if case == "still active" else "inconclusive"
    assert run(items)["scanner_evidence"] == expected


@pytest.mark.parametrize("case", ["image", "platform", "database", "filters", "tag", "baseline"])
def test_comparison_requires_matching_inputs(case):
    items = reports()
    _, scan, after, scanned = items
    if case == "image":
        scanned["source"]["target"] = {
            **scanned["source"]["target"],
            "manifestDigest": "sha256:" + "c" * 64,
        }
    elif case == "platform":
        after["source"]["metadata"]["architecture"] = "arm64"
    elif case == "database":
        scanned["descriptor"]["db"]["status"]["built"] = "2099-01-02T00:00:00Z"
    elif case == "filters":
        scanned["descriptor"]["configuration"]["only-fixed"] = True
    elif case == "tag":
        after["source"]["metadata"]["manifestDigest"] = "latest"
    else:
        scan["matches"] = []
    with pytest.raises(ValueError):
        run(items)


def test_platform_variants_and_removed_layers():
    items = reports()
    items[2]["source"]["metadata"]["architectureVariant"] = "v7"
    with pytest.raises(ValueError, match="platform"):
        run(items)
    items = reports()
    for sbom in (items[0], items[2]):
        sbom["descriptor"]["configuration"]["search"]["scope"] = "all-layers"
    with pytest.raises(ValueError, match="squashed"):
        run(items)


@pytest.mark.parametrize(
    ("package_type", "distro", "next_distro"),
    [
        ("apk", "alpine-3.18", "alpine-3.19"),
        ("deb", "debian-11", "debian-12"),
        ("rpm", "rhel-8.4", "rhel-9.0"),
    ],
)
def test_fixed_version_applies_to_its_distribution(package_type, distro, next_distro):
    items = reports(package_type)
    items[0]["artifacts"][0]["purl"] += f"?distro={distro}"
    package = items[2]["artifacts"][0]
    purl = package["purl"]
    assert run(items, package_type)["scanner_evidence"] == "inconclusive"
    package["purl"] = f"{purl}?arch=x86_64&distro={distro}"
    assert run(items, package_type)["scanner_evidence"] == "reported_fix_present"
    fixed = dict(package)
    package["purl"] += f"&Distro={next_distro}"
    assert run(items, package_type)["scanner_evidence"] == "inconclusive"
    package["purl"] = f"{purl}?distro={next_distro}"
    assert run(items, package_type)["scanner_evidence"] == "inconclusive"
    items[3]["matches"] = [{**items[1]["matches"][0], "artifact": package}]
    assert run(items, package_type)["scanner_evidence"] == "still_reported"
    items[2]["artifacts"].append(fixed)
    package.update(version="1", purl=f"pkg:{package_type}/vendor/example@1?distro={next_distro}")
    assert run(items, package_type)["scanner_evidence"] == "still_reported"


@pytest.mark.parametrize("status", [0, 2, 1, 3])
def test_scan_preserves_completed_reports_and_scanner_failures(
    tmp_path, monkeypatch, capfd, status
):
    contents = b'{ "artifacts": [] }\n'
    path = tmp_path / "image.syft.json"
    path.write_bytes(contents)
    report = {"matches": []}
    scanner = """
import json
import sys

assert sys.stdin.buffer.read() == b'{ "artifacts": [] }\\n'
print(json.dumps({"matches": []}))
sys.stderr.buffer.write(b"synthetic scanner diagnostic\\n")
sys.exit(int(sys.argv[1]))
"""
    run_process = subprocess.run

    def scan(args, **kwargs):
        return run_process([sys.executable, "-c", scanner, str(status)], **kwargs)

    monkeypatch.setattr(image_evidence.subprocess, "run", scan)
    if status in (0, 2):
        evidence, digest = image_evidence.scan_sbom(path)
        assert evidence == (json.loads(contents), report)
        assert digest == hashlib.sha256(contents).hexdigest()
    else:
        with pytest.raises(subprocess.CalledProcessError) as error:
            image_evidence.scan_sbom(path)
        assert error.value.returncode == status
    assert capfd.readouterr().err == "synthetic scanner diagnostic\n"


@pytest.mark.parametrize(
    ("package_type", "installed", "fixed", "outcome"),
    [
        ("rpm", "1.2-3.el9", "0:1.2-3.el9", "reported_fix_present"),
        ("rpm", "0:1.2-3.el9", "1.2-3.el9", "reported_fix_present"),
        ("rpm", "1:1.2-3.el9", "0:1.2-3.el9", "inconclusive"),
        ("rpm", "1.2-3.el9", "1:1.2-3.el9", "inconclusive"),
        ("apk", "1.2-r3", "0:1.2-r3", "inconclusive"),
        ("deb", "1.2-3", "0:1.2-3", "inconclusive"),
    ],
)
def test_zero_rpm_epoch_is_equivalent(package_type, installed, fixed, outcome):
    items = reports(package_type)
    items[1]["matches"][0]["vulnerability"]["fix"]["versions"] = [fixed]
    after = items[2]["artifacts"][0]
    after.update(version=installed, purl=f"pkg:{package_type}/vendor/example@{installed}")
    result = run(items, package_type)
    assert result["scanner_evidence"] == outcome
    assert result["reported_fixed_versions"] == [fixed]
    assert result["after"]["installed_versions"] == [installed]
    items[3]["matches"] = [{**items[1]["matches"][0], "artifact": after}]
    assert run(items, package_type)["scanner_evidence"] == "still_reported"


def test_zero_rpm_epoch_does_not_make_a_version_change():
    items = reports("rpm")
    items[1]["matches"][0]["vulnerability"]["fix"]["versions"] = ["0:1"]
    items[2]["artifacts"][0].update(version="0:1", purl="pkg:rpm/vendor/example@0:1")
    assert run(items, "rpm")["scanner_evidence"] == "inconclusive"


def test_database_origin_is_compared_when_present():
    items = reports()
    del items[1]["descriptor"]["db"]["status"]["from"]
    with pytest.raises(ValueError, match="Incomparable Grype databases"):
        run(items)
    del items[3]["descriptor"]["db"]["status"]["from"]
    assert run(items)["scanner_evidence"] == "reported_fix_present"


@pytest.mark.parametrize(
    ("other_fixed", "outcome"),
    [
        ("1.2-3.el9", "reported_fix_present"),
        ("1:1.2-3.el9", "inconclusive"),
        ("1.2-4.el9", "inconclusive"),
    ],
)
def test_rpm_fix_intersection_across_scanner_namespaces(other_fixed, outcome):
    items = reports("rpm")
    _, scan, after, scanned = items
    for report in (scan, scanned):
        report["descriptor"]["configuration"] = {"match": {"rpm": {"using-cpes": True}}}
    match = scan["matches"][0]
    match["vulnerability"].update(
        id="CVE-2099-1234",
        namespace="redhat:distro:redhat:9",
        fix={"state": "fixed", "versions": ["0:1.2-3.el9", "9.9-1.el9"]},
    )
    other = deepcopy(match)
    other["vulnerability"].update(
        namespace="nvd:cpe", fix={"state": "fixed", "versions": [other_fixed, "8.8-1.el9"]}
    )
    scan["matches"].append(other)
    after["artifacts"][0].update(version="1.2-3.el9", purl="pkg:rpm/vendor/example@1.2-3.el9")
    result = run(items, "rpm", "CVE-2099-1234")
    assert result["before"]["selected_matches"] == 2
    assert result["scanner_evidence"] == outcome
    expected = ["0:1.2-3.el9", "1.2-3.el9"] if outcome == "reported_fix_present" else []
    assert result["reported_fixed_versions"] == expected


@pytest.mark.parametrize("bucket", ["matches", "ignoredMatches"])
@pytest.mark.parametrize("relation", ["same advisory", "unrelated advisory", "other package"])
def test_baseline_alias_selects_residual_matches(bucket, relation):
    items = reports("npm")
    before, scan, after, scanned = items
    for sbom, version in ((before, "1.0.0"), (after, "2.0.0")):
        sbom["artifacts"][0].update(version=version, purl=f"pkg:npm/example@{version}")
    for report in (scan, scanned):
        report["descriptor"]["configuration"] = {"match": {"javascript": {"using-cpes": True}}}
    match = scan["matches"][0]
    match["vulnerability"].update(
        id="GHSA-xxxx-xxxx-xxxx",
        namespace="github:language:javascript",
        fix={"state": "fixed", "versions": ["2.0.0"]},
    )
    match["relatedVulnerabilities"] = [{"id": "CVE-2099-1234", "namespace": "nvd:cpe"}]
    residual = deepcopy(match)
    residual["artifact"] = deepcopy(after["artifacts"][0])
    residual["vulnerability"].update(
        id="CVE-2099-1234", namespace="nvd:cpe", fix={"state": "fixed", "versions": ["3.0.0"]}
    )
    residual["relatedVulnerabilities"] = []
    if relation == "same advisory":
        baseline = deepcopy(residual)
        baseline["artifact"] = deepcopy(before["artifacts"][0])
        scan["matches"].append(baseline)
    elif relation == "unrelated advisory":
        residual["vulnerability"]["id"] = "CVE-2099-1235"
    elif relation == "other package":
        residual["artifact"].update(name="other-example", purl="pkg:npm/other-example@2.0.0")
        after["artifacts"].append(deepcopy(residual["artifact"]))
    scanned[bucket] = [residual]
    result = run(items, "npm", "GHSA-xxxx-xxxx-xxxx")
    assert result["before"]["selected_matches"] == 1
    expected = "reported_fix_present"
    if relation == "same advisory":
        expected = "still_reported" if bucket == "matches" else "inconclusive"
    assert result["scanner_evidence"] == expected
    assert result["after"]["selected_matches"] == (
        relation == "same advisory" and bucket == "matches"
    )
    assert result["after"]["selected_ignored_matches"] == (
        relation == "same advisory" and bucket == "ignoredMatches"
    )

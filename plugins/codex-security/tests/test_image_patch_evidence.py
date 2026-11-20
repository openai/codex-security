"""Image patch evidence binds the selected advisory to a comparable pair of images."""

from copy import deepcopy

import pytest
from workbench_test_support import load_script

compare = load_script("image_patch_evidence").compare

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
    return compare(*inputs, advisory, "example", package_type)


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

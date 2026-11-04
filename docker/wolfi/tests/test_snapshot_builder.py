import base64
import gzip
import hashlib
import io
import runpy
import tempfile
import unittest
from pathlib import Path

snapshot = runpy.run_path(str(Path(__file__).resolve().parents[1] / "snapshot-builder.py"))["snapshot"]


def fixture(name, signed):
    # APK v2 stores consecutive, independently compressed gzip members.
    url = f"https://packages.wolfi.dev/os/x86_64/{name}-1-r0.apk"
    pkg = {"name": name, "version": "1-r0", "url": url, "architecture": "x86_64"}
    data = b""
    for part, algorithm in (("signature", "sha1"), ("control", "sha1"), ("data", "sha256")):
        if part == "signature" and not signed:
            pkg[part] = {"range": "", "checksum": ""}
            continue
        block = gzip.compress(f"{name} {part}".encode(), mtime=0)
        digest = base64.b64encode(hashlib.new(algorithm, block).digest()).decode()
        pkg[part] = {"range": f"bytes={len(data)}-{len(data) + len(block) - 1}",
                     "checksum": f"{algorithm}-{digest}"}
        data += block
    return pkg, data


class SnapshotTest(unittest.TestCase):
    def setUp(self):
        self.first, self.a = fixture("first", signed=False)
        self.second, self.b = fixture("second", signed=True)
        self.lock = {"version": "v1", "contents": {"packages": [self.first, self.second]}}
        self.served = {self.first["url"]: self.a, self.second["url"]: self.b}
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.repo = Path(temp.name) / "repository"

    def fetch(self, url, *, timeout):
        return io.BytesIO(self.served[url])

    def test_stages_exact_bytes_for_signed_and_unsigned_packages(self):
        snapshot(self.lock, self.repo, self.fetch)
        apks = {f.name: f.read_bytes() for f in (self.repo / "x86_64").iterdir()}
        self.assertEqual(apks, {"first-1-r0.apk": self.a, "second-1-r0.apk": self.b})

    def test_same_url_tampering_never_publishes_a_partial_repository(self):
        corrupt = {"truncated": self.b[:-1], "extra": self.b + b"x"}
        for part in ("signature", "control", "data"):
            offset = int(self.second[part]["range"].split("=")[1].split("-")[0])
            corrupt[part] = self.b[:offset] + bytes([self.b[offset] ^ 1]) + self.b[offset + 1:]
        for case, changed in corrupt.items():
            with self.subTest(case=case):
                self.served[self.second["url"]] = changed
                with self.assertRaises(ValueError):
                    snapshot(self.lock, self.repo, self.fetch)
                self.assertEqual(list(self.repo.iterdir()), [])

    def test_refuses_a_gap_before_control_and_an_unlocked_origin(self):
        self.first["control"]["range"] = self.first["control"]["range"].replace("bytes=0-", "bytes=1-")
        with self.assertRaisesRegex(ValueError, "invalid control range"):
            snapshot(self.lock, self.repo, self.fetch)
        self.first["url"] = "https://example.org/first-1-r0.apk"
        with self.assertRaisesRegex(ValueError, "Unexpected package source"):
            snapshot(self.lock, self.repo, self.fetch)


if __name__ == "__main__":
    unittest.main()

"""Exercise the deployed selectors using ordinary mail, without a model or network."""

import os
import sys
from io import BytesIO
from pathlib import Path
from queue import Queue
from runpy import run_path
from shutil import copy
from subprocess import run
from tempfile import TemporaryDirectory
from unittest import TestCase, main
from unittest.mock import patch
from warnings import catch_warnings, simplefilter
from zipfile import ZipFile

import catalog_a
import catalog_b


def bundle(*messages):
    output = BytesIO()
    with ZipFile(output, "w") as archive, catch_warnings():
        # A duplicate filename is intentional in every bundle.
        simplefilter("ignore", UserWarning)
        for message in messages:
            archive.writestr("notice.eml", message)
    return output.getvalue()


class CatalogContract(TestCase):
    def test_member_identity_across_queue(self):
        for catalog in [catalog_a, catalog_b]:
            with self.subTest(catalog=catalog.__name__):
                with patch.dict("sys.modules", catalog=catalog):
                    gateway = run_path(str(Path(__file__).with_name("gateway.py")))
                allowed = gateway["ENVELOPE"] + b"\r\n\r\nA plain notification"
                other = allowed.replace(b"To: archive@", b"To: alternate@")
                jobs = Queue()
                submit = gateway["submit"]
                # Rejecting a later member must reject the whole job.
                for invalid in [
                    other,
                    allowed.replace(
                        b"To: archive@", b"To: alternate@example.invalid\r\nTo: archive@"
                    ),
                    allowed.replace(b"text/plain", b"multipart/mixed"),
                ]:
                    with self.assertRaises(ValueError):
                        submit(bundle(allowed, invalid), jobs)
                    self.assertTrue(jobs.empty())
                if catalog is catalog_b:
                    with self.assertRaises(ValueError):
                        submit(bundle(other, allowed), jobs)
                    self.assertTrue(jobs.empty())
                    expected = [allowed, allowed]
                else:
                    expected = [other, allowed]
                # Exercise the entrypoint and worker in distinct processes; echo
                # the indexer's input so both delivered members can be checked.
                with TemporaryDirectory() as directory:
                    deployed = Path(directory)
                    for name in ["gateway.py", "worker.py", "submit_bundle.py"]:
                        copy(Path(__file__).with_name(name), deployed / name)
                    copy(catalog.__file__, deployed / "catalog.py")
                    (deployed / "index-mail.cjs").write_text(
                        "process.stdin.pipe(process.stdout);\n"
                    )
                    result = run(
                        [sys.executable, deployed / "submit_bundle.py"],
                        cwd=deployed,
                        env={**os.environ, "PYTHONPATH": directory},
                        input=bundle(*expected),
                        capture_output=True,
                    )
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual(result.stdout, b"".join(expected))


if __name__ == "__main__":
    main()

"""Exercise the deployed selectors using ordinary mail, without a model or network."""

from io import BytesIO
from pathlib import Path
from queue import Queue
from runpy import run_path
from unittest import TestCase, main
from unittest.mock import patch
from warnings import catch_warnings, simplefilter
from zipfile import ZipFile

import catalog_a
import catalog_b
import worker


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
                    submit(bundle(allowed, allowed), jobs)
                    expected = [allowed, allowed]
                else:
                    submit(bundle(other, allowed), jobs)
                    expected = [other, allowed]
                with patch.object(worker.subprocess, "run") as index:
                    worker.import_next(jobs)
                delivered = [call.kwargs["input"] for call in index.call_args_list]
                self.assertEqual(delivered, expected)


if __name__ == "__main__":
    main()

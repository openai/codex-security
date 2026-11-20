from io import BytesIO
from zipfile import ZipFile

from catalog import messages

ENVELOPE = (
    b"From: relay@example.invalid\r\n"
    b"To: archive@example.invalid\r\n"
    b"Content-Type: text/plain; charset=us-ascii"
)


def submit(upload, jobs):
    with ZipFile(BytesIO(upload)) as archive:
        for raw in messages(archive):
            headers, separator, body = raw.partition(b"\r\n\r\n")
            if headers != ENVELOPE or not separator or not body.isascii():
                raise ValueError("expected an archive notification")
    jobs.put(upload)

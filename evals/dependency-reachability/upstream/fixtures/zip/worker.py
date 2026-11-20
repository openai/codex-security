import subprocess
from io import BytesIO
from pathlib import Path
from zipfile import ZipFile


def import_next(jobs):
    with ZipFile(BytesIO(jobs.get())) as archive:
        for member in archive.infolist():
            subprocess.run(
                ["node", Path(__file__).with_name("index-mail.cjs")],
                input=archive.read(member),
                check=True,
            )

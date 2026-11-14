"""Package only the three source roots used by the Lambda deployment."""

import sys
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile

ROOT = Path(__file__).resolve().parents[2]
ARTIFACTS = {
    "order": {
        "app/__init__.py": ROOT / "app/__init__.py",
        "app/data.py": ROOT / "app/data.py",
        "app/reports.py": ROOT / "app/reports.py",
        "app/server.py": ROOT / "app/server.py",
        "app/lambda_handler.py": ROOT / "app/lambda_handler.py",
    },
    "billing": {
        "service.py": ROOT / "deployment/services/billing/service.py",
    },
    "analytics": {
        "worker.py": ROOT / "deployment/services/analytics/worker.py",
    },
}


def package(output_dir):
    output_dir.mkdir(parents=True, exist_ok=True)
    archives = []
    for name, files in ARTIFACTS.items():
        archive = output_dir / f"{name}.zip"
        with ZipFile(archive, "w", ZIP_DEFLATED) as bundle:
            for archive_path, source in files.items():
                bundle.write(source, archive_path)
        archives.append(archive)
    return archives


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("usage: python3 deployment/aws/package.py OUTPUT_DIR")
    for path in package(Path(sys.argv[1])):
        print(path)

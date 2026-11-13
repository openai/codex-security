"""Package the two code sources uploaded before stack deployment."""

import sys
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile

ROOT = Path(__file__).resolve().parents[1]


def package(output_dir):
    output_dir.mkdir(parents=True, exist_ok=True)
    for name in ("gateway", "worker"):
        archive = output_dir / f"{name}.zip"
        with ZipFile(archive, "w", ZIP_DEFLATED) as bundle:
            bundle.write(ROOT / "app" / f"{name}.py", f"{name}.py")
        print(archive)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("usage: python3 deployment/package.py OUTPUT_DIR")
    package(Path(sys.argv[1]))

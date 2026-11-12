"""Prepare the Continuum CLI's AWS process without returning credential values."""

import json
import os
import sys
from pathlib import Path

# The installed SDK invokes this entry point with an isolated interpreter.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from collect_continuum import ACCOUNT_DIRECTORIES, installed_aws  # noqa: E402

PATH_SETTINGS = ACCOUNT_DIRECTORIES | {
    "PATH",
    "AWS_CONFIG_FILE",
    "AWS_SHARED_CREDENTIALS_FILE",
    "AWS_DATA_PATH",
}


def main() -> None:
    request = json.load(sys.stdin)
    # Environment settings arrive as data after Python startup. The shared
    # launcher selects the settings AWS and its credential helpers receive.
    os.environ.clear()
    os.environ.update(request["environment"])
    cwd = Path(request["cwd"])
    roots = tuple(Path(path) for path in request["protectedRoots"])
    executable, environment, trusted_cwd = installed_aws(cwd, caller_cwd=cwd, protected_roots=roots)
    json.dump(
        {
            "executable": str(executable),
            "cwd": str(trusted_cwd),
            "forward": sorted(environment.keys() - PATH_SETTINGS),
            "paths": {key: environment[key] for key in PATH_SETTINGS if key in environment},
        },
        sys.stdout,
    )


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError) as error:
        sys.exit(str(error))

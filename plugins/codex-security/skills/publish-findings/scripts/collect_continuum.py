"""Export one AWS Continuum finding and its selected repository's generated patches."""

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

# Isolated Python does not put the installed script directory on sys.path.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from collector_paths import in_source, source_root  # noqa: E402


def installed_aws(target: Path) -> tuple[Path, dict[str, str], Path | None]:
    source = source_root(target)
    name = "aws.exe" if os.name == "nt" else "aws"
    executable = None
    directories = []
    for entry in os.get_exec_path():
        if os.name == "nt" and entry.startswith('"') and entry.endswith('"'):
            entry = entry[1:-1]
        directory = Path(entry)
        if not directory.is_absolute():
            continue
        try:
            # Also exclude a host directory whose aws links through the checkout.
            if in_source(directory / name, source):
                continue
            directory = directory.resolve(strict=True)
            if not directory.is_dir():
                continue
            candidate = directory / name
            if executable is None and candidate.is_file() and os.access(candidate, os.X_OK):
                resolved = candidate.resolve(strict=True)
                if os.name == "nt" and resolved.suffix.lower() != ".exe":
                    continue
                executable = resolved
            directories.append(str(directory))
        except OSError:
            continue
    if executable is None:
        raise ValueError("Could not find an installed AWS CLI outside the selected checkout.")

    # Credential helpers inherit the same lookup boundary, including on Windows
    # where executable searches can also use the current directory.
    environment = os.environ.copy()
    environment["PATH"] = os.pathsep.join(directories)
    cwd = executable.parent if in_source(Path.cwd(), source) else None
    return executable, environment, cwd


def collect(
    environment_id: str, finding_id: str, repository_name: str | None, target: Path
) -> dict:
    executable, child_env, cwd = installed_aws(target)

    def aws(operation: str, *arguments: str) -> dict:
        return json.loads(
            subprocess.check_output(
                [
                    str(executable),
                    "continuum",
                    operation,
                    *arguments,
                    "--output",
                    "json",
                    "--no-cli-pager",
                ],
                env=child_env,
                cwd=cwd,
            )
        )

    environment = ["--environment-id", environment_id]
    finding = aws("get-code-finding", *environment, "--finding-id", finding_id)
    issue_id = finding.get("createdIssueId") or finding.get("duplicateOfIssueId")
    if not issue_id:
        return finding

    issue = [*environment, "--issue-id", issue_id]
    # With JSON output the AWS CLI combines all pages into one items array.
    artifacts = aws("list-code-issue-artifacts", *issue, "--artifact-type", "PATCH")
    patches = []
    for artifact_id in sorted(item["artifactId"] for item in artifacts["items"]):
        artifact = aws("get-code-issue-artifact", *issue, "--artifact-id", artifact_id)
        body = artifact["body"].get("patch")
        if body is None:
            raise ValueError(f"Continuum artifact {artifact_id} has no projected patch body.")
        if repository_name is not None and body.get("repositoryName") != repository_name:
            if not body.get("repositoryName"):
                print(
                    f"Skipped Continuum patch {artifact_id}: AWS did not identify its repository.",
                    file=sys.stderr,
                )
            continue
        patch = {key: body[key] for key in ("patch", "patchSha256", "sizeBytes")}
        for key in ("format", "repositoryName"):
            if key in body:
                patch[key] = body[key]
        patches.append({"artifactId": artifact_id, **patch})

    return {"finding": finding, "patches": patches} if patches else finding


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--source-root",
        type=Path,
        required=True,
        help="Absolute path to the selected local checkout to exclude from executable lookup.",
    )
    parser.add_argument("--environment-id", required=True)
    parser.add_argument("--finding-id", required=True)
    scope = parser.add_mutually_exclusive_group(required=True)
    scope.add_argument(
        "--single-repository",
        action="store_true",
        help="The selected environment has been verified to contain only this repository.",
    )
    scope.add_argument("--repository-name", help="Exact Continuum build repository name.")
    args = parser.parse_args()
    try:
        report = collect(
            args.environment_id, args.finding_id, args.repository_name, args.source_root
        )
    except subprocess.CalledProcessError as error:
        # The AWS CLI already wrote the diagnostic to stderr.
        return error.returncode
    except (KeyError, OSError, ValueError) as error:
        sys.exit(f"Could not export Continuum finding: {error}")
    print(json.dumps(report))
    return 0


if __name__ == "__main__":
    sys.exit(main())

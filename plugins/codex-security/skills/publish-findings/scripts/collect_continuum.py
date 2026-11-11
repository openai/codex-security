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

# Credential helpers may use any interpreter. Forward AWS and host settings
# explicitly so a helper cannot inherit language-specific startup hooks.
ACCOUNT_DIRECTORIES = {"HOME", "USERPROFILE", "APPDATA", "LOCALAPPDATA", "XDG_CONFIG_HOME"}
HOST_SETTINGS = ACCOUNT_DIRECTORIES | {
    "ALL_PROXY",
    "CURL_CA_BUNDLE",
    "HOMEDRIVE",
    "HOMEPATH",
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "LANG",
    "LANGUAGE",
    "LOGNAME",
    "NO_PROXY",
    "REQUESTS_CA_BUNDLE",
    "SSH_AUTH_SOCK",
    "SSL_CERT_DIR",
    "SSL_CERT_FILE",
    "SYSTEMROOT",
    "TEMP",
    "TMP",
    "TMPDIR",
    "TZ",
    "USER",
    "USERNAME",
    "WINDIR",
}


def checked_model_path(path: Path, source: Path | None, levels: int) -> None:
    if in_source(path, source) or (source is not None and source.is_relative_to(path.resolve())):
        raise ValueError(f"Use an AWS model path separate from the selected checkout: {path}")
    if levels and path.is_dir():
        # AWS reads global models and service/<version>/*.json[.gz]. Version
        # names come from the filesystem; even a new version can override AWS.
        for child in path.iterdir():
            if child.name.lower().endswith((".json", ".json.gz")) or (
                levels > 1 and child.is_dir()
            ):
                checked_model_path(child, source, levels - 1)


def pinned_setting(name: str, path: Path) -> str:
    # Preserve paths expanded from parent-only variables; the CLI expands the
    # forwarded value again and splits its model path on the platform separator.
    value = str(path)
    if os.path.expandvars(value) != value or (name == "AWS_DATA_PATH" and os.pathsep in value):
        raise ValueError(f"Use a fully expanded file path for {name}.")
    return value


def aws_environment(source: Path | None, cwd: Path, directories: list[str]) -> dict[str, str]:
    env = {
        name: value
        for name, value in os.environ.items()
        if name.startswith(("AWS_", "LC_")) or name.upper() in HOST_SETTINGS
    }
    env["PATH"] = os.pathsep.join(directories)
    for name in ACCOUNT_DIRECTORIES:
        if env.get(name) and in_source(cwd / env[name], source):
            raise ValueError(f"Use an account {name} directory outside the selected checkout.")

    # AWS can run credential_process from either profile file and shell commands
    # from its per-account alias file. Check the paths AWS will actually read.
    for name, default in (
        ("AWS_CONFIG_FILE", "~/.aws/config"),
        ("AWS_SHARED_CREDENTIALS_FILE", "~/.aws/credentials"),
    ):
        filename = os.path.expanduser(os.path.expandvars(env.get(name, default)))
        path = cwd / filename
        if in_source(path, source):
            raise ValueError(f"Use an {name} file outside the selected checkout.")
        if name in env:
            env[name] = pinned_setting(name, path)
    if in_source(cwd / os.path.expanduser("~/.aws/cli/alias"), source):
        raise ValueError("Use an AWS CLI alias file outside the selected checkout.")
    checked_model_path(cwd / os.path.expanduser("~/.aws/models"), source, 3)
    if "AWS_DATA_PATH" in env:
        paths = []
        for entry in env["AWS_DATA_PATH"].split(os.pathsep):
            directory = os.path.expanduser(os.path.expandvars(entry))
            if directory:
                path = cwd / directory
                checked_model_path(path, source, 3)
                paths.append(pinned_setting("AWS_DATA_PATH", path))
        env["AWS_DATA_PATH"] = os.pathsep.join(paths)
    return env


def installed_aws(target: Path) -> tuple[Path, dict[str, str], Path]:
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
    cwd = executable.parent if in_source(Path.cwd(), source) else Path.cwd()
    return executable, aws_environment(source, cwd, directories), cwd


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

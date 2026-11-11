"""Export one AWS Continuum finding and its selected repository's generated patches."""

import argparse
import json
import subprocess
import sys


def aws(operation: str, *arguments: str) -> dict:
    return json.loads(
        subprocess.check_output(
            ["aws", "continuum", operation, *arguments, "--output", "json", "--no-cli-pager"]
        )
    )


def collect(environment_id: str, finding_id: str, repository_name: str | None) -> dict:
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
        report = collect(args.environment_id, args.finding_id, args.repository_name)
    except subprocess.CalledProcessError as error:
        # The AWS CLI already wrote the diagnostic to stderr.
        return error.returncode
    except (KeyError, OSError, ValueError) as error:
        sys.exit(f"Could not export Continuum finding: {error}")
    print(json.dumps(report))
    return 0


if __name__ == "__main__":
    sys.exit(main())

"""Cover source selection and failures at the AWS CLI boundary."""

import json
import os
import runpy
import shlex
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

SCRIPT = (
    Path(__file__).resolve().parents[1] / "skills/publish-findings/scripts/collect_continuum.py"
)
main = runpy.run_path(str(SCRIPT))["main"]
AWS_NAME = "aws.exe" if os.name == "nt" else "aws"


def arguments(checkout, *scope):
    identity = ["--environment-id", "env", "--finding-id", "f"]
    return [str(SCRIPT), "--source-root", str(checkout), *identity, *scope]


def collect_one(checkout, directories, **environment):
    return subprocess.run(
        [sys.executable, "-I", *arguments(checkout, "--single-repository")],
        cwd=checkout.parent,
        env={**os.environ, "PATH": os.pathsep.join(map(str, directories)), **environment},
        capture_output=True,
        text=True,
    )


def write_service_model(root):
    model = root / "continuum/2099-10-23/service-2.json"
    model.parent.mkdir(parents=True)
    model.write_text("{}")


@pytest.fixture
def checkout(tmp_path):
    checkout = tmp_path / "source"
    checkout.mkdir()
    return checkout


@pytest.fixture
def invoke(monkeypatch, tmp_path, checkout):
    for directory in (checkout, tmp_path):
        executable = directory / AWS_NAME
        executable.touch()
        executable.chmod(0o755)
    monkeypatch.setenv("PATH", os.pathsep.join(map(str, (checkout, tmp_path))))
    monkeypatch.setenv("NODE_OPTIONS", f"--require={checkout / 'startup.cjs'}")

    def run(scope, *responses):
        replies = iter(responses)
        calls = []

        def aws(command, **kwargs):
            assert Path(command[0]) == (tmp_path / AWS_NAME).resolve()
            assert "NODE_OPTIONS" not in kwargs["env"]
            calls.append(command)
            reply = next(replies)
            if isinstance(reply, Exception):
                raise reply
            return json.dumps(reply).encode()

        monkeypatch.setattr(subprocess, "check_output", aws)
        monkeypatch.setattr(sys, "argv", arguments(checkout, *scope))
        return main(), calls

    return run


def patch(source=None):
    return {
        "body": {
            "patch": {
                "patch": "example\n",
                "sizeBytes": 8,
                "patchSha256": "13550350a8681c84c861aac2e5b440161c2b33a3e4f302ac680ca5b686de48de",
                **({"repositoryName": source} if source else {}),
            }
        }
    }


@pytest.mark.cross_platform
def test_collects_only_selected_repository_on_duplicate_issue(invoke, capsys):
    finding = {"duplicateOfIssueId": "original"}
    status, calls = invoke(
        ["--repository-name", "api"],
        finding,
        {"items": [{"artifactId": "two"}, {"artifactId": "one"}]},
        patch("api"),
        patch("web"),
    )
    assert status == 0
    assert [call[2] for call in calls] == [
        "get-code-finding",
        "list-code-issue-artifacts",
        "get-code-issue-artifact",
        "get-code-issue-artifact",
    ]
    for call in calls:
        assert call[3:5] == ["--environment-id", "env"]
    assert calls[0][5:7] == ["--finding-id", "f"]
    assert calls[1][5:9] == ["--issue-id", "original", "--artifact-type", "PATCH"]
    assert [call[5:9] for call in calls[2:]] == [
        ["--issue-id", "original", "--artifact-id", "one"],
        ["--issue-id", "original", "--artifact-id", "two"],
    ]
    assert json.loads(capsys.readouterr().out) == {
        "finding": finding,
        "patches": [{"artifactId": "one", **patch("api")["body"]["patch"]}],
    }


def test_unnamed_patch_does_not_block_matching_patches(invoke, capsys):
    finding = {"createdIssueId": "issue"}
    status, _ = invoke(
        ["--repository-name", "api"],
        finding,
        {"items": [{"artifactId": "one"}, {"artifactId": "two"}]},
        patch(),
        patch("api"),
    )
    output = capsys.readouterr()
    assert status == 0
    assert "Skipped Continuum patch one" in output.err
    assert json.loads(output.out) == {
        "finding": finding,
        "patches": [{"artifactId": "two", **patch("api")["body"]["patch"]}],
    }


@pytest.mark.parametrize(
    ("finding", "replies"),
    [
        ({"findingId": "f"}, []),
        ({"createdIssueId": "issue"}, [{"items": [{"artifactId": "one"}]}, patch("web")]),
    ],
)
def test_no_eligible_patch_preserves_native_finding(invoke, capsys, finding, replies):
    status, _ = invoke(["--repository-name", "api"], finding, *replies)
    assert status == 0
    assert json.loads(capsys.readouterr().out) == finding


def test_failure_after_first_patch_emits_no_partial_report(invoke, capsys):
    status, _ = invoke(
        ["--single-repository"],
        {"createdIssueId": "issue"},
        {"items": [{"artifactId": "one"}, {"artifactId": "two"}]},
        patch(),
        subprocess.CalledProcessError(254, ["aws"]),
    )
    assert status == 254
    assert not capsys.readouterr().out


@pytest.mark.cross_platform
def test_no_installed_aws_never_launches_checkout_executable(checkout, monkeypatch):
    executable = checkout / AWS_NAME
    executable.touch()
    executable.chmod(0o755)
    monkeypatch.setenv("PATH", str(checkout))
    monkeypatch.setattr(sys, "argv", arguments(checkout, "--single-repository"))

    def unexpected(command, **kwargs):
        pytest.fail(f"Collector invoked {command[0]} with no installed AWS CLI on PATH")

    monkeypatch.setattr(subprocess, "check_output", unexpected)
    with pytest.raises(SystemExit, match="(?i)aws"):
        main()


@pytest.mark.cross_platform
@pytest.mark.parametrize("setting", ["AWS_CONFIG_FILE", "AWS_SHARED_CREDENTIALS_FILE"])
def test_checkout_credential_process_file_is_rejected(checkout, invoke, monkeypatch, setting):
    config = checkout / "profile"
    config.write_text("[default]\ncredential_process = checkout-command\n")
    monkeypatch.setenv(setting, str(config))
    with pytest.raises(SystemExit, match="checkout"):
        invoke(["--single-repository"], {})


@pytest.mark.cross_platform
def test_checkout_relative_profile_is_rejected(checkout, invoke, monkeypatch):
    monkeypatch.chdir(checkout)
    (checkout / "profile").write_text("[default]\n")
    monkeypatch.setenv("AWS_CONFIG_FILE", "profile")
    with pytest.raises(SystemExit, match="AWS_CONFIG_FILE file outside the selected checkout"):
        invoke(["--single-repository"], {})


@pytest.mark.skipif(os.name == "nt", reason="Fixture links a settings file into the checkout")
@pytest.mark.parametrize(
    ("name", "contents"),
    [
        ("config", "[default]\ncredential_process = checkout-command\n"),
        ("cli/alias", "[toplevel]\ncontinuum = !checkout-command\n"),
    ],
)
def test_default_settings_linked_into_checkout_are_rejected(
    tmp_path, checkout, invoke, monkeypatch, name, contents
):
    config = checkout / "settings"
    config.write_text(contents)
    home = tmp_path / "home"
    default_file = home / ".aws" / name
    default_file.parent.mkdir(parents=True)
    default_file.symlink_to(config)
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.delenv("AWS_CONFIG_FILE", raising=False)
    with pytest.raises(SystemExit, match="checkout"):
        invoke(["--single-repository"], {})


@pytest.mark.cross_platform
@pytest.mark.parametrize("trusted_first", [False, True])
def test_model_search_path_rejects_checkout_entries(checkout, invoke, monkeypatch, trusted_first):
    write_service_model(checkout)
    trusted = checkout.parent / "installed-models"
    trusted.mkdir()
    paths = (trusted, checkout) if trusted_first else (checkout,)
    monkeypatch.setenv("AWS_DATA_PATH", os.pathsep.join(map(str, paths)))
    with pytest.raises(SystemExit, match="checkout"):
        invoke(["--single-repository"], {})


@pytest.mark.skipif(os.name == "nt", reason="Fixture links service models into the checkout")
@pytest.mark.parametrize(
    ("use_default", "linked_entry"),
    [
        (False, "."),
        (True, "continuum"),
        (False, "continuum/2099-10-23"),
        (True, "continuum/2099-10-23/service-2.json"),
    ],
)
def test_aws_model_links_into_checkout_are_rejected(
    tmp_path, checkout, invoke, monkeypatch, use_default, linked_entry
):
    write_service_model(checkout)
    if use_default:
        monkeypatch.setenv("HOME", str(tmp_path))
        monkeypatch.delenv("AWS_DATA_PATH", raising=False)
        models = tmp_path / ".aws/models"
    else:
        models = tmp_path / "installed-models"
        monkeypatch.setenv("AWS_DATA_PATH", str(models))
    link = models / linked_entry
    link.parent.mkdir(parents=True, exist_ok=True)
    target = checkout / linked_entry
    link.symlink_to(target, target_is_directory=target.is_dir())
    with pytest.raises(SystemExit, match="checkout"):
        invoke(["--single-repository"], {})


@pytest.mark.native_macos
@pytest.mark.skipif(os.name == "nt", reason="Fixture uses Bash scripts and POSIX symlinks")
def test_aws_and_its_credential_helper_skip_checkout_launchers_and_startup_hooks(tmp_path):
    checkout = tmp_path / "source"
    repo_bin = checkout / "bin"
    repo_bin.mkdir(parents=True)
    trusted_bin = tmp_path / "installed"
    helper_bin = tmp_path / "auth-tools"
    linked_bin = tmp_path / "linked"
    for directory in (trusted_bin, helper_bin, linked_bin):
        directory.mkdir()

    def script(path, body):
        path.write_text("#!/bin/bash\n" + body)
        path.chmod(0o755)

    marker = tmp_path / "ran-source-tool"
    for name in ("aws", "fixture-credentials"):
        script(repo_bin / name, f": > {shlex.quote(str(marker))}\nexit 9\n")
    alias = tmp_path / "alias"
    alias.symlink_to(repo_bin, target_is_directory=True)
    (linked_bin / "aws").symlink_to(repo_bin / "aws")
    script(trusted_bin / "aws", "exec fixture-credentials\n")
    credentials = "import json, os\nprint(json.dumps({'profile': os.environ['AWS_PROFILE']}))"
    script(
        helper_bin / "fixture-credentials",
        f"exec {shlex.quote(sys.executable)} -c {shlex.quote(credentials)}\n",
    )
    hook_marker = tmp_path / "ran-startup-hook"
    hook = checkout / "bash-env"
    hook.write_text(f": > {shlex.quote(str(hook_marker))}\n")
    python_marker = tmp_path / "ran-sitecustomize"
    (checkout / "sitecustomize.py").write_text(
        f"from pathlib import Path\nPath({str(python_marker)!r}).touch()\n"
    )
    result = collect_one(
        checkout,
        (repo_bin, alias, linked_bin, trusted_bin, helper_bin),
        AWS_PROFILE="synthetic",
        BASH_ENV=str(hook),
        PYTHONPATH=str(checkout),
    )
    assert not marker.exists()
    assert not hook_marker.exists()
    assert not python_marker.exists()
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout) == {"profile": "synthetic"}


@pytest.mark.skipif(os.name == "nt", reason="Fixture uses POSIX executable scripts")
def test_node_credential_helper_ignores_checkout_preload(tmp_path, checkout):
    node = shutil.which("node")
    if node is None:
        pytest.skip("Node credential helper requires an installed Node runtime")
    preload = checkout / "preload.cjs"
    marker = tmp_path / "ran-node-preload"
    preload.write_text(f"require('node:fs').writeFileSync({json.dumps(str(marker))}, 'ran');\n")

    aws = tmp_path / "aws"
    aws.write_text("#!/bin/sh\nexec fixture-node-credentials\n")
    aws.chmod(0o755)
    helper = tmp_path / "fixture-node-credentials"
    helper.write_text(
        "#!/usr/bin/env node\n"
        "const keys = ['AWS_PROFILE', 'AWS_REGION', 'AWS_CONFIG_FILE', 'HTTPS_PROXY', "
        "'AWS_DATA_PATH'];\n"
        "console.log(JSON.stringify(Object.fromEntries(keys.map(key => [key, process.env[key]]))));\n"
    )
    helper.chmod(0o755)
    config = tmp_path / "profile"
    config.write_text("[profile synthetic]\ncredential_process = fixture-node-credentials\n")
    models = tmp_path / "installed-models"
    write_service_model(models)
    settings = {
        "AWS_PROFILE": "synthetic",
        "AWS_REGION": "us-east-1",
        "AWS_CONFIG_FILE": str(config),
        "AWS_DATA_PATH": str(models),
        "HTTPS_PROXY": "http://proxy.example.invalid:8080",
    }
    result = collect_one(
        checkout,
        (tmp_path, Path(node).parent),
        NODE_OPTIONS=f"--require={json.dumps(str(preload))}",
        **settings,
    )
    assert not marker.exists()
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout) == settings

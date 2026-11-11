import { existsSync } from "node:fs";
import {
  mkdir,
  realpath,
  rename,
  rm,
  symlink,
  writeFile,
} from "node:fs/promises";
import { delimiter, join } from "node:path";
import { expect, test } from "bun:test";
import { main } from "../src/cli.js";
import { dependencies, capture } from "./cli-fixtures.js";
import { PLUGIN_ROOT } from "./plugin-root.js";
import { useTestPython } from "./support/python.js";
import { runPython } from "./support/python-probe.js";
import {
  scopedTemporaryDirectory,
  temporaryDirectory,
} from "./support/temporary-directories.js";
import {
  scanRegistrationArguments,
  workbenchCommand,
} from "./support/workbench-command.js";
import { git } from "./git-fixture.js";
import { runCommand } from "./support/shell.js";

const pythonExecutable = useTestPython();
const ambientPython = useTestPython(false);

const savedAliasFindings = String.raw`
import sqlite3, sys
from pathlib import Path
sys.path.insert(0, sys.argv[1])
import workbench_db as workbench
from filesystem_identity import serialize_filesystem_identity
state, repository, alias = map(Path, sys.argv[2:5])
state.mkdir(exist_ok=True)
with sqlite3.connect(state / "workbench.sqlite3") as connection:
    connection.row_factory = sqlite3.Row
    workbench.apply_migrations(connection)
    def insert(table, **values):
        connection.execute(f"INSERT INTO {table} ({','.join(values)}) VALUES ({','.join('?' for _ in values)})", tuple(values.values()))
    timestamp = "2026-08-01T00:00:00Z"
    for name, target in (("canonical", repository), ("alias", alias)):
        metadata = target.stat()
        insert("security_targets", id=name, current_path=str(target), display_name=name, created_at=timestamp, updated_at=timestamp)
        insert("workspaces", id=name, target_id=name, created_at=timestamp, updated_at=timestamp)
        insert("scans", id=name, workspace_id=name, target_id=name, target_path=str(target), target_revision="unversioned", target_device=serialize_filesystem_identity(metadata.st_dev), target_inode=serialize_filesystem_identity(metadata.st_ino), scope=".", mode="standard", scan_dir=str(state / name), status="complete", phase="reporting", started_at=timestamp, completed_at=timestamp, created_at=timestamp, updated_at=timestamp)
        insert("scan_progress", scan_id=name, updated_at=timestamp)
        insert("findings", id=name, fingerprint=name, rule_id="synthetic-rule", identity_anchor=name, created_at=timestamp, updated_at=timestamp)
        insert("finding_occurrences", id=name, finding_id=name, scan_id=name, title=name, summary="Synthetic finding", severity="high", confidence="high", remediation="Constrain the path", details_json="{}", created_at=timestamp)
    if sys.argv[5] == "stale":
        connection.execute("UPDATE scans SET target_inode = ? WHERE id = 'alias'", (serialize_filesystem_identity(alias.stat().st_ino + 1),))
`;

test("findings list preserves exact saved aliases and rejects their stale ownership", async () => {
  const root = await temporaryDirectory("findings-alias-boundary-");
  try {
    const repository = join(root, "repository");
    const alias = join(root, "saved-alias");
    const unsavedAlias = join(root, "unsaved-alias");
    await mkdir(repository);
    for (const path of [alias, unsavedAlias]) {
      await symlink(
        repository,
        path,
        process.platform === "win32" ? "junction" : "dir",
      );
    }
    const python = pythonExecutable();
    expect(python).not.toBeNull();
    for (const stale of [false, true]) {
      const state = join(root, stale ? "stale-state" : "current-state");
      const initialized = runPython(python!, [
        "-c",
        savedAliasFindings,
        join(PLUGIN_ROOT, "scripts"),
        state,
        repository,
        alias,
        stale ? "stale" : "current",
      ]);
      expect(new TextDecoder().decode(initialized.stderr)).toBe("");
      expect(initialized.exitCode).toBe(0);
      for (const requested of [alias, repository, unsavedAlias]) {
        const stdout = capture();
        const stderr = capture();
        const result = await main(
          ["findings", "list", requested, "--json"],
          stdout.stream,
          stderr.stream,
          dependencies({ onWorkbench: workbenchCommand(python!, state) }),
        );
        if (stale && requested === alias) {
          expect(result).toBe(2);
          expect(stderr.text()).toContain(
            "Repository findings are unavailable",
          );
        } else {
          expect(result, stderr.text()).toBe(0);
          const output = JSON.parse(stdout.text());
          expect(output.repository).toBe(requested);
          expect(
            output.findings.map(
              (finding: { scanId: string }) => finding.scanId,
            ),
          ).toEqual([requested === alias ? "alias" : "canonical"]);
        }
        const scanOutput = capture();
        expect(
          await main(
            ["scans", "list", requested, "--json"],
            scanOutput.stream,
            capture().stream,
            dependencies({ onWorkbench: workbenchCommand(python!, state) }),
          ),
        ).toBe(0);
        expect(
          JSON.parse(scanOutput.text()).scans.map(
            (scan: { scanId: string }) => scan.scanId,
          ),
        ).toEqual(
          stale && requested === alias
            ? []
            : [requested === alias ? "alias" : "canonical"],
        );

        const matchingOutput = capture();
        const matchingErrors = capture();
        const matchingStatus = await main(
          ["scans", "match", "--all", "--json"],
          matchingOutput.stream,
          matchingErrors.stream,
          dependencies({
            currentDirectory: requested,
            onWorkbench: workbenchCommand(python!, state),
          }),
        );
        if (stale && requested === alias) {
          expect(matchingStatus).toBe(2);
          expect(matchingErrors.text()).toContain("no longer matches");
        } else {
          expect(matchingStatus).toBe(0);
          expect(JSON.parse(matchingOutput.text()).scanCount).toBe(1);
          expect(JSON.parse(matchingOutput.text()).repository).toBe(
            await realpath(repository),
          );
        }
      }
    }
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test.skipIf(process.platform !== "linux")(
  "findings list distinguishes an undecodable directory name from its replacement spelling",
  async () => {
    await using temp = await scopedTemporaryDirectory(
      "finding-repository-byte-name-",
    );
    const rawPath = Buffer.concat([
      Buffer.from(join(temp.path, "repo-")),
      Buffer.from([0xff]),
    ]);
    const replacement = join(temp.path, "repo-\uFFFD");
    const requested = join(temp.path, "requested-link");
    await Promise.all([mkdir(rawPath), mkdir(replacement)]);
    await symlink(rawPath, requested);
    expect(await realpath(requested)).toBe(replacement);
    const python = pythonExecutable()!;
    for (const savedMatch of [false, true]) {
      const savedAlias = join(temp.path, `saved-${savedMatch}`);
      const state = join(temp.path, `state-${savedMatch}`);
      await symlink(savedMatch ? rawPath : replacement, savedAlias);
      const setup = runPython(python, [
        "-c",
        savedAliasFindings,
        join(PLUGIN_ROOT, "scripts"),
        state,
        replacement,
        savedAlias,
        "current",
      ]);
      expect(setup.exitCode, new TextDecoder().decode(setup.stderr)).toBe(0);
      const stdout = capture();
      const stderr = capture();
      const status = await main(
        ["findings", "list", requested, "--json"],
        stdout.stream,
        stderr.stream,
        dependencies({ onWorkbench: workbenchCommand(python, state) }),
      );
      expect(status, stderr.text()).toBe(0);
      expect(
        JSON.parse(stdout.text()).findings.map(
          (finding: { scanId: string }) => finding.scanId,
        ),
      ).toEqual(savedMatch ? ["alias"] : []);
    }
  },
);

test.skipIf(process.platform === "win32")(
  "scans list excludes tools in a former checkout and forwards configured Git",
  async () => {
    await using temp = await scopedTemporaryDirectory(
      "history-checkout-tools-",
    );
    const repository = join(temp.path, "repository");
    const linked = join(temp.path, "linked");
    const former = join(temp.path, "former");
    const target = join(former, "component");
    await mkdir(repository);
    await mkdir(target, { recursive: true });
    for (const checkout of [repository, former]) {
      git(checkout, "init", "-q");
      git(checkout, "commit", "--allow-empty", "-qm", "Synthetic history");
    }
    git(repository, "worktree", "add", "--quiet", "--detach", linked);
    const state = join(temp.path, "state");
    const workbench = workbenchCommand(ambientPython()!, state);
    const scanDir = join(temp.path, "scan");
    await mkdir(scanDir, { mode: 0o700 });
    const scan = await workbench(
      scanRegistrationArguments(repository, scanDir),
    );
    await workbench([
      "create-workspace",
      "--workspace-id",
      "00000000-0000-4000-8000-000000000001",
      "--target-path",
      target,
    ]);
    await rename(join(former, ".git"), join(temp.path, "old-git"));
    git(target, "init", "-q");
    const tools = join(former, "bin");
    await mkdir(tools);
    for (const tool of ["git", "python3"]) {
      await writeFile(join(tools, tool), '#!/bin/sh\n: > "$0-ran"\nexit 1\n', {
        mode: 0o700,
      });
    }
    const configured = join(temp.path, "selected-git");
    await symlink(Bun.which("git")!, join(temp.path, "git"));
    await writeFile(
      configured,
      '#!/bin/sh\n: > "$0-ran"\nexec "${0%/*}/git" "$@"\n',
      { mode: 0o700 },
    );
    const cli = new URL("../src/cli.ts", import.meta.url).href;
    for (const binding of [undefined, configured, ""]) {
      const env: NodeJS.ProcessEnv = {
        ...process.env,
        PATH: [tools, process.env["PATH"]].join(delimiter),
        CODEX_SECURITY_STATE_DIR: state,
        CODEX_SECURITY_GIT: binding,
        XDG_CACHE_HOME: join(temp.path, "cache"),
      };
      delete env["PYTHON"];
      const result = await runCommand(
        process.execPath,
        [
          "-e",
          `const { main } = await import(${JSON.stringify(cli)}); process.exitCode = await main(["scans", "list", "--json"]);`,
        ],
        { env, cwd: linked },
      );
      expect(result.status, result.stderr).toBe(0);
      expect(
        JSON.parse(result.stdout).scans.map(
          (row: { scanId: string }) => row.scanId,
        ),
      ).toEqual(binding === "" ? [] : [scan["scanId"]]);
      expect(existsSync(join(tools, "git-ran"))).toBe(false);
      expect(existsSync(join(tools, "python3-ran"))).toBe(false);
      if (binding === configured)
        expect(existsSync(configured + "-ran")).toBe(true);
    }
  },
);

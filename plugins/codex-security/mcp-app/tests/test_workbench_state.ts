import { assertNoError } from "./assertions.ts";
import { WORKBENCH_PYTHON } from "../src/server/workbench-process.ts";
import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { randomUUID } from "node:crypto";
import {
  mkdir,
  mkdtemp,
  readFile,
  realpath,
  rename,
  rm,
  stat,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";

import { applicationRoot as mcpAppRoot, buildServer } from "./build-server.ts";
import { startRpcServer } from "./support/rpc-server.ts";

const pluginRoot = path.resolve(mcpAppRoot, "..");
const fixtureRoot = await realpath(
  await mkdtemp(path.join(tmpdir(), "codex-security-workbench-state-")),
);
const targetPath = path.join(fixtureRoot, "target");
const serverBundlePath = path.join(
  pluginRoot,
  "mcp",
  `.state-test-${randomUUID()}.cjs`,
);
const script = path.join(pluginRoot, "scripts/workbench_db.py");
const python = execFileSync(
  process.env.PYTHON?.trim() || "python3",
  ["-c", "import sys; print(sys.executable)"],
  { encoding: "utf8" },
).trim();
const codexHome = path.join(fixtureRoot, "home");
const defaultState = path.join(codexHome, "state/plugins/codex-security");
const environment = {
  ...process.env,
  CODEX_HOME: codexHome,
  CODEX_SECURITY_SCAN_ROOT: undefined,
  CODEX_SECURITY_STATE_DIR: undefined,
  PYTHON: python,
};

function runWorkbench(args: string[], env: NodeJS.ProcessEnv, framed = false) {
  return spawnSync(
    python,
    framed ? ["-c", WORKBENCH_PYTHON, script] : [script, ...args],
    {
      env,
      encoding: "utf8",
      input: framed ? `${JSON.stringify(args)}\n` : undefined,
    },
  );
}

async function openWorkspace(env: NodeJS.ProcessEnv, sessionId?: string) {
  const server = startRpcServer({
    command: process.execPath,
    args: [serverBundlePath, "--stdio"],
    cwd: pluginRoot,
    env,
  });
  try {
    assertNoError(await server.initialize("workbench-state-test"));
    return await server.callTool(2, {
      name: "open_codex_security_workspace",
      arguments: sessionId
        ? { sessionId }
        : { targetPath, scope: ".", mode: "standard" },
      _meta: { "openai/threadId": "workbench-state-thread" },
    });
  } finally {
    await server.stop();
  }
}

try {
  await mkdir(targetPath);
  await writeFile(path.join(targetPath, "fixture.py"), "print('fixture')\n");
  await buildServer(serverBundlePath, { target: "node20" });

  assertNoError(await openWorkspace(environment));
  assert.equal(
    (await stat(path.join(defaultState, "workbench.sqlite3"))).isFile(),
    true,
  );

  const started = runWorkbench(
    [
      "begin-deep-scan",
      "--target-path",
      targetPath,
      "--thread-id",
      "workbench-state-thread",
    ],
    environment,
  );
  assert.equal(started.status, 0, started.stderr);
  const registered = JSON.parse(started.stdout);
  const sessionId = registered.workspace.id;
  const database = path.join(defaultState, "workbench.sqlite3");
  const savedDatabase = path.join(fixtureRoot, "saved.sqlite3");
  await rename(database, savedDatabase);
  await mkdir(database); // SQLite cannot open a directory, independent of process privileges.
  for (const scanRoot of [undefined, path.join(fixtureRoot, "shared-scans")]) {
    const refused = await openWorkspace({
      ...environment,
      CODEX_SECURITY_SCAN_ROOT: scanRoot,
    });
    assert.equal(refused.result.isError, true);
    assert.match(
      refused.result.content
        .map((item: { text?: string }) => item.text)
        .join("\n"),
      /sqlite3\.OperationalError: unable to open database file/,
    );
  }
  await rm(database, { recursive: true });
  await rename(savedDatabase, database);
  const readers = await Promise.all([
    openWorkspace(environment, sessionId),
    openWorkspace(environment, sessionId),
  ]);
  for (const reopened of readers) {
    assertNoError(reopened);
    assert.equal(
      reopened.result.structuredContent.workspace.results.scanId,
      registered.scan.scanId,
    );
  }
  const rejoined = runWorkbench(
    [
      "begin-deep-scan",
      "--scan-id",
      registered.scan.scanId,
      "--thread-id",
      "workbench-state-thread",
      "--claim-token",
      registered.scan.handoffClaimToken,
    ],
    environment,
  );
  assert.equal(rejoined.status, 0, rejoined.stderr);
  assert.equal(JSON.parse(rejoined.stdout).scan.scanId, registered.scan.scanId);
  const otherHome = {
    ...environment,
    CODEX_HOME: path.join(fixtureRoot, "other-home"),
    CODEX_SECURITY_SCAN_ROOT: path.join(fixtureRoot, "shared-scans"),
  };
  const separate = await openWorkspace(otherHome);
  assertNoError(separate);
  assert.notEqual(separate.result.structuredContent.workspace.id, sessionId);
  assert.equal(
    (await openWorkspace(otherHome, sessionId)).result.isError,
    true,
  );

  // A file in place of the state directory fails regardless of process privileges.
  await rm(defaultState, { recursive: true });
  await writeFile(defaultState, "occupied state path\n");
  const direct = runWorkbench(["database-info"], environment);
  const wrapped = runWorkbench(["database-info"], environment, true);
  assert.equal(direct.status, 1);
  assert.equal(wrapped.status, direct.status);
  const diagnostic = direct.stderr.trim().split("\n").at(-1)!;
  assert.match(diagnostic, /FileExistsError/);
  assert.equal(wrapped.stderr.trim().split("\n").at(-1), diagnostic);
  const failure = await openWorkspace(environment);
  assert.equal(failure.error, undefined);
  assert.equal(failure.result.isError, true);
  assert.ok(
    failure.result.content.some((item: { text?: string }) =>
      item.text?.includes(diagnostic),
    ),
  );

  const explicitState = path.join(fixtureRoot, "explicit-state");
  const explicitEnvironment = {
    ...environment,
    CODEX_SECURITY_STATE_DIR: explicitState,
  };
  const explicitHosts = await Promise.all([
    openWorkspace(explicitEnvironment),
    openWorkspace(explicitEnvironment),
  ]);
  for (const opened of explicitHosts) assertNoError(opened);
  assertNoError(
    await openWorkspace(
      explicitEnvironment,
      explicitHosts[0].result.structuredContent.workspace.id,
    ),
  );
  assert.equal(
    (await stat(path.join(explicitState, "workbench.sqlite3"))).isFile(),
    true,
  );
  assert.equal(await readFile(defaultState, "utf8"), "occupied state path\n");

  for (const args of [
    ["--help"],
    ["create-workspace", "--help"],
    ["resolve-scan-root"],
    ["database-info"],
    ["inspect-target", "--target-path", path.join(fixtureRoot, "missing")],
  ]) {
    const env = {
      ...explicitEnvironment,
      PYTHONSAFEPATH: "1",
      PYTHONIOENCODING: "ascii",
    };
    const direct = runWorkbench(args, env);
    const wrapped = runWorkbench(args, env, true);
    assert.deepEqual(
      [wrapped.status, wrapped.stdout, wrapped.stderr],
      [direct.status, direct.stdout, direct.stderr],
    );
  }
} finally {
  await rm(serverBundlePath, { force: true });
  await rm(fixtureRoot, { recursive: true, force: true });
}

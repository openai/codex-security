import assert from "node:assert/strict";
import { execFile, spawnSync } from "node:child_process";
import { existsSync } from "node:fs";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { after, test } from "node:test";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { importSource } from "./import-module.ts";
import { createTemporaryDirectories } from "./support/temporary-directories.ts";

const { workbenchCommand } = (await importSource(
  "src/workbench/commands.ts",
)) as typeof import("../src/workbench/commands.ts");
const temporary = createTemporaryDirectories(true);
after(() => temporary.cleanup());
const flag = "CODEX_SECURITY_ENABLE_EXTERNAL_IMPORTS";
const commands = ["store-external-findings", "list-external-findings"];
const helper = fileURLToPath(
  new URL(
    "../../../../sdk/typescript/_bundled_plugin/mcp/helpers.mjs",
    import.meta.url,
  ),
);

function helperEnvironment(value?: string): NodeJS.ProcessEnv {
  const environment = Object.fromEntries(
    Object.entries(process.env).filter(([name]) => name.toUpperCase() !== flag),
  );
  if (value !== undefined) environment[flag] = value;
  return environment;
}

test("direct external commands require opt-in before parsing input or creating state", async (t) => {
  const previous = process.env[flag];
  t.after(() => {
    if (previous === undefined) delete process.env[flag];
    else process.env[flag] = previous;
  });
  const stateDirectory = join(
    await temporary.create("external-gate-direct-"),
    "state",
  );
  const input = JSON.stringify({ stateDirectory, payload: {} });
  for (const value of [undefined, "0", "true"]) {
    if (value === undefined) delete process.env[flag];
    else process.env[flag] = value;
    for (const command of commands) {
      await assert.rejects(
        workbenchCommand(command, input),
        /CODEX_SECURITY_ENABLE_EXTERNAL_IMPORTS=1/,
      );
      await assert.rejects(
        workbenchCommand(command, "not JSON"),
        /CODEX_SECURITY_ENABLE_EXTERNAL_IMPORTS=1/,
      );
    }
    assert.equal(existsSync(stateDirectory), false);
  }
});

test("disabled bundled helpers omit external commands and do not create state", async () => {
  const stateDirectory = join(
    await temporary.create("external-gate-disabled-"),
    "state",
  );
  for (const value of [undefined, "0", "true"]) {
    for (const command of commands) {
      const result = spawnSync(process.execPath, [helper, command], {
        env: helperEnvironment(value),
        input: JSON.stringify({ stateDirectory, payload: {} }),
        encoding: "utf8",
      });
      assert.equal(result.status, 2, result.stderr);
      assert.equal(result.stdout, "");
      assert.ok(result.stderr.includes("store-findings"));
      for (const hidden of commands)
        assert.equal(result.stderr.includes(hidden), false);
    }
    assert.equal(existsSync(stateDirectory), false);
  }
  const { stdout } = await promisify(execFile)(
    process.execPath,
    [helper, "store-findings", "--help"],
    { env: helperEnvironment(), timeout: 30_000 },
  );
  assert.ok(stdout.startsWith("Usage: store-findings"));
});

test("opted-in bundled helpers expose help, store and read external evidence", async () => {
  const root = await temporary.create("external-gate-enabled-");
  const stateDirectory = join(root, "state");
  const repository = join(root, "synthetic-repository");
  const payload = {
    repository,
    provider: "synthetic-scanner",
    sourceKey: "synthetic-project",
    findings: [
      {
        source_finding_id: "finding-one",
        evidence: { title: "Synthetic finding" },
      },
    ],
  };
  for (const command of commands) {
    // Open stdin must not delay an enabled help request.
    const { stdout } = await promisify(execFile)(
      process.execPath,
      [helper, command, "--help"],
      { env: helperEnvironment("1"), timeout: 30_000 },
    );
    assert.ok(stdout.startsWith(`Usage: ${command}`));
  }
  for (const command of commands) {
    const result = spawnSync(process.execPath, [helper, command], {
      env: helperEnvironment("1"),
      input: JSON.stringify({ stateDirectory, payload }),
      encoding: "utf8",
    });
    assert.equal(result.status, 0, result.stderr);
    const stored = JSON.parse(result.stdout);
    assert.equal(stored.findings.length, 1);
    assert.deepEqual(stored.findings[0].evidence, payload.findings[0].evidence);
    assert.equal(stored.findings[0].assessment.state, "not_assessed");
  }
  const disabled = spawnSync(
    process.execPath,
    [helper, "list-external-findings"],
    {
      env: helperEnvironment(),
      input: JSON.stringify({ stateDirectory, payload: { repository } }),
      encoding: "utf8",
    },
  );
  assert.equal(disabled.status, 2, disabled.stderr);
  const database = new DatabaseSync(join(stateDirectory, "workbench.sqlite3"), {
    readOnly: true,
  });
  try {
    assert.equal(
      database
        .prepare("SELECT COUNT(*) AS total FROM external_source_reports")
        .get()!.total,
      1,
    );
  } finally {
    database.close();
  }
});

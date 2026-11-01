import assert from "node:assert/strict";
import { test } from "node:test";
import { randomUUID } from "node:crypto";
import path from "node:path";
import { mkdir, readFile, rm, stat, writeFile } from "node:fs/promises";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { temporaryDirectory } from "./support/temporary-directories.ts";
import { loadWorkbenchProcess } from "./support/workbench-process.ts";
import { importSource } from "./import-module.ts";

interface WorkbenchModule {
  executeWorkbench(
    python: string,
    args: string[],
    input?: string | Buffer,
    options?: { isolatedPython?: boolean },
  ): Promise<Record<string, unknown>>;
}

const { executeWorkbench, runWorkbench } = await loadWorkbenchProcess();
const { workbenchArgs } = await importSource(
  path.join(import.meta.dirname, "../src/workbench-arguments.ts"),
);
async function userSitePython(): Promise<string> {
  // A caller's virtualenv may intentionally disable user-site imports.
  const { stdout } = await promisify(execFile)(
    process.env.PYTHON?.trim() || "python3",
    ["-I", "-X", "utf8", "-B", "-c", "import sys; print(sys._base_executable)"],
  );
  return stdout.trim();
}

async function fixtureWorkbench(root: string, source: string) {
  const script = path.join(root, "workbench_db.py");
  await writeFile(script, source);
  const { executeWorkbench } = await loadWorkbenchProcess((source) =>
    source.replace(
      'return join(PLUGIN_ROOT, "scripts", "workbench_db.py");',
      `return ${JSON.stringify(script)};`,
    ),
  );
  return executeWorkbench as WorkbenchModule["executeWorkbench"];
}

await test("workbench scalar arguments reach the Python parser literally", async () => {
  const root = await temporaryDirectory("workbench-literal-arguments-");
  try {
    const scripts = path.resolve(import.meta.dirname, "../../scripts");
    const executeParser = await fixtureWorkbench(
      root,
      `import json, sys
sys.path.insert(0, ${JSON.stringify(scripts)})
from workbench_cli import parse_args
def main():
    print(json.dumps(vars(parse_args("argument transport"))))
`,
    );
    const workerIds = [
      "ordinary",
      "--help",
      "-",
      "",
      "λ 日本語😀\n\0",
      "-key=value",
      "x".repeat(200_000),
      "--help",
    ];
    const result = await executeParser(
      process.env.PYTHON?.trim() || "python3",
      workbenchArgs("claim-deep-scan-dedup", {
        scanId: randomUUID(),
        workerId: randomUUID(),
        promptPath: "--prompt.md",
        artifactDir: "",
        inputWorkerId: workerIds,
      }),
    );
    assert.equal(result.prompt_path, "--prompt.md");
    assert.equal(result.artifact_dir, "");
    assert.deepEqual(result.input_worker_id, workerIds);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

for (const variable of ["PYTHONPATH", "PYTHONUSERBASE"]) {
  await test(`isolated workbench ignores ${variable} startup hooks and preserves its environment`, async () => {
    const root = await temporaryDirectory("workbench-python-startup-");
    const marker = path.join(root, "startup-ran");
    const python = await userSitePython();
    const original = process.env[variable];
    try {
      process.env[variable] = path.join(root, "startup-hooks");
      const hooks =
        variable === "PYTHONPATH"
          ? process.env[variable]
          : (
              await promisify(execFile)(python, [
                "-E",
                "-X",
                "utf8",
                "-B",
                "-c",
                "import site; print(site.getusersitepackages())",
              ])
            ).stdout.trim();
      await mkdir(hooks, { recursive: true });
      await writeFile(
        path.join(
          hooks,
          variable === "PYTHONPATH" ? "sitecustomize.py" : "usercustomize.py",
        ),
        `from pathlib import Path\nPath(${JSON.stringify(marker)}).write_text("startup hook ran")\n`,
      );
      await promisify(execFile)(python, ["-X", "utf8", "-B", "-c", "pass"]);
      assert.equal(await readFile(marker, "utf8"), "startup hook ran");
      await rm(marker);

      const executeFixture = await fixtureWorkbench(
        root,
        'import json, sys\nassert sys.dont_write_bytecode\ndef main():\n    print(json.dumps({"scans": []}))\n',
      );
      const result = await executeFixture(
        python,
        ["list-scans", "--limit", "1"],
        undefined,
        { isolatedPython: true },
      );
      assert.deepEqual(result.scans, []);
      await assert.rejects(stat(marker), { code: "ENOENT" });
      assert.equal(process.env[variable], path.join(root, "startup-hooks"));
    } finally {
      if (original === undefined) delete process.env[variable];
      else process.env[variable] = original;
      await rm(root, { recursive: true, force: true });
    }
  });
}
await test("workbench can import dependencies installed in the Python user site", async () => {
  const root = await temporaryDirectory("workbench-python-user-site-");
  const originalUserBase = process.env.PYTHONUSERBASE;
  try {
    const python = await userSitePython();
    process.env.PYTHONUSERBASE = path.join(root, "user-base");
    const { stdout: userSite } = await promisify(execFile)(python, [
      "-E",
      "-X",
      "utf8",
      "-B",
      "-c",
      "import site; print(site.getusersitepackages())",
    ]);
    await mkdir(userSite.trim(), { recursive: true });
    await writeFile(
      path.join(userSite.trim(), "synthetic_dependency.py"),
      'VALUE = "user-site dependency"\n',
    );
    const { stdout: imported } = await promisify(execFile)(python, [
      "-E",
      "-X",
      "utf8",
      "-B",
      "-c",
      "from synthetic_dependency import VALUE; print(VALUE)",
    ]);
    assert.equal(imported.trim(), "user-site dependency");
    const executeFixture = await fixtureWorkbench(
      root,
      'import json, sys\nassert sys.dont_write_bytecode\nfrom synthetic_dependency import VALUE\ndef main():\n    print(json.dumps({"dependency": VALUE}))\n',
    );
    assert.deepEqual(await executeFixture(python, ["list-scans"]), {
      dependency: "user-site dependency",
    });
  } finally {
    if (originalUserBase === undefined) delete process.env.PYTHONUSERBASE;
    else process.env.PYTHONUSERBASE = originalUserBase;
    await rm(root, { recursive: true, force: true });
  }
});
const root = await temporaryDirectory("workbench-framing-", true);
const stateDir = path.join(root, "state");
const previousStateDir = process.env.CODEX_SECURITY_STATE_DIR;
try {
  process.env.CODEX_SECURITY_STATE_DIR = stateDir;
  const target = path.join(root, "target");
  await mkdir(target);
  const title = "--message\0café\n日本語😀high\ud800low\udfff";
  const input = Buffer.from(
    "--raw context\0café\n".repeat(20_000).trim(),
    "utf8",
  );
  for (const stdin of [true, false]) {
    const result = await executeWorkbench(
      process.env.PYTHON?.trim() || "python3",
      workbenchArgs("create-workspace", {
        workspaceId: randomUUID(),
        targetPath: target,
        targetTitle: title,
        userContextStdin: stdin,
        userContext: stdin ? undefined : input.toString("utf8"),
      }),
      stdin ? input : undefined,
    );
    assert.equal(result.targetTitle, Buffer.from(title).toString("utf8"));
    assert.equal(result.userContext, input.toString("utf8"));
  }
  assert.equal(
    (await stat(path.join(stateDir, "workbench.sqlite3"))).isFile(),
    true,
  );
  const artifactRoot = path.join(root, "artifacts");
  await mkdir(artifactRoot, { mode: 0o700 });
  const binary = Buffer.from([0xff, 0x00, 0x0a, 0x0d, 0xfe]);
  const artifactArgs = [
    "--artifact-root",
    artifactRoot,
    "--artifact-path",
    "raw.bin",
  ];
  await executeWorkbench(
    process.env.PYTHON?.trim() || "python3",
    ["save-artifact", ...artifactArgs],
    binary,
  );
  const saved = await executeWorkbench(
    process.env.PYTHON?.trim() || "python3",
    ["read-artifact", ...artifactArgs],
  );
  assert.deepEqual(Buffer.from(saved.content, "base64"), binary);
  const replacementTarget = path.join(root, "target-\ufffd");
  await mkdir(replacementTarget);
  for (const rawBytePath of [false, true]) {
    await test(
      `workbench path framing with ${rawBytePath ? "a raw-byte collision" : "a Unicode target"}`,
      { skip: rawBytePath && ["win32", "darwin"].includes(process.platform) },
      async () => {
        if (rawBytePath) {
          await mkdir(
            Buffer.concat([
              Buffer.from(path.join(root, "target-")),
              Buffer.from([0xff]),
            ]),
          );
        }
        const inspected = await executeWorkbench(
          process.env.PYTHON?.trim() || "python3",
          ["inspect-target", "--target-path", path.join(root, "target-\udcff")],
        );
        assert.equal(inspected.targetPath, replacementTarget);
      },
    );
  }
} finally {
  if (previousStateDir === undefined)
    delete process.env.CODEX_SECURITY_STATE_DIR;
  else process.env.CODEX_SECURITY_STATE_DIR = previousStateDir;
  await rm(root, { recursive: true, force: true });
}

await test("large saved context retains cancellation results and diagnostics", async () => {
  const root = await temporaryDirectory("workbench-large-context-");
  const previousStateDir = process.env.CODEX_SECURITY_STATE_DIR;
  try {
    const target = path.join(root, "target");
    await mkdir(target);
    await writeFile(path.join(target, "example.py"), "value = 1\n");
    const state = path.join(root, "state");
    process.env.CODEX_SECURITY_STATE_DIR = state;
    const python = process.env.PYTHON || "python3";
    const userContext = "x".repeat(1_500_000);
    const begun = (await executeWorkbench(
      python,
      [
        "begin-deep-scan",
        "--target-path",
        target,
        "--scope",
        ".",
        "--thread-id",
        "synthetic-owner",
        "--scan-root",
        path.join(root, "scans"),
        "--user-context-stdin",
      ],
      userContext,
    )) as { deepScan: { scanId: string } };
    const scanId = begun.deepScan.scanId;
    const readScan = async () =>
      (await executeWorkbench(python, ["get-scan", "--scan-id", scanId])) as {
        workspace: {
          results: { userContext: string; progress: { status: string } };
        };
      };
    const current = await readScan();
    assert.equal(current.workspace.results.userContext, userContext);
    assert.equal(current.workspace.results.progress.status, "running");
    await executeWorkbench(python, ["cancel-scan", "--scan-id", scanId]);
    assert.equal(
      (await readScan()).workspace.results.progress.status,
      "canceled",
    );
    await assert.rejects(
      runWorkbench([
        "cancel-scan",
        "--scan-id",
        "00000000-0000-4000-8000-000000000000",
      ]),
      (error: unknown) => {
        assert.ok(error instanceof Error);
        assert.match(error.message, /Codex Security scan not found/);
        assert.ok(
          error.cause instanceof Error &&
            "stderr" in error.cause &&
            "code" in error.cause,
        );
        assert.equal(error.message, String(error.cause.stderr).trim());
        assert.ok(typeof error.cause.code === "number" && error.cause.code > 0);
        return true;
      },
    );
  } finally {
    if (previousStateDir === undefined)
      delete process.env.CODEX_SECURITY_STATE_DIR;
    else process.env.CODEX_SECURITY_STATE_DIR = previousStateDir;
    await rm(root, { recursive: true, force: true });
  }
});

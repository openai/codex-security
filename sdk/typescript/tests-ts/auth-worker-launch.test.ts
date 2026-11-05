import { expect, mock, test } from "bun:test";
import * as childProcess from "node:child_process";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { join, toNamespacedPath } from "node:path";
import { importAmbientAuth } from "../src/runtime.js";
import { createApiTestFixtures } from "./support/temporary-directories.js";
import { runTestInSubprocess } from "./support/test-subprocess.js";
import { nodeCommand } from "./support/shell.js";

test("dedicated credentials reach fresh resumed and comparison workers", async () => {
  const name =
    "dedicated credentials reach fresh resumed and comparison workers";
  if (runTestInSubprocess(import.meta.path, name)) return;
  // Load MCP fixtures at runtime so each package keeps its own TypeScript checks.
  const {
    createFakeCodexFixture,
    emptyWorkerPermissionProfile,
    trustedParentSandbox,
  } = await import(
    new URL(
      "../../../plugins/codex-security/mcp-app/tests/support/fake-codex-fixture.ts",
      import.meta.url,
    ).href
  );
  const owned = createApiTestFixtures("codex-security-auth-worker-");
  const keys = [
    "CODEX_HOME",
    "CODEX_CLI_PATH",
    "CODEX_SECURITY_CONFIG_PATH",
    "CODEX_SECURITY_DEEP_SCAN_CONFIG_PATH",
    "OPENAI_API_KEY",
    "CODEX_API_KEY",
    "OPENAI_FEDERATION_RULE_ID",
    "OPENAI_IDENTITY_TOKEN_FILE",
    "FAKE_CODEX_MARKER",
  ];
  const previous = keys.map((key) => [key, process.env[key]] as const);
  const original = { ...childProcess };
  const nativeNode = nodeCommand().command;
  try {
    const fixture = await createFakeCodexFixture(
      owned.temporaryDirectories,
      emptyWorkerPermissionProfile,
      true,
      { account: { type: "chatgpt" }, requiresOpenaiAuth: true },
    );
    const ambient = join(fixture.root, "ambient"),
      dedicated = join(fixture.root, "dedicated");
    await mkdir(ambient);
    const credentials = (refresh: string) => ({
      auth_mode: "chatgpt",
      tokens: {
        access_token: "synthetic-access",
        id_token: "synthetic-id",
        refresh_token: refresh,
      },
    });
    const ambientAuth = credentials("synthetic-ambient-refresh");
    const dedicatedAuth = credentials("synthetic-dedicated-refresh");
    await writeFile(join(ambient, "auth.json"), JSON.stringify(ambientAuth), {
      mode: 0o600,
    });
    expect(await importAmbientAuth(ambient, dedicated)).toBe(false);
    await writeFile(
      join(dedicated, "auth.json"),
      JSON.stringify(dedicatedAuth),
      { mode: 0o600 },
    );
    expect(await importAmbientAuth(ambient, dedicated)).toBe(true);
    for (const key of keys.filter((key) => key !== "FAKE_CODEX_MARKER"))
      delete process.env[key];
    process.env["CODEX_HOME"] = dedicated;
    process.env["CODEX_CLI_PATH"] = nativeNode;
    const prompt = join(fixture.root, "prompt.md");
    await writeFile(
      prompt,
      "CAPTURE_SYNTHETIC_FILE_AUTH\nCAPTURE_SYNTHETIC_OPENAI_AUTH",
    );
    const recordedSpawn: typeof childProcess.spawn = ((
      command: string,
      args: readonly string[],
      options: childProcess.SpawnOptions,
    ) =>
      original.spawn(
        command,
        command === nativeNode || command === toNamespacedPath(nativeNode)
          ? [fixture.executablePath, ...args]
          : args,
        options,
      )) as typeof childProcess.spawn;
    for (const module of ["node:child_process", "child_process"])
      mock.module(module, () => ({ ...original, spawn: recordedSpawn }));
    const {
      CodexSdkWorkerExecutor,
      workerRequest,
      assertReadOnlyWorkerPolicy,
    } = await import(
      new URL(
        "../../../plugins/codex-security/mcp-app/tests/deep_scan_executor_fixture.ts",
        import.meta.url,
      ).href
    );
    const executor = new CodexSdkWorkerExecutor({
      model: "synthetic-model",
      parentSandbox: trustedParentSandbox,
    });
    const assertCredentials = async () => {
      const invocation = JSON.parse(await readFile(fixture.markerPath, "utf8"));
      expect(invocation.codexHome).toBe(dedicated);
      expect(invocation.fileAuthentication).toEqual(dedicatedAuth);
      expect(invocation.openaiAuthentication).toEqual({});
      const preflight = JSON.parse(
        await readFile(fixture.preflightMarkerPath, "utf8"),
      );
      expect(preflight.codexHome).toBe(dedicated);
      assertReadOnlyWorkerPolicy(invocation.argv);
      return invocation;
    };
    for (const resumeThreadId of [undefined, "synthetic-resume"]) {
      await executor.run(
        workerRequest(prompt, fixture.root, { resumeThreadId }),
      );
      expect((await assertCredentials()).argv.includes("resume")).toBe(
        resumeThreadId !== undefined,
      );
    }
    await executor.compareFindings(
      "CAPTURE_SYNTHETIC_FILE_AUTH\nCAPTURE_SYNTHETIC_OPENAI_AUTH",
      fixture.root,
      new AbortController().signal,
      { type: "object", properties: {}, additionalProperties: false },
    );
    await assertCredentials();
    expect(
      JSON.parse(await readFile(join(ambient, "auth.json"), "utf8")),
    ).toEqual(ambientAuth);
  } finally {
    for (const module of ["node:child_process", "child_process"])
      mock.module(module, () => original);
    for (const [key, value] of previous) {
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    }
    await owned.cleanup();
  }
});

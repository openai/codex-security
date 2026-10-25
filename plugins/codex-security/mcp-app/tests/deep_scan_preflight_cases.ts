import assert from "node:assert/strict";
import { mkdir, realpath, symlink, writeFile } from "node:fs/promises";
import path from "node:path";
import { readJson } from "./support/json.ts";
import type {
  CodexWorkerRequest,
  CodexWorkerResult,
} from "../src/deep-scan/types.js";
import type { resolveCodexPath as ResolveCodexPath } from "../src/deep-scan/executor.js";

export async function testPreflightBindsExecutableAndHomeBeforeChangingCwd({
  fakeCodexFixture,
  runWorker,
  resolveCodexPath,
  bundledCodexSdkEnvironment,
  assertWorkerProtocol,
  restoreEnv,
}: {
  fakeCodexFixture: () => Promise<{
    root: string;
    executablePath: string;
    markerPath: string;
    preflightMarkerPath: string;
  }>;
  runWorker: (
    promptPath: string,
    workingDirectory: string,
    options?: Partial<CodexWorkerRequest>,
  ) => Promise<CodexWorkerResult>;
  resolveCodexPath: typeof ResolveCodexPath;
  bundledCodexSdkEnvironment: (
    command: string,
    environment: Record<string, string>,
  ) => Record<string, string>;
  assertWorkerProtocol: (
    invocation: Awaited<ReturnType<typeof readJson>>,
  ) => void;
  restoreEnv: (name: string, value: string | undefined) => void;
}) {
  const fixture = await fakeCodexFixture();
  const originalCwd = process.cwd();
  const promptPath = path.join(fixture.root, "prompt.md");
  const workingDirectory = path.join(fixture.root, "artifacts");
  const nonExecutableDirectory = path.join(fixture.root, "non-executable-bin");
  const directoryShadow = path.join(fixture.root, "directory-shadow-bin");
  const binaryDirectory = path.join(fixture.root, "relative-bin");
  const codexPath = path.join(binaryDirectory, "codex");
  const homeTargetRoot = path.join(fixture.root, "home-target");
  const homeTargetChild = path.join(homeTargetRoot, "child");
  const codexHome = path.join(homeTargetRoot, "home");
  const homeLink = path.join(fixture.root, "home-link");
  await mkdir(workingDirectory);
  await mkdir(nonExecutableDirectory);
  await mkdir(path.join(directoryShadow, "codex"), { recursive: true });
  await mkdir(binaryDirectory);
  const bundledTools = path.join(fixture.root, "codex-path");
  await mkdir(bundledTools);
  await writeFile(
    path.join(bundledTools, "rg"),
    "#!/bin/sh\nprintf 'synthetic bundled search\\n'\n",
    { mode: 0o755 },
  );
  await mkdir(homeTargetChild, { recursive: true });
  await mkdir(codexHome, { recursive: true });
  assert.notEqual(workingDirectory, originalCwd);
  await writeFile(promptPath, "fixture bound worker executable and home\n");
  await writeFile(
    path.join(nonExecutableDirectory, "codex"),
    "not executable\n",
  );
  // A shell wrapper lets the OS select this file before Node loads the fixture.
  const shellArguments = [process.execPath, fixture.executablePath]
    .map((value) => `'${value.replaceAll("'", `'"'"'`)}'`)
    .join(" ");
  await writeFile(codexPath, `#!/bin/sh\nexec ${shellArguments} "$@"\n`, {
    mode: 0o755,
  });
  await mkdir(path.join(binaryDirectory, "child"));
  const executableLink = path.join(fixture.root, "executable-link");
  await symlink(path.join(binaryDirectory, "child"), executableLink, "dir");
  await symlink(homeTargetChild, homeLink, "dir");
  const relativeHome = `${path.relative(originalCwd, homeLink)}/../home`;
  const expectedHome = await realpath(relativeHome);
  assert.notEqual(path.resolve(originalCwd, relativeHome), expectedHome);

  const previousCodexPath = process.env.CODEX_CLI_PATH;
  const previousCodexHome = process.env.CODEX_HOME;
  const previousSearchPath = process.env.PATH;
  const previousLowercaseSearchPath = process.env.path;
  process.env.CODEX_HOME = relativeHome;
  process.env.path = path.relative(originalCwd, nonExecutableDirectory);
  process.env.PATH = [
    path.relative(originalCwd, nonExecutableDirectory),
    path.relative(originalCwd, directoryShadow),
    path.relative(originalCwd, binaryDirectory),
    path.dirname(process.execPath),
  ].join(path.delimiter);
  try {
    const defaultSearchPath = process.env.PATH;
    for (const [configured, expectedExecutable, searchPath] of [
      [
        path.relative(originalCwd, fixture.executablePath),
        fixture.executablePath,
      ],
      [undefined, codexPath],
      [`${binaryDirectory}/./codex`, codexPath],
      ["codex", codexPath],
      [`${executableLink}/../codex`, codexPath],
      [`${path.relative(originalCwd, executableLink)}/../codex`, codexPath],
      ...[
        `${executableLink}/..`,
        `${path.relative(originalCwd, executableLink)}/..`,
      ].flatMap(
        (entry) =>
          [
            [
              undefined,
              codexPath,
              `${entry}${path.delimiter}${path.dirname(process.execPath)}`,
            ],
            [
              "codex",
              codexPath,
              `${entry}${path.delimiter}${path.dirname(process.execPath)}`,
            ],
          ] as const,
      ),
    ] as const) {
      process.env.PATH = searchPath ?? defaultSearchPath;
      if (configured === undefined) delete process.env.CODEX_CLI_PATH;
      else process.env.CODEX_CLI_PATH = configured;
      const hasBundledTools = expectedExecutable === codexPath;
      if (hasBundledTools) {
        process.env.PATH = bundledCodexSdkEnvironment(resolveCodexPath(), {
          PATH: process.env.PATH,
        }).PATH;
      }
      await writeFile(
        promptPath,
        hasBundledTools
          ? "CAPTURE_SYNTHETIC_RG"
          : "fixture bound worker executable and home",
      );
      assert.equal(
        await realpath(resolveCodexPath()),
        await realpath(expectedExecutable),
      );
      for (const kind of ["discovery", "dedup"] as const)
        for (const resumeThreadId of [undefined, "resumed-thread"]) {
          const result = await runWorker(promptPath, workingDirectory, {
            kind,
            resumeThreadId,
          });

          assert.equal(result.threadId, resumeThreadId ?? "fixture-thread-id");
          const preflight = await readJson(fixture.preflightMarkerPath);
          const invocation = await readJson(fixture.markerPath);
          assert.equal(preflight.cwd, await realpath(workingDirectory));
          assert.equal(invocation.cwd, await realpath(workingDirectory));
          assert.equal(preflight.codexHome, expectedHome);
          assert.equal(invocation.codexHome, expectedHome);
          assert.equal(process.env.CODEX_HOME, relativeHome);
          assert.deepEqual(preflight.requests, [
            { method: "config/read", cwd: workingDirectory },
            { method: "permissionProfile/list", cwd: workingDirectory },
          ]);
          assertWorkerProtocol(invocation);
          assert.equal(invocation.thread.params.cwd, workingDirectory);
          if (hasBundledTools) {
            assert.equal(
              invocation.runtimeEnvironment.PATH.split(path.delimiter)[0],
              bundledTools,
            );
            assert.equal(invocation.bundledTool, "synthetic bundled search");
            assert.equal(
              preflight.gitEnvironment.PATH,
              invocation.runtimeEnvironment.PATH,
            );
          }
        }
    }
  } finally {
    restoreEnv("CODEX_CLI_PATH", previousCodexPath);
    restoreEnv("CODEX_HOME", previousCodexHome);
    restoreEnv("PATH", previousSearchPath);
    restoreEnv("path", previousLowercaseSearchPath);
  }
}

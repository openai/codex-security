import { temporaryDirectory } from "./support/temporary-directories.ts";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import {
  chmod,
  mkdir,
  readFile,
  readdir,
  realpath,
  rm,
  stat,
  symlink,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";

import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";

import { applicationRoot, buildServer } from "./build-server.ts";

const fixture = await temporaryDirectory("codex-security-storage-test-", true);
const stateRoot = path.join(fixture, "state");
const repository = path.join(fixture, "repository");
const bundle = path.join(fixture, "server.cjs");
const temporaryDirectories = new Set<string>();
let client: Client | undefined;

try {
  await mkdir(repository);
  await writeFile(path.join(repository, "example.py"), "value = 1\n");
  await buildServer(bundle, {
    define: {
      __dirname: JSON.stringify(applicationRoot),
      "import.meta.url": "__filename",
    },
  });
  client = await connect();
  const started = await call<{
    scanId: string;
    scanDir: string;
    handoffClaimToken: string;
  }>("start_codex_security_standard_scan", {
    targetPath: repository,
  });
  const { scanId, scanDir, handoffClaimToken } = started;
  assert.ok(
    scanDir.startsWith(path.join(stateRoot, "scans", "repository") + path.sep),
    `The default scan directory must be persistent, got ${scanDir}`,
  );
  const identity = { scanId, handoffClaimToken };
  const scratch = await save({ ...identity, storage: "temporary" });
  temporaryDirectories.add(scratch.directory);
  assert.ok(
    scratch.directory.startsWith((await realpath(tmpdir())) + path.sep),
  );
  assert.equal(scratch.directory.startsWith(scanDir + path.sep), false);

  const content = "# Threat model\n\nExact café bytes and trailing spaces.  \n";
  const relativePath = "artifacts/01_context/threat_model.md";
  const saved = await save({
    ...identity,
    storage: "persistent",
    path: relativePath,
    content,
  });
  assert.equal(saved.path, path.join(scanDir, ...relativePath.split("/")));
  assert.equal(await readFile(saved.path, "utf8"), content);
  await save({
    ...identity,
    storage: "temporary",
    path: relativePath,
    content: "temporary\n",
  });
  assert.equal(
    (await read({ ...identity, storage: "temporary", path: relativePath }))
      .content,
    "temporary\n",
  );
  assert.equal(
    (await read({ ...identity, storage: "persistent", path: relativePath }))
      .content,
    content,
  );

  const binary = Buffer.from([0, 1, 127, 128, 255]);
  const sourcePath = path.join(scratch.directory, "poc.bin");
  await writeFile(sourcePath, binary);
  const imported = await save({
    ...identity,
    storage: "persistent",
    path: "artifacts/02_discovery/validation_artifacts/example/poc.bin",
    sourcePath,
  });
  assert.deepEqual(await readFile(imported.path), binary);
  assert.equal(
    (
      await read({
        ...identity,
        storage: "persistent",
        path: imported.relativePath,
        encoding: "base64",
      })
    ).content,
    binary.toString("base64"),
  );

  const outside = path.join(fixture, "outside.txt");
  await writeFile(outside, "outside\n");
  await assert.rejects(() =>
    save({
      ...identity,
      storage: "persistent",
      path: "artifacts/copied.txt",
      sourcePath: outside,
    }),
  );
  await symlink(outside, path.join(scratch.directory, "linked.txt"));
  await assert.rejects(() =>
    save({
      ...identity,
      storage: "persistent",
      path: "artifacts/copied.txt",
      sourcePath: path.join(scratch.directory, "linked.txt"),
    }),
  );
  for (const unsafe of [
    "../outside.txt",
    "/outside.txt",
    "C:/outside.txt",
    "artifacts/file:stream",
    "artifacts/../outside.txt",
    "artifacts/CON",
    "artifacts/name.",
    "artifacts/name ",
  ]) {
    await assert.rejects(() =>
      save({
        ...identity,
        storage: "persistent",
        path: unsafe,
        content: "bad",
      }),
    );
  }
  for (const owned of [
    "scan-manifest.json",
    "findings.json",
    "coverage.json",
    "report.md",
    "threatmodel.md",
    "drafts/checkpoint.json",
    "artifacts/deep_discovery/result.json",
    "artifacts/02_discovery/candidate_ledger.jsonl",
    "artifacts/02_discovery/CANDIDATE_LEDGER.JSONL",
    "artifacts/02_discovery/in_scope_files.txt",
  ]) {
    await assert.rejects(() =>
      save({ ...identity, storage: "persistent", path: owned, content: "bad" }),
    );
  }
  await assert.rejects(() =>
    save({
      ...identity,
      handoffClaimToken: "00000000-0000-4000-8000-000000000000",
      storage: "persistent",
      path: relativePath,
      content: "bad",
    }),
  );
  assert.equal(await readFile(saved.path, "utf8"), content);
  assert.equal(await readFile(outside, "utf8"), "outside\n");

  await client.close();
  client = await connect();
  assert.equal(
    (await read({ ...identity, storage: "persistent", path: relativePath }))
      .content,
    content,
  );
  assert.equal(
    (await read({ ...identity, storage: "temporary", path: relativePath }))
      .content,
    "temporary\n",
  );
  await rm(scratch.directory, { recursive: true, force: true });
  assert.equal(
    (await read({ ...identity, storage: "persistent", path: relativePath }))
      .content,
    content,
  );
  assert.deepEqual(await readFile(imported.path), binary);

  const standalone = await save({
    targetPath: repository,
    storage: "persistent",
    path: "threatmodel.md",
    content,
  });
  assert.ok(
    standalone.directory.startsWith(path.join(stateRoot, "scans") + path.sep),
  );
  assert.equal(standalone.directory.startsWith(repository + path.sep), false);
  assert.equal(
    (
      await read({
        targetPath: repository,
        storage: "persistent",
        path: "threatmodel.md",
      })
    ).content,
    content,
  );
  const legacyModel = "# Retained legacy model\n\nKeep this unchanged.\n";
  await writeFile(
    path.join(standalone.directory, "threat_model.md"),
    legacyModel,
  );
  assert.equal(
    (
      await read({
        targetPath: repository,
        storage: "persistent",
        path: "threat_model.md",
      })
    ).content,
    legacyModel,
  );
  await assert.rejects(() =>
    save({
      ...identity,
      targetPath: repository,
      storage: "persistent",
      path: relativePath,
      content,
    }),
  );

  const stateAlias = path.join(fixture, "state-alias");
  await symlink(
    stateRoot,
    stateAlias,
    process.platform === "win32" ? "junction" : "dir",
  );
  await client.close();
  client = await connect({ CODEX_SECURITY_STATE_DIR: stateAlias });
  const standaloneScratch = await save({
    targetPath: repository,
    storage: "temporary",
  });
  temporaryDirectories.add(standaloneScratch.directory);
  const standaloneInput = path.join(standaloneScratch.directory, "input.bin");
  await writeFile(standaloneInput, binary);
  const standaloneImport = await save({
    targetPath: repository,
    storage: "persistent",
    path: "artifacts/input.bin",
    sourcePath: standaloneInput,
  });
  assert.equal(standaloneImport.directory, standalone.directory);
  assert.deepEqual(await readFile(standaloneImport.path), binary);

  await call("record_codex_security_scan_draft", {
    ...identity,
    complete: false,
    findings: [],
    threatModel: { format: "markdown", content, origin: "provided" },
    coverage: {
      completeness: "partial",
      surfaces: [],
      explicitExclusions: [],
      deferred: [],
    },
  });
  const provisionalModel = await read({
    ...identity,
    storage: "persistent",
    path: "threatmodel.md",
  });
  assert.equal(provisionalModel.content.slice(0, content.length), content);
  const exportedModel = await call<{
    export: { format: string; path: string };
  }>("export_codex_security_findings", {
    scanId,
    artifact: "threat-model",
  });
  assert.equal(exportedModel.export.format, "md");
  assert.equal(
    exportedModel.export.path,
    path.join(scanDir, "exports", "threatmodel.md"),
  );
  assert.equal(
    (await readFile(exportedModel.export.path, "utf8")).slice(
      0,
      content.length,
    ),
    content,
  );
  await assert.rejects(() =>
    call("export_codex_security_findings", {
      scanId,
      artifact: "threat-model",
      format: "sarif",
    }),
  );

  await call("record_codex_security_scan_draft", {
    ...identity,
    findings: [],
    threatModel: { format: "markdown", content, origin: "provided" },
    coverage: {
      completeness: "complete",
      surfaces: [
        {
          id: "example",
          label: "Example source",
          disposition: "not_applicable",
          receiptRefs: [relativePath],
        },
      ],
      explicitExclusions: [],
      deferred: [],
    },
  });
  const projectedModel = await read({
    ...identity,
    storage: "persistent",
    path: "threatmodel.md",
  });
  assert.equal(projectedModel.content.slice(0, content.length), content);
  execFileSync(
    process.env.PYTHON || "python3",
    [
      path.resolve(applicationRoot, "../scripts/workbench_db.py"),
      "prepare-scan-completion",
      "--scan-id",
      scanId,
      "--claim-token",
      handoffClaimToken,
    ],
    { env: { ...process.env, CODEX_SECURITY_STATE_DIR: stateRoot } },
  );
  // Preparation seals receipts before the database transitions to complete.
  await assert.rejects(() =>
    save({
      ...identity,
      storage: "persistent",
      path: relativePath,
      content: "changed after seal",
    }),
  );
  assert.equal(await readFile(saved.path, "utf8"), content);
  await call("complete_codex_security_scan", identity);
  await assert.rejects(() =>
    save({
      ...identity,
      storage: "persistent",
      path: "findings/late/late.md",
      content: "late",
    }),
  );
  assert.equal(
    (await read({ ...identity, storage: "persistent", path: relativePath }))
      .content,
    content,
  );

  await client.close();
  client = await connect({
    CODEX_SECURITY_SCAN_ROOT: path.join(stateAlias, "missing", "scans"),
  });
  const relocated = await save({
    targetPath: repository,
    storage: "persistent",
  });
  assert.ok(
    relocated.directory.startsWith(
      path.join(stateRoot, "missing", "scans") + path.sep,
    ),
  );

  const linkedScanRoot = path.join(fixture, "linked-scans");
  await mkdir(linkedScanRoot);
  await symlink(
    repository,
    path.join(linkedScanRoot, path.basename(repository)),
    process.platform === "win32" ? "junction" : "dir",
  );
  const unsafeCollection = path.join(
    repository,
    path.basename(standalone.directory),
  );
  for (const scanRoot of [fixture, linkedScanRoot]) {
    await client.close();
    client = await connect({ CODEX_SECURITY_SCAN_ROOT: scanRoot });
    const location = { targetPath: repository, storage: "persistent" };
    const repositoryEntries = await readdir(repository);
    await assert.rejects(
      () => save(location),
      /Artifact storage must be outside the target repository/,
    );
    await assert.rejects(
      () => save({ ...location, path: "threatmodel.md", content }),
      /Artifact storage must be outside the target repository/,
    );
    await assert.rejects(stat(unsafeCollection), { code: "ENOENT" });

    const temporary = { ...location, storage: "temporary", path: "notes.md" };
    const scratch = await save({ ...temporary, content });
    temporaryDirectories.add(scratch.directory);
    assert.ok(
      scratch.directory.startsWith((await realpath(tmpdir())) + path.sep),
    );
    assert.equal((await read(temporary)).content, content);
    assert.deepEqual(await readdir(repository), repositoryEntries);

    await mkdir(unsafeCollection);
    const retainedPath = path.join(unsafeCollection, "threatmodel.md");
    await writeFile(retainedPath, content);
    await assert.rejects(
      () => read({ ...location, path: "threatmodel.md" }),
      /Artifact storage must be outside the target repository/,
    );
    assert.equal(await readFile(retainedPath, "utf8"), content);
    await rm(unsafeCollection, { recursive: true });
  }

  const repositoryAlias = path.join(fixture, "repository-alias");
  await symlink(
    repository,
    repositoryAlias,
    process.platform === "win32" ? "junction" : "dir",
  );
  await client.close();
  client = await connect({
    CODEX_SECURITY_SCAN_ROOT: path.join(repositoryAlias, "missing-scans"),
  });
  await assert.rejects(
    () => save({ targetPath: repository, storage: "persistent" }),
    /Artifact storage must be outside the target repository/,
  );
  await assert.rejects(stat(path.join(repository, "missing-scans")), {
    code: "ENOENT",
  });

  if (process.platform !== "win32" && process.getuid?.() !== 0) {
    const codexHome = path.join(fixture, "readonly-home");
    const defaultState = path.join(
      codexHome,
      "state",
      "plugins",
      "codex-security",
    );
    await mkdir(defaultState, { recursive: true });
    await chmod(defaultState, 0o500);
    try {
      await client.close();
      client = await connect({
        CODEX_HOME: codexHome,
        CODEX_SECURITY_STATE_DIR: undefined,
        TMPDIR: repositoryAlias,
      });
      await assert.rejects(
        () =>
          save({
            targetPath: repository,
            storage: "persistent",
            path: "artifacts/standalone.md",
            content,
          }),
        /Artifact storage must be outside the target repository/,
      );
      const fallbackStates = (await readdir(repository)).filter((name) =>
        name.startsWith("codex-security-state-"),
      );
      assert.equal(fallbackStates.length, 1);
      await assert.rejects(
        stat(path.join(repository, fallbackStates[0], "scans")),
        { code: "ENOENT" },
      );
    } finally {
      await chmod(defaultState, 0o700);
    }
  }
  console.log(
    "Persistent roots, temporary routing, exact file import, restart readback and artifact boundaries passed",
  );
} finally {
  await client?.close();
  for (const directory of temporaryDirectories)
    await rm(directory, { recursive: true, force: true });
  await rm(fixture, { recursive: true, force: true });
}

async function connect(overrides: NodeJS.ProcessEnv = {}) {
  const result = new Client({
    name: "artifact-storage-test",
    version: "1.0.0",
  });
  const env: Record<string, string> = {
    ...process.env,
    CODEX_SECURITY_STATE_DIR: stateRoot,
    CODEX_HOME: path.join(fixture, "home"),
    ...overrides,
  };
  if (overrides.CODEX_SECURITY_SCAN_ROOT === undefined)
    delete env.CODEX_SECURITY_SCAN_ROOT;
  await result.connect(
    new StdioClientTransport({
      command: process.execPath,
      args: [bundle, "--stdio"],
      cwd: applicationRoot,
      env,
    }),
  );
  return result;
}

async function call<Result = unknown>(
  name: string,
  arguments_: Record<string, unknown>,
): Promise<Result> {
  const result = await client!.callTool({
    name,
    arguments: arguments_,
    _meta: { "openai/threadId": "storage-test-owner" },
  });
  if (result.isError) throw new Error(JSON.stringify(result));
  return result.structuredContent as Result;
}

function save(input: Record<string, unknown>) {
  return call<{ directory: string; path: string; relativePath: string }>(
    "save_codex_security_artifact",
    input,
  );
}
function read(input: Record<string, unknown>) {
  return call<{ content: string }>("read_codex_security_artifact", input);
}

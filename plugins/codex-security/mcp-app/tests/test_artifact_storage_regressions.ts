interface ArtifactToolResults {
  save_codex_security_artifact: {
    directory: string;
    path: string;
    relativePath: string;
  };
  read_codex_security_artifact: { content: string; directory: string };
  start_codex_security_standard_scan: {
    scanId: string;
    scanDir: string;
    handoffClaimToken: string;
  };
  record_codex_security_scan_draft: unknown;
}
import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { promises as fs } from "node:fs";
import { tmpdir, userInfo } from "node:os";
import path from "node:path";
import { test } from "node:test";

import { promisify } from "node:util";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { importModule } from "./import-module.ts";
import { applicationRoot, buildServer } from "./build-server.ts";

const pluginRoot = path.dirname(applicationRoot);
const python = process.env.PYTHON || "python3";
const exec = promisify(execFile);
const fixture = await fs.realpath(
  await fs.mkdtemp(path.join(tmpdir(), "codex-security-storage-regressions-")),
);
const repository = path.join(fixture, "repository");
const bundle = path.join(fixture, "server.cjs");
const environment: Record<string, string | undefined> = {
  ...process.env,
  CODEX_SECURITY_STATE_DIR: path.join(fixture, "state"),
  CODEX_HOME: path.join(fixture, "home"),
};
delete environment.CODEX_SECURITY_SCAN_ROOT;
delete environment.PYTHONSAFEPATH;
const clients: Client[] = [];
const temporaryDirectories: string[] = [];

await fs.mkdir(repository);
await fs.writeFile(path.join(repository, "example.py"), "value = 1\n");
await buildServer(bundle, {
  define: {
    __dirname: JSON.stringify(applicationRoot),
    "import.meta.url": "__filename",
  },
});
const {
  readCodexSecurityArtifact,
  saveCodexSecurityArtifact,
  standaloneArtifactContext,
  createScanArtifactContext,
} = await importModule({
  logLevel: "silent",
  stdin: {
    resolveDir: applicationRoot,
    contents: `
    export { readCodexSecurityArtifact, saveCodexSecurityArtifact, standaloneArtifactContext } from './src/artifact-storage.ts';
    export { createScanArtifactContext } from './src/artifact-context.ts';
  `,
  },
});

async function workbench(args: string[], input?: string, launcher?: string) {
  const command = launcher
    ? [launcher, path.join(pluginRoot, "scripts/workbench_db.py"), ...args]
    : [path.join(pluginRoot, "scripts/workbench_db.py"), ...args];
  const execution = exec(python, command, {
    cwd: pluginRoot,
    env: environment,
    maxBuffer: 4 * 1024 * 1024,
  });
  execution.child.stdin!.on("error", () => {});
  execution.child.stdin!.end(input);
  return JSON.parse((await execution).stdout);
}

async function connect(overrides: Record<string, string | undefined> = {}) {
  const client = new Client({
    name: "artifact-regression-test",
    version: "1.0.0",
  });
  clients.push(client);
  const env = { ...environment, ...overrides };
  for (const key of Object.keys(env))
    if (env[key] === undefined) delete env[key];
  await client.connect(
    new StdioClientTransport({
      command: process.execPath,
      args: [bundle, "--stdio"],
      cwd: repository,
      env: env as Record<string, string>,
    }),
  );
  return async <Name extends keyof ArtifactToolResults>(
    name: Name,
    args: Record<string, unknown>,
  ): Promise<ArtifactToolResults[Name]> => {
    const result = await client.callTool({
      name,
      arguments: args,
      _meta: { "openai/threadId": "artifact-regression-owner" },
    });
    assert.notEqual(result.isError, true, JSON.stringify(result));
    return result.structuredContent as ArtifactToolResults[Name];
  };
}

try {
  await test(
    "temporary artifact operations reject a collection owned by another user",
    { skip: typeof process.geteuid !== "function" },
    async (t) => {
      const context = await standaloneArtifactContext(
        repository,
        workbench,
        true,
        path.join(fixture, "temporary-owner"),
        "persistent",
      );
      const saved = await saveCodexSecurityArtifact(
        context,
        { storage: "temporary", path: "proof.txt", content: "owned evidence" },
        workbench,
      );
      temporaryDirectories.push(saved.directory);
      const lstat = fs.lstat;
      t.mock.method(
        fs,
        "lstat",
        async (...args: Parameters<typeof fs.lstat>) => {
          const metadata = await lstat(...args);
          return String(args[0]) === saved.directory
            ? Object.assign(Object.create(metadata), {
                uid: process.geteuid!() + 1,
              })
            : metadata;
        },
      );
      let calls = 0;
      const run = (...args: Parameters<typeof workbench>) => {
        calls += 1;
        return workbench(...args);
      };
      try {
        const operations = [
          () =>
            saveCodexSecurityArtifact(context, { storage: "temporary" }, run),
          () =>
            saveCodexSecurityArtifact(
              context,
              {
                storage: "temporary",
                path: "proof.txt",
                content: "replacement",
              },
              run,
            ),
          () =>
            readCodexSecurityArtifact(
              context,
              { storage: "temporary", path: "proof.txt", encoding: "utf8" },
              run,
            ),
          () =>
            saveCodexSecurityArtifact(
              context,
              {
                storage: "persistent",
                path: "artifacts/imported.txt",
                sourcePath: saved.path,
              },
              run,
            ),
        ];
        for (const operation of operations) {
          await assert.rejects(operation, /owned by the current user/);
          assert.equal(calls, 0);
        }
      } finally {
        t.mock.restoreAll();
      }
      assert.equal(await fs.readFile(saved.path, "utf8"), "owned evidence");
      await assert.rejects(
        fs.stat(path.join(context.root, "artifacts/imported.txt")),
        {
          code: "ENOENT",
        },
      );
      assert.equal(
        (
          await saveCodexSecurityArtifact(
            context,
            { storage: "temporary" },
            workbench,
          )
        ).directory,
        saved.directory,
      );
      assert.equal(
        (
          await readCodexSecurityArtifact(
            context,
            { storage: "temporary", path: "proof.txt", encoding: "utf8" },
            workbench,
          )
        ).content,
        "owned evidence",
      );
      const imported = await saveCodexSecurityArtifact(
        context,
        {
          storage: "persistent",
          path: "artifacts/imported.txt",
          sourcePath: saved.path,
        },
        workbench,
      );
      assert.equal(await fs.readFile(imported.path, "utf8"), "owned evidence");
    },
  );

  await test(
    "temporary collections use the effective filesystem identity",
    {
      skip:
        typeof process.getuid !== "function" ||
        typeof process.geteuid !== "function",
    },
    async (t) => {
      const context = await standaloneArtifactContext(
        repository,
        workbench,
        true,
        path.join(fixture, "effective-owner"),
        "persistent",
      );
      const effectiveUid = process.geteuid!();
      t.mock.method(
        process as typeof process & { getuid: () => number },
        "getuid",
        () => effectiveUid + 1,
      );
      try {
        const saved = await saveCodexSecurityArtifact(
          context,
          {
            storage: "temporary",
            path: "proof.txt",
            content: "owned evidence",
          },
          workbench,
        );
        temporaryDirectories.push(saved.directory);
        assert.equal((await fs.lstat(saved.directory)).uid, effectiveUid);
        const read = await readCodexSecurityArtifact(
          context,
          { storage: "temporary", path: "proof.txt", encoding: "utf8" },
          workbench,
        );
        assert.equal(read.content, "owned evidence");
      } finally {
        t.mock.restoreAll();
      }
    },
  );

  await test(
    "temporary collections check ownership of the selected path",
    { skip: typeof process.geteuid !== "function" },
    async (t) => {
      const context = await standaloneArtifactContext(
        repository,
        workbench,
        true,
        path.join(fixture, "selected-owner"),
        "persistent",
      );
      const saved = await saveCodexSecurityArtifact(
        context,
        { storage: "temporary" },
        workbench,
      );
      temporaryDirectories.push(saved.directory);
      const resolved = path.join(fixture, "resolved-owner");
      await fs.mkdir(resolved, { mode: 0o700 });
      const realpath = fs.realpath;
      const lstat = fs.lstat;
      t.mock.method(
        fs,
        "realpath",
        async (...args: Parameters<typeof fs.realpath>) =>
          String(args[0]) === saved.directory ? resolved : realpath(...args),
      );
      t.mock.method(
        fs,
        "lstat",
        async (...args: Parameters<typeof fs.lstat>) => {
          const metadata = await lstat(...args);
          return String(args[0]) === saved.directory
            ? Object.assign(Object.create(metadata), {
                uid: process.geteuid!() + 1,
              })
            : metadata;
        },
      );
      try {
        await assert.rejects(
          saveCodexSecurityArtifact(
            context,
            { storage: "temporary" },
            workbench,
          ),
          /owned by the current user/,
        );
      } finally {
        t.mock.restoreAll();
      }
      assert.deepEqual(await fs.readdir(resolved), []);
    },
  );

  await test("binary imports and readback preserve files larger than the workbench JSON buffer", async () => {
    const call = await connect();
    const location = { targetPath: repository };
    const scratch = await call("save_codex_security_artifact", {
      ...location,
      storage: "temporary",
    });
    temporaryDirectories.push(scratch.directory);
    const binary = Buffer.alloc(3 * 1024 * 1024 + 1, 0xa5);
    const sourcePath = path.join(scratch.directory, "large.bin");
    await fs.writeFile(sourcePath, binary);
    const saved = await call("save_codex_security_artifact", {
      ...location,
      storage: "persistent",
      path: "artifacts/large.bin",
      sourcePath,
    });
    assert.deepEqual(await fs.readFile(saved.path), binary);
    const read = await call("read_codex_security_artifact", {
      ...location,
      storage: "persistent",
      path: saved.relativePath,
      encoding: "base64",
    });
    assert.deepEqual(Buffer.from(read.content, "base64"), binary);
  });

  for (const reader of ["import", "temporary", "persistent"]) {
    for (const replacement of ["parent", "file"]) {
      await test(
        `${reader} reads stay bound when the ${replacement} is replaced`,
        { skip: process.platform === "win32" },
        async () => {
          const context = await standaloneArtifactContext(
            repository,
            workbench,
            true,
            path.join(fixture, `read-${reader}-${replacement}`),
            "persistent",
          );
          const storage = reader === "import" ? "temporary" : reader;
          const artifact = "artifacts/nested/proof.bin";
          const source = await saveCodexSecurityArtifact(
            context,
            { storage, path: artifact, content: "original evidence" },
            workbench,
          );
          if (storage === "temporary")
            temporaryDirectories.push(source.directory);
          const parent = path.dirname(source.path);
          const moved = path.join(path.dirname(parent), "original");
          const outside = path.join(
            fixture,
            `outside-read-${reader}-${replacement}`,
          );
          const marker = path.join(
            fixture,
            `read-swapped-${reader}-${replacement}`,
          );
          await fs.mkdir(outside);
          await fs.writeFile(
            path.join(outside, "proof.bin"),
            "unrelated outside bytes",
          );
          const launcher = path.join(
            fixture,
            `read-${reader}-${replacement}.py`,
          );
          await fs.writeFile(
            launcher,
            `
import os, runpy, sys
from pathlib import Path
sys.path.insert(0, str(Path(sys.argv[1]).parent))
import finalize_scan_contract as finalizer
original_open = finalizer._open_scan_local_directory
def open_then_replace(root_fd, parts, *, create):
    descriptor = original_open(root_fd, parts, create=create)
    if not create and parts == ("artifacts", "nested"):
        if ${JSON.stringify(replacement)} == "parent":
            os.rename(${JSON.stringify(parent)}, ${JSON.stringify(moved)})
            os.symlink(${JSON.stringify(outside)}, ${JSON.stringify(parent)})
        else:
            os.unlink(${JSON.stringify(source.path)})
            os.symlink(${JSON.stringify(path.join(outside, "proof.bin"))}, ${JSON.stringify(source.path)})
        Path(${JSON.stringify(marker)}).write_text("python")
    return descriptor
finalizer._open_scan_local_directory = open_then_replace
sys.argv = sys.argv[1:]
runpy.run_path(sys.argv[0], run_name="__main__")
`,
          );
          const run = (args: string[], input?: string) =>
            workbench(args, input, launcher);
          const read = async () => {
            if (reader === "import") {
              const saved = await saveCodexSecurityArtifact(
                context,
                {
                  storage: "persistent",
                  path: "artifacts/imported.bin",
                  sourcePath: source.path,
                },
                run,
              );
              return await fs.readFile(saved.path, "utf8");
            }
            return (
              await readCodexSecurityArtifact(
                context,
                { storage, path: artifact, encoding: "utf8" },
                run,
              )
            ).content;
          };
          if (replacement === "file")
            await assert.rejects(read, /expected a (?:regular|file inside)/);
          else assert.equal(await read(), "original evidence");
          assert.equal(await fs.readFile(marker, "utf8"), "python");
          assert.equal(
            await fs.readFile(path.join(outside, "proof.bin"), "utf8"),
            "unrelated outside bytes",
          );
        },
      );
    }
  }

  await test("host-produced threat models are readable and standalone legacy documents remain intact", async () => {
    const modelRoot = path.join(fixture, "model-documents");
    await fs.mkdir(modelRoot, { mode: 0o700 });
    const content = "# Model\n\nExact paragraph.  \n";
    await fs.writeFile(path.join(modelRoot, "threatmodel.md"), content);
    const context = {
      root: modelRoot,
      repoRoot: repository,
      layout: "scan",
      scanId: "00000000-0000-4000-8000-000000000001",
    };
    const read = await readCodexSecurityArtifact(
      context,
      { storage: "persistent", path: "threatmodel.md", encoding: "utf8" },
      workbench,
    );
    assert.equal(read.content, content);
    await assert.rejects(
      saveCodexSecurityArtifact(
        context,
        { storage: "persistent", path: "threatmodel.md", content: "replaced" },
        workbench,
      ),
      /existing scan tools/,
    );
    const { scanId: _scanId, ...standalone } = context;
    const legacyContent = "# Legacy model\n\nRetained original.\n";
    const legacyPath = path.join(modelRoot, "threat_model.md");
    await fs.writeFile(legacyPath, legacyContent);
    const legacy = await readCodexSecurityArtifact(
      standalone,
      { storage: "persistent", path: "threat_model.md", encoding: "utf8" },
      workbench,
    );
    assert.equal(legacy.content, legacyContent);
    await saveCodexSecurityArtifact(
      standalone,
      { storage: "persistent", path: "threatmodel.md", content },
      workbench,
    );
    assert.equal(await fs.readFile(legacyPath, "utf8"), legacyContent);
  });

  for (const writer of ["mcp", "workbench"]) {
    await test(`${writer} rejects reserved artifact names and their descendants`, async () => {
      const call = await connect();
      const { scanId, handoffClaimToken } = await call(
        "start_codex_security_standard_scan",
        { targetPath: repository },
      );
      for (const reserved of [
        "artifacts/02_discovery/candidate_ledger.jsonl",
        "artifacts/02_discovery/in_scope_files.txt",
        "artifacts/01_context/false_positive_feedback.json",
        "artifacts/deep_discovery",
      ]) {
        for (const suffix of ["/note.txt", ""]) {
          const artifact = reserved + suffix;
          await assert.rejects(
            () =>
              writer === "mcp"
                ? call("save_codex_security_artifact", {
                    scanId,
                    handoffClaimToken,
                    storage: "persistent",
                    path: artifact,
                    content: "reserved",
                  })
                : workbench(
                    [
                      "save-scan-artifact",
                      "--scan-id",
                      scanId,
                      "--claim-token",
                      handoffClaimToken,
                      "--artifact-path",
                      artifact,
                    ],
                    "reserved",
                  ),
            /canonical artifacts/,
          );
        }
        const artifact = reserved + ".backup";
        const saved =
          writer === "mcp"
            ? await call("save_codex_security_artifact", {
                scanId,
                handoffClaimToken,
                storage: "persistent",
                path: artifact,
                content: "allowed sibling",
              })
            : await workbench(
                [
                  "save-scan-artifact",
                  "--scan-id",
                  scanId,
                  "--claim-token",
                  handoffClaimToken,
                  "--artifact-path",
                  artifact,
                ],
                "allowed sibling",
              );
        assert.equal(await fs.readFile(saved.path, "utf8"), "allowed sibling");
      }
    });
  }

  for (const kind of ["missing", "blocked", "alias", "read-only"]) {
    await test(
      `standalone temporary storage works with persistent root: ${kind}`,
      { skip: kind === "read-only" && process.platform === "win32" },
      async () => {
        const parent = path.join(fixture, `temporary-${kind}`);
        let scanRoot = path.join(parent, "scans");
        if (kind === "blocked")
          await fs.writeFile(parent, "unavailable storage");
        if (kind === "alias" || kind === "read-only") await fs.mkdir(parent);
        if (kind === "alias") {
          const alias = path.join(fixture, "temporary-alias-link");
          await fs.symlink(
            parent,
            alias,
            process.platform === "win32" ? "junction" : "dir",
          );
          scanRoot = path.join(alias, "scans");
        }
        if (kind === "read-only") await fs.chmod(parent, 0o500);
        try {
          const overrides = { CODEX_SECURITY_SCAN_ROOT: scanRoot };
          let call = await connect(overrides);
          const location = { targetPath: repository, storage: "temporary" };
          const { directory } = await call(
            "save_codex_security_artifact",
            location,
          );
          temporaryDirectories.push(directory);
          assert.equal(path.dirname(directory), await fs.realpath(tmpdir()));
          const saved = await call("save_codex_security_artifact", {
            ...location,
            path: "note.txt",
            content: "temporary evidence\n",
          });
          assert.equal(saved.directory, directory);
          assert.equal(
            await fs.readFile(saved.path, "utf8"),
            "temporary evidence\n",
          );
          await clients.at(-1)!.close();
          call = await connect(overrides);
          assert.equal(
            (
              await call("read_codex_security_artifact", {
                ...location,
                path: "note.txt",
              })
            ).content,
            "temporary evidence\n",
          );
          if (kind === "blocked") {
            assert.equal(
              await fs.readFile(parent, "utf8"),
              "unavailable storage",
            );
            await fs.unlink(parent);
          } else {
            await assert.rejects(fs.stat(scanRoot), { code: "ENOENT" });
          }
          if (kind === "read-only") await fs.chmod(parent, 0o700);
          const imported = await call("save_codex_security_artifact", {
            targetPath: repository,
            storage: "persistent",
            path: "artifacts/note.txt",
            sourcePath: saved.path,
          });
          assert.equal(
            await fs.readFile(imported.path, "utf8"),
            "temporary evidence\n",
          );
          assert.equal(
            (
              await call("read_codex_security_artifact", {
                ...location,
                path: "note.txt",
              })
            ).directory,
            directory,
          );
        } finally {
          if (kind === "read-only") await fs.chmod(parent, 0o700);
        }
      },
    );
  }

  await test("a save captured before sealing cannot create directories after sealing", async () => {
    const call = await connect();
    const { scanId, scanDir, handoffClaimToken } = await call(
      "start_codex_security_standard_scan",
      { targetPath: repository },
    );
    const identity = { scanId, handoffClaimToken };
    const context = await createScanArtifactContext(scanId, workbench, {
      requireRunning: true,
      requireClaim: true,
      handoffClaimToken,
    });
    const scratch = await saveCodexSecurityArtifact(
      context,
      { ...identity, storage: "temporary" },
      workbench,
    );
    temporaryDirectories.push(scratch.directory);
    await call("record_codex_security_scan_draft", {
      ...identity,
      findings: [],
      threatModel: { summary: "Synthetic test target" },
      coverage: {
        completeness: "complete",
        surfaces: [
          {
            id: "source",
            label: "Source",
            disposition: "not_applicable",
            receiptRefs: [],
          },
        ],
        explicitExclusions: [],
        deferred: [],
      },
    });
    await workbench([
      "prepare-scan-completion",
      "--scan-id",
      scanId,
      "--claim-token",
      handoffClaimToken,
    ]);
    await assert.rejects(
      () =>
        saveCodexSecurityArtifact(
          context,
          {
            ...identity,
            storage: "persistent",
            path: "artifacts/after-seal/proof.txt",
            content: "rejected",
          },
          workbench,
        ),
      /sealed|stopped/,
    );
    await assert.rejects(fs.stat(path.join(scanDir, "artifacts/after-seal")), {
      code: "ENOENT",
    });
  });

  for (const storage of ["temporary", "persistent"]) {
    await test(
      `${storage} publication stays bound to its opened parent during replacement`,
      { skip: process.platform === "win32" },
      async () => {
        const context = await standaloneArtifactContext(
          repository,
          workbench,
          true,
          path.join(fixture, `swap-${storage}`),
          storage,
        );
        const location = { targetPath: repository, storage };
        const { directory } = await saveCodexSecurityArtifact(
          context,
          location,
          workbench,
        );
        if (storage === "temporary") temporaryDirectories.push(directory);
        const parent = path.join(directory, "artifacts", "nested");
        const moved = path.join(directory, "artifacts", "original");
        const outside = path.join(fixture, `outside-${storage}`);
        const marker = path.join(fixture, `swapped-${storage}`);
        await fs.mkdir(parent, { recursive: true });
        await fs.mkdir(outside);
        await fs.writeFile(
          path.join(outside, "proof.bin"),
          "outside remains unchanged",
        );
        // Replace the pathname after Python opens the parent, using real I/O
        // without relying on race timing.
        const launcher = path.join(fixture, `swap-${storage}.py`);
        await fs.writeFile(
          launcher,
          `
import os, runpy, sys
from pathlib import Path
sys.path.insert(0, str(Path(sys.argv[1]).parent))
import finalize_scan_contract as finalizer
original_open = finalizer._open_scan_local_directory
def open_then_replace(root_fd, parts, *, create):
    descriptor = original_open(root_fd, parts, create=create)
    if parts == ("artifacts", "nested"):
        os.rename(${JSON.stringify(parent)}, ${JSON.stringify(moved)})
        os.symlink(${JSON.stringify(outside)}, ${JSON.stringify(parent)})
        Path(${JSON.stringify(marker)}).write_text("python")
    return descriptor
finalizer._open_scan_local_directory = open_then_replace
sys.argv = sys.argv[1:]
runpy.run_path(sys.argv[0], run_name="__main__")
`,
        );
        await saveCodexSecurityArtifact(
          context,
          {
            ...location,
            path: "artifacts/nested/proof.bin",
            content: "new artifact",
          },
          (args: string[], input?: string) => workbench(args, input, launcher),
        );
        assert.equal(await fs.readFile(marker, "utf8"), "python");
        assert.equal(
          await fs.readFile(path.join(outside, "proof.bin"), "utf8"),
          "outside remains unchanged",
        );
        assert.equal(
          await fs.readFile(path.join(moved, "proof.bin"), "utf8"),
          "new artifact",
        );
      },
    );
  }

  for (const variable of [
    "CODEX_SECURITY_SCAN_ROOT",
    "CODEX_SECURITY_STATE_DIR",
    "CODEX_HOME",
  ]) {
    await test(
      `${variable} expands named-user paths for scans and standalone artifacts`,
      { skip: process.platform === "win32" },
      async () => {
        const account = userInfo();
        const destination = path.join(fixture, `named-${variable}`);
        const configured = `~${account.username}/${path.relative(account.homedir, destination)}`;
        temporaryDirectories.push(path.resolve(pluginRoot, configured));
        const state =
          variable === "CODEX_HOME"
            ? path.join(destination, "state", "plugins", "codex-security")
            : variable === "CODEX_SECURITY_STATE_DIR"
              ? destination
              : path.join(fixture, `named-state-${variable}`);
        const expected =
          variable === "CODEX_SECURITY_SCAN_ROOT"
            ? destination
            : path.join(state, "scans");
        const call = await connect({
          CODEX_SECURITY_STATE_DIR:
            variable === "CODEX_HOME" ? undefined : state,
          [variable]: configured,
        });
        const { scanDir } = await call("start_codex_security_standard_scan", {
          targetPath: repository,
        });
        assert.ok(
          scanDir.startsWith(path.join(expected, "repository") + path.sep),
          scanDir,
        );
        assert.ok(
          (await fs.stat(path.join(state, "workbench.sqlite3"))).isFile(),
        );
        const location = {
          targetPath: repository,
          storage: "persistent",
          path: "threatmodel.md",
        };
        const saved = await call("save_codex_security_artifact", {
          ...location,
          content: "named-user root\n",
        });
        assert.ok(
          saved.directory.startsWith(expected + path.sep),
          saved.directory,
        );
        assert.equal(
          await fs.readFile(saved.path, "utf8"),
          "named-user root\n",
        );
        assert.equal(
          (await call("read_codex_security_artifact", location)).content,
          "named-user root\n",
        );
      },
    );

    await test(`${variable} keeps the workbench base when MCP starts in another directory`, async () => {
      const relative = `.${path.basename(fixture)}-${variable}`;
      const destination = path.join(pluginRoot, relative);
      temporaryDirectories.push(destination);
      const call = await connect({
        CODEX_SECURITY_STATE_DIR:
          variable === "CODEX_HOME"
            ? undefined
            : path.join(fixture, `state-${variable}`),
        [variable]: relative,
      });
      const { scanDir } = await call("start_codex_security_standard_scan", {
        targetPath: repository,
      });
      const expected =
        variable === "CODEX_SECURITY_SCAN_ROOT"
          ? destination
          : variable === "CODEX_SECURITY_STATE_DIR"
            ? path.join(destination, "scans")
            : path.join(
                destination,
                "state",
                "plugins",
                "codex-security",
                "scans",
              );
      assert.ok(
        scanDir.startsWith(path.join(expected, "repository") + path.sep),
        scanDir,
      );
      if (variable === "CODEX_SECURITY_STATE_DIR")
        assert.ok(
          (await fs.stat(path.join(destination, "workbench.sqlite3"))).isFile(),
        );
      const saved = await call("save_codex_security_artifact", {
        targetPath: repository,
        storage: "persistent",
        path: "threatmodel.md",
        content: "relative root",
      });
      assert.ok(
        saved.directory.startsWith(expected + path.sep),
        saved.directory,
      );
      assert.equal(await fs.readFile(saved.path, "utf8"), "relative root");
    });
  }
} finally {
  for (const client of clients) await client.close();
  for (const directory of temporaryDirectories)
    await fs.rm(directory, { recursive: true, force: true });
  await fs.rm(fixture, { recursive: true, force: true });
}

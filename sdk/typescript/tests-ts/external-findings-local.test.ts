import { existsSync } from "node:fs";
import { execFileSync, spawnSync } from "node:child_process";
import {
  appendFile,
  mkdir,
  mkdtemp,
  rm,
  symlink,
  writeFile,
} from "node:fs/promises";
import { delimiter, join } from "node:path";
import { pathToFileURL } from "node:url";
import { afterEach, describe, expect, test } from "bun:test";
import type { ExternalFindings } from "../src/external-findings.js";
import {
  listLocalExternalFindings,
  prepareNormalizedLocalImport,
} from "../src/external-findings-local.js";
import { localFindingsFixture } from "./external-findings-local-helpers.js";

const fixtures: Awaited<ReturnType<typeof localFindingsFixture>>[] = [];
async function fixture(
  options: Parameters<typeof localFindingsFixture>[0] = {},
) {
  const result = await localFindingsFixture(options);
  fixtures.push(result);
  return result;
}
afterEach(async () => {
  await Promise.all(fixtures.splice(0).map((item) => item.dispose()));
});

function input(): ExternalFindings {
  return {
    read: 3,
    findings: [
      {
        source_finding_id: "scanner-finding-1",
        evidence: {
          title: "Dependency vulnerability",
          severity: "unknown",
          source_data: {
            id: "scanner-finding-1",
            metadata: { nullable: null, list: [1, "two"] },
          },
        },
      },
      {
        source_finding_id: "scanner-finding-2",
        evidence: {
          title: "Reported source issue",
          severity: "high",
          branch: "release",
          code_revision: "scanner-revision",
          locations: [{ path: "src/main.ts" }],
          source_data: { finding: 2 },
        },
      },
    ],
    excluded: [
      {
        position: 2,
        source_finding_id: null,
        reason: "No supported finding evidence",
      },
    ],
  };
}

const source = { provider: "snyk" as const, sourceKey: "example-project/main" };

describe("local normalized scanner findings", () => {
  test("persists sparse evidence through the native helper and reads it in a separate process", async () => {
    const { repository, stateDirectory, environment } = await fixture();
    const normalized = input();
    const prepared = await prepareNormalizedLocalImport(
      normalized,
      { repository, ...source },
      { environment },
    );
    expect(prepared.preview).toEqual({
      ...normalized,
      repository,
      source: { provider: source.provider, source_key: source.sourceKey },
    });
    expect(existsSync(stateDirectory)).toBe(false);
    normalized.findings[0]!.evidence.title = "Later caller edit";
    prepared.preview.findings[0]!.evidence.title = "Later preview edit";
    const result = await prepared.import();
    expect(result).toMatchObject({
      repository,
      read: 3,
      ready: 2,
      excluded: input().excluded,
      counts: { created: 2, updated: 0, unchanged: 0 },
    });
    expect(existsSync(join(stateDirectory, "workbench.sqlite3"))).toBe(true);
    expect(result.findings.map((row) => row.evidence)).toEqual(
      input().findings.map((row) => row.evidence),
    );
    for (const row of result.findings) {
      expect(row).toMatchObject({
        repository,
        ...source,
        version: 1,
        assessment: { state: "not_assessed" },
      });
      expect(row.createdAt).toBe(row.updatedAt);
    }
    const reloaded = await listLocalExternalFindings(
      { repository },
      { environment },
    );
    expect(new Map(reloaded.map((row) => [row.id, row]))).toEqual(
      new Map(result.findings.map((row) => [row.id, row])),
    );
    expect(
      await listLocalExternalFindings(
        { repository, id: result.findings[0]!.id },
        { environment },
      ),
    ).toEqual([result.findings[0]!]);
  });

  test("upserts reordered and changed exports without deleting omitted records or mixing namespaces", async () => {
    const { root, repository, environment } = await fixture();
    const save = async (
      data: ExternalFindings,
      options = { repository, ...source },
    ) =>
      (
        await prepareNormalizedLocalImport(data, options, { environment })
      ).import();
    const initial = await save(input());
    const reordered = input();
    reordered.findings.reverse();
    reordered.findings[1]!.evidence.source_data = {
      metadata: { list: [1, "two"], nullable: null },
      id: "scanner-finding-1",
    };
    const repeated = await save(reordered);
    expect(repeated.counts).toEqual({ created: 0, updated: 0, unchanged: 2 });
    expect(repeated.findings).toEqual([...initial.findings].reverse());
    const changed = input();
    changed.findings = [changed.findings[0]!];
    changed.findings[0]!.evidence.severity = "critical";
    const updated = await save(changed);
    expect(updated.counts).toEqual({ created: 0, updated: 1, unchanged: 0 });
    expect(updated.findings[0]).toMatchObject({
      id: initial.findings[0]!.id,
      version: 2,
      createdAt: initial.findings[0]!.createdAt,
    });
    expect(
      await listLocalExternalFindings(
        { repository, id: initial.findings[1]!.id },
        { environment },
      ),
    ).toEqual([initial.findings[1]!]);
    const otherSource = await save(changed, {
      repository,
      ...source,
      sourceKey: "other-project/main",
    });
    const otherProvider = await (
      await prepareNormalizedLocalImport(
        changed,
        { repository, ...source, provider: "endor" },
        { environment },
      )
    ).import();
    const otherRepository = join(root, "other-repository");
    await mkdir(otherRepository);
    const otherCheckout = await save(changed, {
      repository: otherRepository,
      ...source,
    });
    expect(
      new Set(
        [updated, otherSource, otherProvider, otherCheckout].map(
          (result) => result.findings[0]!.id,
        ),
      ).size,
    ).toBe(4);
    expect(
      await listLocalExternalFindings(
        { repository: otherRepository },
        { environment },
      ),
    ).toEqual(otherCheckout.findings);
    expect(
      (await listLocalExternalFindings({ repository }, { environment })).length,
    ).toBe(4);
  });

  test("reads retained evidence after the checkout is removed and still requires a directory for new imports", async () => {
    const { repository, environment } = await fixture();
    const result = await (
      await prepareNormalizedLocalImport(
        input(),
        { repository, ...source },
        { environment },
      )
    ).import();
    await rm(repository, { recursive: true });
    const reloaded = await listLocalExternalFindings(
      { repository: result.repository },
      { environment },
    );
    expect(new Map(reloaded.map((row) => [row.id, row]))).toEqual(
      new Map(result.findings.map((row) => [row.id, row])),
    );
    expect(
      await listLocalExternalFindings(
        { repository: result.repository, id: result.findings[0]!.id },
        { environment },
      ),
    ).toEqual([result.findings[0]!]);
    await expect(
      prepareNormalizedLocalImport(
        input(),
        { repository, ...source },
        { environment },
      ),
    ).rejects.toThrow("Repository is not a directory");
  });

  test("preparation and cancellation leave the database untouched", async () => {
    const { repository, stateDirectory, environment } = await fixture();
    const controller = new AbortController();
    const prepared = await prepareNormalizedLocalImport(
      input(),
      { repository, ...source },
      { environment, signal: controller.signal },
    );
    expect(existsSync(stateDirectory)).toBe(false);
    controller.abort();
    await expect(prepared.import()).rejects.toThrow();
    await expect(
      prepareNormalizedLocalImport(
        input(),
        { repository, ...source },
        { environment, signal: controller.signal },
      ),
    ).rejects.toThrow();
    expect(existsSync(stateDirectory)).toBe(false);
  });

  test("refreshes caller protections when importing a previously prepared payload", async () => {
    const { root, repository, stateDirectory, environment } = await fixture();
    const originalCaller = await fixture();
    const nextCaller = await fixture();
    const originalBin = join(originalCaller.repository, "tools");
    const nextBin = join(nextCaller.repository, "tools");
    const nextDirectory = join(nextCaller.repository, "src");
    const unsafeState = join(nextCaller.repository, "state");
    const marker = join(root, "caller-node-executed");
    await Promise.all([
      mkdir(originalBin),
      mkdir(nextBin),
      mkdir(nextDirectory),
    ]);
    await Promise.all(
      [originalBin, nextBin].map((bin) =>
        writeFile(
          join(bin, process.platform === "win32" ? "node.exe" : "node"),
          process.platform === "win32"
            ? "untrusted executable fixture\n"
            : '#!/bin/sh\nprintf executed > "$TEST_LOCAL_IMPORT_NODE_MARKER"\nexit 1\n',
          { mode: 0o700 },
        ),
      ),
    );
    const inheritedPath = Object.entries(environment).find(
      ([name]) => name.toUpperCase() === "PATH",
    )?.[1];
    const module = new URL("../src/external-findings-local.ts", import.meta.url)
      .href;
    const script = `
      import { deepEqual, equal, rejects } from "node:assert/strict";
      const { prepareNormalizedLocalImport } = await import(${JSON.stringify(module)});
      const input = ${JSON.stringify(input())};
      const options = ${JSON.stringify({ repository, ...source })};
      const prepared = await prepareNormalizedLocalImport(input, options);
      const unsafeEnvironment = {
        ...process.env,
        CODEX_SECURITY_STATE_DIR: ${JSON.stringify(unsafeState)},
      };
      const unsafe = await prepareNormalizedLocalImport(input, options, {
        environment: unsafeEnvironment,
      });
      unsafeEnvironment.CODEX_SECURITY_STATE_DIR = ${JSON.stringify(stateDirectory)};
      process.chdir(${JSON.stringify(nextDirectory)});
      await rejects(unsafe.import(), /outside/);
      const result = await prepared.import();
      equal(result.repository, options.repository);
      deepEqual(result.counts, { created: 2, updated: 0, unchanged: 0 });
      console.log("IMPORTED");
    `;
    const result = spawnSync(process.execPath, ["-e", script], {
      cwd: originalCaller.repository,
      encoding: "utf8",
      env: {
        ...Object.fromEntries(
          Object.entries(environment).filter(
            ([name]) => name.toUpperCase() !== "PATH",
          ),
        ),
        PATH: [nextBin, originalBin, inheritedPath ?? ""].join(delimiter),
        TEST_LOCAL_IMPORT_NODE_MARKER: marker,
      },
    });
    expect(result.status, result.stderr).toBe(0);
    expect(result.stdout.trim()).toBe("IMPORTED");
    expect(existsSync(marker)).toBe(false);
    expect(existsSync(unsafeState)).toBe(false);
    expect(existsSync(join(stateDirectory, "workbench.sqlite3"))).toBe(true);
  });

  test.each(["bare", "linked-metadata", "linked-worktree"] as const)(
    "protects %s caller metadata during preparation, readback, and deferred import",
    async (kind) => {
      const { root, repository, stateDirectory, environment } = await fixture({
        remote: "https://github.com/example/project",
      });
      const originalCaller = await fixture();
      const caller = join(root, "caller");
      const common = join(root, "common.git");
      const git = (args: string[], stdin?: string): string =>
        execFileSync("git", args, {
          encoding: "utf8",
          input: stdin,
          stdio: ["pipe", "pipe", "pipe"],
        }).trim();
      let metadataRoots: string[];
      let pointerPaths: string[] = [];
      if (kind === "bare") {
        git(["init", "--quiet", "--bare", caller]);
        metadataRoots = [caller];
      } else {
        git(["init", "--quiet", "--bare", common]);
        if (kind === "linked-metadata") {
          await mkdir(caller);
          await writeFile(join(caller, "HEAD"), "ref: refs/heads/main\n");
          await writeFile(join(caller, "commondir"), `${common}\n`);
          metadataRoots = [caller, common];
          pointerPaths = [join(caller, "commondir")];
        } else {
          const tree = git(["--git-dir", common, "mktree"], "");
          const commit = git(
            [
              "--git-dir",
              common,
              "-c",
              "user.name=Fixture",
              "-c",
              "user.email=fixture@example.test",
              "-c",
              "commit.gpgsign=false",
              "commit-tree",
              tree,
            ],
            "Synthetic worktree fixture\n",
          );
          git([
            "--git-dir",
            common,
            "worktree",
            "add",
            "--detach",
            caller,
            commit,
          ]);
          const gitDirectory = git([
            "-C",
            caller,
            "rev-parse",
            "--absolute-git-dir",
          ]);
          metadataRoots = [gitDirectory, common];
          pointerPaths = [
            join(caller, ".git"),
            join(gitDirectory, "commondir"),
          ];
        }
        // A linked repository owns HEAD; its shared object store need not.
        await rm(join(common, "HEAD"));
      }
      const callerDirectory = join(caller, "src");
      await mkdir(callerDirectory);
      const gitMarker = join(root, "metadata-git-executed");
      const nodeMarker = join(root, "metadata-node-executed");
      const bins = metadataRoots.map((directory) => join(directory, "tools"));
      for (const bin of bins) {
        await mkdir(bin);
        for (const executable of ["git", "node"]) {
          await writeFile(
            join(
              bin,
              process.platform === "win32" ? `${executable}.exe` : executable,
            ),
            process.platform === "win32"
              ? "untrusted executable fixture\n"
              : `#!/bin/sh\nprintf executed > "$TEST_METADATA_${executable.toUpperCase()}_MARKER"\nexit 1\n`,
            { mode: 0o700 },
          );
        }
      }
      const inheritedPath = Object.entries(environment).find(
        ([name]) => name.toUpperCase() === "PATH",
      )?.[1];
      const module = new URL(
        "../src/external-findings-local.ts",
        import.meta.url,
      ).href;
      const script = `
        import { deepEqual, equal, rejects } from "node:assert/strict";
        import { existsSync, readFileSync } from "node:fs";
        import { join } from "node:path";
        const { prepareNormalizedLocalImport, listLocalExternalFindings } =
          await import(${JSON.stringify(module)});
        const input = ${JSON.stringify(input())};
        const options = ${JSON.stringify({ repository, ...source })};
        const pointerPaths = ${JSON.stringify(pointerPaths)};
        const pointerContents = pointerPaths.map((path) => readFileSync(path, "utf8"));
        for (const metadataRoot of ${JSON.stringify(metadataRoots)}) {
          const state = join(metadataRoot, "security-state");
          const environment = { ...process.env, CODEX_SECURITY_STATE_DIR: state };
          process.chdir(${JSON.stringify(originalCaller.repository)});
          const prepared = await prepareNormalizedLocalImport(input, options, {
            environment,
          });
          equal(existsSync(state), false);
          process.chdir(${JSON.stringify(callerDirectory)});
          await rejects(
            prepareNormalizedLocalImport(input, options, { environment }),
            /outside/,
          );
          await rejects(
            listLocalExternalFindings({ repository: options.repository }, { environment }),
            /outside/,
          );
          await rejects(prepared.import(), /outside/);
          equal(existsSync(state), false);
        }
        // The metadata shims must be excluded for both Git discovery and Node launch.
        const prepared = await prepareNormalizedLocalImport(input, options, {
          sourceRepositories: [{ url: "https://github.com/example/project" }],
        });
        const result = await prepared.import();
        deepEqual(result.counts, { created: 2, updated: 0, unchanged: 0 });
        equal(existsSync(${JSON.stringify(gitMarker)}), false);
        equal(existsSync(${JSON.stringify(nodeMarker)}), false);
        deepEqual(
          pointerPaths.map((path) => readFileSync(path, "utf8")),
          pointerContents,
        );
        console.log("PROTECTED");
      `;
      const result = spawnSync(process.execPath, ["-e", script], {
        cwd: originalCaller.repository,
        encoding: "utf8",
        env: {
          ...Object.fromEntries(
            Object.entries(environment).filter(
              ([name]) => name.toUpperCase() !== "PATH",
            ),
          ),
          PATH: [...bins, inheritedPath ?? ""].join(delimiter),
          TEST_METADATA_GIT_MARKER: gitMarker,
          TEST_METADATA_NODE_MARKER: nodeMarker,
        },
      });
      expect(result.status, result.stderr).toBe(0);
      expect(result.stdout.trim()).toBe("PROTECTED");
      expect(existsSync(gitMarker)).toBe(false);
      expect(existsSync(nodeMarker)).toBe(false);
      for (const metadataRoot of metadataRoots)
        expect(existsSync(join(metadataRoot, "security-state"))).toBe(false);
      expect(existsSync(join(stateDirectory, "workbench.sqlite3"))).toBe(true);
    },
  );

  test.each(["repository", "prepare-state", "read-state", "prepare-metadata"])(
    "cancels %s resolution while its filesystem lookup is pending",
    async (operation) => {
      const { repository, stateDirectory, environment } = await fixture();
      if (operation === "prepare-metadata")
        await rm(join(repository, ".git"), { recursive: true });
      const module = new URL(
        "../src/external-findings-local.ts",
        import.meta.url,
      ).href;
      const mocks = new URL("./support/module-mocks.ts", import.meta.url).href;
      const script = `
      import { strictEqual } from "node:assert/strict";
      import * as fs from "node:fs/promises";
      import { setImmediate } from "node:timers/promises";
      import { mockFs } from ${JSON.stringify(mocks)};
      const repository = ${JSON.stringify(repository)};
      const operation = ${JSON.stringify(operation)};
      const heldPath = operation === "repository" ? repository
        : operation === "prepare-metadata" ? ${JSON.stringify(join(repository, "HEAD"))}
        : ${JSON.stringify(stateDirectory)};
      const originalRealpath = fs.realpath;
      const originalLstat = fs.lstat;
      let enteredLookup, releaseLookup;
      const entered = new Promise((resolve) => { enteredLookup = resolve; });
      const lookup = new Promise((_, reject) => { releaseLookup = reject; });
      mockFs(() => ({
        realpath: (path, ...args) => {
          if (operation === "prepare-metadata" || path !== heldPath)
            return originalRealpath(path, ...args);
          enteredLookup();
          return lookup;
        },
        lstat: (path, ...args) => {
          if (operation !== "prepare-metadata" || path !== heldPath)
            return originalLstat(path, ...args);
          enteredLookup();
          return lookup;
        },
      }));
      const { listLocalExternalFindings, prepareNormalizedLocalImport } =
        await import(${JSON.stringify(module)});
      const controller = new AbortController();
      const reason = new Error("Synthetic path resolution cancellation");
      let outcome;
      const pending = operation.startsWith("prepare-")
        ? prepareNormalizedLocalImport(
            { read: 0, findings: [], excluded: [] },
            { repository, provider: "snyk", sourceKey: "synthetic-project" },
            { signal: controller.signal,
              sourceRepositories: [{ url: "https://github.com/example/project" }] },
          )
        : listLocalExternalFindings(
            { repository }, { signal: controller.signal },
          );
      const reading = pending.then(
        () => { outcome = "fulfilled"; },
        (error) => { outcome = error; },
      );
      await entered;
      controller.abort(reason);
      await setImmediate();
      try {
        strictEqual(outcome, reason);
      } finally {
        releaseLookup(new Error("Synthetic filesystem failure"));
        await reading;
      }
      strictEqual(outcome, reason);
      console.log("CANCELLED");
    `;
      const result = spawnSync(process.execPath, ["-e", script], {
        encoding: "utf8",
        env: environment,
      });
      expect(result.status, result.stderr).toBe(0);
      expect(result.stdout.trim()).toBe("CANCELLED");
      expect(existsSync(stateDirectory)).toBe(false);
    },
  );

  test.each([
    ["selected-roots", "prepare"],
    ["selected-roots", "read"],
    ["caller-roots", "prepare"],
    ["caller-roots", "read"],
    ["caller-roots", "import"],
    ["plugin-manifest", "prepare"],
    ["plugin-path", "read"],
    ["git-executable", "prepare"],
    ["workbench-path", "read"],
    ["workbench-path", "import"],
  ])("cancels pending %s lookup during %s", async (site, operation) => {
    const { repository, stateDirectory, environment } = await fixture({
      remote: "https://github.com/example/project",
    });
    const caller = await fixture();
    const module = new URL("../src/external-findings-local.ts", import.meta.url)
      .href;
    const mocks = new URL("./support/module-mocks.ts", import.meta.url).href;
    const trusted = new URL("../src/trusted-executable.ts", import.meta.url)
      .href;
    const plugin = new URL("../_bundled_plugin", import.meta.url).href;
    const script = `
      import { strictEqual } from "node:assert/strict";
      import * as fs from "node:fs/promises";
      import { dirname, join } from "node:path";
      import { fileURLToPath } from "node:url";
      import { setImmediate } from "node:timers/promises";
      import { mockFs } from ${JSON.stringify(mocks)};
      const site = ${JSON.stringify(site)};
      const operation = ${JSON.stringify(operation)};
      const repository = ${JSON.stringify(repository)};
      const original = { lstat: fs.lstat, realpath: fs.realpath, stat: fs.stat };
      const held = new Map();
      function lookup(method, path, args) {
        const gate = held.get(method + ":" + path);
        if (gate) { gate.entered(); return gate.wait; }
        return original[method](path, ...args);
      }
      mockFs(() => ({
        lstat: (path, ...args) => lookup("lstat", path, args),
        realpath: (path, ...args) => lookup("realpath", path, args),
        stat: (path, ...args) => lookup("stat", path, args),
      }));
      const { prepareNormalizedLocalImport, listLocalExternalFindings } =
        await import(${JSON.stringify(module)});
      const { resolveTrustedExecutable } = await import(${JSON.stringify(trusted)});
      const nodeDirectory = site === "workbench-path"
        ? dirname((await resolveTrustedExecutable("node", process.env, [repository])).executable)
        : undefined;
      const controller = new AbortController();
      const reason = new Error("Synthetic setup cancellation");
      let helperCalls = 0;
      const dependencies = {
        signal: controller.signal,
        sourceRepositories: site === "git-executable"
          ? [{ url: "https://github.com/example/project" }] : [],
        ...(site === "workbench-path" ? {
          environment: {
            ...Object.fromEntries(Object.entries(process.env).filter(([name]) => name.toUpperCase() !== "PATH")),
            PATH: nodeDirectory,
          },
        } : {
          runWorkbench: async () => {
            helperCalls++;
            return { findings: [], counts: { created: 0, updated: 0, unchanged: 0 } };
          },
        }),
      };
      const input = { read: 0, findings: [], excluded: [] };
      const options = { repository, provider: "snyk", sourceKey: "synthetic-project" };
      const prepared = operation === "import"
        ? await prepareNormalizedLocalImport(input, options, dependencies)
        : undefined;
      let paths;
      if (site.endsWith("-roots")) {
        const directory = site === "selected-roots" ? repository
          : await original.realpath(process.cwd());
        paths = [["lstat", directory], ["lstat", join(directory, ".git")]];
      } else if (site.startsWith("plugin-")) {
        const plugin = fileURLToPath(${JSON.stringify(plugin)});
        paths = site === "plugin-manifest"
          ? [["lstat", join(plugin, ".codex-plugin", "plugin.json")]]
          : [["realpath", plugin]];
      } else if (site === "workbench-path") {
        paths = [["realpath", nodeDirectory]];
      } else {
        const git = await resolveTrustedExecutable("git", process.env, [repository]);
        paths = [["stat", await original.realpath(git.executable)]];
      }
      const gates = [];
      for (const [method, path] of paths) {
        const value = await original[method](path);
        let entered, release;
        const reached = new Promise((resolve) => { entered = resolve; });
        const wait = new Promise((resolve, reject) => {
          release = site === "workbench-path"
            ? () => reject(Object.assign(new Error("Synthetic PATH lookup failure"), { code: "EIO" }))
            : resolve;
        });
        const gate = { key: method + ":" + path, entered, release, reached, wait, value };
        held.set(gate.key, gate);
        gates.push(gate);
      }
      let outcome;
      const pending = (operation === "import" ? prepared.import()
        : operation === "prepare" ? prepareNormalizedLocalImport(input, options, dependencies)
        : listLocalExternalFindings({ repository }, dependencies)).then(
          () => { outcome = "fulfilled"; }, (error) => { outcome = error; },
        );
      await Promise.all(gates.map((gate) => gate.reached));
      controller.abort(reason);
      await setImmediate();
      try {
        strictEqual(outcome, reason);
      } finally {
        for (const gate of gates) {
          held.delete(gate.key);
          gate.release(gate.value);
        }
        await pending;
      }
      await setImmediate();
      strictEqual(outcome, reason);
      strictEqual(helperCalls, 0);
      console.log("CANCELLED");
    `;
    const result = spawnSync(process.execPath, ["-e", script], {
      cwd: caller.repository,
      encoding: "utf8",
      env: environment,
    });
    expect(result.status, result.stderr).toBe(0);
    expect(result.stdout.trim()).toBe("CANCELLED");
    expect(existsSync(stateDirectory)).toBe(false);
  });

  test("rejects duplicate occurrence identities before creating local state", async () => {
    const { repository, stateDirectory, environment } = await fixture();
    const duplicate = input();
    duplicate.findings.push(duplicate.findings[0]!);
    await expect(
      prepareNormalizedLocalImport(
        duplicate,
        { repository, ...source },
        { environment },
      ),
    ).rejects.toThrow("Duplicate source finding id");
    expect(existsSync(stateDirectory)).toBe(false);
  });

  test("rejects non-finite JSON before it can be stored as null", async () => {
    const { repository, stateDirectory, environment } = await fixture();
    const data = input();
    data.findings[0]!.evidence.source_data = JSON.parse('{"score":1e999}');
    await expect(
      prepareNormalizedLocalImport(
        data,
        { repository, ...source },
        { environment },
      ),
    ).rejects.toThrow("non-finite numbers");
    expect(existsSync(stateDirectory)).toBe(false);
  });

  test("uses the canonical selected checkout and rejects state inside it", async () => {
    const { root, repository, environment } = await fixture();
    const link = join(root, "repository-link");
    await symlink(
      repository,
      link,
      process.platform === "win32" ? "junction" : "dir",
    );
    const prepared = await prepareNormalizedLocalImport(
      input(),
      { repository: link, ...source },
      { environment },
    );
    expect(prepared.preview.repository).toBe(repository);
    await expect(
      prepareNormalizedLocalImport(
        input(),
        { repository, ...source },
        {
          environment: {
            ...environment,
            CODEX_SECURITY_STATE_DIR: join(repository, "state"),
          },
        },
      ),
    ).rejects.toThrow();
    const child = join(repository, "src");
    await mkdir(child);
    await expect(
      prepareNormalizedLocalImport(
        input(),
        { repository: child, ...source },
        {
          environment: {
            ...environment,
            CODEX_SECURITY_STATE_DIR: join(repository, "state"),
          },
        },
      ),
    ).rejects.toThrow();
    expect(existsSync(join(repository, "state"))).toBe(false);
  });

  test.each(["bare", "linked", "ordinary"] as const)(
    "protects selected %s roots through nested paths and aliases",
    async (kind) => {
      const { root, repository, environment } = await fixture();
      const owner = join(root, "owner");
      const common = join(root, "common.git");
      if (kind === "linked") {
        execFileSync("git", ["init", "--bare", "--quiet", common]);
        await mkdir(owner);
        await writeFile(join(owner, "HEAD"), "ref: refs/heads/main\n");
        await writeFile(join(owner, "commondir"), "../common.git\n");
      } else {
        execFileSync("git", [
          "init",
          "--quiet",
          ...(kind === "bare" ? ["--bare"] : []),
          owner,
        ]);
      }
      const nested = join(owner, "nested", "selected");
      await mkdir(nested, { recursive: true });
      const linkType = process.platform === "win32" ? "junction" : "dir";
      await symlink(repository, join(owner, "to-selected"), linkType);
      const alias = join(root, "owner-alias");
      await symlink(owner, alias, linkType);
      const selections = [
        owner,
        nested,
        join(owner, "to-selected"),
        join(alias, "to-selected"),
      ];
      if (kind === "bare") {
        const inner = join(owner, "inner-worktree");
        execFileSync("git", ["init", "--quiet", inner]);
        selections.push(inner);
      }
      for (const protectedDirectory of kind === "linked"
        ? [owner, common]
        : [owner]) {
        const state = join(protectedDirectory, "runtime-state");
        let helperCalls = 0;
        const dependencies = {
          environment: { ...environment, CODEX_SECURITY_STATE_DIR: state },
          runWorkbench: async () => {
            helperCalls++;
            return {
              findings: [],
              counts: { created: 0, updated: 0, unchanged: 0 },
            };
          },
        };
        for (const selected of selections) {
          await expect(
            (async () => {
              const prepared = await prepareNormalizedLocalImport(
                input(),
                { repository: selected, ...source },
                dependencies,
              );
              await prepared.import();
            })(),
          ).rejects.toThrow("must be outside the protected scan root");
          await expect(
            listLocalExternalFindings({ repository: selected }, dependencies),
          ).rejects.toThrow("must be outside the protected scan root");
          expect(helperCalls).toBe(0);
          expect(existsSync(state)).toBe(false);
        }
      }
    },
  );

  test.each([
    ["gitdir", "spaces"],
    ["commondir", "spaces"],
    ["commondir", "nul-suffix"],
    ["gitdir", "self-nul"],
    ["commondir", "self-nul"],
    ["commondir", "self-newline"],
    ...(process.platform === "win32"
      ? []
      : [
          ["gitdir", "newline-before-nul"],
          ["commondir", "newline-before-nul"],
        ]),
  ])("preserves Git %s pointer format %s", async (kind, format) => {
    const { root, stateDirectory, environment } = await fixture();
    const common = join(
      root,
      format === "spaces"
        ? process.platform === "win32"
          ? "metadata with spaces"
          : " metadata with spaces "
        : format === "newline-before-nul"
          ? "metadata.git\n"
          : "metadata.git",
    );
    execFileSync("git", ["init", "--quiet", "--bare", common]);
    execFileSync("git", [
      "-C",
      common,
      "remote",
      "add",
      "origin",
      "https://github.com/example/project",
    ]);
    let repository = join(root, "pointer-source");
    await mkdir(repository);
    if (format.startsWith("self-")) {
      if (kind === "gitdir") {
        repository = common;
        await writeFile(join(common, ".git"), "gitdir: \0ignored\r\n");
      } else {
        await writeFile(join(repository, ".git"), `gitdir: ${common}\n`);
        await writeFile(
          join(common, "commondir"),
          format === "self-nul" ? "\0ignored\r\n" : "\r\n",
        );
      }
    } else {
      const pointer = `${common}${format === "spaces" ? "" : "\0ignored"}\r\n`;
      if (kind === "gitdir")
        await writeFile(join(repository, ".git"), `gitdir: ${pointer}`);
      else {
        await writeFile(join(repository, "HEAD"), "ref: refs/heads/main\n");
        await writeFile(join(repository, "commondir"), pointer);
      }
    }
    // Git accepts the exact bytes, including a path newline immediately before NUL.
    expect(
      execFileSync("git", ["-C", repository, "remote"], {
        encoding: "utf8",
      }).trim(),
    ).toBe("origin");
    const bin = join(common, "tools");
    const marker = join(root, "pointer-git-executed");
    await mkdir(bin);
    await writeFile(
      join(bin, process.platform === "win32" ? "git.exe" : "git"),
      process.platform === "win32"
        ? "untrusted executable fixture\n"
        : '#!/bin/sh\nprintf executed > "$TEST_POINTER_GIT_MARKER"\nexit 61\n',
      { mode: 0o700 },
    );
    const inheritedPath = Object.entries(environment).find(
      ([name]) => name.toUpperCase() === "PATH",
    )?.[1];
    await prepareNormalizedLocalImport(
      input(),
      { repository, ...source },
      {
        environment: {
          ...Object.fromEntries(
            Object.entries(environment).filter(
              ([name]) => name.toUpperCase() !== "PATH",
            ),
          ),
          PATH: [bin, inheritedPath ?? ""].join(delimiter),
          TEST_POINTER_GIT_MARKER: marker,
        },
        sourceRepositories: [{ url: "https://github.com/example/project" }],
      },
    );
    expect(existsSync(marker)).toBe(false);
    expect(existsSync(stateDirectory)).toBe(false);
  });

  test.skipIf(process.platform === "win32")(
    "Node protects associated metadata through POSIX path syntax",
    async () => {
      const { root, environment } = await fixture();
      const storage = join(root, "storage");
      await mkdir(join(storage, "child"), { recursive: true });
      await symlink(join(storage, "child"), join(root, "pointer-link"), "dir");
      const cases: { repository: string; state: string }[] = [];
      for (const syntax of ["parent-traversal", "literal-backslash"]) {
        const name =
          syntax === "parent-traversal" ? "common.git" : "common\\data.git";
        const common = join(storage, name);
        execFileSync("git", ["init", "--quiet", "--bare", common]);
        const pointer =
          syntax === "parent-traversal"
            ? "../pointer-link/../common.git"
            : `../storage/${name}`;
        for (const kind of ["gitdir", "commondir"]) {
          const repository = join(root, `${syntax}-${kind}`);
          await mkdir(repository);
          if (kind === "gitdir") {
            await writeFile(join(repository, ".git"), `gitdir: ${pointer}\n`);
          } else {
            await writeFile(join(repository, "HEAD"), "ref: refs/heads/main\n");
            await writeFile(join(repository, "commondir"), `${pointer}\n`);
          }
          // Git must accept the pointer before testing the SDK's state boundary.
          execFileSync("git", [
            "-C",
            repository,
            "rev-parse",
            "--git-common-dir",
          ]);
          cases.push({ repository, state: join(common, "runtime-state") });
        }
      }
      // Exercise supported Node filesystem semantics, independent of Bun's realpath.
      // Keep the bundle beneath the SDK so Node resolves external packages.
      const bundle = await mkdtemp(
        join(import.meta.dir, "..", ".import-metadata-"),
      );
      try {
        const built = await Bun.build({
          entrypoints: [
            join(import.meta.dir, "..", "src", "external-findings-local.ts"),
          ],
          outdir: bundle,
          target: "node",
          format: "esm",
          packages: "external",
        });
        expect(built.success).toBe(true);
        const invocation = join(bundle, "invoke.mjs");
        await writeFile(
          invocation,
          `
          import assert from "node:assert/strict";
          import { existsSync } from "node:fs";
          import { listLocalExternalFindings, prepareNormalizedLocalImport } from ${JSON.stringify(pathToFileURL(built.outputs[0]!.path).href)};
          for (const { repository, state } of ${JSON.stringify(cases)}) {
            let helperCalls = 0;
            const dependencies = {
              environment: { ...process.env, CODEX_SECURITY_STATE_DIR: state },
              runWorkbench: async () => {
                helperCalls++;
                return { findings: [], counts: { created: 0, updated: 0, unchanged: 0 } };
              },
            };
            await assert.rejects(async () => {
              const prepared = await prepareNormalizedLocalImport(
                ${JSON.stringify(input())},
                { repository, ...${JSON.stringify(source)} },
                dependencies,
              );
              await prepared.import();
            }, /must be outside the protected scan root/);
            await assert.rejects(
              listLocalExternalFindings({ repository }, dependencies),
              /must be outside the protected scan root/,
            );
            assert.equal(helperCalls, 0, repository);
            assert.equal(existsSync(state), false, state);
          }
          console.log("metadata-pointer-cases:4");
        `,
        );
        const child = Bun.spawn([Bun.which("node")!, invocation], {
          env: environment,
          stdout: "pipe",
          stderr: "pipe",
        });
        const [code, stdout, stderr] = await Promise.all([
          child.exited,
          new Response(child.stdout).text(),
          new Response(child.stderr).text(),
        ]);
        expect({ code, stderr }).toEqual({ code: 0, stderr: "" });
        expect(stdout.trim()).toBe("metadata-pointer-cases:4");
      } finally {
        await rm(bundle, { recursive: true, force: true });
      }
    },
  );

  test.skipIf(process.platform !== "win32")(
    "Node protects Windows metadata resolved from selected and discovered directories",
    async () => {
      const { root, environment } = await fixture();
      const caller = join(root, "caller");
      await mkdir(caller);
      const bundle = await mkdtemp(
        join(import.meta.dir, "..", ".import-metadata-"),
      );
      try {
        const built = await Bun.build({
          entrypoints: [
            join(import.meta.dir, "..", "src", "external-findings-local.ts"),
          ],
          outdir: bundle,
          target: "node",
          format: "esm",
          packages: "external",
        });
        expect(built.success).toBe(true);
        const invocation = join(bundle, "invoke.mjs");
        await writeFile(
          invocation,
          String.raw`
          import assert from "node:assert/strict";
          import { execFileSync } from "node:child_process";
          import { existsSync } from "node:fs";
          import { mkdir, realpath, writeFile } from "node:fs/promises";
          import { join, parse } from "node:path";
          import { listLocalExternalFindings, prepareNormalizedLocalImport } from ${JSON.stringify(pathToFileURL(built.outputs[0]!.path).href)};
          const root = ${JSON.stringify(root)};
          const drive = parse(root).root.slice(0, 2);
          const git = (args) => execFileSync("git", args, {
            encoding: "utf8", stdio: ["ignore", "pipe", "pipe"],
          }).trim();
          const createStore = (path) => {
            git(["init", "--quiet", "--bare", path]);
            // These stores back worktrees, so Git changes to the discovered checkout.
            git(["config", "--file", join(path, "config"), "core.bare", "false"]);
          };
          const cases = [];
          {
            const checkout = join(root, "drive-relative-checkout");
            const selected = join(checkout, "src");
            const common = join(root, "drive-relative-common.git");
            await mkdir(selected, { recursive: true });
            createStore(common);
            await writeFile(join(checkout, ".git"),
              "gitdir: " + drive + "..\\..\\drive-relative-common.git\n");
            cases.push({ selected, common, protectedRoots: [common] });
          }
          {
            const checkout = join(root, "commondir-checkout");
            const selected = join(checkout, "src");
            const metadata = join(root, "linked-metadata");
            const discoveryCommon = join(checkout, "common.git");
            const configuredCommon = join(root, "common.git");
            await mkdir(selected, { recursive: true });
            await mkdir(metadata);
            createStore(discoveryCommon);
            createStore(configuredCommon);
            await writeFile(join(checkout, ".git"), "gitdir: " + metadata + "\n");
            await writeFile(join(metadata, "HEAD"), "ref: refs/heads/main\n");
            await writeFile(join(metadata, "commondir"), drive + "..\\common.git\n");
            cases.push({
              selected,
              common: configuredCommon,
              protectedRoots: [discoveryCommon, configuredCommon],
            });
          }
          let protectedRootCount = 0;
          for (const { selected, common, protectedRoots } of cases) {
            assert.notEqual(await realpath(process.cwd()), await realpath(selected));
            // Check Git's final metadata resolution before relying on the fixture.
            const actual = git(["-C", selected, "rev-parse", "--path-format=absolute", "--git-common-dir"]);
            assert.equal(await realpath(actual), await realpath(common));
            for (const protectedRoot of protectedRoots) {
              const state = join(protectedRoot, "runtime-state");
              let helperCalls = 0;
              const dependencies = {
                environment: { ...process.env, CODEX_SECURITY_STATE_DIR: state },
                runWorkbench: async () => {
                  helperCalls++;
                  return { findings: [], counts: { created: 0, updated: 0, unchanged: 0 } };
                },
              };
              await assert.rejects(async () => {
                const prepared = await prepareNormalizedLocalImport(
                  ${JSON.stringify(input())},
                  { repository: selected, ...${JSON.stringify(source)} },
                  dependencies,
                );
                await prepared.import();
              }, /must be outside the protected scan root/);
              await assert.rejects(
                listLocalExternalFindings({ repository: selected }, dependencies),
                /must be outside the protected scan root/,
              );
              assert.equal(helperCalls, 0, protectedRoot);
              assert.equal(existsSync(state), false, state);
              protectedRootCount++;
            }
          }
          assert.equal(protectedRootCount, 3);
          console.log("windows-metadata-roots:3");
        `,
        );
        const child = Bun.spawn([Bun.which("node")!, invocation], {
          cwd: caller,
          env: environment,
          stdout: "pipe",
          stderr: "pipe",
        });
        const [code, stdout, stderr] = await Promise.all([
          child.exited,
          new Response(child.stdout).text(),
          new Response(child.stderr).text(),
        ]);
        expect({ code, stderr }).toEqual({ code: 0, stderr: "" });
        expect(stdout.trim()).toBe("windows-metadata-roots:3");
      } finally {
        await rm(bundle, { recursive: true, force: true });
      }
    },
  );

  test("preserves Git pointer formats and invalid-pointer diagnostics", async () => {
    const { root, environment, stateDirectory } = await fixture();
    const repository = join(root, "linked");
    const common = join(root, "common.git");
    await mkdir(repository);
    execFileSync("git", ["init", "--quiet", "--bare", common]);
    execFileSync("git", [
      "-C",
      common,
      "remote",
      "add",
      "origin",
      "https://github.com/example/project",
    ]);
    const marker = join(repository, ".git");
    const dependencies = {
      environment,
      sourceRepositories: [{ url: "https://github.com/example/project" }],
    };
    await writeFile(marker, `gitdir: ${common}\0trailing\n`);
    await prepareNormalizedLocalImport(
      input(),
      { repository, ...source },
      dependencies,
    );
    await writeFile(marker, "gitdir: \0invalid\n");
    const diagnostic = spawnSync(
      "git",
      ["-c", "core.fsmonitor=false", "-C", repository, "remote"],
      {
        encoding: "utf8",
        env: environment,
      },
    );
    expect(diagnostic.status).toBe(128);
    await expect(
      prepareNormalizedLocalImport(
        input(),
        { repository, ...source },
        dependencies,
      ),
    ).rejects.toMatchObject({
      code: diagnostic.status,
      stderr: diagnostic.stderr,
    });
    const unrelated = join(root, "unrelated");
    for (const name of ["HEAD", "objects", "refs"])
      await mkdir(join(unrelated, name), { recursive: true });
    await writeFile(marker, `gitdir: ${unrelated}\n`);
    let helperCalls = 0;
    await listLocalExternalFindings(
      { repository },
      {
        environment: {
          ...environment,
          CODEX_SECURITY_STATE_DIR: join(unrelated, "state"),
        },
        runWorkbench: async () => {
          helperCalls++;
          return { findings: [] };
        },
      },
    );
    expect(helperCalls).toBe(1);
    expect(existsSync(stateDirectory)).toBe(false);
    expect(existsSync(join(unrelated, "state"))).toBe(false);
  });

  test("protects the checkout containing a directory link when selecting another repository", async () => {
    const { root, repository, stateDirectory, environment } = await fixture({
      remote: "https://github.com/example/project",
    });
    const outer = await fixture();
    const link = join(outer.repository, "linked-repository");
    await symlink(
      repository,
      link,
      process.platform === "win32" ? "junction" : "dir",
    );
    const unsafeState = join(outer.repository, "state");
    await expect(
      prepareNormalizedLocalImport(
        input(),
        { repository: link, ...source },
        {
          environment: {
            ...environment,
            CODEX_SECURITY_STATE_DIR: unsafeState,
          },
        },
      ),
    ).rejects.toThrow("outside");

    const bin = join(outer.repository, "tools");
    const marker = join(root, "linked-checkout-git-executed");
    await mkdir(bin);
    await writeFile(
      join(bin, process.platform === "win32" ? "git.exe" : "git"),
      process.platform === "win32"
        ? "untrusted executable fixture\n"
        : '#!/bin/sh\nprintf executed > "$TEST_LOCAL_IMPORT_GIT_MARKER"\nexit 1\n',
      { mode: 0o700 },
    );
    const inheritedPath = Object.entries(environment).find(
      ([name]) => name.toUpperCase() === "PATH",
    )?.[1];
    const selectedEnvironment = {
      ...Object.fromEntries(
        Object.entries(environment).filter(
          ([name]) => name.toUpperCase() !== "PATH",
        ),
      ),
      PATH: [bin, inheritedPath ?? ""].join(delimiter),
      TEST_LOCAL_IMPORT_GIT_MARKER: marker,
    };
    const prepared = await prepareNormalizedLocalImport(
      input(),
      { repository: link, ...source },
      {
        environment: selectedEnvironment,
        sourceRepositories: [{ url: "https://github.com/example/project" }],
      },
    );
    expect(prepared.preview.repository).toBe(repository);
    await expect(
      prepareNormalizedLocalImport(
        input(),
        { repository: link, ...source },
        {
          environment: selectedEnvironment,
          sourceRepositories: [{ url: "https://github.com/example/other" }],
        },
      ),
    ).rejects.toThrow("does not match a configured remote");
    expect(existsSync(marker)).toBe(false);
    expect(existsSync(unsafeState)).toBe(false);
    expect(existsSync(stateDirectory)).toBe(false);
  });

  test("matches source repository context against SSH remotes and reader metadata", async () => {
    const { repository, stateDirectory, environment } = await fixture({
      remote: "git@github.com:Example/Project.git",
    });
    const data = input();
    data.findings[0]!.evidence.details = {
      kind: "sast",
      repository: { url: "https://github.com/example/project" },
    };
    await prepareNormalizedLocalImport(
      data,
      { repository, ...source },
      { environment },
    );
    await expect(
      prepareNormalizedLocalImport(
        data,
        { repository, ...source },
        {
          environment,
          sourceRepositories: [{ url: "https://github.com/example/other" }],
        },
      ),
    ).rejects.toThrow("does not match a configured remote");
    data.findings[0]!.evidence.details.repository!.url =
      "https://github.com/example/other";
    await expect(
      prepareNormalizedLocalImport(
        data,
        { repository, ...source },
        { environment },
      ),
    ).rejects.toThrow("does not match a configured remote");
    execFileSync("git", [
      "-C",
      repository,
      "remote",
      "add",
      "upstream",
      "https://github.com/example/other.git",
    ]);
    await prepareNormalizedLocalImport(
      data,
      { repository, ...source },
      { environment },
    );
    expect(existsSync(stateDirectory)).toBe(false);
  });

  test.each(
    [
      ["git", "9418"],
      ["ftp", "21"],
      ["ftps", "990"],
      ["git+ssh", "22"],
      ["ssh+git", "22"],
    ].flatMap(([protocol, defaultPort]) =>
      ["", `:${defaultPort}`, ":19418"].map(
        (port) => [protocol, port] as const,
      ),
    ),
  )("matches %s transport remotes with port %s", async (protocol, port) => {
    const { repository, stateDirectory, environment } = await fixture({
      remote: `${protocol}://git.example.test${port}/Example/Project.git`,
    });
    const expectedPort = port === ":19418" ? port : "";
    await prepareNormalizedLocalImport(
      input(),
      { repository, ...source },
      {
        environment,
        sourceRepositories: [
          {
            url: `https://git.example.test${expectedPort}/Example/Project`,
          },
        ],
      },
    );
    for (const url of [
      `https://git.example.test${expectedPort}/Example/Other`,
      `https://git.example.test${expectedPort}/example/project`,
      `https://git.example.test${expectedPort ? "" : ":19418"}/Example/Project`,
    ]) {
      await expect(
        prepareNormalizedLocalImport(
          input(),
          { repository, ...source },
          { environment, sourceRepositories: [{ url }] },
        ),
      ).rejects.toThrow("does not match a configured remote");
    }
    expect(existsSync(stateDirectory)).toBe(false);
  });

  test.each(
    ["ssh", "git+ssh", "ssh+git"].flatMap((protocol) =>
      ["ssh.github.com", "SSH.GITHUB.COM"].map(
        (host) => [protocol, host] as const,
      ),
    ),
  )(
    "matches %s on %s over the HTTPS port without equating other SSH ports",
    async (protocol, host) => {
      const { repository, stateDirectory, environment } = await fixture({
        remote: `${protocol}://git@${host}:443/example/project.git`,
      });
      const dependencies = {
        environment,
        sourceRepositories: [{ url: "https://github.com/example/project" }],
      };
      await prepareNormalizedLocalImport(
        input(),
        { repository, ...source },
        dependencies,
      );
      await expect(
        prepareNormalizedLocalImport(
          input(),
          { repository, ...source },
          {
            environment,
            sourceRepositories: [{ url: "https://github.com/example/other" }],
          },
        ),
      ).rejects.toThrow("does not match a configured remote");
      execFileSync("git", [
        "-C",
        repository,
        "remote",
        "set-url",
        "origin",
        `${protocol}://git@ssh.github.com:2222/example/project.git`,
      ]);
      await expect(
        prepareNormalizedLocalImport(
          input(),
          { repository, ...source },
          dependencies,
        ),
      ).rejects.toThrow("does not match a configured remote");
      expect(existsSync(stateDirectory)).toBe(false);
    },
  );

  test.each(["local", "global"])(
    "matches all effective fetch URLs with %s Git URL rewrites",
    async (scope) => {
      const { root, repository, stateDirectory, environment } = await fixture({
        remote: "gh:example/project.git",
      });
      const gitEnvironment = {
        ...environment,
        GIT_CONFIG_GLOBAL: join(root, "global-git-config"),
        GIT_CONFIG_NOSYSTEM: "1",
      };
      for (const args of [
        ["config", `--${scope}`, "url.https://github.com/.insteadOf", "gh:"],
        ["config", "--add", "remote.origin.url", "gh:example/secondary.git"],
        ["remote", "add", "upstream", "gh:example/library.git"],
      ]) {
        execFileSync("git", ["-C", repository, ...args], {
          env: gitEnvironment,
        });
      }
      const module = new URL(
        "../src/external-findings-local.ts",
        import.meta.url,
      ).href;
      const script = `
        import { rejects } from "node:assert/strict";
        const { prepareNormalizedLocalImport } = await import(${JSON.stringify(module)});
        const input = { read: 0, findings: [], excluded: [] };
        const options = ${JSON.stringify({ repository, ...source })};
        for (const name of ["project", "secondary", "library"]) {
          await prepareNormalizedLocalImport(input, options, {
            sourceRepositories: [{ url: "https://github.com/example/" + name }],
          });
        }
        await rejects(
          prepareNormalizedLocalImport(input, options, {
            sourceRepositories: [{ url: "https://github.com/example/other" }],
          }),
          /does not match a configured remote/,
        );
      `;
      const result = spawnSync(process.execPath, ["-e", script], {
        encoding: "utf8",
        env: gitEnvironment,
      });
      expect(result.status, result.stderr).toBe(0);
      expect(existsSync(stateDirectory)).toBe(false);
    },
  );

  test.each(["HOME", "GIT_CONFIG_GLOBAL"])(
    "isolates concurrent injected %s configurations without redirecting the selected repository",
    async (setting) => {
      const { root, repository, stateDirectory, environment } = await fixture({
        remote: "gh:project.git",
      });
      const other = await fixture({
        remote: "https://github.com/redirected/project",
      });
      const configurations = await Promise.all(
        ["first", "second"].map(async (name) => {
          const home = join(root, name);
          await mkdir(home);
          const config = join(home, ".gitconfig");
          await writeFile(
            config,
            `[url "https://github.com/${name}/"]\n\tinsteadOf = gh:\n`,
          );
          return {
            url: `https://github.com/${name}/project`,
            environment: {
              ...environment,
              ...(setting === "HOME" ? { HOME: home, USERPROFILE: home } : {}),
              GIT_CONFIG_GLOBAL:
                setting === "GIT_CONFIG_GLOBAL" ? config : undefined,
              XDG_CONFIG_HOME: join(home, "config"),
              GIT_CONFIG_NOSYSTEM: "1",
              GIT_DIR: join(other.repository, ".git"),
              GIT_WORK_TREE: other.repository,
            },
          };
        }),
      );
      const originalEnvironments = configurations.map((configuration) => ({
        ...configuration.environment,
      }));
      await Promise.all(
        configurations.map((configuration) =>
          prepareNormalizedLocalImport(
            input(),
            { repository, ...source },
            {
              environment: configuration.environment,
              sourceRepositories: [{ url: configuration.url }],
            },
          ),
        ),
      );
      await Promise.all(
        configurations.map((configuration, index) =>
          expect(
            prepareNormalizedLocalImport(
              input(),
              { repository, ...source },
              {
                environment: configuration.environment,
                sourceRepositories: [{ url: configurations[1 - index]!.url }],
              },
            ),
          ).rejects.toThrow("does not match a configured remote"),
        ),
      );
      expect(
        configurations.map((configuration) => configuration.environment),
      ).toEqual(originalEnvironments);
      expect(existsSync(stateDirectory)).toBe(false);
      expect(existsSync(other.stateDirectory)).toBe(false);
    },
  );

  test.each([
    "C:\\repos\\source",
    "C:/repos/source",
    "/synthetic/repos/source",
    "file:///C:/repos/source",
  ])(
    "ignores local remote %s while enforcing any network remote",
    async (remote) => {
      const { repository, stateDirectory, environment } = await fixture({
        remote,
      });
      const dependencies = {
        environment,
        sourceRepositories: [{ url: "https://github.com/example/project" }],
      };
      await prepareNormalizedLocalImport(
        input(),
        { repository, ...source },
        dependencies,
      );
      execFileSync("git", [
        "-C",
        repository,
        "remote",
        "add",
        "upstream",
        "https://github.com/example/project",
      ]);
      await prepareNormalizedLocalImport(
        input(),
        { repository, ...source },
        dependencies,
      );
      await expect(
        prepareNormalizedLocalImport(
          input(),
          { repository, ...source },
          {
            environment,
            sourceRepositories: [{ url: "https://github.com/example/other" }],
          },
        ),
      ).rejects.toThrow("does not match a configured remote");
      expect(existsSync(stateDirectory)).toBe(false);
    },
  );

  test("preserves Git configuration errors during repository matching", async () => {
    const { repository, stateDirectory, environment } = await fixture({
      remote: "https://github.com/example/project",
    });
    await appendFile(join(repository, ".git", "config"), "[invalid\n");
    const git = spawnSync("git", ["-C", repository, "remote"], {
      encoding: "utf8",
      env: { ...environment, LC_ALL: "C" },
    });
    expect(git.status).toBe(128);
    expect(git.stderr).toContain("fatal: bad config line");
    await expect(
      prepareNormalizedLocalImport(
        input(),
        { repository, ...source },
        {
          environment,
          sourceRepositories: [{ url: "https://github.com/example/other" }],
        },
      ),
    ).rejects.toMatchObject({ code: git.status, stderr: git.stderr });
    expect(existsSync(stateDirectory)).toBe(false);
  });

  test("accepts repository context for checkouts without remotes and plain source directories", async () => {
    const { repository, stateDirectory, environment } = await fixture();
    const dependencies = {
      environment,
      sourceRepositories: [{ url: "https://github.com/example/project" }],
    };
    await prepareNormalizedLocalImport(
      input(),
      { repository, ...source },
      dependencies,
    );
    await rm(join(repository, ".git"), { recursive: true });
    const prepared = await prepareNormalizedLocalImport(
      input(),
      { repository, ...source },
      dependencies,
    );
    expect(prepared.preview.repository).toBe(repository);
    expect(existsSync(stateDirectory)).toBe(false);
  });

  test("requires Git for bare and linked metadata but permits plain directories without it", async () => {
    const { root, repository, stateDirectory, environment } = await fixture({
      remote: "https://github.com/example/project",
    });
    const plain = join(root, "plain");
    const bare = join(root, "bare");
    const nested = join(bare, "objects", "nested");
    const linked = join(root, "linked");
    const invalid = join(root, "invalid");
    await Promise.all([mkdir(plain), mkdir(linked), mkdir(invalid)]);
    execFileSync("git", ["init", "--bare", "--quiet", bare]);
    execFileSync("git", [
      "-C",
      bare,
      "remote",
      "add",
      "origin",
      "https://github.com/example/project",
    ]);
    await mkdir(nested);
    await Promise.all([
      writeFile(join(linked, "HEAD"), "ref: refs/heads/main\n"),
      writeFile(join(linked, "commondir"), `${bare}\n`),
      writeFile(join(invalid, ".git"), "not a Git file\n"),
    ]);
    const sourceRepositories = [{ url: "https://github.com/example/other" }];
    const withoutGit = {
      ...Object.fromEntries(
        Object.entries(environment).filter(
          ([name]) => name.toUpperCase() !== "PATH",
        ),
      ),
      PATH: "",
    };
    const prepared = await prepareNormalizedLocalImport(
      input(),
      { repository: plain, ...source },
      { environment: withoutGit, sourceRepositories },
    );
    expect(prepared.preview.repository).toBe(plain);
    for (const selected of [repository, bare, nested, linked]) {
      await expect(
        prepareNormalizedLocalImport(
          input(),
          { repository: selected, ...source },
          { environment, sourceRepositories },
        ),
      ).rejects.toThrow("does not match a configured remote");
      await expect(
        prepareNormalizedLocalImport(
          input(),
          { repository: selected, ...source },
          { environment: withoutGit, sourceRepositories },
        ),
      ).rejects.toThrow("Git is not available on a trusted PATH");
    }
    const git = spawnSync("git", ["-C", invalid, "remote"], {
      encoding: "utf8",
      env: { ...environment, LC_ALL: "C" },
    });
    expect(git.status).toBe(128);
    expect(git.stderr).toContain("fatal: invalid gitfile format");
    await expect(
      prepareNormalizedLocalImport(
        input(),
        { repository: invalid, ...source },
        { environment, sourceRepositories },
      ),
    ).rejects.toMatchObject({ code: git.status, stderr: git.stderr });
    expect(existsSync(stateDirectory)).toBe(false);
  });

  test.each(["checkout", "plain", "plain-with-head-directory"])(
    "repository matching ignores Git executables in a separate %s caller directory",
    async (kind) => {
      const { root, repository, stateDirectory, environment } = await fixture({
        remote: "https://github.com/example/project",
      });
      const caller = join(root, "caller");
      const callerDirectory = join(caller, "src");
      const callerBin =
        kind === "checkout"
          ? join(caller, "tools")
          : join(callerDirectory, "node_modules", ".bin");
      const marker = join(root, "caller-git-executed");
      await Promise.all([
        mkdir(callerDirectory, { recursive: true }),
        mkdir(callerBin, { recursive: true }),
      ]);
      if (kind === "checkout") await mkdir(join(caller, ".git"));
      if (kind === "plain-with-head-directory")
        for (const name of ["HEAD", "objects", "refs"])
          await mkdir(join(callerDirectory, name));
      await writeFile(
        join(callerBin, process.platform === "win32" ? "git.exe" : "git"),
        process.platform === "win32"
          ? "untrusted executable fixture\n"
          : '#!/bin/sh\nprintf executed > "$TEST_LOCAL_IMPORT_GIT_MARKER"\nexit 1\n',
        { mode: 0o700 },
      );
      const inheritedPath = Object.entries(environment).find(
        ([name]) => name.toUpperCase() === "PATH",
      )?.[1];
      const module = new URL(
        "../src/external-findings-local.ts",
        import.meta.url,
      ).href;
      const script = `
      import { rejects } from "node:assert/strict";
      const { prepareNormalizedLocalImport } = await import(${JSON.stringify(module)});
      const input = { read: 0, findings: [], excluded: [] };
      const options = ${JSON.stringify({ repository, ...source })};
      await prepareNormalizedLocalImport(input, options, {
        sourceRepositories: [{ url: "https://github.com/example/project" }],
      });
      await rejects(
        prepareNormalizedLocalImport(input, options, {
          sourceRepositories: [{ url: "https://github.com/example/other" }],
        }),
        /does not match a configured remote/,
      );
    `;
      const result = spawnSync(process.execPath, ["-e", script], {
        cwd: callerDirectory,
        encoding: "utf8",
        env: {
          ...Object.fromEntries(
            Object.entries(environment).filter(
              ([name]) =>
                name.toUpperCase() !== "PATH" &&
                (kind === "checkout" ||
                  name.toUpperCase() !== "CODEX_SECURITY_STATE_DIR"),
            ),
          ),
          ...(kind !== "checkout"
            ? {
                HOME: callerDirectory,
                USERPROFILE: callerDirectory,
                CODEX_HOME: join(callerDirectory, ".codex"),
              }
            : {}),
          PATH: [callerBin, inheritedPath ?? ""].join(delimiter),
          TEST_LOCAL_IMPORT_GIT_MARKER: marker,
        },
      });
      expect(result.status, result.stderr).toBe(0);
      expect(existsSync(marker)).toBe(false);
      expect(existsSync(stateDirectory)).toBe(false);
      expect(existsSync(join(callerDirectory, ".codex", "state"))).toBe(false);
    },
  );

  test("matches custom GitHub Enterprise names without changing other VCS identities", async () => {
    const { repository, stateDirectory, environment } = await fixture({
      remote: "git@git.example.test:example/project.git",
    });
    const data = input();
    data.findings[0]!.evidence.details = {
      kind: "sast",
      repository: { url: "https://git.example.test/Example/Project" },
    };
    const options = { repository, ...source, provider: "github" as const };
    const dependencies = {
      environment,
      sourceRepositories: [{ url: "https://git.example.test/EXAMPLE/PROJECT" }],
    };
    const prepared = await prepareNormalizedLocalImport(
      data,
      options,
      dependencies,
    );
    expect(prepared.preview.findings).toEqual(data.findings);
    await expect(
      prepareNormalizedLocalImport(
        data,
        { ...options, provider: "semgrep" },
        dependencies,
      ),
    ).rejects.toThrow("does not match a configured remote");
    for (const url of [
      "https://git.example.test/example/other",
      "https://other.example.test/example/project",
      "http://git.example.test/example/project",
      "https://git.example.test:8443/example/project",
    ]) {
      data.findings[0]!.evidence.details.repository!.url = url;
      await expect(
        prepareNormalizedLocalImport(data, options, dependencies),
      ).rejects.toThrow("does not match a configured remote");
    }
    expect(existsSync(stateDirectory)).toBe(false);
  });

  test.each([
    "https://git.example.test/Example/Project",
    "https://git.example.test/example/project",
    "https://git.example.test/example/project.git/",
    "HTTPS://GIT.EXAMPLE.TEST/example/project",
    "https://%67it.example.test/example/project",
    "https://git.example.test/other/../example/project",
    "https://git.example.test:443/example/project",
    "git@git.example.test:example/project.git",
    "ssh://git@git.example.test:22/example/project.git",
    "git://git.example.test:9418/example/project.git",
  ])("retains reader-provided GitHub identity from %s", async (metadataUrl) => {
    const { repository, stateDirectory, environment } = await fixture({
      remote: "git@git.example.test:example/project.git",
    });
    const data = input();
    const url = "https://git.example.test/Example/Project";
    data.findings[0]!.evidence.details = { kind: "sast", repository: { url } };
    const options = { repository, ...source, provider: "wiz" as const };
    await expect(
      prepareNormalizedLocalImport(data, options, { environment }),
    ).rejects.toThrow("does not match a configured remote");
    const dependencies = {
      environment,
      sourceRepositories: [
        {
          url: metadataUrl,
          platform: "github" as const,
          extra: { retained: true },
        },
        { url },
      ],
    };
    const originalSources = structuredClone(dependencies.sourceRepositories);
    const prepared = await prepareNormalizedLocalImport(
      data,
      options,
      dependencies,
    );
    expect(prepared.preview.findings).toEqual(data.findings);
    expect(dependencies.sourceRepositories).toEqual(originalSources);
    for (const different of [
      "https://git.example.test/example/other",
      "https://other.example.test/example/project",
      "http://git.example.test/example/project",
      "https://git.example.test:8443/example/project",
    ]) {
      await expect(
        prepareNormalizedLocalImport(data, options, {
          ...dependencies,
          sourceRepositories: [
            ...dependencies.sourceRepositories,
            { url: different, platform: "github" },
          ],
        }),
      ).rejects.toThrow("does not match a configured remote");
    }
    expect(existsSync(stateDirectory)).toBe(false);
  });

  test("does not impose Cloud field-size limits on normalized local evidence", async () => {
    const { repository, environment } = await fixture();
    const data = input();
    data.findings[0]!.evidence.description = "x".repeat(65537);
    data.findings[0]!.evidence.locations = Array.from(
      { length: 101 },
      (_, index) => ({ path: `src/file-${index}.ts` }),
    );
    const result = await (
      await prepareNormalizedLocalImport(
        data,
        { repository, ...source },
        { environment },
      )
    ).import();
    expect(
      (
        await listLocalExternalFindings(
          { repository, id: result.findings[0]!.id },
          { environment },
        )
      )[0]!.evidence,
    ).toEqual(data.findings[0]!.evidence);
  });
});

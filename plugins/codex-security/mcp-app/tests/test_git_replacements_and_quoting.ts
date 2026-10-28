import assert from "node:assert/strict";
import childProcess, { execFileSync } from "node:child_process";
import { mkdir, readFile, unlink, utimes, writeFile } from "node:fs/promises";
import { syncBuiltinESMExports } from "node:module";
import { join } from "node:path";
import { test } from "node:test";
import { pathToFileURL } from "node:url";
import { build } from "esbuild";
import { importSource } from "./import-module.ts";
import { createTemporaryDirectories } from "./support/temporary-directories.ts";

const options = {
  define: {
    "import.meta.url": JSON.stringify(
      new URL(
        "../../../../sdk/typescript/_bundled_plugin/mcp/helpers.mjs",
        import.meta.url,
      ).href,
    ),
  },
};
const { changedPaths, gitInspectionEnvironment, trustedGitExecutable } =
  await importSource("src/helpers/inventory-git.ts", options);
const { generateInventory } = await importSource(
  "src/helpers/generate-inventory.ts",
  options,
);

const configuration = () => ({
  PATH: process.env.PATH,
  SystemRoot: process.env.SystemRoot,
  GIT_CONFIG_GLOBAL: process.platform === "win32" ? "NUL" : "/dev/null",
  GIT_CONFIG_SYSTEM: process.platform === "win32" ? "NUL" : "/dev/null",
  GIT_CONFIG_NOSYSTEM: "1",
});

for (const view of [
  "default",
  "uppercase",
  "chain",
  "custom",
  "missing-original",
  "disabled",
  "disabled-empty",
  "core-false",
  "core-inline-false",
  "config-query-scope",
])
  test(`local diff preserves the ${view} native replacement view`, async () => {
    const temporary = createTemporaryDirectories(true);
    const root = await temporary.create("git-replacement-view-");
    const repo = join(root, "repository");
    const originalEnvironment = { ...process.env };
    try {
      for (const name of [
        "GIT_NO_REPLACE_OBJECTS",
        "GIT_REPLACE_REF_BASE",
        "GIT_CONFIG_PARAMETERS",
        "GIT_CONFIG_COUNT",
        "GIT_CONFIG",
        "CODEX_SECURITY_GIT_ENVIRONMENT_FILE",
      ])
        delete process.env[name];
      await mkdir(repo);
      const executable = trustedGitExecutable(repo);
      assert.ok(executable);
      const git = (...args: string[]) =>
        execFileSync(executable, ["-C", repo, ...args], { stdio: "pipe" });
      git("init", "-q");
      git("config", "user.name", "Fixture");
      git("config", "user.email", "fixture@example.test");
      git("config", "core.autocrlf", "false");
      await writeFile(join(repo, "source.py"), "value = 1\n");
      await writeFile(join(repo, "unchanged.py"), "unchanged = 1\n");
      git("add", ".");
      git("commit", "-qm", "replacement fixture");
      const original = git("rev-parse", "HEAD:source.py").toString().trim();
      const object = (contents: string) =>
        execFileSync(executable, ["-C", repo, "hash-object", "-w", "--stdin"], {
          input: contents,
        })
          .toString()
          .trim();
      const replacement = object("value = 2\n");
      if (view === "custom")
        process.env.GIT_REPLACE_REF_BASE = "refs/fixture-replacements/";
      if (view === "uppercase")
        git(
          "update-ref",
          `refs/replace/${original.toUpperCase()}`,
          replacement,
        );
      else git("replace", original, replacement);
      if (view === "chain") git("replace", replacement, object("value = 3\n"));
      else if (view === "missing-original")
        await unlink(
          join(
            repo,
            ".git",
            "objects",
            original.slice(0, 2),
            original.slice(2),
          ),
        );
      else if (view === "disabled" || view === "disabled-empty")
        process.env.GIT_NO_REPLACE_OBJECTS = view === "disabled" ? "1" : "";
      else if (view === "core-false")
        git("config", "core.useReplaceRefs", "false");
      else if (view === "core-inline-false")
        process.env.GIT_CONFIG_PARAMETERS = "'core.useReplaceRefs=false'";
      else if (view === "config-query-scope") {
        const config = join(root, "command-only-config");
        await writeFile(config, "[core]\nuseReplaceRefs = false\n");
        process.env.GIT_CONFIG = config;
      }
      for (const name of ["source.py", "unchanged.py"])
        await utimes(join(repo, name), 1, 1);
      const before = await readFile(join(repo, ".git/index"));
      const expected = ![
        "disabled",
        "disabled-empty",
        "core-false",
        "core-inline-false",
      ].includes(view);
      assert.equal(
        Boolean(
          git(
            "-c",
            "diff.autoRefreshIndex=false",
            "diff",
            "--no-ext-diff",
            "--no-textconv",
            "HEAD",
          ).length,
        ),
        expected,
      );
      assert.deepEqual(
        await changedPaths(repo, "HEAD", "HEAD", "local-patch"),
        expected ? [{ path: "source.py", status: "M" }] : [],
      );
      for (const command of [
        "generate-in-scope-files",
        "make-diff-rank-input",
      ]) {
        const out = join(root, command);
        assert.equal(
          await generateInventory(command, {
            repo,
            out,
            base: "HEAD",
            head: "HEAD",
            mode: "local-patch",
          }),
          Number(expected),
        );
        const rows = (await readFile(out, "utf8"))
          .trim()
          .split("\n")
          .filter(Boolean);
        assert.deepEqual(
          command === "generate-in-scope-files"
            ? rows
            : rows.map((row) => JSON.parse(row).path),
          expected ? ["source.py"] : [],
        );
      }
      assert.deepEqual(await readFile(join(repo, ".git/index")), before);
    } finally {
      for (const name of Object.keys(process.env)) delete process.env[name];
      Object.assign(process.env, originalEnvironment);
      await temporary.cleanup();
    }
  });

for (const contract of [
  { code: "E2BIG" },
  { code: "ENAMETOOLONG" },
  { code: "WINDOWS_PROCESS_ERROR", errno: 206 },
])
  test(`Git parameter quoting retries native ${contract.code}`, async () => {
    const temporary = createTemporaryDirectories(true);
    const root = await temporary.create("git-quote-length-");
    const originalSpawn = childProcess.spawn;
    try {
      const executable = trustedGitExecutable(root);
      assert.ok(executable);
      const calls: number[] = [];
      childProcess.spawn = ((
        command: string,
        args: string[],
        options: childProcess.SpawnOptions,
      ) => {
        const index = args.indexOf("--sq-quote");
        if (index >= 0) {
          calls.push(args.length - index - 1);
          if (calls.length === 1)
            throw Object.assign(new Error("native quote fixture"), contract);
        }
        return originalSpawn(command, args, options);
      }) as typeof childProcess.spawn;
      syncBuiltinESMExports();
      const selected = await gitInspectionEnvironment(
        {
          ...configuration(),
          GIT_CONFIG_PARAMETERS:
            "'fixture.first=one' 'fixture.empty=' 'http.extraHeader=synthetic'",
        },
        executable,
        root,
      );
      assert.ok(calls[0]! > 1);
      assert.equal(
        calls.slice(1).reduce((sum, count) => sum + count, 0),
        calls[0],
      );
      const quoted = selected.GIT_CONFIG_PARAMETERS!;
      assert.ok(quoted.includes("'fixture.first=one'"));
      assert.ok(quoted.includes("'fixture.empty='"));
      assert.ok(
        quoted.indexOf("'fixture.first=one'") <
          quoted.indexOf("'fixture.empty='"),
      );
      assert.equal(quoted.toLowerCase().includes("http.extraheader"), false);
    } finally {
      childProcess.spawn = originalSpawn;
      syncBuiltinESMExports();
      await temporary.cleanup();
    }
  });

for (const failure of ["fatal", "other-os", "singleton"])
  test(`Git parameter quoting preserves ${failure} errors`, async () => {
    const temporary = createTemporaryDirectories(true);
    const root = await temporary.create("git-quote-failure-");
    const originalSpawn = childProcess.spawn;
    const error = Object.assign(new Error("native quote fixture"), {
      code: failure === "other-os" ? "EACCES" : "E2BIG",
    });
    const calls: number[] = [];
    try {
      const executable = trustedGitExecutable(root);
      assert.ok(executable);
      childProcess.spawn = ((
        command: string,
        args: string[],
        options: childProcess.SpawnOptions,
      ) => {
        const index = args.indexOf("--sq-quote");
        if (index < 0) return originalSpawn(command, args, options);
        calls.push(args.length - index - 1);
        if (failure === "fatal")
          return originalSpawn(
            process.execPath,
            [
              "-e",
              "process.stderr.write('native quote failure');process.exit(128)",
            ],
            options,
          );
        throw error;
      }) as typeof childProcess.spawn;
      syncBuiltinESMExports();
      await assert.rejects(
        gitInspectionEnvironment(
          {
            ...configuration(),
            GIT_CONFIG_PARAMETERS:
              "'fixture.first=one' 'http.extraHeader=synthetic'",
          },
          executable,
          root,
        ),
        (actual: unknown) =>
          failure === "fatal"
            ? actual instanceof Error &&
              actual.message === "native quote failure"
            : actual === error,
      );
      if (failure === "singleton") assert.equal(calls.at(-1), 1);
      else assert.equal(calls.length, 1);
    } finally {
      childProcess.spawn = originalSpawn;
      syncBuiltinESMExports();
      await temporary.cleanup();
    }
  });

test(
  "Git quotes native-valid parameters under the OS argv limit",
  { skip: process.platform !== "linux" },
  async () => {
    const temporary = createTemporaryDirectories(true);
    const root = await temporary.create("git-quote-native-limit-");
    try {
      const executable = trustedGitExecutable(root);
      assert.ok(executable);
      const module = join(root, "inventory.mjs");
      await build({
        entryPoints: ["src/helpers/inventory-git.ts"],
        outfile: module,
        bundle: true,
        format: "esm",
        platform: "node",
        ...options,
      });
      const runner = join(root, "run.mjs");
      await writeFile(
        runner,
        `
import assert from 'node:assert/strict';
import {execFileSync} from 'node:child_process';
import {gitInspectionEnvironment} from ${JSON.stringify(pathToFileURL(module).href)};
const environment = {...process.env, GIT_CONFIG_PARAMETERS:"'x.b' ".repeat(18000)+"'http.extraHeader=synthetic'"};
const args=['-C',process.argv[2],'config','--null','--list','--show-origin','--no-includes'];
const native=execFileSync(process.argv[3],args,{env:environment});
assert.equal(native.toString().split('\\0').filter(value=>value==='x.b').length,18000);
const projected=await gitInspectionEnvironment(environment,process.argv[3],process.argv[2]);
const actual=execFileSync(process.argv[3],args,{env:projected});
assert.equal(actual.toString().split('\\0').filter(value=>value==='x.b').length,18000);
assert.equal(actual.includes(Buffer.from('http.extraheader')),false);
environment.GIT_CONFIG_PARAMETERS="'x.b' ".repeat(17999)+"'x.b'";
assert.deepEqual(await gitInspectionEnvironment(environment,process.argv[3],process.argv[2]),environment);
`,
      );
      execFileSync(
        "/bin/sh",
        [
          "-c",
          'ulimit -s 512; exec "$@"',
          "quote-fixture",
          process.execPath,
          runner,
          root,
          executable,
        ],
        { env: configuration(), stdio: "pipe" },
      );
    } finally {
      await temporary.cleanup();
    }
  },
);

import assert from "node:assert/strict";
import { test } from "node:test";
import fs from "node:fs";
import childProcess from "node:child_process";
import { createRequire, syncBuiltinESMExports } from "node:module";
import { constants, tmpdir } from "node:os";
import { join } from "node:path";
import { importSource } from "./import-module.ts";
import type { WindowsBinding } from "../../native/windows-binding.mjs";

const helperUrl = new URL(
  "../../../../sdk/typescript/_bundled_plugin/mcp/helpers.mjs",
  import.meta.url,
);
const {
  git,
  runTool,
  changedPaths,
  decodeGitPath,
  encodeGitPath,
  gitInspectionEnvironment,
  trustedGitExecutable,
} = await importSource("src/helpers/inventory-git.ts", {
  define: { "import.meta.url": JSON.stringify(helperUrl.href) },
});

function commandFixtureSettings(output: Buffer): string[] {
  const fields = output.toString().split("\0"),
    settings: string[] = [];
  for (let index = 0; index < fields.length - 1; index += 2)
    if (
      fields[index] === "command line:" &&
      fields[index + 1]!.startsWith("fixture.")
    )
      settings.push(fields[index + 1]!);
  return settings;
}

test("Git bridge expands only in children and preserves enforced guards", async () => {
  const root = fs.mkdtempSync(join(tmpdir(), "inventory-git-bridge-"));
  const originalEnvironment = { ...process.env };
  const originalSpawn = childProcess.spawn;
  let childEnvironment: NodeJS.ProcessEnv | undefined;
  childProcess.spawn = ((...args: Parameters<typeof childProcess.spawn>) => {
    const options = args[2] as childProcess.SpawnOptions;
    childEnvironment = options.env;
    return originalSpawn(
      process.execPath,
      ["-e", "process.stdout.write('ok')"],
      options,
    );
  }) as typeof childProcess.spawn;
  syncBuiltinESMExports();
  try {
    process.env.CODEX_SECURITY_GIT = process.execPath;
    const bridge = join(root, "git-environment.json");
    fs.writeFileSync(
      bridge,
      JSON.stringify({
        GIT_CONFIG_GLOBAL: "bridge-global",
        GIT_CONFIG_SYSTEM: "bridge-system",
        GIT_CONFIG_PARAMETERS: "bridge-parameters",
        GIT_ATTR_SOURCE: "HEAD",
        GIT_REPLACE_REF_BASE: "refs/fixture-replacements/",
        GIT_DIR: "other-repository",
        HOME: "other-home",
        GIT_NO_LAZY_FETCH: "0",
        GIT_ALLOW_PROTOCOL: "all",
      }),
    );
    process.env.CODEX_SECURITY_GIT_ENVIRONMENT_FILE = bridge;
    delete process.env.GIT_CONFIG_SYSTEM;
    process.env.GIT_CONFIG_GLOBAL = "";
    process.env.GIT_CONFIG_PARAMETERS = "";
    process.env.GIT_ATTR_SOURCE = "";
    process.env.GIT_REPLACE_REF_BASE = "";
    process.env.GIT_DIR = "other-repository";
    process.env.GIT_NO_LAZY_FETCH = "0";
    process.env.GIT_ALLOW_PROTOCOL = "all";
    const before = { ...process.env };
    assert.equal((await git(root, ["status"])).status, 0);
    assert.equal(childEnvironment?.GIT_CONFIG_GLOBAL, "");
    assert.equal(childEnvironment?.GIT_CONFIG_SYSTEM, "bridge-system");
    assert.equal(childEnvironment?.GIT_CONFIG_PARAMETERS, "");
    assert.equal(childEnvironment?.GIT_ATTR_SOURCE, "");
    assert.equal(childEnvironment?.GIT_REPLACE_REF_BASE, "");
    assert.equal(childEnvironment?.GIT_DIR, undefined);
    assert.equal(childEnvironment?.HOME, before.HOME);
    assert.equal(childEnvironment?.GIT_NO_LAZY_FETCH, "1");
    assert.equal(childEnvironment?.GIT_ALLOW_PROTOCOL, "");
    assert.equal(
      childEnvironment?.CODEX_SECURITY_GIT_ENVIRONMENT_FILE,
      undefined,
    );
    assert.deepEqual({ ...process.env }, before);
  } finally {
    childProcess.spawn = originalSpawn;
    syncBuiltinESMExports();
    for (const name of Object.keys(process.env))
      if (!(name in originalEnvironment)) delete process.env[name];
    Object.assign(process.env, originalEnvironment);
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test(
  "Git bridge retains raw configuration paths in the native launch path",
  { skip: process.platform !== "linux" },
  async () => {
    const root = fs.mkdtempSync(join(tmpdir(), "inventory-git-raw-bridge-"));
    const originalEnvironment = { ...process.env };
    const config = root + "/configuration-\udcff";
    fs.writeFileSync(
      Buffer.concat([
        Buffer.from(root + "/configuration-"),
        Buffer.from([0xff]),
      ]),
      "[core]\nexcludesFile = selected-fixture\n",
    );
    try {
      for (const name of Object.keys(process.env))
        if (name.startsWith("GIT_CONFIG_")) delete process.env[name];
      delete process.env.CODEX_SECURITY_GIT;
      const bridge = join(root, "git-environment.json");
      fs.writeFileSync(
        bridge,
        JSON.stringify({
          GIT_CONFIG_GLOBAL: config,
          GIT_CONFIG_NOSYSTEM: "1",
        }),
      );
      process.env.CODEX_SECURITY_GIT_ENVIRONMENT_FILE = bridge;
      const executable = trustedGitExecutable(root) as string | undefined;
      assert.ok(executable);
      const projected = await gitInspectionEnvironment(
        process.env,
        executable,
        root,
      );
      assert.equal(projected.GIT_CONFIG_GLOBAL, config);
      const plainConfig = join(root, "configuration-plain");
      fs.writeFileSync(
        plainConfig,
        "[core]\nexcludesFile = selected-fixture\n",
      );
      const native = childProcess.spawnSync(
        executable,
        ["-C", root, "config", "--get", "core.excludesFile"],
        {
          env: {
            ...process.env,
            GIT_CONFIG_GLOBAL: plainConfig,
            GIT_CONFIG_NOSYSTEM: "1",
          },
        },
      );
      const result = await git(root, ["config", "--get", "core.excludesFile"]);
      assert.equal(result.status, native.status, result.stderr);
      assert.deepEqual(result.stdout, native.stdout);
      assert.equal(result.stderr, native.stderr.toString());
    } finally {
      for (const name of Object.keys(process.env))
        if (!(name in originalEnvironment)) delete process.env[name];
      Object.assign(process.env, originalEnvironment);
      fs.rmSync(root, { recursive: true, force: true });
    }
  },
);

test(
  "Git retains raw replacement namespaces from bridge and explicit selectors",
  { skip: process.platform !== "linux" },
  async () => {
    const root = fs.mkdtempSync(join(tmpdir(), "inventory-git-replacements-"));
    const originalEnvironment = { ...process.env };
    try {
      delete process.env.CODEX_SECURITY_GIT;
      delete process.env.CODEX_SECURITY_GIT_ENVIRONMENT_FILE;
      delete process.env.GIT_REPLACE_REF_BASE;
      delete process.env.GIT_NO_REPLACE_OBJECTS;
      assert.equal((await git(root, ["init", "-q"])).status, 0);
      const original = Buffer.from("original text\n"),
        replacement = Buffer.from("\0binary replacement\n");
      fs.writeFileSync(join(root, "original"), original);
      fs.writeFileSync(join(root, "replacement"), replacement);
      const object = async (name: string) => {
        const result = await git(root, ["hash-object", "-w", name]);
        assert.equal(result.status, 0, result.stderr);
        return result.stdout.toString().trim();
      };
      const old = await object("original"),
        updated = await object("replacement"),
        prefix = "refs/fixture-\udcff/";
      const ref = await git(root, ["update-ref", prefix + old, updated]);
      assert.equal(ref.status, 0, ref.stderr);
      const bridge = join(root, "git-environment.json");
      fs.writeFileSync(
        bridge,
        JSON.stringify({ GIT_REPLACE_REF_BASE: prefix }),
      );
      process.env.CODEX_SECURITY_GIT_ENVIRONMENT_FILE = bridge;
      const bridged = await git(root, ["cat-file", "blob", old]);
      assert.equal(bridged.status, 0, bridged.stderr);
      assert.deepEqual(bridged.stdout, replacement);
      process.env.GIT_REPLACE_REF_BASE = "refs/other/";
      const result = await git(root, ["cat-file", "blob", old]);
      assert.equal(result.status, 0, result.stderr);
      assert.deepEqual(result.stdout, original);

      // A JavaScript process.env assignment encodes lone surrogates. Launch the
      // native-env control with real POSIX bytes before the helper reads them.
      fs.writeFileSync(
        bridge,
        JSON.stringify({ GIT_REPLACE_REF_BASE: "refs/other/" }),
      );
      const probe = join(root, "raw-environment.mjs");
      fs.writeFileSync(
        probe,
        `
import { importSource } from ${JSON.stringify(new URL("./import-module.ts", import.meta.url).href)};
const { git } = await importSource("src/helpers/inventory-git.ts", {
  define: { "import.meta.url": ${JSON.stringify(JSON.stringify(helperUrl.href))} },
});
const result = await git(${JSON.stringify(root)}, ["cat-file", "blob", ${JSON.stringify(old)}]);
if (result.status !== 0) throw new Error(result.stderr);
process.stdout.write(result.stdout);
`,
      );
      const octal = [
        ...Buffer.concat([
          Buffer.from("refs/fixture-"),
          Buffer.from([0xff]),
          Buffer.from("/"),
        ]),
      ]
        .map((byte) => `\\0${byte.toString(8).padStart(3, "0")}`)
        .join("");
      const native = childProcess.spawnSync("/bin/sh", [
        "-c",
        `GIT_REPLACE_REF_BASE=$(printf '%b' '${octal}'); export GIT_REPLACE_REF_BASE; exec "$@"`,
        "raw-selector",
        process.execPath,
        "--experimental-strip-types",
        probe,
      ]);
      assert.equal(native.status, 0, native.stderr.toString());
      assert.deepEqual(native.stdout, replacement);
    } finally {
      for (const name of Object.keys(process.env))
        if (!(name in originalEnvironment)) delete process.env[name];
      Object.assign(process.env, originalEnvironment);
      fs.rmSync(root, { recursive: true, force: true });
    }
  },
);

for (const carrier of ["indexed", "parameters"])
  test(`Git filters keep behavior settings without ${carrier} header carriers`, async () => {
    const root = fs.mkdtempSync(
      join(tmpdir(), "inventory-git-filter-settings-"),
    );
    const originalEnvironment = { ...process.env };
    try {
      delete process.env.CODEX_SECURITY_GIT_ENVIRONMENT_FILE;
      for (const name of Object.keys(process.env))
        if (name.startsWith("GIT_CONFIG_")) delete process.env[name];
      const setup = async (args: string[]) => {
        const result = await git(root, args);
        assert.equal(result.status, 0, result.stderr);
      };
      await setup(["init", "-q"]);
      fs.writeFileSync(
        join(root, ".gitattributes"),
        "source.py filter=fixture\n",
      );
      fs.writeFileSync(join(root, "source.py"), "source\n");
      await setup(["add", "."]);
      await setup([
        "-c",
        "user.name=Fixture",
        "-c",
        "user.email=fixture@example.test",
        "commit",
        "-qm",
        "filter settings fixture",
      ]);
      const marker = join(root, ".git", "filter-environment.json"),
        filter = join(root, ".git", "filter.cjs");
      fs.writeFileSync(
        filter,
        `
const fs = require("node:fs");
const selected = Object.fromEntries(Object.entries(process.env).filter(([name]) => name.startsWith("GIT_CONFIG_") || name.toUpperCase().startsWith("CODEX_SECURITY_GIT_ENVIRONMENT")));
fs.writeFileSync(${JSON.stringify(marker)}, JSON.stringify(selected));
process.stdout.write(fs.readFileSync(0).toString().toLowerCase());
`,
      );
      await setup([
        "config",
        "filter.fixture.clean",
        `${JSON.stringify(process.execPath.replaceAll("\\", "/"))} ${JSON.stringify(filter.replaceAll("\\", "/"))}`,
      ]);
      const configuration =
        carrier === "indexed"
          ? {
              GIT_CONFIG_COUNT: "3",
              GIT_CONFIG_KEY_0: "fixture.keep",
              GIT_CONFIG_VALUE_0: "Authorization: retained behavior value",
              GIT_CONFIG_KEY_1: "HTTP.https://synthetic.invalid/.ExtraHeader",
              GIT_CONFIG_VALUE_1: "HEADER_ONLY_SYNTHETIC",
              GIT_CONFIG_KEY_2: "fixture.empty",
              GIT_CONFIG_VALUE_2: "",
              GIT_CONFIG_KEY_999999: "http.extraHeader",
              GIT_CONFIG_VALUE_999999: "UNUSED_HEADER_SYNTHETIC",
            }
          : {
              GIT_CONFIG_PARAMETERS:
                "'fixture.keep=Authorization: retained behavior value' 'http.extraHeader=HEADER_ONLY_SYNTHETIC' 'fixture.empty=' 'fixture.boolean'",
            };
      const executable = trustedGitExecutable(root) as string | undefined;
      assert.ok(executable);
      const native = childProcess.spawnSync(
        executable,
        [
          "-C",
          root,
          "config",
          "--null",
          "--list",
          "--show-origin",
          "--no-includes",
        ],
        { env: { ...process.env, ...configuration } },
      );
      assert.equal(native.status, 0, native.stderr.toString());
      const indexed = commandFixtureSettings(native.stdout).some(
        (row) => row === "fixture.keep\nAuthorization: retained behavior value",
      );
      const bridge = join(root, ".git", "git-environment.json");
      fs.writeFileSync(bridge, JSON.stringify(configuration));
      process.env.CODEX_SECURITY_GIT_ENVIRONMENT_FILE = bridge;
      process.env.codex_security_git_environment =
        "OLD_INLINE_HEADER_SYNTHETIC";
      fs.writeFileSync(join(root, "source.py"), "SOURCE\n");
      fs.utimesSync(join(root, "source.py"), 1, 1);
      assert.deepEqual(
        await changedPaths(root, "HEAD", "HEAD", "local-patch"),
        [],
      );
      const captured = JSON.parse(fs.readFileSync(marker, "utf8")) as Record<
        string,
        string
      >;
      assert.equal(
        Object.keys(captured).some((name) =>
          name.toUpperCase().startsWith("CODEX_SECURITY_GIT_ENVIRONMENT"),
        ),
        false,
      );
      assert.equal(
        JSON.stringify(captured).includes("HEADER_ONLY_SYNTHETIC"),
        false,
      );
      assert.equal(
        JSON.stringify(captured).includes("UNUSED_HEADER_SYNTHETIC"),
        false,
      );
      assert.equal(
        JSON.stringify(captured).includes(
          "Authorization: retained behavior value",
        ),
        true,
      );
      if (carrier === "indexed") {
        assert.equal(
          captured.GIT_CONFIG_COUNT,
          indexed ? "2" : configuration.GIT_CONFIG_COUNT,
        );
        assert.equal(captured.GIT_CONFIG_KEY_0, "fixture.keep");
        assert.equal(
          captured[`GIT_CONFIG_KEY_${indexed ? 1 : 2}`],
          "fixture.empty",
        );
        assert.equal(captured[`GIT_CONFIG_VALUE_${indexed ? 1 : 2}`], "");
      }
    } finally {
      for (const name of Object.keys(process.env))
        if (!(name in originalEnvironment)) delete process.env[name];
      Object.assign(process.env, originalEnvironment);
      fs.rmSync(root, { recursive: true, force: true });
    }
  });

test("Git projection preserves parameter order, empty values, and native failures", async () => {
  const root = fs.mkdtempSync(join(tmpdir(), "inventory-git-projection-"));
  try {
    const executable = trustedGitExecutable(root) as string | undefined;
    assert.ok(executable);
    const base: NodeJS.ProcessEnv = {
      PATH: process.env.PATH,
      SystemRoot: process.env.SystemRoot,
      GIT_CONFIG_GLOBAL: process.platform === "win32" ? "NUL" : "/dev/null",
      GIT_CONFIG_SYSTEM: process.platform === "win32" ? "NUL" : "/dev/null",
      GIT_CONFIG_NOSYSTEM: "1",
    };
    const entries = [
      "fixture.order=first",
      "fixture.empty=",
      "fixture.boolean",
      "fixture.lines=one\ntwo\n",
      "fixture.quote=it's a \\literal",
      "http.extraHeader=HEADER_ONLY_SYNTHETIC",
      "HTTP.https://synthetic.invalid/.ExtraHeader=",
      "fixture.order=last",
    ];
    const quoted = childProcess.spawnSync(
      executable,
      ["rev-parse", "--sq-quote", ...entries],
      { cwd: root, env: base },
    );
    assert.equal(quoted.status, 0, quoted.stderr.toString());
    const source = {
      ...base,
      GIT_CONFIG_COUNT: "4",
      GIT_CONFIG_KEY_0: "fixture.order",
      GIT_CONFIG_VALUE_0: "indexed-first",
      GIT_CONFIG_KEY_1: "fixture.large.first",
      GIT_CONFIG_VALUE_1: "x".repeat(
        process.platform === "win32" ? 256 : 65536,
      ),
      GIT_CONFIG_KEY_2: "http.extraHeader",
      GIT_CONFIG_VALUE_2: "INDEXED_HEADER_SYNTHETIC",
      GIT_CONFIG_KEY_3: "fixture.large.last",
      GIT_CONFIG_VALUE_3: "y".repeat(
        process.platform === "win32" ? 256 : 65536,
      ),
      GIT_CONFIG_PARAMETERS: quoted.stdout.toString().trim(),
      GIT_CONFIG: base.GIT_CONFIG_GLOBAL,
    };
    const args = [
      "config",
      "--null",
      "--list",
      "--show-origin",
      "--no-includes",
    ];
    const original = { ...source };
    delete original.GIT_CONFIG;
    const native = childProcess.spawnSync(executable, args, {
      cwd: root,
      env: original,
    });
    assert.equal(native.status, 0, native.stderr.toString());
    const nativeSettings = commandFixtureSettings(native.stdout);
    const indexed = nativeSettings.includes("fixture.order\nindexed-first");
    const selected = await gitInspectionEnvironment(source, executable, root);
    // Older Git ignores COUNT; preserve its native meaning instead of enabling it.
    assert.equal(
      selected.GIT_CONFIG_COUNT,
      indexed ? "3" : source.GIT_CONFIG_COUNT,
    );
    assert.equal(selected.GIT_CONFIG_VALUE_1, source.GIT_CONFIG_VALUE_1);
    assert.equal(
      Object.values(selected).includes("INDEXED_HEADER_SYNTHETIC"),
      false,
    );
    const inspected = { ...selected };
    delete inspected.GIT_CONFIG;
    const actual = childProcess.spawnSync(executable, args, {
      cwd: root,
      env: inspected,
    });
    assert.equal(actual.status, 0, actual.stderr.toString());
    assert.deepEqual(commandFixtureSettings(actual.stdout), nativeSettings);
    assert.equal(
      actual.stdout.includes(Buffer.from("HEADER_ONLY_SYNTHETIC")),
      false,
    );
    assert.equal(
      actual.stdout.includes(Buffer.from("INDEXED_HEADER_SYNTHETIC")),
      false,
    );
    const benign = {
      ...base,
      GIT_CONFIG_PARAMETERS: "'fixture.keep=unchanged spelling'",
    };
    assert.deepEqual(
      await gitInspectionEnvironment(benign, executable, root),
      benign,
    );
    for (const malformed of [
      { GIT_CONFIG_PARAMETERS: "'unterminated" },
      {
        GIT_CONFIG_COUNT: "bogus",
        GIT_CONFIG_KEY_0: "http.extraHeader",
        GIT_CONFIG_VALUE_0: "synthetic",
      },
      { GIT_CONFIG_COUNT: "1", GIT_CONFIG_KEY_0: "http.extraHeader" },
      {
        GIT_CONFIG_PARAMETERS: "'http.subsection\nname.extraHeader=synthetic'",
      },
      {
        GIT_CONFIG_COUNT: "1",
        GIT_CONFIG_KEY_0: "http.subsection\nname.extraHeader",
        GIT_CONFIG_VALUE_0: "synthetic",
      },
    ]) {
      const environment = { ...base, ...malformed };
      const native: childProcess.SpawnSyncReturns<Buffer> =
        childProcess.spawnSync(executable, args, {
          cwd: root,
          env: environment,
        });
      let projected: NodeJS.ProcessEnv;
      try {
        projected = await gitInspectionEnvironment(
          environment,
          executable,
          root,
        );
      } catch (error) {
        assert.notEqual(native.status, 0);
        assert.equal((error as Error).message, native.stderr.toString().trim());
        continue;
      }
      const actual: childProcess.SpawnSyncReturns<Buffer> =
        childProcess.spawnSync(executable, args, {
          cwd: root,
          env: projected,
        });
      assert.equal(actual.status, native.status);
      assert.equal(actual.stderr.toString(), native.stderr.toString());
      if (native.status === 0) assert.deepEqual(actual.stdout, native.stdout);
    }
    const noGit = await gitInspectionEnvironment(source, undefined, root);
    assert.equal(
      Object.keys(noGit).some((name) =>
        /^GIT_CONFIG_(?:COUNT|PARAMETERS|(?:KEY|VALUE)_\d+)$/u.test(name),
      ),
      false,
    );
    assert.equal(noGit.GIT_CONFIG_GLOBAL, base.GIT_CONFIG_GLOBAL);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

for (const style of ["legacy", "separate"])
  test(`Git projection preserves ${style} native parameter key boundaries`, async () => {
    const root = fs.mkdtempSync(
      join(tmpdir(), "inventory-git-parameter-keys-"),
    );
    try {
      const executable = trustedGitExecutable(root) as string | undefined;
      assert.ok(executable);
      const base: NodeJS.ProcessEnv = {
        PATH: process.env.PATH,
        SystemRoot: process.env.SystemRoot,
        GIT_CONFIG_GLOBAL: process.platform === "win32" ? "NUL" : "/dev/null",
        GIT_CONFIG_SYSTEM: process.platform === "win32" ? "NUL" : "/dev/null",
        GIT_CONFIG_NOSYSTEM: "1",
      };
      const raw = process.platform === "linux" ? "\udcff" : "雪",
        valueRaw = process.platform === "linux" ? "\udcfe" : "雪",
        subsection = style === "separate" ? "?a=b" : "plain",
        key = `url.https://example.test/${subsection}.insteadof`;
      const settings: [string, string | undefined][] = [
        ["fixture.order", "first"],
        [key, "https://other.test/"],
        [`url.https://example.test/${subsection}.boolean`, undefined],
        [`url.https://example.test/${subsection}.empty`, ""],
        [
          `url.https://raw-${raw}.test/${subsection}.insteadof`,
          `it's ! \\literal-${valueRaw}\nvalue\n`,
        ],
        [key, "https://last.test/"],
        ["http.extraHeader", "HEADER_ONLY_SYNTHETIC"],
        ["fixture.order", "last"],
      ];
      const quote = async (values: string[]): Promise<string> => {
        const result = await git(root, ["rev-parse", "--sq-quote", ...values]);
        assert.equal(result.status, 0, result.stderr);
        return decodeGitPath(result.stdout).trim();
      };
      let parameters: string;
      if (style === "legacy")
        parameters = await quote(
          settings.map(([name, value]) =>
            value === undefined ? name : `${name}=${value}`,
          ),
        );
      else {
        const pieces: string[] = [];
        for (const [name, value] of settings)
          pieces.push(
            `${await quote([name])}=${value === undefined ? "" : await quote([value])}`,
          );
        parameters = pieces.join(" ");
      }
      const large = "x".repeat(process.platform === "win32" ? 256 : 65536);
      const source: NodeJS.ProcessEnv = {
        ...base,
        GIT_CONFIG_COUNT: "2",
        GIT_CONFIG_KEY_0: "fixture.large.first",
        GIT_CONFIG_VALUE_0: large,
        GIT_CONFIG_KEY_1: "fixture.large.last",
        GIT_CONFIG_VALUE_1: large,
        GIT_CONFIG_PARAMETERS: parameters,
      };
      const args = [
        "config",
        "--null",
        "--list",
        "--show-origin",
        "--no-includes",
      ];
      const inspect = (
        environment: NodeJS.ProcessEnv,
      ): childProcess.SpawnSyncReturns<Buffer> => {
        if (process.platform === "win32")
          return childProcess.spawnSync(executable, args, {
            cwd: root,
            env: environment,
          });
        const env = { ...environment };
        delete env.GIT_CONFIG_PARAMETERS;
        const octal = [...encodeGitPath(environment.GIT_CONFIG_PARAMETERS!)]
          .map((byte: number) => `\\0${byte.toString(8).padStart(3, "0")}`)
          .join("");
        return childProcess.spawnSync(
          "/bin/sh",
          [
            "-c",
            `value=$(printf '%b.' '${octal}'); GIT_CONFIG_PARAMETERS=\${value%.}; export GIT_CONFIG_PARAMETERS; exec "$@"`,
            "parameter-fixture",
            executable,
            ...args,
          ],
          { cwd: root, env },
        );
      };
      const native: childProcess.SpawnSyncReturns<Buffer> = inspect(source);
      if (native.status !== 0) {
        assert.equal(style, "separate");
        assert.ok(
          native.stderr.includes(
            Buffer.from("bogus format in GIT_CONFIG_PARAMETERS"),
          ),
        );
        await assert.rejects(
          gitInspectionEnvironment(source, executable, root),
          (error: Error) => error.message === native.stderr.toString().trim(),
        );
        return;
      }
      const projected = await gitInspectionEnvironment(
        source,
        executable,
        root,
      );
      const actual: childProcess.SpawnSyncReturns<Buffer> = inspect(projected);
      assert.equal(actual.status, 0, actual.stderr.toString());
      assert.equal(
        actual.stdout.includes(Buffer.from("HEADER_ONLY_SYNTHETIC")),
        false,
      );
      assert.equal(projected.GIT_CONFIG_VALUE_0, large);
      assert.equal(projected.GIT_CONFIG_VALUE_1, large);
      const userSettings = (output: Buffer): string[] => {
        const fields = decodeGitPath(output).split("\0"),
          rows: string[] = [];
        for (let index = 0; index < fields.length - 1; index += 2)
          if (
            fields[index] === "command line:" &&
            /^(?:fixture|url)\./u.test(fields[index + 1]!)
          )
            rows.push(fields[index + 1]!);
        return rows;
      };
      assert.deepEqual(
        userSettings(actual.stdout),
        userSettings(native.stdout),
      );
    } finally {
      fs.rmSync(root, { recursive: true, force: true });
    }
  });

test("Git projection handles native HTTP subsection separators", async () => {
  const root = fs.mkdtempSync(join(tmpdir(), "inventory-git-header-keys-"));
  try {
    const executable = trustedGitExecutable(root) as string | undefined;
    assert.ok(executable);
    const base: NodeJS.ProcessEnv = {
      PATH: process.env.PATH,
      SystemRoot: process.env.SystemRoot,
      GIT_CONFIG_GLOBAL: process.platform === "win32" ? "NUL" : "/dev/null",
      GIT_CONFIG_SYSTEM: process.platform === "win32" ? "NUL" : "/dev/null",
      GIT_CONFIG_NOSYSTEM: "1",
    };
    const args = [
      "config",
      "--null",
      "--list",
      "--show-origin",
      "--no-includes",
    ];
    for (const separator of ["\r", "\u2028", "\u2029"])
      for (const carrier of ["indexed", "parameters"]) {
        const key = `http.https://synthetic.invalid/${separator}.extraHeader`,
          benign = `Authorization: retained${separator}behavior`;
        let source: NodeJS.ProcessEnv;
        if (carrier === "indexed")
          source = {
            ...base,
            GIT_CONFIG_COUNT: "2",
            GIT_CONFIG_KEY_0: key,
            GIT_CONFIG_VALUE_0: "HEADER_ONLY_SYNTHETIC",
            GIT_CONFIG_KEY_1: "fixture.keep",
            GIT_CONFIG_VALUE_1: benign,
          };
        else {
          const quoted: childProcess.SpawnSyncReturns<Buffer> =
            childProcess.spawnSync(
              executable,
              [
                "rev-parse",
                "--sq-quote",
                `${key}=HEADER_ONLY_SYNTHETIC`,
                `fixture.keep=${benign}`,
              ],
              { cwd: root, env: base },
            );
          assert.equal(quoted.status, 0, quoted.stderr.toString());
          source = {
            ...base,
            GIT_CONFIG_PARAMETERS: quoted.stdout.toString().trim(),
          };
        }
        const native: childProcess.SpawnSyncReturns<Buffer> =
          childProcess.spawnSync(executable, args, {
            cwd: root,
            env: source,
          });
        assert.equal(native.status, 0, native.stderr.toString());
        const active = native.stdout.includes(
          Buffer.from("HEADER_ONLY_SYNTHETIC"),
        );
        const projected: NodeJS.ProcessEnv = await gitInspectionEnvironment(
          source,
          executable,
          root,
        );
        const actual: childProcess.SpawnSyncReturns<Buffer> =
          childProcess.spawnSync(executable, args, {
            cwd: root,
            env: projected,
          });
        assert.equal(actual.status, 0, actual.stderr.toString());
        assert.equal(
          actual.stdout.includes(Buffer.from("HEADER_ONLY_SYNTHETIC")),
          false,
        );
        assert.deepEqual(
          commandFixtureSettings(actual.stdout),
          commandFixtureSettings(native.stdout),
        );
        assert.equal(
          Object.values(projected).some((value) =>
            value?.includes("HEADER_ONLY_SYNTHETIC"),
          ),
          false,
        );
        assert.ok(
          Object.values(projected).some((value) => value?.includes(benign)),
        );
        if (carrier === "indexed")
          assert.equal(
            projected.GIT_CONFIG_COUNT,
            active ? "1" : source.GIT_CONFIG_COUNT,
          );
      }
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("Git configuration inspection cancels a blocked selected executable", async () => {
  const root = fs.mkdtempSync(join(tmpdir(), "inventory-git-cancellation-"));
  const originalSpawn = childProcess.spawn;
  const controller = new AbortController();
  let child: childProcess.ChildProcess | undefined;
  let childSignal: AbortSignal | null | undefined;
  let closed: Promise<void> | undefined;
  let readyResolve!: () => void;
  const ready = new Promise<void>((resolve) => {
    readyResolve = resolve;
  });
  childProcess.spawn = ((...args: Parameters<typeof childProcess.spawn>) => {
    const options = args[2] as childProcess.SpawnOptions;
    childSignal = options.signal;
    child = originalSpawn(
      process.execPath,
      ["-e", "process.stdout.write('ready'); setInterval(() => {}, 1000);"],
      options,
    );
    child.stdout!.once("data", readyResolve);
    closed = new Promise((resolve) => {
      child!.once("close", () => resolve());
    });
    return child;
  }) as typeof childProcess.spawn;
  syncBuiltinESMExports();
  const outcome = gitInspectionEnvironment(
    { GIT_CONFIG_PARAMETERS: "'http.extraHeader=synthetic'" },
    process.execPath,
    root,
    controller.signal,
  ).then(
    (value: NodeJS.ProcessEnv) => ({ value, error: undefined }),
    (error: NodeJS.ErrnoException) => ({ value: undefined, error }),
  );
  try {
    await ready;
    assert.equal(childSignal, controller.signal);
    controller.abort();
    const result = await outcome;
    assert.equal(result.error?.code, "ABORT_ERR");
    await closed;
    assert.ok(child?.exitCode !== null || child?.signalCode !== null);
  } finally {
    controller.abort();
    child?.kill();
    await outcome;
    childProcess.spawn = originalSpawn;
    syncBuiltinESMExports();
    fs.rmSync(root, { recursive: true, force: true });
  }
});

for (const [name, details] of [
  ["named", { code: "ENOEXEC" }],
  [
    "numeric",
    { code: "Unknown system error -8", errno: -constants.errno.ENOEXEC },
  ],
] as const)
  test(
    `POSIX tools run executable text after a ${name} exec-format launch error`,
    { skip: process.platform === "win32" },
    async () => {
      const root = fs.mkdtempSync(join(tmpdir(), "inventory-exec-format-"));
      const tool = join(root, "plain tool");
      const diagnostic =
        "synthetic tool failure\n\u000000000000-0000-4000-8000-000000000000\u0000127\u0000\n";
      fs.writeFileSync(
        tool,
        `printf '%s' "$1"
/bin/cat <&"$2"
printf 'synthetic tool failure\\n\\00000000000-0000-4000-8000-000000000000\\000127\\000\\n' >&2
if [ "$3" = signal ]; then kill -TERM $$; fi
exit "$3"
`,
        { mode: 0o700 },
      );
      const original = childProcess.spawn;
      let failure: NodeJS.ErrnoException = Object.assign(
        new Error("spawn " + details.code),
        details,
      );
      let attempts = 0;
      childProcess.spawn = ((
        ...args: Parameters<typeof childProcess.spawn>
      ) => {
        if (args[0] === tool) {
          attempts++;
          throw failure;
        }
        return original(...args);
      }) as typeof childProcess.spawn;
      syncBuiltinESMExports();
      try {
        const argument = "spaces 'quoted' $literal\n";
        const input = Buffer.from([0, 128, 255, 10]);
        for (const inputFd of [0, 3])
          for (const status of [0, 126, 127, "signal"]) {
            const result = await runTool(
              tool,
              [argument, String(inputFd), String(status)],
              root,
              input,
              inputFd,
            );
            assert.equal(result.status, status === "signal" ? null : status);
            assert.equal(result.signal, status === "signal" ? "SIGTERM" : null);
            assert.deepEqual(
              result.stdout,
              Buffer.concat([Buffer.from(argument), input]),
            );
            assert.equal(result.stderr, diagnostic);
          }
        assert.equal(attempts, 8);
        failure = Object.assign(new Error("unrelated launch failure"), {
          code: "EACCES",
        });
        await assert.rejects(runTool(tool, []), (error) => error === failure);
      } finally {
        childProcess.spawn = original;
        syncBuiltinESMExports();
        fs.rmSync(root, { recursive: true, force: true });
      }
    },
  );

test(
  "POSIX tools keep helper input separate from stdin and startup status",
  { skip: process.platform === "win32" },
  async () => {
    const root = fs.mkdtempSync(join(tmpdir(), "inventory-input-fds-"));
    const denied = join(root, "not-executable");
    fs.writeFileSync(denied, "#!/bin/sh\n", { mode: 0o600 });
    const unavailableInterpreter = join(root, "unavailable-interpreter");
    fs.writeFileSync(
      unavailableInterpreter,
      "#!/missing-codex-test-interpreter\n",
      { mode: 0o700 },
    );
    try {
      for (const argument of ["ordinary", "raw-\udcff"])
        for (const inputFd of [0, 3]) {
          const input = Buffer.from([0, 128, 255, 10]);
          const result = await runTool(
            process.execPath,
            [
              "-e",
              `const fs = require('node:fs');
fs.writeFileSync(1, fs.readFileSync(${inputFd}));
${inputFd === 3 ? "fs.writeFileSync(2, String(fs.readFileSync(0).length));" : ""}`,
              argument,
            ],
            undefined,
            input,
            inputFd,
          );
          assert.equal(result.status, 0, result.stderr);
          assert.deepEqual(result.stdout, input);
          assert.equal(result.stderr, inputFd === 3 ? "0" : "");
          for (const [command, code] of [
            [join(root, "missing"), "ENOENT"],
            [unavailableInterpreter, "ENOENT"],
            [denied, "EACCES"],
          ])
            await assert.rejects(
              runTool(command, [argument], undefined, input, inputFd),
              { code },
            );
          for (const status of [126, 127]) {
            const launched = await runTool(
              process.execPath,
              ["-e", `process.exit(${status})`, argument],
              undefined,
              input,
              inputFd,
            );
            assert.equal(launched.status, status);
          }
          const statusFd = inputFd === 3 ? 4 : 3;
          const descendant = await runTool(
            "/bin/sh",
            [
              "-c",
              `/bin/sh -c 'if ( : >&${statusFd} ) 2>/dev/null; then printf inherited; else printf closed; fi'`,
              "inventory-fixture",
              argument,
            ],
            undefined,
            input,
            inputFd,
          );
          assert.equal(descendant.status, 0, descendant.stderr);
          assert.equal(descendant.stdout.toString(), "closed");
        }
    } finally {
      fs.rmSync(root, { recursive: true, force: true });
    }
  },
);

test(
  "POSIX tools retain loader settings across the raw argument shell bridge",
  { skip: process.platform === "win32" },
  async () => {
    const names = ["LD_LIBRARY_PATH", "DYLD_LIBRARY_PATH"];
    const saved = names.map((name) => [name, process.env[name]] as const);
    try {
      for (const name of names) process.env[name] = "/fixture/libraries";
      for (const argument of ["ordinary", "raw-\udcff"]) {
        const result = await runTool(process.execPath, [
          "-e",
          `process.stdout.write(JSON.stringify(${JSON.stringify(names)}.map(name => process.env[name])));`,
          argument,
        ]);
        assert.equal(result.status, 0, result.stderr);
        assert.equal(result.stderr, "");
        assert.deepEqual(JSON.parse(result.stdout.toString()), [
          "/fixture/libraries",
          "/fixture/libraries",
        ]);
        for (const name of names)
          assert.equal(process.env[name], "/fixture/libraries");
      }
    } finally {
      for (const [name, value] of saved) {
        if (value === undefined) delete process.env[name];
        else process.env[name] = value;
      }
    }
  },
);

const { windowsFileSystem } = (await importSource(
  "../native/windows-files.mts",
)) as typeof import("../../native/windows-files.mjs");

test(
  "Windows inventory honors an explicit Git .com executable beside a .com.exe sibling",
  { skip: process.platform !== "win32" },
  async () => {
    const binary = createRequire(helperUrl).resolve(
      `./native/win32-${process.arch}/windows.node`,
    );
    const root = fs.mkdtempSync(join(tmpdir(), "inventory-git-com-"));
    const repo = join(root, "repository with spaces");
    const tools = join(root, "trusted tools");
    const preload = join(root, "probe.cjs");
    const callerCwd = process.cwd();
    const names = [
      "CODEX_SECURITY_GIT",
      "NODE_OPTIONS",
      "INVENTORY_PROCESS_FIXTURE",
    ];
    const saved = names.map((name) => [name, process.env[name]] as const);
    try {
      fs.mkdirSync(repo);
      fs.mkdirSync(tools);
      // Preloads run before Node handles Git's -c arguments as syntax checking.
      fs.writeFileSync(
        preload,
        `const fs = require('node:fs');
const native = require(${JSON.stringify(binary)});
fs.writeFileSync(1, fs.readFileSync(0));
fs.writeFileSync(2, JSON.stringify({
  executable: process.execPath,
  args: native.windowsArguments().slice(1).map(value => value.toString('utf16le')),
  cwd: process.cwd(),
  setting: process.env.INVENTORY_PROCESS_FIXTURE,
}));
process.exit(23);
`,
      );
      process.env.NODE_OPTIONS = `--require ${JSON.stringify(preload.replaceAll("\\", "/"))}`;
      process.env.INVENTORY_PROCESS_FIXTURE = "configured target";
      for (const basename of ["git.com", ".COM"]) {
        const executable = join(tools, basename);
        fs.copyFileSync(process.execPath, executable);
        fs.copyFileSync(process.execPath, `${executable}.exe`);
        process.env.CODEX_SECURITY_GIT = executable;
        for (const argument of ["ordinary", "raw-\ud800\ttab"]) {
          const args = ["--fixture", argument];
          const result = await git(repo, args);
          assert.equal(result.status, 23, result.stderr);
          assert.equal(result.signal, null);
          assert.deepEqual(result.stdout, Buffer.alloc(0));
          assert.deepEqual(JSON.parse(result.stderr), {
            executable,
            args: [
              "-c",
              "core.fsmonitor=false",
              "-c",
              "i18n.logOutputEncoding=UTF-8",
              "-C",
              repo,
              ...args,
            ],
            cwd: callerCwd,
            setting: "configured target",
          });

          const input = Buffer.from([0, 128, 255, 10]);
          const toolArgs = ["-e", "", argument];
          const tool = await runTool(executable, toolArgs, repo, input);
          assert.equal(tool.status, 23, tool.stderr);
          assert.equal(tool.signal, null);
          assert.deepEqual(tool.stdout, input);
          assert.deepEqual(JSON.parse(tool.stderr), {
            executable,
            args: toolArgs,
            cwd: repo,
            setting: "configured target",
          });
          assert.equal(process.cwd(), callerCwd);
        }
      }
    } finally {
      for (const [name, value] of saved) {
        if (value === undefined) delete process.env[name];
        else process.env[name] = value;
      }
      fs.rmSync(root, { recursive: true, force: true });
    }
  },
);

test(
  "Windows tools preserve PATH selection and resolve relative PATH and cwd-only executables",
  { skip: process.platform !== "win32" },
  async () => {
    const root = fs.mkdtempSync(join(tmpdir(), "inventory-relative-path-"));
    const repo = join(root, "repo");
    const tools = join(repo, "tools");
    const shim = join(root, "shim");
    const callerCwd = process.cwd();
    const originalExecutable = process.execPath;
    const names = [
      "PATH",
      "INVENTORY_PROCESS_FIXTURE",
      "NoDefaultCurrentDirectoryInExePath",
    ];
    const saved = names.map((name) => [name, process.env[name]] as const);
    try {
      fs.mkdirSync(tools, { recursive: true });
      fs.copyFileSync(process.execPath, join(tools, "rg.exe"));
      fs.mkdirSync(shim);
      fs.copyFileSync(process.execPath, join(shim, "node.exe"));
      fs.copyFileSync(process.execPath, join(shim, "rg.exe"));
      process.env.INVENTORY_PROCESS_FIXTURE = "target setting";
      delete process.env.NoDefaultCurrentDirectoryInExePath;
      for (const location of ["relative PATH", "PATH collision", "cwd only"]) {
        process.env.PATH = location === "relative PATH" ? "tools" : tools;
        process.execPath =
          location === "PATH collision"
            ? join(shim, "node.exe")
            : originalExecutable;
        if (location === "cwd only")
          fs.renameSync(join(tools, "rg.exe"), join(repo, "rg.exe"));
        for (const argument of ["ordinary", "raw-\ud800"]) {
          const result = await runTool(
            "rg",
            [
              "-e",
              "process.stdout.write(JSON.stringify({executable:process.execPath,cwd:process.cwd(),setting:process.env.INVENTORY_PROCESS_FIXTURE}));",
              argument,
            ],
            repo,
          );
          assert.equal(result.status, 0, result.stderr);
          assert.deepEqual(JSON.parse(result.stdout.toString()), {
            executable: join(location === "cwd only" ? repo : tools, "rg.exe"),
            cwd: repo,
            setting: "target setting",
          });
          assert.equal(result.stderr, "");
          assert.equal(process.cwd(), callerCwd);
        }
      }
    } finally {
      process.execPath = originalExecutable;
      for (const [name, value] of saved) {
        if (value === undefined) delete process.env[name];
        else process.env[name] = value;
      }
      fs.rmSync(root, { recursive: true, force: true });
    }
  },
);

for (const platform of ["linux", "win32"]) {
  test(`Git paths retain platform byte encoding on ${platform}`, async () => {
    const { decodeGitPath, encodeGitPath } = await importSource(
      "src/helpers/inventory-git.ts",
      {
        define: {
          "process.platform": JSON.stringify(platform),
          "import.meta.url": JSON.stringify(helperUrl.href),
        },
      },
    );
    const bytes = Buffer.concat([
      Buffer.from("résumé/😀/high-"),
      Buffer.from([0xed, 0xa0, 0x80]),
      Buffer.from("/low-"),
      Buffer.from([0xed, 0xbf, 0xbf]),
      Buffer.from("\0ordinary\0"),
    ]);
    const text =
      platform === "win32"
        ? "résumé/😀/high-\ud800/low-\udfff\0ordinary\0"
        : "résumé/😀/high-\udced\udca0\udc80/low-\udced\udcbf\udcbf\0ordinary\0";
    assert.equal(decodeGitPath(bytes), text);
    assert.deepEqual(encodeGitPath(text), bytes);
  });
}

const { sampleFile, createSourceSampler, PREVIEW_READ_BYTES } =
  await importSource("src/helpers/source-preview.ts", {
    define: {
      "import.meta.url": JSON.stringify(helperUrl.href),
    },
  });

for (const [name, reparseTag, surrogate] of [
  ["cloud directory", 0x9000001a, false],
  ["directory junction", 0xa0000003, true],
  ["symbolic link", 0xa000000c, true],
] as const)
  test(`Windows metadata identifies ${name} without treating every reparse point as a link`, () => {
    const binding = {
      windowsAbsolutePath: (value: Buffer) => ({ error: 0, value }),
      openWindowsFile: () => ({
        error: 0,
        handle: {
          attributes: () => ({ error: 0, attributes: 0x410, reparseTag }),
          fileType: () => ({ error: 0, value: 1 }),
          close: () => 0,
        },
      }),
    } as unknown as WindowsBinding;
    const info = windowsFileSystem(binding).stat(
      Buffer.from("C:\\fixture", "utf16le"),
      false,
    );
    assert.equal(info.isReparsePoint(), true);
    assert.equal(info.isNameSurrogate(), surrogate);
    if (!surrogate) assert.equal(info.isDirectory(), true);
  });

test("POSIX file identities retain all 64 inode bits", async () => {
  const original = fs.statSync;
  fs.statSync = ((path, options) => {
    if (!["left", "right"].includes(String(path)))
      return original(path, options);
    const ino = String(path) === "left" ? 9007199254740992n : 9007199254740993n;
    return options?.bigint ? { dev: 1n, ino } : { dev: 1, ino: Number(ino) };
  }) as typeof fs.statSync;
  syncBuiltinESMExports();
  try {
    const { sameFile } = await importSource("src/helpers/inventory-paths.ts", {
      define: {
        "process.platform": '"linux"',
        "import.meta.url": JSON.stringify(helperUrl.href),
      },
    });
    assert.equal(sameFile("left", "right"), false);
    assert.equal(sameFile("left", "left"), true);
  } finally {
    fs.statSync = original;
    syncBuiltinESMExports();
  }
});

test(
  "short file reads preserve the complete preview prefix and UTF-16 units",
  { skip: process.platform === "win32" },
  () => {
    const root = fs.mkdtempSync(join(tmpdir(), "inventory-short-read-"));
    const file = join(root, "source");
    const original = fs.readSync;
    let calls = 0;
    fs.readSync = ((descriptor, buffer, offset, length, position) =>
      original(
        descriptor,
        buffer,
        offset,
        Math.min(length, [1, 3, 5, 4096][calls++ % 4]!),
        position,
      )) as typeof fs.readSync;
    syncBuiltinESMExports();
    try {
      const utf16 = Buffer.concat([
        Buffer.from([0xff, 0xfe]),
        Buffer.from("Ā source\n".repeat(8000), "utf16le"),
      ]);
      for (const data of [
        Buffer.alloc(0),
        Buffer.from([0xff]),
        Buffer.from([0xff, 0xfe]),
        Buffer.from([0xff, 0xfe, 0]),
        Buffer.from([0xfe, 0xff, 0]),
        Buffer.from("source\n".repeat(12000)),
        utf16,
        Buffer.from(utf16).swap16(),
      ]) {
        fs.writeFileSync(file, data);
        calls = 0;
        const [sample, binary] = sampleFile(file);
        assert.equal(binary, false);
        assert.deepEqual(sample, data.subarray(0, PREVIEW_READ_BYTES));
        fs.writeFileSync(file, Buffer.concat([data, Buffer.from([0, 0])]));
        calls = 0;
        assert.equal(sampleFile(file)[1], true);
      }
    } finally {
      fs.readSync = original;
      syncBuiltinESMExports();
      fs.rmSync(root, { recursive: true, force: true });
    }
  },
);

test("Windows short file reads preserve previews across split BOMs and units", () => {
  const text = Buffer.concat([
    Buffer.from([0xff, 0xfe]),
    Buffer.from("Ā source\n".repeat(8000), "utf16le"),
  ]);
  for (const source of [Buffer.alloc(0), Buffer.from([0xff, 0xfe, 0]), text])
    for (const binary of [false, true]) {
      const data = binary
        ? Buffer.concat([source, Buffer.from([0, 0])])
        : source;
      let cursor = 0,
        calls = 0,
        closes = 0;
      const native = {
        windowsAbsolutePath: (value: Buffer) => ({ error: 0, value }),
        openWindowsFile: () => ({
          error: 0,
          handle: {
            read: (buffer: Buffer, offset: number, length: number) => {
              const count = Math.min(
                length,
                data.length - cursor,
                [1, 3, 5, 4096][calls++ % 4]!,
              );
              data.copy(buffer, offset, cursor, cursor + count);
              cursor += count;
              return { error: 0, value: count };
            },
            close: () => {
              closes++;
              return 0;
            },
          },
        }),
      } as unknown as WindowsBinding;
      const sampler = createSourceSampler();
      assert.equal(sampler.consume(Buffer.alloc(0)), true);
      windowsFileSystem(native).readChunks(
        Buffer.from("C:\\fixture", "utf16le"),
        sampler.consume,
      );
      assert.deepEqual(sampler.finish(), [
        binary ? Buffer.alloc(0) : source.subarray(0, PREVIEW_READ_BYTES),
        binary,
      ]);
      assert.equal(closes, 1);
    }
});

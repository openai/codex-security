import { spawnSync } from "node:child_process";
import { access, mkdir, readFile, stat, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import type { CodexOptions } from "@openai/codex-sdk";
import { afterEach, expect, test } from "bun:test";
import { parse as parseToml } from "smol-toml";
import { DiffTarget } from "../src/index.js";
import {
  pluginExecutionEnvironment,
  gitConfigurationEnvironment,
  gitInspectionEnvironment,
  type WorkbenchCommandOptions,
} from "../src/runtime.js";
import { git } from "./git-fixture.js";
import { PLUGIN_ROOT } from "./plugin-root.js";
import { mockWorkbench, TestClient } from "./support/api-client.js";
import {
  preparedRuntime,
  scanRuntimeDependencies,
} from "./support/api-events.js";
import { runNodePython } from "./support/python-probe.js";
import { pythonExecutable, nodeCommand } from "./support/shell.js";
import { createApiTestFixtures } from "./support/temporary-directories.js";

const { cleanup, temporaryDirectory } = createApiTestFixtures();
afterEach(cleanup);

test("Git snapshots match Windows child environment alias precedence", () => {
  const platform = Object.getOwnPropertyDescriptor(process, "platform")!;
  const cases: {
    environment: NodeJS.ProcessEnv;
    expected: Record<string, string>;
  }[] = [
    {
      environment: { git_config_global: "lower", GIT_CONFIG_GLOBAL: "upper" },
      expected: { GIT_CONFIG_GLOBAL: "upper" },
    },
    {
      environment: { git_config_global: "lower", GIT_CONFIG_GLOBAL: "" },
      expected: { GIT_CONFIG_GLOBAL: "" },
    },
    {
      environment: { git_config_global: "lower", GIT_CONFIG_GLOBAL: undefined },
      expected: {},
    },
    {
      environment: { git_config_global: undefined, GIT_CONFIG_GLOBAL: "upper" },
      expected: { GIT_CONFIG_GLOBAL: "upper" },
    },
  ];
  let selected: Record<string, string>[];
  try {
    Object.defineProperty(process, "platform", { value: "win32" });
    selected = cases.map(({ environment }) =>
      gitConfigurationEnvironment(environment),
    );
  } finally {
    Object.defineProperty(process, "platform", platform);
  }
  expect(selected).toEqual(cases.map(({ expected }) => expected));
});

test.each(["standard", "deep"] as const)(
  "%s scan forwards selected Git configuration to its MCP helpers",
  async (mode) => {
    const root = await temporaryDirectory();
    const repository = join(root, "repository");
    const codexHome = join(root, "codex-home");
    await mkdir(repository);
    await mkdir(codexHome);
    git(repository, "init", "-q");
    await writeFile(join(repository, "old.py"), "value = 1\n");
    git(repository, "add", ".");
    git(repository, "commit", "-qm", "base");
    const base = git(repository, "rev-parse", "HEAD");
    git(repository, "mv", "old.py", "new.py");
    git(repository, "commit", "-qm", "rename");
    const head = git(repository, "rev-parse", "HEAD");
    const configFile = join(root, "operator.gitconfig");
    await writeFile(configFile, "[diff]\nrenames = false\n");
    const cases = [
      { environment: { GIT_CONFIG_GLOBAL: configFile }, count: 2 },
      {
        environment: {
          GIT_CONFIG_COUNT: "2",
          GIT_CONFIG_KEY_0: "fixture.first",
          GIT_CONFIG_VALUE_0: "a".repeat(65_536),
          GIT_CONFIG_KEY_1: "fixture.second",
          GIT_CONFIG_VALUE_1: "b".repeat(65_536),
          GIT_ATTR_NOSYSTEM: "1",
          GIT_NO_REPLACE_OBJECTS: "1",
        },
        count: 1,
      },
      {
        environment: {
          GIT_CONFIG_GLOBAL: configFile,
          GIT_CONFIG_COUNT: "1",
          GIT_CONFIG_KEY_0: "diff.renames",
          GIT_CONFIG_VALUE_0: "true",
          // Git ignores unused indexes; forwarding their names has no wrapper cap.
          GIT_CONFIG_KEY_1234567: "synthetic.unused",
          GIT_CONFIG_VALUE_1234567: "fixture value",
        },
        count: 1,
      },
      {
        environment: {
          GIT_CONFIG_GLOBAL: configFile,
          GIT_CONFIG_PARAMETERS: "'diff.renames=true'",
        },
        count: 1,
      },
      {
        environment: {
          GIT_CONFIG_COUNT: "3",
          GIT_CONFIG_KEY_0: "http.extraHeader",
          GIT_CONFIG_VALUE_0: "synthetic-private-indexed-header",
          GIT_CONFIG_KEY_1: "diff.renames",
          GIT_CONFIG_VALUE_1: "true",
          GIT_CONFIG_KEY_2: "http.https://example.test/.extraHeader",
          GIT_CONFIG_VALUE_2: "synthetic-private-url-header",
          GIT_CONFIG_KEY_1234567: "http.extraHeader",
          GIT_CONFIG_VALUE_1234567: "synthetic-private-unused-header",
          GIT_CONFIG_PARAMETERS:
            "'http.extraHeader=synthetic-private-parameter-header' 'diff.renames=false' 'fixture.empty='",
        },
        protectedHeaders: true,
        count: 2,
      },
      {
        environment: {
          GIT_CONFIG_COUNT: "4",
          GIT_CONFIG_KEY_0: "http.https://example.test/\r.extraHeader",
          GIT_CONFIG_VALUE_0: "synthetic-private-cr-header",
          GIT_CONFIG_KEY_1: "diff.renames",
          GIT_CONFIG_VALUE_1: "true",
          GIT_CONFIG_KEY_2: "http.https://example.test/\u2028.extraHeader",
          GIT_CONFIG_VALUE_2: "synthetic-private-line-separator-header",
          GIT_CONFIG_KEY_3: "http.https://example.test/\u2029.extraHeader",
          GIT_CONFIG_VALUE_3: "synthetic-private-paragraph-separator-header",
        },
        protectedHeaders: true,
        count: 1,
      },
      {
        environment: {
          GIT_CONFIG_COUNT: "1",
          GIT_CONFIG_KEY_0: "diff.renames",
          GIT_CONFIG_VALUE_0: "true",
          GIT_CONFIG_PARAMETERS:
            ["\r", "\u2028", "\u2029"]
              .map(
                (separator) =>
                  `'http.https://example.test/${separator}.extraHeader=synthetic-private-parameter-header'`,
              )
              .join(" ") + " 'diff.renames=false'",
        },
        protectedHeaders: true,
        count: 2,
      },
    ];
    const python = pythonExecutable();
    expect(python).not.toBeNull();
    await Promise.all(
      cases.map(async (scenario, index) => {
        const scanDir = join(root, `scan-${index}`);
        await mkdir(scanDir, { mode: 0o700 });
        const environment = {
          PATH: process.env["PATH"],
          HOME: process.env["HOME"],
          SystemRoot: process.env["SystemRoot"],
          ...scenario.environment,
          CODEX_SECURITY_GIT_ENVIRONMENT:
            '{"GIT_CONFIG_COUNT":"invalid-stale-count"}',
          codex_security_git_environment_file: join(root, "obsolete-file.json"),
        };
        let registrationEnvironment: WorkbenchCommandOptions["environment"];
        let launch: CodexOptions | undefined;
        const client = new TestClient(
          {
            codexOverrides: {
              shell_environment_policy: { inherit: "all", exclude: ["GIT_*"] },
            },
          },
          {
            ...scanRuntimeDependencies(codexHome, scanDir),
            resolvePluginPython: async () => python!,
            environment,
            prepareRuntime: async () => {
              const runtime = preparedRuntime(codexHome);
              if (mode === "standard" && index === 0)
                delete runtime.deepScanConfigPath;
              return {
                ...runtime,
                environment: Object.fromEntries(
                  Object.entries(environment).filter(
                    (entry): entry is [string, string] =>
                      entry[1] !== undefined,
                  ),
                ),
              };
            },
            runWorkbench: async (options, args, input) => {
              if (args[0] === "register-cli-scan")
                registrationEnvironment = options.environment;
              return mockWorkbench(args, input);
            },
            canRunDirectDeepScan: () => false,
            createCodex: (options) => {
              launch = options;
              return {
                startThread: () => ({
                  id: null,
                  async runStreamed() {
                    throw new Error("scan launch captured");
                  },
                }),
              };
            },
          },
        );
        try {
          await expect(
            client.run(repository, {
              mode,
              ...(mode === "standard"
                ? { target: DiffTarget.refs({ base, head }) }
                : {}),
            }),
          ).rejects.toThrow("scan launch captured");
          expect(launch!.config!["mcp_servers"]).toBeUndefined();
          const manifest = JSON.parse(
            await readFile(join(PLUGIN_ROOT, ".mcp.json"), "utf8"),
          );
          const names: string[] =
            manifest.mcpServers["codex-security"].env_vars;
          expect(names).toContain("CODEX_SECURITY_GIT_ENVIRONMENT_FILE");
          expect(
            launch!.env!["CODEX_SECURITY_GIT_ENVIRONMENT"],
          ).toBeUndefined();
          expect(
            launch!.env!["codex_security_git_environment_file"],
          ).toBeUndefined();
          expect(
            registrationEnvironment!["CODEX_SECURITY_GIT_ENVIRONMENT"],
          ).toBeUndefined();
          expect(
            registrationEnvironment!["codex_security_git_environment_file"],
          ).toBeUndefined();
          const file = launch!.env!["CODEX_SECURITY_GIT_ENVIRONMENT_FILE"]!;
          const projected = JSON.parse(await readFile(file, "utf8"));
          if (scenario.protectedHeaders) {
            expect(projected.GIT_CONFIG_COUNT).toBe("1");
            expect(projected.GIT_CONFIG_KEY_0).toBe("diff.renames");
            expect(projected.GIT_CONFIG_VALUE_0).toBe("true");
            expect(JSON.stringify(projected)).not.toContain(
              "synthetic-private-",
            );
            expect(JSON.stringify(registrationEnvironment!)).not.toContain(
              "synthetic-private-",
            );
            expect(launch!.env).toMatchObject(scenario.environment);
          } else expect(projected).toEqual(scenario.environment);
          expect(dirname(dirname(file))).toBe(codexHome);
          const permissions = parseToml(
            launch!.configOverrides!.find((value) =>
              value.startsWith("permissions.codex_security_scan.filesystem="),
            )!,
          )["permissions"] as {
            codex_security_scan: { filesystem: Record<string, unknown> };
          };
          expect(permissions.codex_security_scan.filesystem[codexHome]).toEqual(
            { ".": "deny" },
          );
          expect(
            permissions.codex_security_scan.filesystem["undefined"],
          ).toBeUndefined();
          expect(launch!.config!["shell_environment_policy"]).toEqual({
            inherit: "all",
            exclude: ["GIT_*"],
          });
          if (process.platform !== "win32")
            expect((await stat(file)).mode & 0o777).toBe(0o600);
          // Native Codex starts local MCP servers with its core variables plus
          // env_vars and explicit env. Spawn the resulting helper environment.
          const mcpEnvironment = {
            ...Object.fromEntries(
              ["PATH", "HOME", "SystemRoot", ...names].flatMap((name) => {
                const value = launch!.env![name];
                return value === undefined ? [] : [[name, value]];
              }),
            ),
          };
          const count = runNodePython(
            python!,
            [
              "-c",
              "import pathlib,sys; sys.path.insert(0,sys.argv[1]); import workbench_target as w; print(w.diff_scope_file_count(pathlib.Path(sys.argv[2]), {'kind':'range','baseRevision':sys.argv[3],'headRevision':sys.argv[4]}))",
              join(PLUGIN_ROOT, "scripts"),
              repository,
              base,
              head,
            ],
            { env: registrationEnvironment! },
          );
          expect(count.status, count.stderr).toBe(0);
          expect(Number(count.stdout.trim())).toBe(scenario.count);
          const inventory = join(root, `inventory-${index}.txt`);
          const result = spawnSync(
            nodeCommand().command,
            [
              join(PLUGIN_ROOT, "mcp", "helpers.mjs"),
              "generate-in-scope-files",
              "--repo",
              repository,
              "--scope",
              ".",
              "--diff-base",
              base,
              "--diff-head",
              head,
              "--out",
              inventory,
            ],
            { env: mcpEnvironment, encoding: "utf8" },
          );
          expect(result.status, result.stderr).toBe(0);
          const paths = (await readFile(inventory, "utf8")).trim().split("\n");
          expect(paths).toHaveLength(scenario.count);
          await expect(
            client.run(repository, {
              mode,
              ...(mode === "standard"
                ? { target: DiffTarget.refs({ base, head }) }
                : {}),
            }),
          ).rejects.toThrow("scan launch captured");
          expect(launch!.env!["CODEX_SECURITY_GIT_ENVIRONMENT_FILE"]).not.toBe(
            file,
          );
          expect(JSON.parse(await readFile(file, "utf8"))).toEqual(projected);
        } finally {
          await client.close();
          if (launch !== undefined)
            await expect(
              access(launch.env!["CODEX_SECURITY_GIT_ENVIRONMENT_FILE"]!),
            ).rejects.toThrow();
        }
      }),
    );
  },
);

test("internal Git transport aliases are replaced before each launch", () => {
  const environment: NodeJS.ProcessEnv = {
    GIT_CONFIG_GLOBAL: "selected.gitconfig",
    CODEX_SECURITY_GIT_ENVIRONMENT:
      '{"GIT_CONFIG_GLOBAL":"obsolete.gitconfig"}',
    codex_security_git_environment_file: "obsolete.json",
  };
  const result = pluginExecutionEnvironment("python", environment);
  expect(result["GIT_CONFIG_GLOBAL"]).toBe("selected.gitconfig");
  expect(result["CODEX_SECURITY_GIT_ENVIRONMENT"]).toBeUndefined();
  expect(result["codex_security_git_environment_file"]).toBeUndefined();
  expect(environment["codex_security_git_environment_file"]).toBe(
    "obsolete.json",
  );
});

test("optional Git omits unused inline config from helper settings", async () => {
  const environment = {
    PATH: "",
    GIT_CONFIG_GLOBAL: "selected.gitconfig",
    GIT_CONFIG_COUNT: "1",
    GIT_CONFIG_KEY_0: "http.extraHeader",
    GIT_CONFIG_VALUE_0: "synthetic-private-header",
    GIT_CONFIG_PARAMETERS: "'http.extraHeader=synthetic-private-parameter'",
  };
  const projected = await gitInspectionEnvironment({
    python: "unused-python",
    repository: ".",
    environment,
    git: { executable: null, environment },
  });
  expect(gitConfigurationEnvironment(projected)).toEqual({
    GIT_CONFIG_GLOBAL: "selected.gitconfig",
  });
  expect(environment.GIT_CONFIG_VALUE_0).toBe("synthetic-private-header");
});

test.skipIf(spawnSync("git", ["--attr-source=HEAD", "--version"]).status !== 0)(
  "MCP diff inventory preserves the selected Git attributes revision",
  async () => {
    const root = await temporaryDirectory();
    const repository = join(root, "repository");
    await mkdir(repository);
    git(repository, "init", "-q");
    await writeFile(join(repository, ".gitattributes"), "");
    await writeFile(join(repository, "source.py"), "alpha\n");
    git(repository, "add", ".");
    git(repository, "commit", "-qm", "base");
    const attributesRevision = git(repository, "rev-parse", "HEAD");
    const filter = join(root, "clean-filter.mjs");
    await writeFile(
      filter,
      'import { readFileSync } from "node:fs"; process.stdout.write(readFileSync(0, "utf8").toLowerCase());\n',
    );
    git(
      repository,
      "config",
      "filter.lower.clean",
      `${JSON.stringify(nodeCommand().command.replaceAll("\\", "/"))} ${JSON.stringify(filter.replaceAll("\\", "/"))}`,
    );
    await writeFile(join(repository, ".gitattributes"), "*.py filter=lower\n");
    git(repository, "add", ".gitattributes");
    git(repository, "commit", "-qm", "attributes");
    const head = git(repository, "rev-parse", "HEAD");
    await writeFile(join(repository, "source.py"), "ALPHA\n");
    // GIT_ATTR_SOURCE was introduced in Git 2.41; older supported Git keeps
    // ordinary worktree attributes, so probe the upstream feature directly.
    const attributes = spawnSync(
      "git",
      ["-C", repository, "check-attr", "filter", "--", "source.py"],
      {
        env: { ...process.env, GIT_ATTR_SOURCE: attributesRevision },
        encoding: "utf8",
      },
    );
    expect(attributes.status, attributes.stderr).toBe(0);
    expect(attributes.stdout).toContain("unspecified");
    const file = join(root, "git-environment.json");
    await writeFile(
      file,
      JSON.stringify({ GIT_ATTR_SOURCE: attributesRevision }),
      { flag: "wx", mode: 0o600 },
    );
    const environment: NodeJS.ProcessEnv = {
      ...pluginExecutionEnvironment(pythonExecutable()!, {
        PATH: process.env["PATH"],
        HOME: process.env["HOME"],
        SystemRoot: process.env["SystemRoot"],
        GIT_ATTR_SOURCE: attributesRevision,
      }),
      CODEX_SECURITY_GIT_ENVIRONMENT_FILE: file,
    };
    const manifest = JSON.parse(
      await readFile(join(PLUGIN_ROOT, ".mcp.json"), "utf8"),
    );
    const names: string[] = manifest.mcpServers["codex-security"].env_vars;
    const mcpEnvironment = Object.fromEntries(
      ["PATH", "HOME", "SystemRoot", ...names].flatMap((name) => {
        const value = environment[name];
        return value === undefined ? [] : [[name, value]];
      }),
    );
    const count = runNodePython(
      pythonExecutable()!,
      [
        "-c",
        "import pathlib,sys; sys.path.insert(0,sys.argv[1]); import workbench_target as w; print(w.diff_scope_file_count(pathlib.Path(sys.argv[2]), {'kind':'working_tree','baseRevision':sys.argv[3],'headRevision':sys.argv[3]}))",
        join(PLUGIN_ROOT, "scripts"),
        repository,
        head,
      ],
      { env: environment },
    );
    expect(count.status, count.stderr).toBe(0);
    expect(Number(count.stdout.trim())).toBe(1);
    for (const override of [undefined, head]) {
      const output = join(
        root,
        `inventory-${override === undefined ? "selected" : "override"}.txt`,
      );
      const result = spawnSync(
        nodeCommand().command,
        [
          join(PLUGIN_ROOT, "mcp", "helpers.mjs"),
          "generate-in-scope-files",
          "--repo",
          repository,
          "--scope",
          ".",
          "--diff-base",
          head,
          "--diff-mode",
          "local-patch",
          "--out",
          output,
        ],
        {
          env: {
            ...mcpEnvironment,
            ...(override === undefined ? {} : { GIT_ATTR_SOURCE: override }),
          },
          encoding: "utf8",
        },
      );
      expect(result.status, result.stderr).toBe(0);
      expect((await readFile(output, "utf8")).trim()).toBe(
        override === undefined ? "source.py" : "",
      );
    }
  },
);

test("MCP diff inventory preserves replacement-ref selection and explicit opt-out", async () => {
  const root = await temporaryDirectory();
  const repository = join(root, "repository");
  await mkdir(repository);
  git(repository, "init", "-q");
  await writeFile(join(repository, "source.py"), "before\n");
  git(repository, "add", ".");
  git(repository, "commit", "-qm", "base");
  const base = git(repository, "rev-parse", "HEAD");
  await writeFile(join(repository, "source.py"), "after\n");
  git(repository, "commit", "-qam", "head");
  const head = git(repository, "rev-parse", "HEAD");
  const headBlob = git(repository, "rev-parse", "HEAD:source.py");
  const binary = join(root, "binary");
  await writeFile(binary, "binary\0content\n");
  const binaryBlob = git(repository, "hash-object", "-w", binary);
  git(
    repository,
    "update-ref",
    `refs/fixture-replacements/${headBlob}`,
    binaryBlob,
  );
  const settings = join(root, "git-environment.json");
  await writeFile(
    settings,
    JSON.stringify({ GIT_REPLACE_REF_BASE: "refs/fixture-replacements/" }),
    { mode: 0o600, flag: "wx" },
  );
  for (const optOut of [undefined, "1"]) {
    const environment = {
      PATH: process.env["PATH"],
      HOME: process.env["HOME"],
      SystemRoot: process.env["SystemRoot"],
      CODEX_SECURITY_GIT_ENVIRONMENT_FILE: settings,
      ...(optOut === undefined ? {} : { GIT_NO_REPLACE_OBJECTS: optOut }),
    };
    const count = runNodePython(
      pythonExecutable()!,
      [
        "-c",
        "import pathlib,sys; sys.path.insert(0,sys.argv[1]); import workbench_target as w; print(w.diff_scope_file_count(pathlib.Path(sys.argv[2]), {'kind':'range','baseRevision':sys.argv[3],'headRevision':sys.argv[4]}))",
        join(PLUGIN_ROOT, "scripts"),
        repository,
        base,
        head,
      ],
      { env: environment },
    );
    expect(count.status, count.stderr).toBe(0);
    expect(Number(count.stdout.trim())).toBe(optOut === undefined ? 0 : 1);
    const output = join(root, `inventory-${optOut ?? "replacement"}.txt`);
    const inventory = spawnSync(
      nodeCommand().command,
      [
        join(PLUGIN_ROOT, "mcp", "helpers.mjs"),
        "generate-in-scope-files",
        "--repo",
        repository,
        "--scope",
        ".",
        "--diff-base",
        base,
        "--diff-head",
        head,
        "--out",
        output,
      ],
      { env: environment, encoding: "utf8" },
    );
    expect(inventory.status, inventory.stderr).toBe(0);
    expect((await readFile(output, "utf8")).trim()).toBe(
      optOut === undefined ? "" : "source.py",
    );
  }
});

test.each(["patch", "policy"] as const)(
  "%s Git configuration inspection excludes enclosing checkouts",
  async (operation) => {
    const root = await temporaryDirectory();
    const outer = join(root, "outer");
    const repository = join(outer, "inner");
    const bin = join(outer, "bin");
    const codexHome = join(root, "home");
    const output = join(root, "output");
    const marker = join(root, "repository-git-executed");
    await mkdir(repository, { recursive: true });
    await mkdir(bin);
    await mkdir(codexHome, { mode: 0o700 });
    await mkdir(output, { mode: 0o700 });
    const selectedGit = Bun.which("git")!;
    for (const checkout of [outer, repository]) git(checkout, "init", "-q");
    await writeFile(
      join(bin, process.platform === "win32" ? "git.exe" : "git"),
      process.platform === "win32"
        ? "synthetic repository executable\n"
        : `#!${nodeCommand().command}\nconst fs = require("node:fs");\nfs.writeFileSync(${JSON.stringify(marker)}, "executed");\nconst { spawnSync } = require("node:child_process");\nconst child = spawnSync(${JSON.stringify(selectedGit)}, process.argv.slice(2), {env: {...process.env, PATH: ${JSON.stringify(process.env["PATH"])}}, stdio: "inherit"});\nprocess.exit(child.status ?? 1);\n`,
      { mode: 0o700 },
    );
    const environment = {
      PATH: `${bin}${process.platform === "win32" ? ";" : ":"}${process.env["PATH"]}`,
      HOME: process.env["HOME"] ?? "",
      SystemRoot: process.env["SystemRoot"] ?? "",
      GIT_CONFIG_PARAMETERS: "'fixture.keep=true'",
    };
    const client = new TestClient(
      {},
      {
        ...scanRuntimeDependencies(codexHome, output),
        environment,
        prepareRuntime: async () => ({
          ...preparedRuntime(codexHome),
          environment,
        }),
        resolvePluginPython: async () => pythonExecutable()!,
        createCodex: () => {
          throw new Error("Codex boundary reached");
        },
      },
    );
    try {
      await expect(
        operation === "patch"
          ? client.patch({
              repositoryPath: repository,
              finding: "Synthetic candidate",
            })
          : client.generatePolicy(repository),
      ).rejects.toThrow("Codex boundary reached");
      await expect(access(marker)).rejects.toThrow();
    } finally {
      await client.close();
    }
  },
);

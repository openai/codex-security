import { createCliTest, runCapturedCli } from "./support/cli-run.js";
import { once } from "node:events";
import {
  copyFileSync,
  existsSync,
  linkSync,
  mkdirSync,
  readFileSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { join } from "node:path";
import { resolving } from "./support/promises.js";
import { describe, expect, test, mock } from "bun:test";
import {
  checkForUpdate,
  formatUpdateNotice,
  installUpdate,
  updateCommand,
} from "../src/version.js";
import { capture, dependencies, FakeSignals } from "./cli-fixtures.js";
import { main } from "../src/cli.js";
import { rejecting } from "./support/errors.js";
import { responding } from "./support/responses.js";
import { createTemporaryDirectoriesSync } from "./support/temporary-directories.js";

function registryResponse(version: unknown) {
  return async () => new Response(JSON.stringify({ version }));
}

describe("CLI update notice", () => {
  test("checks the npm latest tag and reports a newer version", async () => {
    let requestedUrl: string | undefined;
    const notice = await checkForUpdate({
      environment: { npm_command: "exec" },
      currentVersion: "0.1.0",
      fetch: async (url) => {
        requestedUrl = url.toString();
        return new Response(JSON.stringify({ version: "0.2.0" }));
      },
    });

    expect(requestedUrl).toBe(
      "https://registry.npmjs.org/%40openai%2Fcodex-security/latest",
    );
    expect(notice).toEqual({
      currentVersion: "0.1.0",
      latestVersion: "0.2.0",
      command: "npx @openai/codex-security@latest",
    });
  });

  test("uses the configured npm registry", async () => {
    let requestedUrl: string | undefined;
    await checkForUpdate({
      environment: { npm_config_registry: "https://registry.example.test/npm" },
      currentVersion: "0.1.0",
      fetch: async (url) => {
        requestedUrl = url.toString();
        return new Response(JSON.stringify({ version: "0.2.0" }));
      },
    });

    expect(requestedUrl).toBe(
      "https://registry.example.test/npm/%40openai%2Fcodex-security/latest",
    );
  });

  test("cancels registry requests when the caller aborts", async () => {
    const controller = new AbortController();
    let requestSignal: AbortSignal | undefined;
    const pending = checkForUpdate({
      environment: {},
      signal: controller.signal,
      fetch: async (_url, options) => {
        requestSignal = options?.signal ?? undefined;
        await once(requestSignal!, "abort");
        throw requestSignal!.reason;
      },
    });

    controller.abort();
    expect(requestSignal?.aborted).toBe(true);
    await expect(pending).resolves.toBeUndefined();
  });

  test("recognizes npx and local or global npm, pnpm, Yarn, and Bun", () => {
    const installed = "/workspace/node_modules/pkg/dist/version.js";
    const packageName = "@openai/codex-security@latest";

    for (const [environment, entrypoint, command, nodeExecutable] of [
      [{ npm_command: "exec" }, installed, `npx ${packageName}`],
      [{}, "/cache/_npx/pkg", `npx ${packageName}`],
      [{}, installed, `npm install ${packageName}`],
      [{}, "/usr/lib/node_modules/pkg", `npm install -g ${packageName}`],
      [
        {},
        "C:\\AppData\\Roaming\\npm\\node_modules\\pkg",
        `npm install -g ${packageName}`,
      ],
      [
        {},
        "C:\\AppData\\Local\\nvm\\v22.20.0\\node_modules\\pkg",
        `npm install -g ${packageName}`,
        "C:\\AppData\\Local\\nvm\\v22.20.0\\node.exe",
      ],
      [
        {},
        "D:/Node Versions/v22.20.0/node_modules/pkg",
        `npm install -g ${packageName}`,
        "d:\\node versions\\v22.20.0\\node.exe",
      ],
      [
        {},
        "D:/Node Versions/v22.20.0/project/node_modules/pkg",
        `npm install ${packageName}`,
        "D:/Node Versions/v22.20.0/node.exe",
      ],
      [
        { npm_command: "exec" },
        "D:/Node Versions/v22.20.0/node_modules/pkg",
        `npx ${packageName}`,
        "D:/Node Versions/v22.20.0/node.exe",
      ],
      [
        {},
        "D:/release/.install/node_modules/pkg",
        "download and extract the latest Codex Security release",
        "D:/release/.install/node.exe",
      ],
      [
        { npm_config_user_agent: "pnpm/10.0.0" },
        installed,
        `pnpm add ${packageName}`,
      ],
      [
        { npm_config_user_agent: "pnpm/10.0.0" },
        "/pnpm/global/pkg",
        `pnpm add -g ${packageName}`,
      ],
      [
        { npm_config_user_agent: "yarn/1.22.0" },
        installed,
        `yarn add ${packageName}`,
      ],
      [{}, "/.yarn/global/pkg", `yarn global add ${packageName}`],
      [{}, "/.config/yarn/global/pkg", `yarn global add ${packageName}`],
      [
        {},
        "C:\\AppData\\Local\\Yarn\\Data\\global\\node_modules\\pkg",
        `yarn global add ${packageName}`,
      ],
      [
        { npm_config_user_agent: "bun/1.3.0" },
        installed,
        `bun add ${packageName}`,
      ],
      [{}, "/.bun/install/global/pkg", `bun add -g ${packageName}`],
      [
        {},
        "/release/.install/node_modules/pkg",
        "download and extract the latest Codex Security release",
      ],
      [{}, "/workspace/src/version.ts", `npx ${packageName}`],
    ] as const) {
      expect(updateCommand(environment, entrypoint, nodeExecutable)).toBe(
        command,
      );
    }
  });

  test("selects supported options for workspace roots and optional dependencies", () => {
    const directories = createTemporaryDirectoriesSync(true);
    const root = directories.create("codex-update-options-");
    const entrypoint = join(
      root,
      "node_modules",
      "@openai",
      "codex-security",
      "dist",
      "version.js",
    );
    try {
      writeFileSync(join(root, "pnpm-workspace.yaml"), "packages: ['apps/*']");
      for (const [manager, expected] of [
        ["pnpm", "pnpm add --workspace-root -O"],
        ["bun", "bun add --optional"],
      ]) {
        writeFileSync(
          join(root, "package.json"),
          JSON.stringify({
            packageManager: manager + "@1.0.0",
            optionalDependencies: { "@openai/codex-security": "0.9.0" },
          }),
        );
        expect(updateCommand({}, entrypoint)).toBe(
          expected + " @openai/codex-security@latest",
        );
      }
    } finally {
      directories.cleanup();
    }
  });

  test("project updates provide a command without loading package-manager configuration", async () => {
    const directories = createTemporaryDirectoriesSync(true);
    const project = directories.create("codex-update-project-");
    const marker = join(project, "manager-ran");
    const entrypoint = join(
      project,
      "node_modules",
      "@openai",
      "codex-security",
      "dist",
      "version.js",
    );
    try {
      writeFileSync(
        join(project, ".npmrc"),
        "@openai:registry=http://127.0.0.1:1/",
      );
      writeFileSync(
        join(project, "package.json"),
        JSON.stringify({
          devDependencies: { "@openai/codex-security": "0.9.0" },
          scripts: { preinstall: "node hook.cjs" },
        }),
      );
      writeFileSync(
        join(project, "hook.cjs"),
        'require("node:fs").writeFileSync("manager-ran", "ran")',
      );
      writeFileSync(
        join(project, process.platform === "win32" ? "npm.cmd" : "npm"),
        process.platform === "win32"
          ? '@echo ran > "%UPDATE_MARKER%"'
          : '#!/bin/sh\necho ran > "$UPDATE_MARKER"',
        { mode: 0o755 },
      );
      const env = {
        PATH: project,
        UPDATE_MARKER: marker,
        npm_config_userconfig: join(project, ".npmrc"),
      };
      await expect(installUpdate(env, entrypoint)).rejects.toThrow(
        `Run npm install -D @openai/codex-security@latest from ${JSON.stringify(project)}`,
      );
      expect(existsSync(marker)).toBe(false);
      writeFileSync(join(project, "package.json"), "{}");
      await expect(installUpdate(env, entrypoint)).rejects.toThrow(
        "from the project that declares",
      );
      await expect(
        installUpdate({ ...env, npm_command: "exec" }, entrypoint),
      ).rejects.toThrow("npx @openai/codex-security@latest");
    } finally {
      directories.cleanup();
    }
  });

  test("global npm updates support nvm checkouts and isolate npm from the invoking project", async () => {
    const directories = createTemporaryDirectoriesSync(true);
    const root = directories.create("codex-update-global-");
    const nvm = join(root, ".nvm");
    const prefix = join(nvm, "versions", "node", "v24.0.0");
    const project = join(root, "project");
    const originalCwd = process.cwd();
    const windows = process.platform === "win32";
    const bin = windows ? prefix : join(prefix, "bin");
    const modules = join(
      windows ? prefix : join(prefix, "lib"),
      "node_modules",
    );
    const npmBin = join(modules, "npm", "bin");
    const node = join(bin, windows ? "node.exe" : "node");
    const entrypoint = join(
      modules,
      "@openai",
      "codex-security",
      "dist",
      "version.js",
    );
    const record = join(prefix, "invocation.json");
    try {
      mkdirSync(join(nvm, ".git"), { recursive: true });
      mkdirSync(join(project, ".git"), { recursive: true });
      process.chdir(project);
      mkdirSync(bin, { recursive: true });
      mkdirSync(npmBin, { recursive: true });
      try {
        linkSync(process.execPath, node);
      } catch {
        copyFileSync(process.execPath, node);
      }
      writeFileSync(
        join(npmBin, "npm-cli.js"),
        `require("node:fs").writeFileSync(${JSON.stringify(record)}, JSON.stringify({cwd: process.cwd(), env: process.env, args: process.argv.slice(2)}));`,
      );
      const env = {
        PATH: prefix,
        OPENAI_API_KEY: "test-value",
        NODE_OPTIONS: "--require=missing.cjs",
        npm_config_registry: "http://127.0.0.1:1/",
      };
      await installUpdate(env, entrypoint, node);
      const call = JSON.parse(readFileSync(record, "utf8"));
      expect(call.env.OPENAI_API_KEY).toBeUndefined();
      expect(call.env.NODE_OPTIONS).toBeUndefined();
      expect(call.env.npm_config_registry).toBeUndefined();
      expect(existsSync(call.cwd)).toBe(false);
      expect(call.env.HOME).toBe(call.cwd);
      expect(call.env.PATH).toBe(bin);
      expect(call.env.npm_config_userconfig).toBe(join(call.cwd, "user.npmrc"));
      expect(call.env.npm_config_globalconfig).toBe(
        join(call.cwd, "global.npmrc"),
      );
      expect(call.args).toEqual([
        "install",
        "-g",
        "@openai/codex-security@latest",
        "--prefix",
        prefix,
        "--ignore-scripts",
        "--registry=https://registry.npmjs.org/",
        "--@openai:registry=https://registry.npmjs.org/",
      ]);
      // If this same distribution belongs to the checkout we are running in,
      // the explicit update must give manual instructions instead.
      process.chdir(join(nvm, "versions"));
      await expect(installUpdate(env, entrypoint, node)).rejects.toThrow(
        "Use the installation at",
      );
    } finally {
      process.chdir(originalCwd);
      directories.cleanup();
    }
  });

  test("metadata takes precedence over an explicit update", async () => {
    for (const flag of ["--help", "--version", "--schema", "--llms"]) {
      const { stdout, stderr, runCli } = createCliTest(main);
      expect(
        await runCli(
          ["--update", flag],
          dependencies({
            environment: { npm_command: "exec" },
          }),
        ),
      ).toBe(0);
      expect(stdout.text()).not.toBe("");
      expect(stderr.text()).toBe("");
    }
  });

  test("recognizes Windows globals through a linked Node directory", () => {
    const temporaryDirectories = createTemporaryDirectoriesSync(true);
    const root = temporaryDirectories.create("codex-update-notice-");
    const nodeDirectory = join(root, "Node Versions", "v22.20.0");
    const nodeLink = join(root, "nodejs");
    const platform = Object.getOwnPropertyDescriptor(process, "platform")!;
    const execPath = Object.getOwnPropertyDescriptor(process, "execPath")!;

    try {
      mkdirSync(nodeDirectory, { recursive: true });
      writeFileSync(join(nodeDirectory, "node.exe"), "");
      symlinkSync(nodeDirectory, nodeLink, "junction");
      Object.defineProperties(process, {
        platform: { value: "win32" },
        execPath: { value: join(nodeLink, "node.exe") },
      });
      expect(
        updateCommand({}, join(nodeDirectory, "node_modules", "pkg")),
      ).toBe("npm install -g @openai/codex-security@latest");
    } finally {
      Object.defineProperties(process, { platform, execPath });
      temporaryDirectories.cleanup();
    }
  });

  test.skipIf(process.platform !== "linux")(
    "keeps local npm updates local in case-distinct Linux directories",
    () => {
      for (const directory of ["Lib", "_NPX", ".YARN"]) {
        const entrypoint = `/workspace/${directory}/node_modules/pkg/dist/version.js`;
        expect(updateCommand({}, entrypoint)).toBe(
          "npm install @openai/codex-security@latest",
        );
      }
    },
  );

  test("ignores current, older, invalid, and lower prerelease versions", async () => {
    for (const [current, latest, available] of [
      ["0.1.0", "0.1.0", false],
      ["0.1.0+local", "0.1.0+registry", false],
      ["0.2.0", "0.1.0", false],
      ["0.2.0", "not-a-version", false],
      ["not-a-version", "0.2.0", false],
      ["0.2.0", "0.2.0-beta.1", false],
      ["0.2.0-beta.2", "0.2.0-beta.1", false],
      ["0.2.0-beta.1", "0.2.0-beta.2", true],
      ["0.2.0-beta.9", "0.2.0-beta.10", true],
      ["0.2.0-beta.1", "0.2.0", true],
    ] as const) {
      const notice = await checkForUpdate({
        environment: {},
        currentVersion: current,
        fetch: registryResponse(latest),
      });
      expect(notice !== undefined).toBe(available);
    }

    expect(
      await checkForUpdate({
        environment: {},
        currentVersion: "0.1.0",
        fetch: registryResponse(null),
      }),
    ).toBeUndefined();
  });

  test("orders prerelease identifiers by SemVer precedence, not locale collation", async () => {
    for (const [current, latest, available] of [
      // ASCII case ordering: "a" (97) sorts after "A" (65) in SemVer.
      ["1.0.0-A", "1.0.0-a", true],
      ["1.0.0-a", "1.0.0-A", false],
      // Numeric identifiers have lower precedence than non-numeric ones.
      ["1.0.0-1", "1.0.0-alpha", true],
      ["1.0.0-alpha", "1.0.0-1", false],
      // When shared identifiers are equal, the longer list wins.
      ["1.0.0-alpha", "1.0.0-alpha.1", true],
      ["1.0.0-alpha.1", "1.0.0-alpha", false],
      // Numeric identifiers compare numerically regardless of width.
      ["1.0.0-alpha.9", "1.0.0-alpha.10", true],
      ["1.0.0-alpha.10", "1.0.0-alpha.9", false],
      // Mixed identifier lists follow pairwise precedence.
      ["1.0.0-alpha.2", "1.0.0-alpha.10", true],
      ["1.0.0-alpha.2", "1.0.0-alpha.beta", true],
    ] as const) {
      const notice = await checkForUpdate({
        environment: {},
        currentVersion: current,
        fetch: registryResponse(latest),
      });
      expect(notice !== undefined).toBe(available);
    }
  });

  test("suppresses registry checks in CI or when disabled", async () => {
    const fetchLatest = mock(registryResponse("0.2.0"));

    for (const environment of [
      { CODEX_SECURITY_NO_UPDATE_NOTICE: "1" },
      { NO_UPDATE_NOTIFIER: "1" },
      { npm_config_update_notifier: "false" },
      { CI: "true" },
    ]) {
      expect(
        await checkForUpdate({
          environment,
          currentVersion: "0.1.0",
          fetch: fetchLatest,
        }),
      ).toBeUndefined();
    }

    expect(fetchLatest).toHaveBeenCalledTimes(0);
  });

  test("ignores unavailable registries and invalid registry responses", async () => {
    for (const fetchLatest of [
      rejecting("network unavailable"),
      responding("unavailable", 503),
      responding("not JSON", 200),
    ]) {
      expect(
        await checkForUpdate({
          environment: {},
          currentVersion: "0.1.0",
          fetch: fetchLatest,
        }),
      ).toBeUndefined();
    }
  });

  test("prints the update banner to interactive stderr without changing JSON", async () => {
    const { stdout, stderr, runCli } = createCliTest(main, { stderr: true });

    const notice = {
      currentVersion: "0.1.0",
      latestVersion: "0.2.0",
      command: "npm install -g @openai/codex-security@latest",
    };

    expect(
      await runCli(
        ["info", "--json"],
        dependencies({ onUpdateCheck: async () => notice }),
      ),
    ).toBe(0);
    expect(JSON.parse(stdout.text())).toMatchObject({
      cliVersion: expect.any(String),
    });
    expect(stderr.text()).toBe(formatUpdateNotice(notice));
    expect(stderr.text()).not.toContain("CODEX_SECURITY_NO_UPDATE_NOTICE");
  });

  test("finishes the command and aborts an unfinished update check", async () => {
    const { stdout, stderr, runCli } = createCliTest(main, { stderr: true });

    const onUpdateCheck = mock(async (_signal: AbortSignal) => {
      return await new Promise<undefined>(() => {});
    });
    const result = await runCli(
      ["info", "--json"],
      dependencies({
        onUpdateCheck,
      }),
    );

    expect(result).toBe(0);
    expect(onUpdateCheck.mock.lastCall?.[0]?.aborted).toBe(true);
    expect(JSON.parse(stdout.text())).toMatchObject({
      cliVersion: expect.any(String),
    });
    expect(stderr.text()).toBe("");
  });

  test("skips checks for noninteractive output, help, dry runs, and disabled notices", async () => {
    const onUpdateCheck = mock(resolving(undefined));

    await runCapturedCli(
      main,
      ["info", "--json"],
      dependencies({ onUpdateCheck }),
    );
    for (const argv of [
      ["--help"],
      ["--version"],
      ["scan", "--dry-run"],
      ["info", "--workers"],
    ]) {
      await main(
        argv,
        capture().stream,
        capture(true).stream,
        dependencies({ onUpdateCheck }),
      );
    }
    await main(
      ["info", "--json"],
      capture().stream,
      capture(true).stream,
      dependencies({
        environment: { CODEX_SECURITY_NO_UPDATE_NOTICE: "1" },
        onUpdateCheck,
      }),
    );

    expect(onUpdateCheck).toHaveBeenCalledTimes(0);
  });

  test("keeps commands successful when the update check fails", async () => {
    const { stdout, stderr, runCli } = createCliTest(main, { stderr: true });

    expect(
      await runCli(
        ["info", "--json"],
        dependencies({
          onUpdateCheck: rejecting("registry unavailable"),
        }),
      ),
    ).toBe(0);
    expect(JSON.parse(stdout.text())).toMatchObject({
      cliVersion: expect.any(String),
    });
    expect(stderr.text()).toBe("");
  });

  const notice = {
    currentVersion: "0.1.0",
    latestVersion: "0.2.0",
    command: "synthetic update command",
  };

  test("preserves JSON output when formatting the update banner fails", async () => {
    const { stdout, stderr, runCli } = createCliTest(main, { stderr: true });
    let attempts = 0;
    expect(
      await runCli(
        ["info", "--json"],
        dependencies({
          onUpdateCheck: resolving({
            ...notice,
            get command(): string {
              attempts += 1;
              throw new Error("Synthetic update formatting failure");
            },
          }),
        }),
      ),
    ).toBe(0);
    expect(attempts).toBe(1);
    expect(JSON.parse(stdout.text())).toMatchObject({
      cliVersion: expect.any(String),
    });
    expect(stderr.text()).toBe("");
  });

  test.each([
    ["success", 0, ""],
    ["failure", 2, "Synthetic scan failure"],
    ["SIGINT", 130, "Scan canceled by Ctrl-C."],
    ["SIGTERM", 143, "Scan terminated by SIGTERM."],
  ] as const)(
    "preserves %s results when writing the update banner fails",
    async (outcome, exitCode, message) => {
      const stdout = capture();
      const stderr = capture(true);
      const signals = new FakeSignals();
      let attempts = 0;
      const write = stderr.stream.write;
      stderr.stream.write = (chunk) => {
        if (chunk.toString() === formatUpdateNotice(notice)) {
          attempts += 1;
          throw new Error("Synthetic update write failure");
        }
        return write(chunk);
      };
      const deps = dependencies({
        signals,
        onUpdateCheck: resolving(notice),
        onRun: () => {
          if (outcome === "SIGINT" || outcome === "SIGTERM")
            signals.emit(outcome);
          if (outcome === "failure") throw new Error(message);
        },
      });

      expect(
        await main(
          outcome === "success" ? ["info", "--json"] : ["scan", ".", "--json"],
          stdout.stream,
          stderr.stream,
          deps,
        ),
      ).toBe(exitCode);
      expect(attempts).toBe(1);
      expect(JSON.parse(stdout.text())).toMatchObject(
        outcome === "success"
          ? { cliVersion: expect.any(String) }
          : { status: "failed", code: "SCAN_FAILED", message },
      );
      if (outcome !== "success") expect(stderr.text()).toContain(message);
      expect(signals.listeners.get("SIGINT")?.size ?? 0).toBe(0);
      expect(signals.listeners.get("SIGTERM")?.size ?? 0).toBe(0);
    },
  );

  test("still reports required stdout failures after an update banner failure", async () => {
    const stderr = capture(true);
    const write = stderr.stream.write;
    stderr.stream.write = (chunk) => {
      if (chunk.toString() === formatUpdateNotice(notice))
        throw new Error("Synthetic update write failure");
      return write(chunk);
    };

    expect(
      await main(
        ["info", "--json"],
        {
          write() {
            throw new Error("Synthetic stdout failure");
          },
        },
        stderr.stream,
        dependencies({ onUpdateCheck: resolving(notice) }),
      ),
    ).toBe(2);
    expect(stderr.text()).toContain("Synthetic stdout failure");
    expect(stderr.text()).not.toContain("Synthetic update write failure");
  });
});

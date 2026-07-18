import { spawnSync } from "node:child_process";
import {
  copyFile,
  mkdir,
  mkdtemp,
  readFile,
  rm,
  symlink,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, test } from "bun:test";
import type { CodexSecurity, CodexSecurityConfig } from "../src/index.js";
import {
  CodexSecurityError,
  DiffTarget,
  ScanResult,
  VERSION,
} from "../src/index.js";
import type {
  CoverageDocument,
  FindingsDocument,
  ScanManifest,
} from "../src/index.js";
import {
  main,
  parseCodexOverrides,
  parseScanArguments,
  resultJson,
  rootHelp,
  scanHelp,
  targetFromArguments,
  versionText,
} from "../src/cli.js";

type MainDependencies = NonNullable<Parameters<typeof main>[3]>;

function capture(isTTY = false): {
  stream: Pick<NodeJS.WriteStream, "write"> &
    Partial<Pick<NodeJS.WriteStream, "isTTY">>;
  text(): string;
} {
  let value = "";
  return {
    stream: {
      isTTY,
      write(chunk: string | Uint8Array): boolean {
        value += chunk.toString();
        return true;
      },
    },
    text: () => value,
  };
}

function fakeResult(): ScanResult {
  const manifest = {
    documentType: "codex-security.scan-manifest",
    schemaVersion: "1.0",
    scan: {
      id: "scan",
      producer: { name: "codex-security-plugin", version: "1.2.3" },
      status: "completed",
      startedAt: "2026-01-01T00:00:00Z",
      completedAt: "2026-01-01T00:00:01Z",
      sealedAt: "2026-01-01T00:00:01Z",
      target: {
        kind: "directory_snapshot",
        targetId: "id",
        displayName: "repo",
      },
      scope: { includePaths: ["."], excludePaths: [] },
      coverageRef: "coverage.json",
      findingsRef: "findings.json",
      artifacts: [],
    },
  } satisfies ScanManifest;
  const findings = {
    documentType: "codex-security.findings",
    schemaVersion: "1.0",
    scanId: "scan",
    findings: [],
  } satisfies FindingsDocument;
  const coverage = {
    documentType: "codex-security.coverage",
    schemaVersion: "1.0",
    scanId: "scan",
    mode: "repository",
    completeness: "complete",
    inventoryStrategy: "repository",
    includePaths: ["."],
    excludePaths: [],
    surfaces: [],
    explicitExclusions: [],
    deferred: [],
  } satisfies CoverageDocument;
  return new ScanResult({
    manifest,
    findings,
    coverage,
    scanDir: "/tmp/scan",
    threadId: "thread-1",
    turnResult: {
      status: "completed",
      finalResponse: "done",
      usage: null,
    },
  });
}

class FakeSignals {
  readonly listeners = new Map<string, Set<() => void>>();

  public add(signal: string, listener: () => void): void {
    const listeners = this.listeners.get(signal) ?? new Set();
    listeners.add(listener);
    this.listeners.set(signal, listeners);
  }

  public remove(signal: string, listener: () => void): void {
    this.listeners.get(signal)?.delete(listener);
  }

  public emit(signal: string): void {
    for (const listener of this.listeners.get(signal) ?? []) listener();
  }
}

function dependencies(
  options: {
    onConfig?: (config: CodexSecurityConfig) => void;
    onTurn?: (repository: string, options: unknown) => void;
    onRun?: () => void;
    onInterrupt?: () => void;
    onClose?: () => void | Promise<void>;
    signals?: FakeSignals;
    result?: ScanResult;
  } = {},
): MainDependencies {
  const signals = options.signals ?? new FakeSignals();
  const result = options.result ?? fakeResult();
  const security = {
    run: async (repository: string, runOptions: unknown) => {
      options.onTurn?.(repository, runOptions);
      const signal = (runOptions as { signal?: AbortSignal }).signal;
      signal?.addEventListener("abort", () => options.onInterrupt?.(), {
        once: true,
      });
      options.onRun?.();
      return result;
    },
    close: async () => await options.onClose?.(),
  } as Pick<CodexSecurity, "run" | "close">;
  return {
    createSecurity: (config) => {
      options.onConfig?.(config);
      return security;
    },
    currentDirectory: () => "/current/repository",
    now: () => 0,
    setInterval: () => ({}) as NodeJS.Timeout,
    clearInterval: () => {},
    addSignalListener: (signal, listener) => signals.add(signal, listener),
    removeSignalListener: (signal, listener) =>
      signals.remove(signal, listener),
    writeSynchronously: (stream, value) => stream.write(value),
    forceExit: () => {},
  };
}

describe("CLI compatibility contract", () => {
  test("matches the documented CLI help and version contracts", async () => {
    const goldenRoot = await readFile(
      join(import.meta.dir, "../compatibility/golden/root-help.txt"),
      "utf8",
    );
    const goldenVersion = await readFile(
      join(import.meta.dir, "../compatibility/golden/version.txt"),
      "utf8",
    );
    const goldenScan = await readFile(
      join(import.meta.dir, "../compatibility/golden/scan-help.txt"),
      "utf8",
    );
    expect(`${rootHelp()}\n`).toBe(goldenRoot);
    expect(
      `${versionText().replace(
        `codex-security ${VERSION}`,
        "codex-security 0.1.0b3",
      )}\n`,
    ).toBe(goldenVersion);
    expect(`${scanHelp()}\n`).toBe(goldenScan);
  });

  test("runs through an installed npm-style bin symlink", async () => {
    const root = await mkdtemp(join(tmpdir(), "codex-security-cli-bin-"));
    try {
      const bin = join(root, "codex-security");
      await symlink(join(import.meta.dir, "../src/cli.ts"), bin);
      const child = spawnSync(process.execPath, [bin, "--version"], {
        encoding: "utf8",
      });
      expect(child.status).toBe(0);
      expect(child.stderr).toBe("");
      expect(child.stdout).toContain("codex-security plugin");
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  test("runs split TypeScript output from an npm-style bin when Node preserves main symlinks", async () => {
    const root = await mkdtemp(join(tmpdir(), "codex-security-cli-node-bin-"));
    try {
      const source = join(import.meta.dir, "..");
      const installed = join(root, "node_modules", "@openai", "codex-security");
      const dist = join(installed, "dist");
      const build = spawnSync(
        "node",
        [
          join(source, "node_modules", "typescript", "bin", "tsc"),
          "-p",
          join(source, "tsconfig.build.json"),
          "--outDir",
          dist,
          "--pretty",
          "false",
        ],
        { encoding: "utf8", cwd: source },
      );
      expect(build.status).toBe(0);
      expect(build.stderr).toBe("");
      expect(await readFile(join(dist, "cli.js"), "utf8")).toContain(
        'from "./api.js"',
      );
      const launcher = join(installed, "bin", "codex-security.mjs");
      await mkdir(join(installed, "bin"), { recursive: true });
      await copyFile(join(source, "bin", "codex-security.mjs"), launcher);
      await copyFile(
        join(source, "package.json"),
        join(installed, "package.json"),
      );
      await symlink(
        join(source, "node_modules"),
        join(installed, "node_modules"),
        "dir",
      );
      const binDirectory = join(root, "node_modules", ".bin");
      await mkdir(binDirectory, { recursive: true });
      const bin = join(binDirectory, "codex-security");
      await symlink(launcher, bin);
      const child = spawnSync("node", [bin, "--version"], {
        encoding: "utf8",
        env: {
          ...process.env,
          NODE_OPTIONS:
            "--preserve-symlinks-main --no-experimental-detect-module",
          NODE_USE_ENV_PROXY: undefined,
        },
      });
      expect(child.status).toBe(0);
      expect(child.stderr).toBe("");
      expect(child.stdout).toContain("codex-security plugin");
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  }, 30_000);

  test("keeps argparse version-action precedence", async () => {
    const stdout = capture();
    const stderr = capture();
    expect(
      await main(
        ["--version", "scan"],
        stdout.stream,
        stderr.stream,
        dependencies(),
      ),
    ).toBe(0);
    expect(stdout.text()).toBe(`${versionText()}\n`);
    expect(stderr.text()).toBe("");
  });

  test("accepts unambiguous root and scan help/version abbreviations", async () => {
    const cases: ReadonlyArray<[readonly string[], string]> = [
      [["--he"], "usage: codex-security"],
      [["--ver"], "codex-security plugin"],
      [["--vers"], "codex-security plugin"],
      [["scan", "--hel"], "usage: codex-security scan"],
      [["-hx"], "usage: codex-security"],
      [["-hfoo"], "usage: codex-security"],
      [["-hx=y"], "usage: codex-security"],
      [["-hfoo=bar"], "usage: codex-security"],
      [["scan", "-hx"], "usage: codex-security scan"],
      [["scan", "-hfoo"], "usage: codex-security scan"],
      [["scan", "-hx=y"], "usage: codex-security scan"],
      [["scan", "-hfoo=bar"], "usage: codex-security scan"],
    ];
    for (const [argv, expected] of cases) {
      const stdout = capture();
      const stderr = capture();
      expect(
        await main(argv, stdout.stream, stderr.stream, dependencies()),
      ).toBe(0);
      expect(stdout.text()).toContain(expected);
      expect(stderr.text()).toBe("");
    }
  });

  test("parses every target and repeatable option", () => {
    const pathArguments = parseScanArguments([
      "repo",
      "--path",
      "src",
      "--path=tests",
      "--mode",
      "deep",
      "--plugin-path",
      "plugin.zip",
      "--python=/managed/python",
      "--codex",
      "features.goals=true",
      "--json",
    ]);
    expect(pathArguments).toMatchObject({
      repository: "repo",
      paths: ["src", "tests"],
      mode: "deep",
      pluginPath: "plugin.zip",
      pythonPath: "/managed/python",
      codex: ["features.goals=true"],
      json: true,
    });
    expect(targetFromArguments(pathArguments)).toEqual(["src", "tests"]);

    expect(
      targetFromArguments(
        parseScanArguments(["--diff", "origin/main", "--head", "HEAD"]),
      ),
    ).toEqual(DiffTarget.refs({ base: "origin/main", head: "HEAD" }));
    expect(
      targetFromArguments(
        parseScanArguments(["--working-tree", "--base", "origin/main"]),
      ),
    ).toEqual(DiffTarget.workingTree({ base: "origin/main" }));

    expect(parseScanArguments(["--cod", "x=true"]).codex).toEqual(["x=true"]);
    expect(parseScanArguments(["--dif", "HEAD"]).diff).toBe("HEAD");
    expect(parseScanArguments(["--path", "-1"]).paths).toEqual(["-1"]);
    expect(parseScanArguments(["--path", "-.5"]).paths).toEqual(["-.5"]);
    for (const positional of ["-١", "-１２", "-.٥", "-१२३", "-foo bar"]) {
      expect(parseScanArguments(["--path", positional]).paths).toEqual([
        positional,
      ]);
      expect(parseScanArguments([positional]).repository).toBe(positional);
    }
    expect(parseScanArguments(["-"]).repository).toBe("-");
    expect(parseScanArguments(["-1"]).repository).toBe("-1");
    expect(parseScanArguments(["-.5"]).repository).toBe("-.5");
    expect(parseScanArguments(["--path", "-"]).paths).toEqual(["-"]);
    expect(parseScanArguments(["--diff", "-"]).diff).toBe("-");
    expect(parseScanArguments(["--diff", "HEAD", "--head", "-"]).head).toBe(
      "-",
    );
    expect(parseScanArguments(["--working-tree", "--base", "-"]).base).toBe(
      "-",
    );
    expect(parseScanArguments(["--output-dir", "-"]).outputDir).toBe("-");
    expect(parseScanArguments(["--plugin-path", "-"]).pluginPath).toBe("-");
    expect(parseScanArguments(["--codex", "-"]).codex).toEqual(["-"]);
    expect(() => parseScanArguments(["--path", "-foo"])).toThrow(
      "expected one argument",
    );
    expect(() => parseScanArguments(["--p", "value"])).toThrow(
      "ambiguous option",
    );
    for (const invalid of ["-foo", "-1e3", "-1.", "-0x1"]) {
      expect(() => parseScanArguments(["--path", invalid])).toThrow(
        "expected one argument",
      );
    }
  });

  test("parses attached scan-option values containing spaces before positional fallback", () => {
    for (const repository of [undefined, "repo"]) {
      const prefix = repository === undefined ? [] : [repository];
      expect(
        parseScanArguments([
          ...prefix,
          "--pa=src folder",
          '--codex=model="hello world"',
          "--output-dir=/tmp/output folder",
          "--plugin-path=/tmp/plugin folder",
          "--python=/tmp/python folder/bin/python",
        ]),
      ).toMatchObject({
        repository: repository ?? process.cwd(),
        paths: ["src folder"],
        codex: ['model="hello world"'],
        outputDir: "/tmp/output folder",
        pluginPath: "/tmp/plugin folder",
        pythonPath: "/tmp/python folder/bin/python",
      });
      expect(
        parseScanArguments([
          ...prefix,
          "--diff=release branch",
          "--head=feature branch",
        ]),
      ).toMatchObject({
        repository: repository ?? process.cwd(),
        diff: "release branch",
        head: "feature branch",
      });
      expect(
        parseScanArguments([
          ...prefix,
          "--working-tree",
          "--base=release branch",
        ]),
      ).toMatchObject({
        repository: repository ?? process.cwd(),
        workingTree: true,
        base: "release branch",
      });
    }

    expect(parseScanArguments(["--path", "--unknown=x y"]).paths).toEqual([
      "--unknown=x y",
    ]);
    expect(parseScanArguments(["--unknown=x y"]).repository).toBe(
      "--unknown=x y",
    );
    expect(() =>
      parseScanArguments(["--path", '--codex=model="hello world"']),
    ).toThrow("expected one argument");
    expect(() => parseScanArguments(["--p=src folder"])).toThrow(
      "ambiguous option",
    );
    expect(() => parseScanArguments(["--json=not allowed"])).toThrow(
      "ignored explicit argument",
    );
  });

  test("parses TOML override literals and rejects conflicts", () => {
    expect(
      parseCodexOverrides([
        "agents.max_threads=4",
        'model_reasoning_effort="high"',
        "features.goals=true",
      ]),
    ).toEqual({
      agents: { max_threads: 4 },
      model_reasoning_effort: "high",
      features: { goals: true },
    });
    expect(() =>
      parseCodexOverrides(["agents.max_threads=4", "agents.max_threads=8"]),
    ).toThrow("Duplicate --codex key");
    expect(() =>
      parseCodexOverrides(["agents=4", "agents.max_threads=8"]),
    ).toThrow("Conflicting --codex key");
  });

  test("redacts malformed and bounded --codex overrides", () => {
    const secret = "SYNTHETIC_TOML_SECRET_MUST_NOT_ECHO";
    let malformed: unknown;
    try {
      parseCodexOverrides([`model=\"${secret}`]);
    } catch (error) {
      malformed = error;
    }
    expect(malformed).toBeInstanceOf(CodexSecurityError);
    expect(String(malformed)).toContain("Invalid --codex TOML value");
    expect(String(malformed)).not.toContain(secret);
    expect((malformed as Error).cause).toBeUndefined();

    const deep = `${Array.from({ length: 3_072 }, () => "a").join(".")}=1`;
    expect(() => parseCodexOverrides([deep])).toThrow("--codex key");
    expect(() => parseCodexOverrides([`${"a".repeat(1_025)}=1`])).toThrow(
      "--codex key",
    );
    expect(() =>
      parseCodexOverrides([`model=\"${"x".repeat(64 * 1_024)}\"`]),
    ).toThrow("--codex key or value exceeds the limit");
    expect(() => parseCodexOverrides([`${"ࠀ".repeat(342)}=1`])).toThrow(
      "--codex key or value exceeds the limit",
    );
    expect(() =>
      parseCodexOverrides([`model=\"${"ࠀ".repeat(65_534)}\"`]),
    ).toThrow("--codex key or value exceeds the limit");
  });

  test("rejects prototype-bearing override paths", () => {
    for (const key of ["__proto__", "constructor", "prototype"]) {
      expect(() => parseCodexOverrides([`${key}.polluted=true`])).toThrow(
        "Invalid --codex key",
      );
    }
    expect(({} as Record<string, unknown>)["polluted"]).toBeUndefined();
  });

  test("returns parser exit 2 without starting the SDK", async () => {
    const stdout = capture();
    const stderr = capture();
    expect(
      await main(
        ["scan", ".", "--path", "src", "--diff", "HEAD"],
        stdout.stream,
        stderr.stream,
        dependencies(),
      ),
    ).toBe(2);
    expect(stdout.text()).toBe("");
    expect(stderr.text()).toContain("mutually exclusive");
  });

  test("preserves validation exit 1 for invalid target-specific options", async () => {
    const cases: ReadonlyArray<[readonly string[], string]> = [
      [["scan", ".", "--head", "HEAD"], "--head requires --diff"],
      [["scan", ".", "--base", "HEAD"], "--base requires --working-tree"],
      [["scan", ".", "--path="], "--path must not be empty"],
    ];
    for (const [argv, message] of cases) {
      const stdout = capture();
      const stderr = capture();
      let started = false;
      expect(
        await main(
          argv,
          stdout.stream,
          stderr.stream,
          dependencies({ onRun: () => (started = true) }),
        ),
      ).toBe(1);
      expect(stdout.text()).toBe("");
      expect(stderr.text()).toContain(message);
      expect(started).toBe(false);
    }
  });

  test("returns parser exit 2 for empty attached revision values", async () => {
    for (const option of ["--diff=", "--head=", "--base="]) {
      const stdout = capture();
      const stderr = capture();
      expect(
        await main(
          ["scan", ".", option],
          stdout.stream,
          stderr.stream,
          dependencies(),
        ),
      ).toBe(2);
      expect(stdout.text()).toBe("");
      expect(stderr.text()).toContain("expected one argument");
    }
  });

  test("uses the final repeated revision value when an earlier value is empty", async () => {
    for (const argv of [
      ["scan", "--diff=", "--diff=HEAD"],
      ["scan", "--head=", "--diff=HEAD", "--head=HEAD"],
      ["scan", "--base=", "--working-tree", "--base=HEAD"],
    ]) {
      const stdout = capture();
      const stderr = capture();
      let started = false;
      expect(
        await main(
          argv,
          stdout.stream,
          stderr.stream,
          dependencies({ onRun: () => (started = true) }),
        ),
      ).toBe(0);
      expect(started).toBe(true);
      expect(stdout.text()).toContain("Scan:");
    }
  });

  test("preserves help precedence for attached empty revisions without resolving cwd", async () => {
    for (const option of ["--diff=", "--head=", "--base="]) {
      const stdout = capture();
      const stderr = capture();
      const deps = dependencies();
      deps.currentDirectory = () => {
        throw new Error("SYNTHETIC_DELETED_CWD");
      };
      expect(
        await main(
          ["scan", option, "--help"],
          stdout.stream,
          stderr.stream,
          deps,
        ),
      ).toBe(0);
      expect(stdout.text()).toContain("usage: codex-security scan");
      expect(stderr.text()).toBe("");
    }
  });

  test("preserves help precedence after attached scan-option values containing spaces", async () => {
    for (const option of [
      "--path=src folder",
      '--codex=model="hello world"',
      "--output-dir=/tmp/output folder",
      "--plugin-path=/tmp/plugin folder",
      "--python=/tmp/python folder/bin/python",
      "--diff=release branch",
      "--head=feature branch",
      "--base=release branch",
    ]) {
      const stdout = capture();
      const stderr = capture();
      const deps = dependencies();
      deps.currentDirectory = () => {
        throw new Error("SYNTHETIC_DELETED_CWD");
      };
      expect(
        await main(
          ["scan", option, "--help"],
          stdout.stream,
          stderr.stream,
          deps,
        ),
      ).toBe(0);
      expect(stdout.text()).toContain("usage: codex-security scan");
      expect(stderr.text()).toBe("");
    }
  });

  test("does not start scans for help-shaped positional or option values", async () => {
    for (const help of ["-h foo", "-help me", "-hx y"]) {
      const standaloneOutput = capture();
      const standaloneError = capture();
      let standaloneStarted = false;
      expect(
        await main(
          ["scan", help],
          standaloneOutput.stream,
          standaloneError.stream,
          dependencies({ onRun: () => (standaloneStarted = true) }),
        ),
      ).toBe(0);
      expect(standaloneOutput.text()).toContain("usage: codex-security scan");
      expect(standaloneError.text()).toBe("");
      expect(standaloneStarted).toBe(false);

      for (const option of ["--path", "--diff"]) {
        const stdout = capture();
        const stderr = capture();
        let started = false;
        expect(
          await main(
            ["scan", option, help],
            stdout.stream,
            stderr.stream,
            dependencies({ onRun: () => (started = true) }),
          ),
        ).toBe(2);
        expect(stdout.text()).toBe("");
        expect(stderr.text()).toContain("expected one argument");
        expect(started).toBe(false);
      }
    }
  });

  test("rejects malformed attached short-help flags without starting a scan", async () => {
    for (const option of ["-h--", "-h--diff", "-h--help", "-h=", "-h=foo"]) {
      for (const argv of [
        ["scan", option],
        ["scan", option, "--hel"],
      ]) {
        const stdout = capture();
        const stderr = capture();
        let started = false;
        expect(
          await main(
            argv,
            stdout.stream,
            stderr.stream,
            dependencies({ onRun: () => (started = true) }),
          ),
        ).toBe(2);
        expect(stdout.text()).toBe("");
        expect(stderr.text()).toContain(
          option.startsWith("-h=")
            ? "--help must be used immediately after scan"
            : "unrecognized argument",
        );
        if (!option.startsWith("-h=")) {
          expect(stderr.text()).toContain(option);
        }
        expect(started).toBe(false);
      }
    }
    for (const option of ["-h--", "-h--diff", "-h=", "-h=foo"]) {
      const stdout = capture();
      const stderr = capture();
      let started = false;
      expect(
        await main(
          [option],
          stdout.stream,
          stderr.stream,
          dependencies({ onRun: () => (started = true) }),
        ),
      ).toBe(2);
      expect(stdout.text()).toBe("");
      expect(stderr.text()).toContain(option);
      expect(started).toBe(false);
    }
  });

  test("rejects a trailing option terminator after an option follows the repository", async () => {
    for (const argv of [
      ["scan", "repo", "--path=x", "--"],
      ["scan", "repo", "--path", "x", "--"],
      ["scan", "repo", "--json", "--"],
      ["scan", "repo", "--diff=HEAD", "--"],
    ]) {
      const stdout = capture();
      const stderr = capture();
      let started = false;
      expect(
        await main(
          argv,
          stdout.stream,
          stderr.stream,
          dependencies({ onRun: () => (started = true) }),
        ),
      ).toBe(2);
      expect(stdout.text()).toBe("");
      expect(stderr.text()).toContain("unrecognized argument: --");
      expect(started).toBe(false);
    }
  });

  test("preserves valid trailing option terminators", async () => {
    for (const argv of [
      ["scan", "repo", "--"],
      ["scan", "--path=x", "--"],
      ["scan", "--path=x", "repo", "--"],
      ["scan", "--", "--help"],
    ]) {
      const stdout = capture();
      const stderr = capture();
      let started = false;
      expect(
        await main(
          argv,
          stdout.stream,
          stderr.stream,
          dependencies({ onRun: () => (started = true) }),
        ),
      ).toBe(0);
      expect(stdout.text()).toContain("Scan:");
      expect(started).toBe(true);
    }
  });

  test("treats help-shaped tokens after the option terminator as repository", async () => {
    for (const repository of ["--p", "--h", "--hel", "--help"]) {
      const stdout = capture();
      const stderr = capture();
      let received = "";
      expect(
        await main(
          ["scan", "--", repository],
          stdout.stream,
          stderr.stream,
          dependencies({ onTurn: (value) => (received = value) }),
        ),
      ).toBe(0);
      expect(received).toBe(repository);
      expect(stdout.text()).toContain("Scan:");
      expect(stderr.text()).not.toContain("ambiguous option");
    }
  });

  test("rejects a missing option value before honoring scan help", async () => {
    const options = [
      "--path",
      "--codex",
      "--diff",
      "--head",
      "--base",
      "--output-dir",
      "--plugin-path",
      "--python",
      "--mode",
    ];
    for (const option of options) {
      const stdout = capture();
      const stderr = capture();
      expect(
        await main(
          ["scan", option, "--help"],
          stdout.stream,
          stderr.stream,
          dependencies(),
        ),
      ).toBe(2);
      expect(stdout.text()).toBe("");
      expect(stderr.text()).toContain(
        `argument ${option}: expected one argument`,
      );
    }

    const stdout = capture();
    const stderr = capture();
    expect(
      await main(
        ["scan", "--path", "--p", "--help"],
        stdout.stream,
        stderr.stream,
        dependencies(),
      ),
    ).toBe(2);
    expect(stdout.text()).toBe("");
    expect(stderr.text()).toContain("argument --path: expected one argument");
    expect(stderr.text()).not.toContain("ambiguous option");
  });

  test("validates prior scan options before honoring help", async () => {
    const cases: ReadonlyArray<[readonly string[], string]> = [
      [
        ["scan", "--mode", "bogus", "--help"],
        "argument --mode: invalid choice",
      ],
      [
        ["scan", "--path", "src", "--diff", "HEAD", "--help"],
        "mutually exclusive",
      ],
      [
        ["scan", "--json=x", "--help"],
        "argument --json: ignored explicit argument",
      ],
    ];
    for (const [argv, message] of cases) {
      const stdout = capture();
      const stderr = capture();
      expect(
        await main(argv, stdout.stream, stderr.stream, dependencies()),
      ).toBe(2);
      expect(stdout.text()).toBe("");
      expect(stderr.text()).toContain(message);
    }

    const stdout = capture();
    const stderr = capture();
    expect(
      await main(
        ["scan", "--unknown", "--help"],
        stdout.stream,
        stderr.stream,
        dependencies(),
      ),
    ).toBe(0);
    expect(stdout.text()).toContain("usage: codex-security scan");
    expect(stderr.text()).toBe("");
  });

  test("maps configuration and emits JSON only on stdout", async () => {
    const stdout = capture();
    const stderr = capture();
    const captured: { config?: CodexSecurityConfig } = {};
    let repository = "";
    const exit = await main(
      [
        "scan",
        "repo",
        "--plugin-path",
        "plugin.zip",
        "--python",
        "/managed/python",
        "--codex",
        "features.goals=true",
        "--json",
      ],
      stdout.stream,
      stderr.stream,
      dependencies({
        onConfig: (value) => {
          captured.config = value;
        },
        onTurn: (value) => {
          repository = value;
        },
      }),
    );
    expect(exit).toBe(0);
    expect(JSON.parse(stdout.text())).toEqual(resultJson(fakeResult()));
    expect(stderr.text()).toContain("Preparing scan");
    expect(stderr.text()).toContain("Running scan");
    expect(stderr.text()).toContain("Scan complete");
    expect(captured.config).toEqual({
      pluginPath: "plugin.zip",
      pythonPath: "/managed/python",
      codexOverrides: { features: { goals: true } },
    });
    expect(repository).toBe("repo");
  });

  test("emits the human result summary", async () => {
    const stdout = capture();
    const stderr = capture();
    expect(
      await main(["scan"], stdout.stream, stderr.stream, dependencies()),
    ).toBe(0);
    expect(stdout.text()).toBe(
      "Scan: /tmp/scan\n" +
        `Report: ${join("/tmp/scan", "report.md")}\n` +
        "Plugin: 1.2.3\n" +
        "Findings: 0\n",
    );
  });

  test("maps Ctrl-C and SIGTERM to conventional exits and preserves partial output", async () => {
    for (const [signal, expectedExit, phrase] of [
      ["SIGINT", 130, "Scan canceled by Ctrl-C."],
      ["SIGTERM", 143, "Scan terminated by SIGTERM."],
    ] as const) {
      const stdout = capture();
      const stderr = capture();
      const signals = new FakeSignals();
      let interrupted = false;
      const exit = await main(
        ["scan", "."],
        stdout.stream,
        stderr.stream,
        dependencies({
          signals,
          onRun: () => signals.emit(signal),
          onInterrupt: () => {
            interrupted = true;
          },
        }),
      );
      expect(exit).toBe(expectedExit);
      expect(stdout.text()).toBe("");
      expect(stderr.text()).toContain(phrase);
      expect(stderr.text()).toContain("Partial output was kept at /tmp/scan.");
      expect(interrupted).toBe(true);
      expect(signals.listeners.get(signal)?.size).toBe(0);
    }
  });

  test("cancels runtime preparation when a signal arrives", async () => {
    const stdout = capture();
    const stderr = capture();
    const signals = new FakeSignals();
    const deps = dependencies({ signals });
    deps.createSecurity = () => ({
      run: async (_repository, options) => {
        signals.emit("SIGINT");
        const signal = (options as { signal?: AbortSignal }).signal;
        expect(signal?.aborted).toBe(true);
        throw new DOMException("aborted", "AbortError");
      },
      close: async () => {},
    });
    expect(await main(["scan", "."], stdout.stream, stderr.stream, deps)).toBe(
      130,
    );
    expect(stdout.text()).toBe("");
    expect(stderr.text()).toContain("Scan canceled by Ctrl-C.");
    expect(stderr.text()).toContain("No partial output was kept.");
  });

  test("preserves signals received during client cleanup", async () => {
    const stdout = capture();
    const stderr = capture();
    const signals = new FakeSignals();
    const exit = await main(
      ["scan", "."],
      stdout.stream,
      stderr.stream,
      dependencies({
        signals,
        onClose: () => signals.emit("SIGTERM"),
      }),
    );
    expect(exit).toBe(143);
    expect(stdout.text()).toBe("");
    expect(stderr.text()).toContain("Scan terminated by SIGTERM.");
    expect(signals.listeners.get("SIGTERM")?.size).toBe(0);
  });

  test("lets a later repeated signal escape cleanup while suppressing delivery duplicates", async () => {
    const stdout = capture();
    const stderr = capture(true);
    const signals = new FakeSignals();
    const forced: string[] = [];
    const synchronousWrites: string[] = [];
    let now = 0;
    const deps = dependencies({ signals });
    deps.now = () => now;
    deps.writeSynchronously = (_stream, value) => synchronousWrites.push(value);
    deps.forceExit = (signal) => forced.push(signal);
    deps.createSecurity = () => ({
      run: async () => {
        signals.emit("SIGINT");
        signals.emit("SIGINT");
        expect(forced).toEqual([]);
        now = 1_000;
        signals.emit("SIGINT");
        return fakeResult();
      },
      close: async () => {},
    });

    expect(await main(["scan", "."], stdout.stream, stderr.stream, deps)).toBe(
      130,
    );
    expect(forced).toEqual(["SIGINT"]);
    expect(synchronousWrites).toEqual(["\u001B[?25h"]);
    expect(stderr.text()).toContain("\u001B[?25h");
    expect(signals.listeners.get("SIGINT")?.size).toBe(0);
  });

  test("does not debounce a different termination signal", async () => {
    const signals = new FakeSignals();
    const forced: string[] = [];
    let now = 0;
    const deps = dependencies({ signals });
    deps.now = () => now;
    deps.forceExit = (signal) => forced.push(signal);
    deps.createSecurity = () => ({
      run: async () => {
        signals.emit("SIGINT");
        now = 100;
        signals.emit("SIGTERM");
        return fakeResult();
      },
      close: async () => {},
    });

    await main(["scan", "."], capture().stream, capture().stream, deps);
    expect(forced).toEqual(["SIGTERM"]);
  });

  test("forces exit when synchronous terminal restoration fails", async () => {
    const signals = new FakeSignals();
    const forced: string[] = [];
    let now = 0;
    const deps = dependencies({ signals });
    deps.now = () => now;
    deps.writeSynchronously = () => {
      throw new Error("terminal unavailable");
    };
    deps.forceExit = (signal) => forced.push(signal);
    deps.createSecurity = () => ({
      run: async () => {
        signals.emit("SIGINT");
        now = 1_000;
        signals.emit("SIGINT");
        return fakeResult();
      },
      close: async () => {},
    });

    await main(["scan", "."], capture().stream, capture(true).stream, deps);
    expect(forced).toEqual(["SIGINT"]);
  });

  test("reports SDK errors without a stack trace", async () => {
    const stdout = capture();
    const stderr = capture();
    const failing = dependencies();
    failing.createSecurity = () => ({
      run: async () => {
        throw new CodexSecurityError("invalid scan request");
      },
      close: async () => {},
    });
    expect(
      await main(["scan", "."], stdout.stream, stderr.stream, failing),
    ).toBe(1);
    expect(stdout.text()).toBe("");
    expect(stderr.text()).toContain("codex-security: invalid scan request\n");
    expect(stderr.text()).not.toContain("CodexSecurityError");
  });

  test("does not report success when SDK cleanup fails", async () => {
    for (const json of [false, true]) {
      const stdout = capture();
      const stderr = capture();
      expect(
        await main(
          json ? ["scan", ".", "--json"] : ["scan", "."],
          stdout.stream,
          stderr.stream,
          dependencies({
            onClose: () => {
              throw new Error("SYNTHETIC_AUTH_HOME_CLEANUP_FAILED");
            },
          }),
        ),
      ).toBe(1);
      expect(stdout.text()).toBe("");
      expect(stderr.text()).toContain("SYNTHETIC_AUTH_HOME_CLEANUP_FAILED");
      expect(stderr.text()).toContain("Partial output was kept at /tmp/scan.");
    }
  });

  test("preserves the original scan failure when SDK cleanup also fails", async () => {
    const stdout = capture();
    const stderr = capture();
    expect(
      await main(
        ["scan", "."],
        stdout.stream,
        stderr.stream,
        dependencies({
          onRun: () => {
            throw new Error("SYNTHETIC_ORIGINAL_SCAN_FAILED");
          },
          onClose: () => {
            throw new Error("SYNTHETIC_AUTH_HOME_CLEANUP_FAILED");
          },
        }),
      ),
    ).toBe(1);
    expect(stdout.text()).toBe("");
    expect(stderr.text()).toContain("SYNTHETIC_ORIGINAL_SCAN_FAILED");
    expect(stderr.text()).not.toContain("SYNTHETIC_AUTH_HOME_CLEANUP_FAILED");
  });
});

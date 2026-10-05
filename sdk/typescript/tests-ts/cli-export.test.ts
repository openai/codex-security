import { resolving } from "./support/promises.js";
import { createHash } from "node:crypto";
import {
  chmod,
  lstat,
  mkdir,
  mkdtemp,
  readFile,
  realpath,
  rm,
  stat,
  symlink,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Writable } from "node:stream";
import { pathToFileURL } from "node:url";
import { describe, expect, test, mock } from "bun:test";
import { exportEnvironment, main } from "../src/cli.js";
import type { JsonObject } from "../src/config.js";
import {
  CodexSecurityError,
  type CoverageDocument,
  type ScanManifest,
} from "../src/index.js";
import { resolvePluginPython, runWorkbench } from "../src/runtime.js";
import {
  SYNTHETIC_CREDENTIALS,
  capture,
  dependencies,
  mustNotInitializeCodex,
} from "./cli-fixtures.js";
import { copyCompletedScanFixture, PLUGIN_ROOT } from "./plugin-root.js";
import { temporaryDirectory } from "./support/temporary-directories.js";
import { runCommand } from "./support/shell.js";
import {
  createCliTest,
  runCapturedCli,
  captureCli,
} from "./support/cli-run.js";

async function copyCompletedScan(root: string): Promise<string> {
  const scan = join(root, "scan");
  await copyCompletedScanFixture(scan);
  if (process.platform !== "win32") await chmod(scan, 0o700);
  return scan;
}

describe("CLI", () => {
  test("does not pass credentials or Python startup paths to the exporter", () => {
    expect(
      exportEnvironment({
        Path: "C:\\Python;C:\\Windows\\System32",
        PYTHON: "/managed/python",
        TMPDIR: "/tmp",
        OPENAI_API_KEY: "openai-secret",
        CODEX_API_KEY: "codex-secret",
        GITHUB_TOKEN: "github-secret",
        PYTHONPATH: ".",
      }),
    ).toEqual({
      Path: "C:\\Python;C:\\Windows\\System32",
      PYTHON: "/managed/python",
      PYTHONUTF8: "1",
      TMPDIR: "/tmp",
    });
  });

  test("exports findings to stdout without initializing Codex", async () => {
    for (const [format, expected] of [
      ["csv", "occurrence_id,finding_id\n"],
      ["json", '{"documentType":"codex-security.findings"}\n'],
      ["sarif", '{"version":"2.1.0"}\n'],
    ] as const) {
      const { stdout, stderr, runCli } = createCliTest(main);

      const deps = dependencies();
      deps.createSecurity = mustNotInitializeCodex;
      expect(
        await runCli(
          ["export", "scan", "--export-format", format, "--output", "-"],
          deps,
        ),
      ).toBe(0);
      expect(stdout.text()).toBe(expected);
      expect(stderr.text()).toBe("");
    }
  });

  test("exports the latest completed scan when no directory is provided", async () => {
    const scanDir = join(tmpdir(), "codex-security-latest-scan");
    const deps = dependencies({
      onWorkbench: (args): JsonObject =>
        args[0] === "list-scans"
          ? { scans: [{ scanId: "latest-scan", scanDir }] }
          : { scan: { scanId: "latest-scan", scanDir } },
    });
    let exportedScanDir = "";
    deps.exportFindings = async (arguments_) => {
      exportedScanDir = arguments_.scanDir;
      return new Uint8Array();
    };

    expect(await runCapturedCli(main, ["export", "--output", "-"], deps)).toBe(
      0,
    );
    expect(exportedScanDir).toBe(scanDir);
  });

  test("reports default-source history failures once without running the exporter", async () => {
    for (const lookupFails of [false, true]) {
      const deps = dependencies({
        onWorkbench: () => {
          if (lookupFails) throw new Error("Synthetic history failure.");
          return { scans: [] };
        },
      });
      let exports = 0;
      deps.exportFindings = async () => {
        exports += 1;
        return undefined;
      };
      const { stdout, stderr, runCli } = createCliTest(main);

      expect(await runCli(["export"], deps)).toBe(2);
      expect(stderr.text()).toBe(
        lookupFails
          ? "codex-security: Synthetic history failure.\n"
          : "codex-security: No completed scans found for the current repository.\n",
      );
      expect(stdout.text()).toBe("");
      expect(exports).toBe(0);
    }
  });

  test("exports saved models with the selected Python and rejects changed recorded manifests", async () => {
    const root = await realpath(
      await mkdtemp(join(tmpdir(), "codex-security-export-python-")),
    );
    try {
      const python = await resolvePluginPython();
      const repository = join(root, "repository");
      const scanDir = join(root, "scan");
      await mkdir(repository);
      await mkdir(scanDir, { mode: 0o700 });
      const environment = {
        ...exportEnvironment(),
        CODEX_HOME: join(root, "codex-home"),
        CODEX_SECURITY_STATE_DIR: join(root, "state"),
        PYTHON: join(root, "missing-python"),
      };
      const workbench = (args: readonly string[]) =>
        runWorkbench({ python, pluginRoot: PLUGIN_ROOT, environment }, args);
      const registered = await workbench([
        "register-cli-scan",
        "--repository",
        repository,
        "--scan-dir",
        scanDir,
        "--recipe-json",
        JSON.stringify({
          config: {},
          mode: "standard",
          repository,
          target: { kind: "repository", paths: [] },
        }),
      ]);
      const scanId = registered["scanId"] as string;
      await copyCompletedScan(root);
      const content = "# Saved model\n\nSynthetic component boundaries.\n";
      for (const name of ["scan-manifest", "findings", "coverage"]) {
        const path = join(scanDir, `${name}.json`);
        const document = JSON.parse(await readFile(path, "utf8"));
        if (name === "scan-manifest") {
          document.scan.id = scanId;
          document.scan.target.kind = "directory_snapshot";
          document.scan.threatModel = { format: "markdown", content };
          delete document.scan.sealedAt;
          delete document.scan.artifacts;
        } else {
          document.scanId = scanId;
          if (name === "findings") document.findings = [];
        }
        await writeFile(path, JSON.stringify(document));
      }
      await workbench(["complete-scan", "--scan-id", scanId]);
      const manifestPath = join(scanDir, "scan-manifest.json");
      const sealedManifest = await readFile(manifestPath);
      if (process.platform !== "win32") {
        await chmod(scanDir, 0o500);
        await chmod(join(scanDir, "exports"), 0o500);
      }

      for (const selector of [["--scan", scanId.slice(0, 8)], []]) {
        const result = await runCommand(
          process.execPath,
          [
            join(import.meta.dir, "../src/cli.ts"),
            "export",
            ...selector,
            "--artifact",
            "threat-model",
            "--output",
            "-",
            "--python",
            python,
          ],
          { cwd: repository, env: environment, timeout: 30_000 },
        );
        expect(result.stderr).toBe("");
        expect(result.status).toBe(0);
        expect(result.stdout).toStartWith(content);
      }
      const sdkOptions = {
        source: { scanId },
        artifact: "threat-model",
        output: join(root, "exported-model.md"),
        pythonPath: python,
      };
      const exportWithSdk = () =>
        runCommand(
          process.execPath,
          [
            "-e",
            `import { exportArtifact } from ${JSON.stringify(pathToFileURL(join(import.meta.dir, "../src/index.ts")).href)}; await exportArtifact(JSON.parse(process.argv[1]));`,
            JSON.stringify(sdkOptions),
          ],
          { cwd: repository, env: environment, timeout: 30_000 },
        );
      const sdkExport = await exportWithSdk();
      expect(sdkExport.status, sdkExport.stderr).toBe(0);
      expect(sdkExport.stdout).toBe("");
      const exportedModel = await readFile(sdkOptions.output, "utf8");
      expect(exportedModel).toStartWith(content);
      expect(await readFile(manifestPath)).toEqual(sealedManifest);
      await expect(
        lstat(join(scanDir, "exports", "threatmodel.md")),
      ).rejects.toHaveProperty("code", "ENOENT");
      if (process.platform !== "win32") {
        await chmod(scanDir, 0o700);
        await chmod(join(scanDir, "exports"), 0o700);
      }

      const changed = JSON.parse(await readFile(manifestPath, "utf8"));
      changed.scan.threatModel.content = "# Changed after completion\n";
      await writeFile(manifestPath, JSON.stringify(changed));
      for (const selector of [["--scan", scanId.slice(0, 8)], []]) {
        const rejected = await runCommand(
          process.execPath,
          [
            join(import.meta.dir, "../src/cli.ts"),
            "export",
            ...selector,
            "--artifact",
            "threat-model",
            "--output",
            "-",
            "--python",
            python,
          ],
          { cwd: repository, env: environment, timeout: 30_000 },
        );
        expect(rejected.status).toBe(2);
        expect(rejected.stdout).toBe("");
        expect(rejected.stderr).toContain("manifest changed after completion");
      }
      const rejectedSdk = await exportWithSdk();
      expect(rejectedSdk.status).not.toBe(0);
      expect(rejectedSdk.stdout).toBe("");
      expect(rejectedSdk.stderr).toContain("manifest changed after completion");
      expect(await readFile(sdkOptions.output, "utf8")).toBe(exportedModel);
    } finally {
      if (process.platform !== "win32") {
        await chmod(join(root, "scan"), 0o700).catch(() => {});
        await chmod(join(root, "scan", "exports"), 0o700).catch(() => {});
      }
      await rm(root, { recursive: true, force: true });
    }
  });

  test("exports a saved provisional model by scan prefix without starting Codex", async () => {
    const root = await mkdtemp(join(tmpdir(), "codex-security-export-model-"));
    const { stdout, stderr, runCli } = createCliTest(main);

    const calls: string[][] = [];
    const deps = dependencies({
      onWorkbench: (args) => {
        calls.push([...args]);
        return {
          scan: {
            scanId: "scan-provisional",
            scanDir: root,
            progress: { status: "running" },
          },
        };
      },
    });
    deps.createSecurity = () => {
      throw new Error("must not initialize Codex");
    };
    let selected: Record<string, unknown> | undefined;
    deps.exportFindings = async (args) => {
      selected = { ...args };
      return Buffer.from("# Retained model\n");
    };
    try {
      expect(
        await runCli(
          [
            "export",
            "--scan",
            "scan-prov",
            "--artifact",
            "threat-model",
            "--output",
            "-",
          ],
          deps,
        ),
      ).toBe(0);
      expect(selected).toMatchObject({
        scanDir: root,
        artifact: "threat-model",
        format: "md",
        output: "-",
      });
      expect(calls).toEqual([
        [
          "export-findings",
          "--scan-id",
          "scan-prov",
          "--artifact",
          "threat-model",
          "--format",
          "md",
          "--validate-only",
        ],
      ]);
      expect(stdout.text()).toBe("# Retained model\n");
      expect(stderr.text()).toBe("");
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  test("defaults model exports to threatmodel.md and findings to results.sarif", async () => {
    const root = await mkdtemp(
      join(tmpdir(), "codex-security-export-default-"),
    );
    const deps = dependencies();
    deps.currentDirectory = () => root;
    const selected: Record<string, unknown>[] = [];
    deps.exportFindings = async (args) => {
      selected.push({ ...args });
      return undefined;
    };
    try {
      expect(
        await runCapturedCli(
          main,
          ["export", "saved", "--artifact", "threat-model"],
          deps,
        ),
      ).toBe(0);
      expect(await runCapturedCli(main, ["export", "saved"], deps)).toBe(0);
      expect(selected).toMatchObject([
        {
          artifact: "threat-model",
          format: "md",
          output: join(root, "threatmodel.md"),
        },
        {
          artifact: "findings",
          format: "sarif",
          output: join(root, "results.sarif"),
        },
      ]);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  test("rejects ambiguous sources, incompatible formats, and Markdown in JSON stdout", async () => {
    for (const [args, expected] of [
      [["saved", "--scan", "scan-id"], "--scan cannot be combined"],
      [
        ["saved", "--artifact", "threat-model", "--export-format", "json"],
        "only support --export-format md",
      ],
      [
        ["saved", "--artifact", "threat-model", "--export-format", "sarif"],
        "only support --export-format md",
      ],
      [["saved", "--export-format", "md"], "Findings exports support"],
      [
        ["saved", "--artifact", "threat-model", "--output", "-", "--json"],
        "Markdown stdout cannot",
      ],
    ] as const) {
      const stderr = captureCli(main, "stderr");
      const deps = dependencies();
      deps.exportFindings = async () => {
        throw new Error("must not export invalid input");
      };
      expect(await stderr.run(["export", ...args], deps)).toBe(2);
      expect(stderr.text()).toContain(expected);
    }
  });

  test("waits for delayed stdout writes without closing the destination", async () => {
    let contents = "";
    const stdout = new Writable({
      write(chunk, _encoding, callback) {
        setTimeout(() => {
          contents += chunk.toString();
          callback();
        }, 20);
      },
    });

    try {
      expect(
        await main(
          ["export", "scan", "--export-format", "json", "--output", "-"],
          stdout,
          capture().stream,
          dependencies(),
        ),
      ).toBe(0);
      expect(contents).toBe('{"documentType":"codex-security.findings"}\n');
      expect(stdout.writableEnded).toBe(false);
    } finally {
      stdout.destroy();
    }
  });

  test.skipIf(process.platform === "win32")(
    "streams a large stdout export through a slow destination without buffering or status noise",
    async () => {
      const root = await temporaryDirectory("codex-security-export-stream-");
      const fakePython = join(root, "fake-python");
      const expectedBytes = 2 * 1024 * 1024;
      await writeFile(
        fakePython,
        [
          "#!/bin/sh",
          'if test "$1" = "-I" && test "$2" = "-c"; then printf "codex-security-python-ok\\n"; exit 0; fi',
          `exec ${JSON.stringify(process.execPath)} -e 'const chunk=Buffer.alloc(64*1024,97);let left=${expectedBytes};const write=()=>{while(left>0){const size=Math.min(left,chunk.length);left-=size;if(!process.stdout.write(chunk.subarray(0,size))){process.stdout.once("drain",write);return;}}};write();'`,
          "",
        ].join("\n"),
        { mode: 0o700 },
      );
      let bytes = 0;
      let writes = 0;
      const drains = mock(() => {});
      let emptyWrites = 0;
      const stdout = new Writable({
        highWaterMark: 32 * 1024,
        write(chunk, _encoding, callback) {
          if (chunk.length === 0) emptyWrites += 1;
          bytes += chunk.length;
          writes += 1;
          setTimeout(callback, 1);
        },
      });
      stdout.on("drain", drains);
      const stderr = capture();

      try {
        expect(
          await main(
            [
              "export",
              "scan",
              "--export-format",
              "json",
              "--output",
              "-",
              "--python",
              fakePython,
            ],
            stdout,
            stderr.stream,
          ),
        ).toBe(0);
        expect(bytes).toBe(expectedBytes);
        expect(writes).toBeGreaterThan(1);
        expect(drains.mock.calls.length).toBeGreaterThan(0);
        expect(emptyWrites).toBe(0);
        expect(stderr.text()).toBe("");

        const lightweight = capture();
        expect(
          await main(
            [
              "export",
              "scan",
              "--export-format",
              "json",
              "--output",
              "-",
              "--python",
              fakePython,
            ],
            lightweight.stream,
            capture().stream,
          ),
        ).toBe(0);
        expect(lightweight.text()).toHaveLength(expectedBytes);
      } finally {
        stdout.destroy();
        await rm(root, { recursive: true, force: true });
      }
    },
    30_000,
  );

  for (const [failure, diagnostic] of [
    ["an asynchronous write fails", "SYNTHETIC_ASYNC_EPIPE"],
    [
      "the destination cannot report backpressure",
      "cannot report backpressure safely",
    ],
  ] as const) {
    test.skipIf(process.platform === "win32")(
      `terminates a stdout exporter promptly when ${failure}`,
      async () => {
        const root = await temporaryDirectory("codex-security-export-fail-");
        const fakePython = join(root, "fake-python");
        await writeFile(
          fakePython,
          [
            "#!/bin/sh",
            'if test "$1" = "-I" && test "$2" = "-c"; then printf "codex-security-python-ok\\n"; exit 0; fi',
            'printf "small export\\n"; sleep 8',
            "",
          ].join("\n"),
          { mode: 0o700 },
        );
        let writes = 0;
        const stdout =
          failure === "an asynchronous write fails"
            ? new Writable({
                highWaterMark: 1024 * 1024,
                write(_chunk, _encoding, callback) {
                  writes += 1;
                  setTimeout(() => callback(new Error(diagnostic)), 30);
                },
              })
            : { write: () => false };
        const stderr = capture();

        try {
          const result = await Promise.race([
            main(
              [
                "export",
                "scan",
                "--export-format",
                "json",
                "--output",
                "-",
                "--python",
                fakePython,
              ],
              stdout,
              stderr.stream,
            ),
            new Promise<"timeout">((resolve) =>
              setTimeout(() => resolve("timeout"), 3_000),
            ),
          ]);
          expect(result).toBe(2);
          if (stdout instanceof Writable) expect(writes).toBe(1);
          expect(stderr.text()).toContain(diagnostic);
          expect(stderr.text()).not.toContain("JSON: -");
        } finally {
          if (stdout instanceof Writable) stdout.destroy();
          await rm(root, { recursive: true, force: true });
        }
      },
      30_000,
    );
  }

  test.skipIf(process.platform === "win32")(
    "terminates a stdout exporter promptly when the destination fails under backpressure",
    async () => {
      const root = await temporaryDirectory("codex-security-export-fail-");
      const fakePython = join(root, "fake-python");
      await writeFile(
        fakePython,
        [
          "#!/bin/sh",
          'if test "$1" = "-I" && test "$2" = "-c"; then printf "codex-security-python-ok\\n"; exit 0; fi',
          `exec ${JSON.stringify(process.execPath)} -e 'const chunk=Buffer.alloc(64*1024,97);let left=4*1024*1024;const write=()=>{while(left>0){left-=chunk.length;if(!process.stdout.write(chunk)){process.stdout.once("drain",write);return;}}};write();'`,
          "",
        ].join("\n"),
        { mode: 0o700 },
      );
      let writes = 0;
      const stdout = new Writable({
        highWaterMark: 32 * 1024,
        write(_chunk, _encoding, callback) {
          writes += 1;
          callback(new Error("SYNTHETIC_STDOUT_WRITE_FAILED"));
        },
      });
      const stderr = capture();

      try {
        const result = await Promise.race([
          main(
            [
              "export",
              "scan",
              "--export-format",
              "json",
              "--output",
              "-",
              "--python",
              fakePython,
            ],
            stdout,
            stderr.stream,
          ),
          new Promise<"timeout">((resolve) =>
            setTimeout(() => resolve("timeout"), 3_000),
          ),
        ]);
        expect(result).toBe(2);
        expect(writes).toBe(1);
        expect(stderr.text()).toContain("SYNTHETIC_STDOUT_WRITE_FAILED");
        expect(stderr.text()).not.toContain("JSON: -");
      } finally {
        stdout.destroy();
        await rm(root, { recursive: true, force: true });
      }
    },
    30_000,
  );

  test.each([
    ["complete", false],
    ["partial", true],
    ["unknown", true],
    ["partial", false],
    ["unknown", false],
  ] as const)("exports %s, deferred: %j", async (completeness, hasDeferred) => {
    const directory = await temporaryDirectory("codex-security-export-");
    try {
      const scan = await copyCompletedScan(directory);
      const manifestPath = join(scan, "scan-manifest.json");
      const manifest = JSON.parse(
        await readFile(manifestPath, "utf8"),
      ) as ScanManifest;
      const coveragePath = join(scan, manifest.scan.coverageRef);
      const coverage = JSON.parse(
        await readFile(coveragePath, "utf8"),
      ) as CoverageDocument;
      coverage.completeness = completeness;
      coverage.deferred = hasDeferred
        ? [
            { id: "review", reason: "Source review did not finish." },
            { id: "validation", reason: "Validation did not finish." },
          ]
        : [];
      const coverageBytes = JSON.stringify(coverage);
      await writeFile(coveragePath, coverageBytes);
      manifest.scan.artifacts.find(
        (artifact) => artifact.path === manifest.scan.coverageRef,
      )!.sha256 = createHash("sha256").update(coverageBytes).digest("hex");
      await writeFile(manifestPath, JSON.stringify(manifest));

      const paths = [
        manifestPath,
        join(scan, manifest.scan.findingsRef),
        coveragePath,
      ];
      const before = await Promise.all(paths.map((path) => readFile(path)));
      const source = JSON.parse(before[1]!.toString()).findings[0];
      for (const [format, filename] of [
        ["csv", "findings.csv"],
        ["json", "findings.json"],
        ["sarif", "results.sarif"],
      ] as const) {
        const stdout = capture();
        const stderr = capture();
        const output = join(directory, filename);
        expect(
          await main(
            ["export", scan, "--export-format", format, "--output", output],
            stdout.stream,
            stderr.stream,
          ),
        ).toBe(0);
        const contents = await readFile(output, "utf8");
        if (format === "csv") {
          expect(contents).toContain("occurrence_id,finding_id,");
        } else if (format === "json") {
          expect(JSON.parse(contents)).toMatchObject({
            documentType: "codex-security.findings",
          });
        } else {
          const sarif = JSON.parse(contents);
          expect(sarif.version).toBe("2.1.0");
          const run = sarif.runs[0];
          expect(run.properties.codexSecurityCoverageCompleteness).toBe(
            completeness === "complete" ? undefined : completeness,
          );
          if (completeness === "complete") {
            expect(run.invocations).toBeUndefined();
          } else {
            expect(run.invocations).toHaveLength(1);
            const invocation = run.invocations[0];
            expect(invocation.executionSuccessful).toBe(true);
            expect(invocation.toolExecutionNotifications).toEqual(
              coverage.deferred.map(({ reason: text }) => ({
                level: "warning",
                message: { text },
              })),
            );
          }
          expect(run.tool.driver.rules[0]).toMatchObject({
            id: source.ruleId,
            help: { markdown: expect.stringContaining(source.remediation) },
            properties: {
              "security-severity": "8.1",
              tags: expect.arrayContaining([
                "security",
                "external/cwe/cwe-022",
              ]),
            },
          });
          expect(run.results).toHaveLength(1);
          expect(run.results[0]).toMatchObject({
            ruleId: source.ruleId,
            message: { text: expect.stringContaining(source.remediation) },
            partialFingerprints: {
              "codexSecurity/v1": source.fingerprints.primary,
            },
          });
        }
        if (process.platform !== "win32")
          expect((await stat(output)).mode & 0o777).toBe(0o600);
        expect(stdout.text()).toBe("");
        expect(stderr.text()).toBe(`${format.toUpperCase()}: ${output}\n`);
      }
      expect(manifest.scan.status).toBe("completed");
      expect(await Promise.all(paths.map((path) => readFile(path)))).toEqual(
        before,
      );
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  });

  test("expands home-relative export paths", async () => {
    const root = await temporaryDirectory("codex-security-export-home-");
    const home = join(root, "home");
    const currentDirectory = join(root, "current");
    const previousHome = process.env["HOME"];
    const previousUserProfile = process.env["USERPROFILE"];
    try {
      await mkdir(home);
      await mkdir(currentDirectory);
      const scan = await copyCompletedScan(home);
      const sourceRoot = join(home, "source");
      await mkdir(sourceRoot);
      process.env["HOME"] = home;
      process.env["USERPROFILE"] = home;

      const deps = dependencies({ currentDirectory });
      const exports = mock<typeof deps.exportFindings>(resolving(undefined));
      deps.exportFindings = exports;
      expect(
        await runCapturedCli(
          main,
          [
            "export",
            "~/scan",
            "--export-format",
            "sarif",
            "--output",
            "~/findings.sarif",
            "--source-root",
            "~/source",
          ],
          deps,
        ),
      ).toBe(0);
      expect(exports.mock.calls.map(([value]) => value)).toEqual([
        expect.objectContaining({
          scanDir: await realpath(scan),
          output: join(await realpath(home), "findings.sarif"),
          sourceRoot,
        }),
      ]);
    } finally {
      if (previousHome === undefined) delete process.env["HOME"];
      else process.env["HOME"] = previousHome;
      if (previousUserProfile === undefined) delete process.env["USERPROFILE"];
      else process.env["USERPROFILE"] = previousUserProfile;
      await rm(root, { recursive: true, force: true });
    }
  });

  test("explains a missing export-output directory", async () => {
    const root = await temporaryDirectory("codex-security-export-missing-");
    try {
      const output = join(root, "reports", "results.sarif");
      const stderr = captureCli(main, "stderr");
      expect(
        await stderr.run(
          ["export", "scan", "--output", output],
          dependencies(),
        ),
      ).toBe(2);
      expect(stderr.text()).toContain(
        `Export output directory does not exist: ${join(root, "reports")}`,
      );
      expect(stderr.text()).toContain("Create the directory and retry");
      expect(stderr.text()).not.toContain("ENOENT");
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  test("rejects a repository-controlled output symlink without following it", async () => {
    const directory = await temporaryDirectory("codex-security-export-");
    try {
      const scan = await copyCompletedScan(directory);
      const outside = join(directory, "outside.txt");
      const output = join(directory, "results.sarif");
      await writeFile(outside, "unchanged\n");
      await symlink(outside, output);
      const stderr = capture();
      expect(
        await main(
          ["export", scan, "--output", output],
          capture().stream,
          stderr.stream,
        ),
      ).toBe(2);
      expect(await readFile(outside, "utf8")).toBe("unchanged\n");
      expect((await lstat(output)).isSymbolicLink()).toBe(true);
      expect(stderr.text()).toMatch(
        /codex-security: results\.sarif: (?:expected a regular non-symlink file|\[Errno 22\] scan-local files must not be reparse points)/u,
      );
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  });

  test("passes the canonical scan directory to the exporter", async () => {
    const directory = await temporaryDirectory("codex-security-export-");
    try {
      const actual = join(directory, "actual");
      const linked = join(directory, "linked");
      const scan = join(actual, "scan");
      await mkdir(scan, { recursive: true });
      await symlink(actual, linked, "dir");
      for (const output of ["-", join(directory, "results.sarif")] as const) {
        const deps = dependencies();
        let received = "";
        deps.exportFindings = async (arguments_) => {
          received = arguments_.scanDir;
          return new TextEncoder().encode('{"version":"2.1.0"}\n');
        };
        expect(
          await runCapturedCli(
            main,
            ["export", join(linked, "scan"), "--output", output],
            deps,
          ),
        ).toBe(0);
        expect(received).toBe(await realpath(scan));
      }
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  });

  test("creates the optional scan-local exports directory", async () => {
    const directory = await temporaryDirectory("codex-security-export-");
    try {
      const scan = await copyCompletedScan(directory);
      const output = join(scan, "exports", "results.sarif");
      expect(
        await main(
          ["export", scan, "--output", output],
          capture().stream,
          capture().stream,
        ),
      ).toBe(0);
      expect(JSON.parse(await readFile(output, "utf8"))).toMatchObject({
        version: "2.1.0",
      });
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  });

  test("exports through a symlinked output parent", async () => {
    const directory = await temporaryDirectory("codex-security-export-");
    try {
      const scan = await copyCompletedScan(directory);
      const actualOutput = join(directory, "actual-output");
      const linkedOutput = join(directory, "linked-output");
      const output = join(linkedOutput, "results.json");
      await mkdir(actualOutput);
      await writeFile(join(actualOutput, "results.json"), "old\n");
      await symlink(
        actualOutput,
        linkedOutput,
        process.platform === "win32" ? "junction" : "dir",
      );
      const stdout = capture();
      const stderr = capture();

      expect(
        await main(
          ["export", scan, "--export-format", "json", "--output", output],
          stdout.stream,
          stderr.stream,
        ),
      ).toBe(0);
      expect(
        JSON.parse(await readFile(join(actualOutput, "results.json"), "utf8")),
      ).toMatchObject({ documentType: "codex-security.findings" });
      expect(stdout.text()).toBe("");
      expect(stderr.text()).toBe(`JSON: ${output}\n`);
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  });

  test("rejects a symlinked output parent inside the scan directory", async () => {
    const directory = await temporaryDirectory("codex-security-export-");
    try {
      const scan = join(directory, "scan");
      const outside = join(directory, "outside");
      const linked = join(scan, "reports");
      await mkdir(scan);
      await mkdir(outside);
      await writeFile(join(outside, "results.json"), "unchanged\n");
      await symlink(
        outside,
        linked,
        process.platform === "win32" ? "junction" : "dir",
      );
      const stderr = captureCli(main, "stderr");

      expect(
        await stderr.run(
          [
            "export",
            scan,
            "--export-format",
            "json",
            "--output",
            join(linked, "results.json"),
          ],
          dependencies(),
        ),
      ).toBe(2);
      expect(await readFile(join(outside, "results.json"), "utf8")).toBe(
        "unchanged\n",
      );
      expect(stderr.text()).toContain(
        "The export output path cannot overwrite a scan artifact",
      );
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  });

  test("rejects a repository-controlled output-directory symlink", async () => {
    const directory = await temporaryDirectory("codex-security-export-");
    try {
      const scan = join(directory, "scan");
      const repository = join(directory, "repo");
      const outside = join(directory, "outside");
      await mkdir(scan);
      await mkdir(repository);
      await mkdir(outside);
      await symlink(
        outside,
        join(repository, "reports"),
        process.platform === "win32" ? "junction" : "dir",
      );
      const stderr = captureCli(main, "stderr");
      const deps = dependencies();
      deps.currentDirectory = () => repository;
      deps.exportFindings = async () => {
        throw new Error("must not export before rejecting the output path");
      };

      expect(
        await stderr.run(
          [
            "export",
            scan,
            "--output",
            join(repository, "reports", "results.sarif"),
          ],
          deps,
        ),
      ).toBe(2);
      expect(stderr.text()).toBe(
        "codex-security: The export output path cannot traverse a repository symlink.\n",
      );
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  });

  test("reports strict export failures without a stack trace", async () => {
    const { stdout, stderr, runCli } = createCliTest(main);

    const deps = dependencies();
    deps.exportFindings = async () => {
      throw new CodexSecurityError(
        "manifest.scan: SARIF projection requires a sealed scan",
      );
    };
    expect(await runCli(["export", "scan", "--output", "-"], deps)).toBe(2);
    expect(stdout.text()).toBe("");
    expect(stderr.text()).toBe(
      "codex-security: manifest.scan: SARIF projection requires a sealed scan\n",
    );
  });

  test("preserves caught export failures", async () => {
    const { stdout, stderr, runCli } = createCliTest(main);

    const deps = dependencies();
    deps.exportFindings = async () => {
      throw new CodexSecurityError(`export failed ${SYNTHETIC_CREDENTIALS}`);
    };

    expect(await runCli(["export", "scan", "--output", "-"], deps)).toBe(2);
    expect(stdout.text()).toBe("");
    expect(stderr.text()).toBe(
      `codex-security: export failed ${SYNTHETIC_CREDENTIALS}\n`,
    );
  });
});

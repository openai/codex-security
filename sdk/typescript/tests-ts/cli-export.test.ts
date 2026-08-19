import {
  chmod,
  cp,
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
import { describe, expect, test } from "bun:test";
import { exportEnvironment, main } from "../src/cli.js";
import { CodexSecurityError } from "../src/index.js";
import {
  SYNTHETIC_CREDENTIALS,
  capture,
  dependencies,
} from "./cli-fixtures.js";
import { PLUGIN_ROOT } from "./plugin-root.js";

async function copyCompletedScan(root: string): Promise<string> {
  const scan = join(root, "scan");
  await cp(join(PLUGIN_ROOT, "examples", "completed-scan"), scan, {
    recursive: true,
  });
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
      TMPDIR: "/tmp",
    });
  });

  test("exports findings to stdout without initializing Codex", async () => {
    for (const [format, expected] of [
      ["csv", "occurrence_id,finding_id\n"],
      ["json", '{"documentType":"codex-security.findings"}\n'],
      ["sarif", '{"version":"2.1.0"}\n'],
    ] as const) {
      const stdout = capture();
      const stderr = capture();
      const deps = dependencies();
      deps.createSecurity = () => {
        throw new Error("must not initialize Codex");
      };
      expect(
        await main(
          ["export", "scan", "--export-format", format, "--output", "-"],
          stdout.stream,
          stderr.stream,
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
      onWorkbench: () => ({ scans: [{ scanId: "latest-scan", scanDir }] }),
    });
    let exportedScanDir = "";
    deps.exportFindings = async (arguments_) => {
      exportedScanDir = arguments_.scanDir;
      return new Uint8Array();
    };

    expect(
      await main(
        ["export", "--output", "-"],
        capture().stream,
        capture().stream,
        deps,
      ),
    ).toBe(0);
    expect(exportedScanDir).toBe(scanDir);
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
      const root = await mkdtemp(
        join(tmpdir(), "codex-security-export-stream-"),
      );
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
      let drains = 0;
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
      stdout.on("drain", () => {
        drains += 1;
      });
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
        expect(drains).toBeGreaterThan(0);
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
        const root = await mkdtemp(
          join(tmpdir(), "codex-security-export-fail-"),
        );
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
      const root = await mkdtemp(join(tmpdir(), "codex-security-export-fail-"));
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

  test("writes exported findings to the requested file", async () => {
    const directory = await mkdtemp(join(tmpdir(), "codex-security-export-"));
    try {
      const scan = await copyCompletedScan(directory);
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
          expect(JSON.parse(contents)).toMatchObject({ version: "2.1.0" });
        }
        if (process.platform !== "win32")
          expect((await stat(output)).mode & 0o777).toBe(0o600);
        expect(stdout.text()).toBe("");
        expect(stderr.text()).toBe(`${format.toUpperCase()}: ${output}\n`);
      }
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  });

  test("expands home-relative export paths", async () => {
    const root = await mkdtemp(join(tmpdir(), "codex-security-export-home-"));
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

      const exports: Array<{
        scanDir: string;
        output: string;
        sourceRoot?: string;
      }> = [];
      const deps = dependencies({ currentDirectory });
      deps.exportFindings = async (arguments_) => {
        exports.push(arguments_);
        return undefined;
      };
      expect(
        await main(
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
          capture().stream,
          capture().stream,
          deps,
        ),
      ).toBe(0);
      expect(exports).toEqual([
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
    const root = await mkdtemp(
      join(tmpdir(), "codex-security-export-missing-"),
    );
    try {
      const output = join(root, "reports", "results.sarif");
      const stderr = capture();
      expect(
        await main(
          ["export", "scan", "--output", output],
          capture().stream,
          stderr.stream,
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
    const directory = await mkdtemp(join(tmpdir(), "codex-security-export-"));
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
    const directory = await mkdtemp(join(tmpdir(), "codex-security-export-"));
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
          await main(
            ["export", join(linked, "scan"), "--output", output],
            capture().stream,
            capture().stream,
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
    const directory = await mkdtemp(join(tmpdir(), "codex-security-export-"));
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
    const directory = await mkdtemp(join(tmpdir(), "codex-security-export-"));
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
    const directory = await mkdtemp(join(tmpdir(), "codex-security-export-"));
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
      const stderr = capture();

      expect(
        await main(
          [
            "export",
            scan,
            "--export-format",
            "json",
            "--output",
            join(linked, "results.json"),
          ],
          capture().stream,
          stderr.stream,
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
    const directory = await mkdtemp(join(tmpdir(), "codex-security-export-"));
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
      const stderr = capture();
      const deps = dependencies();
      deps.currentDirectory = () => repository;
      deps.exportFindings = async () => {
        throw new Error("must not export before rejecting the output path");
      };

      expect(
        await main(
          [
            "export",
            scan,
            "--output",
            join(repository, "reports", "results.sarif"),
          ],
          capture().stream,
          stderr.stream,
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
    const stdout = capture();
    const stderr = capture();
    const deps = dependencies();
    deps.exportFindings = async () => {
      throw new CodexSecurityError(
        "manifest.scan: SARIF projection requires a sealed scan",
      );
    };
    expect(
      await main(
        ["export", "scan", "--output", "-"],
        stdout.stream,
        stderr.stream,
        deps,
      ),
    ).toBe(2);
    expect(stdout.text()).toBe("");
    expect(stderr.text()).toBe(
      "codex-security: manifest.scan: SARIF projection requires a sealed scan\n",
    );
  });

  test("preserves caught export failures", async () => {
    const stdout = capture();
    const stderr = capture();
    const deps = dependencies();
    deps.exportFindings = async () => {
      throw new CodexSecurityError(`export failed ${SYNTHETIC_CREDENTIALS}`);
    };

    expect(
      await main(
        ["export", "scan", "--output", "-"],
        stdout.stream,
        stderr.stream,
        deps,
      ),
    ).toBe(2);
    expect(stdout.text()).toBe("");
    expect(stderr.text()).toBe(
      `codex-security: export failed ${SYNTHETIC_CREDENTIALS}\n`,
    );
  });
});

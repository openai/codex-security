import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdir, mkdtemp, realpath, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { expect, mock, test } from "bun:test";
import { runTestInSubprocess } from "./support/test-subprocess.js";

test.each(["native", "win32"] as const)(
  "requirements filename casing preserves input coverage (%s)",
  async (platform) => {
    const name = `requirements filename casing preserves input coverage (${platform})`;
    if (runTestInSubprocess(import.meta.path, name)) return;
    const { additionalScaFormat, inspectAdditionalScaInput, scaInputBasename } =
      await import("../src/sca-inputs.js");
    // Only the filename predicate observes the simulated platform. Filesystem,
    // Git, path handling, and process execution retain their native behavior.
    if (platform === "win32") {
      mock.module("../src/sca-inputs.js", () => ({
        additionalScaFormat: (path: string) => {
          const descriptor = Object.getOwnPropertyDescriptor(
            process,
            "platform",
          )!;
          Object.defineProperty(process, "platform", {
            ...descriptor,
            value: platform,
          });
          try {
            return additionalScaFormat(path);
          } finally {
            Object.defineProperty(process, "platform", descriptor);
          }
        },
        inspectAdditionalScaInput,
        scaInputBasename,
      }));
    }
    const { discoverScaInputs, runOsvScan } = await import("../src/sca-osv.js");
    const windows = platform === "win32" || process.platform === "win32";
    const root = await realpath(await mkdtemp(join(tmpdir(), "sca-casing-")));
    const content = "synthetic-py==1.2.0\n";
    const digest = createHash("sha256").update(content).digest("hex");
    const mixed = [
      "capital/Requirements.txt",
      "extension/requirements.TXT",
      "both/REQUIREMENTS-PROD.TXT",
    ];
    const ordinary = [
      "ordinary/requirements.txt",
      "dev/requirements-dev.txt",
      "prefixed/my-requirements.txt",
    ];
    const excluded = [
      "node_modules/synthetic/Requirements.txt",
      ".venv/lib/requirements.TXT",
      "node_modules/synthetic/requirements.txt",
      "notes.txt",
      "requirements.in",
      "required.txt",
    ];
    const lock = JSON.stringify({
      lockfileVersion: 3,
      packages: { "node_modules/synthetic-lib": { version: "1.2.0" } },
    });
    try {
      for (const mode of ["non-Git", "untracked", "tracked", "subtree"]) {
        const checkout = join(root, mode, "checkout");
        const selected =
          mode === "subtree" ? join(checkout, "selected") : checkout;
        await mkdir(selected, { recursive: true });
        if (mode !== "non-Git")
          execFileSync("git", ["init", "--quiet", checkout]);
        for (const path of [...mixed, ...ordinary, ...excluded]) {
          await mkdir(dirname(join(selected, path)), { recursive: true });
          await writeFile(join(selected, path), content);
        }
        if (mode === "subtree") {
          await mkdir(join(checkout, "sibling"));
          await writeFile(
            join(checkout, "sibling", "Requirements.txt"),
            content,
          );
        }
        if (mode === "tracked" || mode === "subtree")
          execFileSync("git", ["-C", checkout, "add", "."]);
        const discovered = await discoverScaInputs(selected);
        expect(discovered.inputs).toEqual(
          [...ordinary, ...(windows ? mixed : [])].sort().map((path) => ({
            path,
            sha256: digest,
            format: "requirements",
            status: "scanned",
            reason: null,
          })),
        );
      }
      const repository = join(root, "scan");
      await mkdir(repository);
      await writeFile(join(repository, "package-lock.json"), lock);
      await writeFile(join(repository, "Requirements.txt"), content);
      execFileSync("git", ["init", "--quiet", repository]);
      execFileSync("git", ["-C", repository, "add", "."]);
      const result = await runOsvScan(
        { repositoryPath: repository, outputDir: join(root, "output") },
        {
          executable: process.execPath,
          runProcess: async (_executable, argv) => {
            if (argv[0] === "--version")
              return { stdout: "2.6.0", stderr: "", exitCode: 0 };
            const path = argv.at(-1)!;
            // Pinned OSV also compares requirements names case-sensitively.
            if (path.endsWith("Requirements.txt"))
              return {
                stdout: "",
                stderr:
                  "No package sources found, --help for usage information.",
                exitCode: 128,
              };
            return {
              stdout: JSON.stringify({
                results: [
                  {
                    source: { path, type: "lockfile" },
                    packages: [
                      {
                        package: {
                          name: "synthetic-lib",
                          version: "1.2.0",
                          ecosystem: "npm",
                        },
                        vulnerabilities: [],
                      },
                    ],
                  },
                ],
              }),
              stderr: "",
              exitCode: 0,
            };
          },
        },
      );
      expect(result.coverage.inputs.map((input) => input.path)).toEqual(
        windows
          ? ["Requirements.txt", "package-lock.json"]
          : ["package-lock.json"],
      );
      expect(result.status).toBe(windows ? "partial" : "completed");
      expect(result.coverage.status).toBe(windows ? "partial" : "complete");
      expect(result.components).toHaveLength(1);
      if (windows) {
        expect(result.coverage.inputs[0]).toMatchObject({
          path: "Requirements.txt",
          sha256: digest,
          format: "requirements",
          status: "failed",
        });
        expect(
          result.diagnostics.some((message) =>
            message.includes("Requirements.txt"),
          ),
        ).toBe(true);
        expect(result.scanner.invocations?.[0]?.argv.at(-1)).toBe(
          join(repository, "Requirements.txt"),
        );
      }
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  },
);

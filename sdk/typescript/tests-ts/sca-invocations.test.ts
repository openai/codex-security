import {
  mkdir,
  mkdtemp,
  readFile,
  realpath,
  rm,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, relative, sep } from "node:path";
import { afterEach, expect, test } from "bun:test";
import { runOsvScan, type OsvScanResult } from "../src/sca-osv.js";

const directories: string[] = [];
afterEach(async () => {
  await Promise.all(
    directories
      .splice(0)
      .map((path) => rm(path, { recursive: true, force: true })),
  );
});
const lockfile = (local = false) =>
  JSON.stringify({
    lockfileVersion: 3,
    packages: {
      "node_modules/synthetic-lib": {
        version: "1.2.0",
        ...(local ? { resolved: "file:../local-lib.tgz" } : {}),
      },
    },
  });
async function setup(paths: string[], local = false) {
  const root = await realpath(
    await mkdtemp(join(tmpdir(), "sca-invocations-")),
  );
  directories.push(root);
  const repository = join(root, "repository, with commas");
  const output = join(root, "output");
  for (const path of paths) {
    await mkdir(join(repository, path, ".."), { recursive: true });
    await writeFile(join(repository, path), lockfile(local));
  }
  return { repository, output };
}
function outputFor(path: string) {
  return JSON.stringify({
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
            vulnerabilities: [{ id: "SYNTHETIC-ADVISORY" }],
          },
        ],
      },
    ],
  });
}
const version = {
  stdout: "osv-scanner version: 2.6.0",
  stderr: "",
  exitCode: 0,
};

test("passes comma-bearing filenames literally, retaining each invocation before merging final artifacts", async () => {
  const paths = [
    "-nested, workspace/package-lock.json",
    "another, workspace/package-lock.json",
  ];
  const { repository, output } = await setup(paths);
  const calls: string[][] = [];
  const result = await runOsvScan(
    { repositoryPath: repository, outputDir: output },
    {
      executable: process.execPath,
      runProcess: async (_executable, argv) => {
        calls.push(argv);
        if (calls.length === 3) {
          expect(
            await readFile(join(output, "osv-invocation-1.json"), "utf8"),
          ).toBe(outputFor(calls[1]!.at(-1)!));
          expect(
            await readFile(join(output, "osv-invocation-1.stderr.log"), "utf8"),
          ).toBe(`Synthetic receipt: ${calls[1]!.at(-1)}`);
          expect(await readFile(join(output, "osv-output.json"), "utf8")).toBe(
            "",
          );
          expect(await readFile(join(output, "osv-stderr.log"), "utf8")).toBe(
            "",
          );
        }
        return argv[0] === "--version"
          ? version
          : {
              stdout: outputFor(argv.at(-1)!),
              stderr: `Synthetic receipt: ${argv.at(-1)}`,
              exitCode: 1,
            };
      },
    },
  );
  expect(result.status).toBe("completed");
  expect(calls.filter((argv) => argv[0] === "--version")).toHaveLength(1);
  expect(result.scanner.argv).toEqual(calls[1]!);
  expect(
    result.scanner.invocations?.map((invocation) => invocation.argv),
  ).toEqual(calls.slice(1));
  expect(
    result.components.map((component) => component.sourcePath).sort(),
  ).toEqual(paths);
  for (const [index, invocation] of result.scanner.invocations!.entries()) {
    expect(invocation.argv.slice(-2)).toEqual([
      "--",
      join(repository, paths[index]!),
    ]);
    expect(await readFile(invocation.rawOutputPath, "utf8")).toBe(
      outputFor(invocation.argv.at(-1)!),
    );
    expect(invocation.exitCode).toBe(1);
  }
  expect(
    JSON.parse(await readFile(result.scanner.rawOutputPath, "utf8")).results,
  ).toHaveLength(2);
  expect(await readFile(result.scanner.stderrPath, "utf8")).toContain(
    "Synthetic receipt:",
  );
});

test.skipIf(process.platform === "win32")(
  "recognizes OSV empty-input receipts for literal CR/LF paths",
  async () => {
    const paths = [
      "empty\nline\rreturn/package-lock.json",
      "normal/package-lock.json",
    ];
    const { repository, output } = await setup(paths);
    await writeFile(
      join(repository, paths[0]!),
      JSON.stringify({ lockfileVersion: 3, packages: {} }),
    );
    // OSV-Scanner 2.6.0 encodes CR/LF in extraction receipts.
    const emptyReceipt = `Scanned ${join(repository, "empty%0Aline%0Dreturn/package-lock.json")} file and found 0 packages\n`;
    const result = await runOsvScan(
      { repositoryPath: repository, outputDir: output },
      {
        executable: process.execPath,
        runProcess: async (_executable, argv) => {
          if (argv[0] === "--version") return version;
          return argv.at(-1) === join(repository, paths[0]!)
            ? { stdout: "", stderr: emptyReceipt, exitCode: 128 }
            : { stdout: outputFor(argv.at(-1)!), stderr: "", exitCode: 1 };
        },
      },
    );
    expect(result.status).toBe("completed");
    expect(result.coverage.status).toBe("complete");
    expect(result.coverage.inputs.map(({ status }) => status)).toEqual([
      "scanned",
      "scanned",
    ]);
    expect(result.components.map(({ sourcePath }) => sourcePath)).toEqual([
      paths[1]!,
    ]);
    expect(result.matches).toHaveLength(1);
    expect(result.diagnostics).toEqual([]);
    expect(result.scanner.exitCode).toBe(1);
    expect(result.scanner.invocations).toHaveLength(2);
    const empty = result.scanner.invocations![0]!;
    expect(empty.argv.at(-1)).toBe(join(repository, paths[0]!));
    expect(await readFile(empty.rawOutputPath, "utf8")).toBe("");
    expect(await readFile(empty.stderrPath, "utf8")).toBe(emptyReceipt);
  },
);

test("scans monorepo inputs whose combined argv would exceed the Windows command-line limit", async () => {
  const paths = Array.from(
    { length: 400 },
    (_, index) =>
      `workspace-${String(index).padStart(3, "0")}-${"long-name-".repeat(7)}/package-lock.json`,
  );
  const { repository, output } = await setup(paths);
  expect(
    paths.reduce((size, path) => size + join(repository, path).length + 3, 0),
  ).toBeGreaterThan(32767);
  const selections: string[] = [];
  const result = await runOsvScan(
    { repositoryPath: repository, outputDir: output },
    {
      executable: process.execPath,
      runProcess: async (_executable, argv) => {
        if (argv[0] === "--version") return version;
        expect(argv.slice(argv.indexOf("--") + 1)).toHaveLength(1);
        expect(
          [process.execPath, ...argv].map((arg) => `"${arg}"`).join(" ")
            .length + 1,
        ).toBeLessThanOrEqual(32767);
        selections.push(argv.at(-1)!);
        return { stdout: outputFor(argv.at(-1)!), stderr: "", exitCode: 1 };
      },
    },
  );
  expect(result.status).toBe("completed");
  expect(selections).toEqual(paths.map((path) => join(repository, path)));
  expect(result.components).toHaveLength(paths.length);
  expect(result.matches).toHaveLength(paths.length);
  expect(result.scanner.invocations).toHaveLength(paths.length);
  expect(
    JSON.parse(await readFile(result.scanner.rawOutputPath, "utf8")).results,
  ).toHaveLength(paths.length);
});

test.each([
  ["exit", 1],
  ["invalid-json", 0],
  ["invalid-json", 1],
  ["failure", 1],
  ["cancel", 1],
] as const)(
  "retains independent inputs and partial evidence after %s at input %d",
  async (failure, failedIndex) => {
    const paths = [
      "a/package-lock.json",
      "b/package-lock.json",
      "c/package-lock.json",
    ];
    const { repository, output } = await setup(paths);
    const controller = new AbortController();
    let scanned = 0;
    const operation = runOsvScan(
      {
        repositoryPath: repository,
        outputDir: output,
        signal: controller.signal,
      },
      {
        executable: process.execPath,
        runProcess: async (_executable, argv, options) => {
          if (argv[0] === "--version") return version;
          scanned++;
          const stdout = outputFor(argv.at(-1)!);
          if (scanned === failedIndex + 1) {
            if (failure === "invalid-json")
              return {
                stdout: "incomplete JSON",
                stderr: "Synthetic failure",
                exitCode: 127,
              };
            if (failure === "exit")
              return { stdout, stderr: "Synthetic failure", exitCode: 130 };
            await writeFile(options.stdoutPath!, stdout);
            await writeFile(
              options.stderrPath!,
              "Synthetic interrupted output",
            );
            if (failure === "cancel")
              controller.abort(new Error("requested stop"));
            throw new Error("Synthetic process failure");
          }
          return { stdout, stderr: "", exitCode: 1 };
        },
      },
    );
    const result =
      failure === "cancel"
        ? await operation.catch(
            (error: { osvResult: OsvScanResult }) => error.osvResult,
          )
        : await operation;
    expect(result.status).toBe("partial");
    expect(result.coverage.status).toBe("partial");
    const continues = failure === "exit" || failure === "invalid-json";
    const retained = failure === "exit" ? 3 : 2;
    expect(result.components).toHaveLength(retained);
    expect(result.matches).toHaveLength(retained);
    expect(scanned).toBe(continues ? 3 : 2);
    expect(result.scanner.invocations).toHaveLength(continues ? 3 : 2);
    expect(result.coverage.inputs.map((input) => input.status)).toEqual(
      paths.map((_, index) =>
        index === failedIndex || (!continues && index > failedIndex)
          ? "failed"
          : "scanned",
      ),
    );
    expect(
      JSON.parse(await readFile(result.scanner.rawOutputPath, "utf8")).results,
    ).toHaveLength(retained);
    for (const [index, invocation] of result.scanner.invocations!.entries()) {
      expect(await readFile(invocation.rawOutputPath, "utf8")).toBe(
        failure === "invalid-json" && index === failedIndex
          ? "incomplete JSON"
          : outputFor(join(repository, paths[index]!)),
      );
      expect(await readFile(invocation.stderrPath, "utf8")).toBe(
        index !== failedIndex
          ? ""
          : continues
            ? "Synthetic failure"
            : "Synthetic interrupted output",
      );
    }
    if (failure === "invalid-json")
      expect(result.diagnostics.join("\n")).toContain(paths[failedIndex]!);
    expect(result.scanner.exitCode).toBe(
      failure === "exit" ? 130 : failure === "invalid-json" ? 127 : null,
    );
  },
);

test("does not apply an exclusion receipt to the same local package in another source", async () => {
  const { repository, output } = await setup(
    ["a/package-lock.json", "b/package-lock.json"],
    true,
  );
  await writeFile(
    join(repository, "a", "osv-scanner.toml"),
    '[[PackageOverrides]]\nname="synthetic-lib"\nignore=true\n',
  );
  const result = await runOsvScan(
    { repositoryPath: repository, outputDir: output },
    {
      executable: process.execPath,
      runProcess: async (_executable, argv) => {
        if (argv[0] === "--version") return version;
        const source = relative(repository, argv.at(-1)!).split(sep).join("/");
        return source === "a/package-lock.json"
          ? {
              stdout: '{"results":[]}',
              stderr:
                "Package npm/synthetic-lib/1.2.0 has been filtered out because: synthetic exclusion\n",
              exitCode: 0,
            }
          : { stdout: outputFor(argv.at(-1)!), stderr: "", exitCode: 1 };
      },
    },
  );
  expect(result.status).toBe("partial");
  expect(result.coverage.unresolvedPackages).toBe(1);
  expect(result.components.map((component) => component.sourcePath)).toEqual([
    "b/package-lock.json",
  ]);
  expect(result.matches).toHaveLength(1);
});

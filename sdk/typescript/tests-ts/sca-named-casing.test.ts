import { hash } from "node:crypto";
import { link, mkdir } from "node:fs/promises";
import { join } from "node:path";
import { expect, mock, test } from "bun:test";
import type { ScaInput } from "../src/sca-types.js";
import { git } from "./git-fixture.js";
import { writeSource } from "./support/shell.js";
import { scopedTemporaryDirectory } from "./support/temporary-directories.js";
import { runTestInSubprocess } from "./support/test-subprocess.js";

const npm = JSON.stringify({
  lockfileVersion: 3,
  packages: { "node_modules/synthetic-lib": { version: "1.2.0" } },
});
const pins = "synthetic-py==1.2.0\n";

function fixture(
  name: string,
  format: ScaInput["format"],
  content: string,
  variant = name.toUpperCase(),
) {
  return { name, variant, format, content, sha256: hash("sha256", content) };
}

const fixtures = [
  fixture("package-lock.json", "npm", npm),
  fixture("npm-shrinkwrap.json", "npm", npm),
  fixture("pnpm-lock.yaml", "pnpm", "lockfileVersion: '9.0'\npackages: {}\n"),
  fixture("requirements.txt", "requirements", pins, "Requirements.txt"),
  fixture("requirements-dev.txt", "requirements", pins, "requirements.TXT"),
  fixture("my-requirements.txt", "requirements", pins, "REQUIREMENTS-PROD.TXT"),
  fixture(
    "go.mod",
    "go",
    "module example.test/application\ngo 1.20\nrequire example.test/synthetic-go v1.2.0\n",
    "Go.Mod",
  ),
  fixture(
    "Pipfile.lock",
    "pipenv",
    JSON.stringify({
      default: { "synthetic-py": { version: "==1.2.0" } },
      develop: {},
    }),
    "Pipfile.Lock",
  ),
  fixture(
    "dependency.pom",
    "maven",
    "<project><modelVersion>4.0.0</modelVersion><dependencies><dependency><groupId>example.test</groupId><artifactId>synthetic-java</artifactId><version>1.2.0</version></dependency></dependencies></project>",
    "dependency.POM",
  ),
];

function onWindows<T>(predicate: (path: string) => T) {
  return (path: string) => {
    const descriptor = Object.getOwnPropertyDescriptor(process, "platform")!;
    Object.defineProperty(process, "platform", {
      ...descriptor,
      value: "win32",
    });
    try {
      return predicate(path);
    } finally {
      Object.defineProperty(process, "platform", descriptor);
    }
  };
}

test.each(["native", "win32"] as const)(
  "dependency filenames preserve format and coverage (%s)",
  async (platform) => {
    const name = `dependency filenames preserve format and coverage (${platform})`;
    if (runTestInSubprocess(import.meta.path, name)) return;
    if (platform === "win32") {
      // Only filename comparisons see Windows. Git and filesystem I/O stay native.
      const { scaInputFormat, scaInputBasename, ...rest } =
        await import("../src/sca-inputs.js");
      mock.module("../src/sca-inputs.js", () => ({
        ...rest,
        scaInputFormat: onWindows(scaInputFormat),
        scaInputBasename: onWindows(scaInputBasename),
      }));
    }
    const { discoverScaInputs, runOsvScan } = await import("../src/sca-osv.js");
    const windows = platform === "win32" || process.platform === "win32";
    await using root = await scopedTemporaryDirectory("sca-casing-");
    for (const mode of ["non-Git", "untracked", "tracked", "subtree"]) {
      const checkout = join(root.path, mode);
      const repository =
        mode === "subtree" ? join(checkout, "selected") : checkout;
      await mkdir(repository, { recursive: true });
      if (mode !== "non-Git") git(checkout, "init", "--quiet");
      const expected: ScaInput[] = [];
      for (const [index, file] of fixtures.entries()) {
        for (const [group, filename] of [
          ["canonical", file.name],
          ["variant", file.variant],
          ["node_modules/library", file.variant],
          [".venv/lib", file.name],
        ]) {
          const path = `${group}/${index}/${filename}`;
          writeSource(repository, path, file.content);
          if (group === "canonical" || (group === "variant" && windows)) {
            expected.push({
              path,
              format: file.format,
              status: "scanned",
              reason: null,
              sha256: file.sha256,
            });
          }
        }
      }
      for (const filename of [
        "package-lock.json.backup",
        "other.lock",
        "synthetic.POM.backup",
        "node_modules/synthetic/requirements.txt",
        ".venv/lib/requirements.TXT",
        "notes.txt",
        "requirements.in",
        "required.txt",
      ])
        writeSource(repository, filename, pins);
      if (mode === "subtree") {
        writeSource(checkout, "sibling/package-lock.json", npm);
        writeSource(checkout, "sibling/Requirements.txt", pins);
      }
      if (mode === "tracked" || mode === "subtree") git(checkout, "add", ".");
      expect((await discoverScaInputs(repository)).inputs).toEqual(
        expected.sort((a, b) => a.path.localeCompare(b.path)),
      );
    }

    const precedence = join(root.path, "precedence");
    for (const path of [
      "package/PACKAGE-LOCK.JSON",
      "package/npm-shrinkwrap.json",
      "shrinkwrap/package-lock.json",
      "shrinkwrap/NPM-SHRINKWRAP.JSON",
    ])
      writeSource(precedence, path, npm);
    git(precedence, "init", "--quiet");
    git(precedence, "add", ".");
    // A hardlink models the canonical lookup on case-sensitive hosts.
    writeSource(precedence, ".gitignore", "shrinkwrap/npm-shrinkwrap.json\n");
    await link(
      join(precedence, "shrinkwrap", "NPM-SHRINKWRAP.JSON"),
      join(precedence, "shrinkwrap", "npm-shrinkwrap.json"),
    ).catch((error: NodeJS.ErrnoException) => {
      if (error.code !== "EEXIST") throw error;
    });
    const { inputs } = await discoverScaInputs(precedence);
    expect(
      inputs.map(({ path, format, status }) => [path, format, status]),
    ).toEqual(
      windows
        ? [
            ["package/PACKAGE-LOCK.JSON", "npm", "excluded"],
            ["package/npm-shrinkwrap.json", "npm", "scanned"],
            ["shrinkwrap/NPM-SHRINKWRAP.JSON", "npm", "scanned"],
            ["shrinkwrap/package-lock.json", "npm", "excluded"],
          ]
        : [
            ["package/npm-shrinkwrap.json", "npm", "scanned"],
            ["shrinkwrap/package-lock.json", "npm", "unsupported"],
          ],
    );

    const repository = join(root.path, "scan");
    const lock = "package-lock.json";
    writeSource(repository, lock, npm);
    const variants = fixtures.map(({ variant, format, content, sha256 }, i) => {
      const path =
        variant === "Requirements.txt" ? variant : `variants/${i}/${variant}`;
      writeSource(repository, path, content);
      return { path, format, sha256, status: "failed" };
    });
    git(repository, "init", "--quiet");
    git(repository, "add", ".");
    const result = await runOsvScan(
      { repositoryPath: repository, outputDir: join(root.path, "output") },
      {
        executable: process.execPath,
        runProcess: async (_executable, argv) => {
          if (argv[0] === "--version")
            return { stdout: "2.6.0", stderr: "", exitCode: 0 };
          const path = argv.at(-1)!;
          if (path !== join(repository, lock))
            return {
              stdout: "",
              stderr: "No package sources found, --help for usage information.",
              exitCode: 128,
            };
          const pkg = {
            name: "synthetic-lib",
            version: "1.2.0",
            ecosystem: "npm",
          };
          const source = { path, type: "lockfile" };
          const packages = [{ package: pkg, vulnerabilities: [] }];
          return {
            stdout: JSON.stringify({ results: [{ source, packages }] }),
            stderr: "",
            exitCode: 0,
          };
        },
      },
    );
    expect(result.status).toBe(windows ? "partial" : "completed");
    expect(result.coverage.status).toBe(windows ? "partial" : "complete");
    expect(result.components).toHaveLength(1);
    const paths = windows
      ? [lock, ...variants.map((v) => v.path)].sort()
      : [lock];
    expect(result.coverage.inputs.map((input) => input.path)).toEqual(paths);
    if (windows) {
      expect(
        result.scanner.invocations?.map((call) => call.argv.at(-1)),
      ).toEqual(paths.map((path) => join(repository, path)));
      expect(result.diagnostics.join("\n")).toContain("Requirements.txt");
      for (const variant of variants)
        expect(result.coverage.inputs).toContainEqual(
          expect.objectContaining(variant),
        );
    }
  },
);

import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  link,
  mkdir,
  mkdtemp,
  realpath,
  rm,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { expect, mock, test } from "bun:test";
import { runTestInSubprocess } from "./support/test-subprocess.js";

const npm = JSON.stringify({
  lockfileVersion: 3,
  packages: { "node_modules/synthetic-lib": { version: "1.2.0" } },
});
const fixtures = [
  {
    name: "package-lock.json",
    variant: "PACKAGE-LOCK.JSON",
    format: "npm",
    content: npm,
  },
  {
    name: "npm-shrinkwrap.json",
    variant: "NPM-SHRINKWRAP.JSON",
    format: "npm",
    content: npm,
  },
  {
    name: "pnpm-lock.yaml",
    variant: "PNPM-LOCK.YAML",
    format: "pnpm",
    content: "lockfileVersion: '9.0'\npackages: {}\n",
  },
  {
    name: "go.mod",
    variant: "Go.Mod",
    format: "go",
    content:
      "module example.test/application\ngo 1.20\nrequire example.test/synthetic-go v1.2.0\n",
  },
  {
    name: "Pipfile.lock",
    variant: "Pipfile.Lock",
    format: "pipenv",
    content: JSON.stringify({
      default: { "synthetic-py": { version: "==1.2.0" } },
      develop: {},
    }),
  },
  {
    name: "dependency.pom",
    variant: "dependency.POM",
    format: "maven",
    content:
      "<project><modelVersion>4.0.0</modelVersion><dependencies><dependency><groupId>example.test</groupId><artifactId>synthetic-java</artifactId><version>1.2.0</version></dependency></dependencies></project>",
  },
] as const;

test.each(["native", "win32"] as const)(
  "dependency filenames preserve format and coverage (%s)",
  async (platform) => {
    const name = `dependency filenames preserve format and coverage (${platform})`;
    if (runTestInSubprocess(import.meta.path, name)) return;
    const { additionalScaFormat, inspectAdditionalScaInput, scaInputBasename } =
      await import("../src/sca-inputs.js");
    if (platform === "win32") {
      const onWindows =
        <T>(predicate: (path: string) => T) =>
        (path: string) => {
          const descriptor = Object.getOwnPropertyDescriptor(
            process,
            "platform",
          )!;
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
      // Only filename comparisons see Windows. Git and filesystem I/O stay native.
      mock.module("../src/sca-inputs.js", () => ({
        additionalScaFormat: onWindows(additionalScaFormat),
        scaInputBasename: onWindows(scaInputBasename),
        inspectAdditionalScaInput,
      }));
    }
    const { discoverScaInputs, runOsvScan } = await import("../src/sca-osv.js");
    const windows = platform === "win32" || process.platform === "win32";
    const root = await realpath(
      await mkdtemp(join(tmpdir(), "sca-named-casing-")),
    );
    const git = (repository: string, ...args: string[]) =>
      execFileSync("git", ["-C", repository, ...args]);
    try {
      for (const mode of ["non-Git", "untracked", "tracked", "subtree"]) {
        const checkout = join(root, mode);
        const repository =
          mode === "subtree" ? join(checkout, "selected") : checkout;
        await mkdir(repository, { recursive: true });
        if (mode !== "non-Git") git(checkout, "init", "--quiet");
        const expected = [];
        for (const [index, fixture] of fixtures.entries()) {
          for (const [group, filename] of [
            ["canonical", fixture.name],
            ["variant", fixture.variant],
            ["node_modules/library", fixture.variant],
            [".venv/lib", fixture.name],
          ]) {
            const path = `${group}/${index}/${filename}`;
            await mkdir(dirname(join(repository, path)), { recursive: true });
            await writeFile(join(repository, path), fixture.content);
            if (group === "canonical" || (group === "variant" && windows))
              expected.push({
                path,
                format: fixture.format,
                status: "scanned" as const,
                reason: null,
                sha256: createHash("sha256")
                  .update(fixture.content)
                  .digest("hex"),
              });
          }
        }
        for (const filename of [
          "package-lock.json.backup",
          "other.lock",
          "synthetic.POM.backup",
        ])
          await writeFile(join(repository, filename), npm);
        if (mode === "subtree") {
          await mkdir(join(checkout, "sibling"));
          await writeFile(join(checkout, "sibling", "package-lock.json"), npm);
        }
        if (mode === "tracked" || mode === "subtree") git(checkout, "add", ".");
        expect((await discoverScaInputs(repository)).inputs).toEqual(
          expected.sort((a, b) => a.path.localeCompare(b.path)),
        );
      }

      const precedence = join(root, "precedence");
      await mkdir(precedence);
      git(precedence, "init", "--quiet");
      for (const [directory, packageName, shrinkwrapName] of [
        ["package", "PACKAGE-LOCK.JSON", "npm-shrinkwrap.json"],
        ["shrinkwrap", "package-lock.json", "NPM-SHRINKWRAP.JSON"],
      ] as const) {
        await mkdir(join(precedence, directory));
        await writeFile(join(precedence, directory, packageName!), npm);
        await writeFile(join(precedence, directory, shrinkwrapName!), npm);
        git(
          precedence,
          "add",
          `${directory}/${packageName}`,
          `${directory}/${shrinkwrapName}`,
        );
      }
      // A hardlink models the one canonical-name lookup on case-sensitive hosts.
      // On Windows the canonical name already resolves to this same file.
      await writeFile(
        join(precedence, ".gitignore"),
        "shrinkwrap/npm-shrinkwrap.json\n",
      );
      await link(
        join(precedence, "shrinkwrap", "NPM-SHRINKWRAP.JSON"),
        join(precedence, "shrinkwrap", "npm-shrinkwrap.json"),
      ).catch((error: NodeJS.ErrnoException) => {
        if (error.code !== "EEXIST") throw error;
      });
      const discovered = await discoverScaInputs(precedence);
      expect(
        discovered.inputs.map(({ path, format, status }) => ({
          path,
          format,
          status,
        })),
      ).toEqual(
        windows
          ? [
              {
                path: "package/PACKAGE-LOCK.JSON",
                format: "npm",
                status: "excluded",
              },
              {
                path: "package/npm-shrinkwrap.json",
                format: "npm",
                status: "scanned",
              },
              {
                path: "shrinkwrap/NPM-SHRINKWRAP.JSON",
                format: "npm",
                status: "scanned",
              },
              {
                path: "shrinkwrap/package-lock.json",
                format: "npm",
                status: "excluded",
              },
            ]
          : [
              {
                path: "package/npm-shrinkwrap.json",
                format: "npm",
                status: "scanned",
              },
              {
                path: "shrinkwrap/package-lock.json",
                format: "npm",
                status: "unsupported",
              },
            ],
      );

      const repository = join(root, "scan");
      await mkdir(join(repository, "ordinary"), { recursive: true });
      await writeFile(join(repository, "ordinary", "package-lock.json"), npm);
      for (const fixture of fixtures) {
        await mkdir(join(repository, fixture.name));
        await writeFile(
          join(repository, fixture.name, fixture.variant),
          fixture.content,
        );
      }
      git(repository, "init", "--quiet");
      git(repository, "add", ".");
      const result = await runOsvScan(
        { repositoryPath: repository, outputDir: join(root, "output") },
        {
          executable: process.execPath,
          runProcess: async (_executable, argv) => {
            if (argv[0] === "--version")
              return { stdout: "2.6.0", stderr: "", exitCode: 0 };
            const path = argv.at(-1)!;
            if (path !== join(repository, "ordinary", "package-lock.json"))
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
      expect(result.status).toBe(windows ? "partial" : "completed");
      expect(result.coverage.status).toBe(windows ? "partial" : "complete");
      expect(result.components).toHaveLength(1);
      expect(result.coverage.inputs).toHaveLength(
        windows ? fixtures.length + 1 : 1,
      );
      if (windows)
        for (const fixture of fixtures) {
          const path = `${fixture.name}/${fixture.variant}`;
          expect(result.coverage.inputs).toContainEqual(
            expect.objectContaining({
              path,
              format: fixture.format,
              status: "failed",
              sha256: createHash("sha256")
                .update(fixture.content)
                .digest("hex"),
            }),
          );
          expect(
            result.scanner.invocations?.some(
              (call) => call.argv.at(-1) === join(repository, path),
            ),
          ).toBe(true);
        }
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  },
);

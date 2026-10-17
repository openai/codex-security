import { mkdir, mkdtemp, realpath, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, expect, test } from "bun:test";
import { runOsvScan } from "../src/sca-osv.js";

const temporaryDirectories: string[] = [];
afterEach(async () => {
  await Promise.all(
    temporaryDirectories
      .splice(0)
      .map((path) => rm(path, { recursive: true, force: true })),
  );
});

async function scan(
  stderr: string,
  allExcluded = false,
  retainedLocal = false,
) {
  const root = await realpath(await mkdtemp(join(tmpdir(), "sca-exclusions-")));
  temporaryDirectories.push(root);
  const repository = join(root, "repository");
  const output = join(root, "output");
  await mkdir(repository);
  await writeFile(
    join(repository, "package-lock.json"),
    JSON.stringify({
      lockfileVersion: 3,
      packages: {
        "node_modules/@synthetic/local": {
          version: "1.0.0",
          resolved: "file:../synthetic-local.tgz",
        },
        ...(!allExcluded
          ? { "node_modules/synthetic-registry": { version: "2.0.0" } }
          : {}),
      },
    }),
  );
  await writeFile(
    join(repository, "osv-scanner.toml"),
    '[[PackageOverrides]]\nname="@synthetic/local"\nignore=true\n',
  );
  return runOsvScan(
    { repositoryPath: repository, outputDir: output },
    {
      executable: process.execPath,
      runProcess: async (_executable, argv) =>
        argv[0] === "--version"
          ? { stdout: "osv-scanner version: 2.6.0", stderr: "", exitCode: 0 }
          : {
              stdout: JSON.stringify({
                results: allExcluded
                  ? []
                  : [
                      {
                        source: { path: "package-lock.json" },
                        packages: [
                          {
                            package: {
                              name: "synthetic-registry",
                              version: "2.0.0",
                              ecosystem: "npm",
                            },
                          },
                          ...(retainedLocal
                            ? [
                                {
                                  package: {
                                    name: "@synthetic/local",
                                    version: "1.0.0",
                                    ecosystem: "npm",
                                  },
                                },
                              ]
                            : []),
                        ],
                      },
                    ],
              }),
              stderr,
              exitCode: 0,
            },
    },
  );
}

test.each([false, true])(
  "effective local package exclusions preserve complete coverage when all excluded: %p",
  async (allExcluded) => {
    const result = await scan(
      "Package npm/@synthetic/local/1.0.0 has been filtered out because: synthetic exclusion\n",
      allExcluded,
    );
    expect(result.status).toBe("completed");
    expect(result.coverage.status).toBe("complete");
    expect(result.coverage.unresolvedPackages).toBe(0);
    expect(result.components).toHaveLength(allExcluded ? 0 : 1);
    expect(result.coverage.configFiles).toHaveLength(1);
    expect(
      result.coverage.limitations.some((line) =>
        line.includes("suppressed counts"),
      ),
    ).toBe(true);
  },
);

test.each([
  ["absent receipt", ""],
  [
    "different package",
    "Package npm/@synthetic/local-other/1.0.0 has been filtered out because: synthetic exclusion\n",
  ],
  [
    "different version",
    "Package npm/@synthetic/local/1.0.1 has been filtered out because: synthetic exclusion\n",
  ],
  [
    "different ecosystem",
    "Package Go/@synthetic/local/1.0.0 has been filtered out because: synthetic exclusion\n",
  ],
  [
    "advisory-only exclusion",
    "Filtered 1 ignored vulnerability/s from the scan.\n",
  ],
])(
  "%s does not establish that a local package was excluded",
  async (_label, stderr) => {
    const result = await scan(stderr);
    expect(result.status).toBe("partial");
    expect(result.coverage.unresolvedPackages).toBe(1);
  },
);

test("a retained local tuple remains unresolved when another occurrence was excluded", async () => {
  const result = await scan(
    "Package npm/@synthetic/local/1.0.0 has been filtered out because: synthetic exclusion\n",
    false,
    true,
  );
  expect(result.components).toHaveLength(2);
  expect(result.coverage.unresolvedPackages).toBe(1);
  expect(result.status).toBe("partial");
});

test.each([
  ["registry", {}, false],
  ["local", { path: "../synthetic-local" }, false],
  ["local, custom category first", { path: "../synthetic-local" }, true],
  ["alternate index", { index: "synthetic-private" }, false],
] as const)(
  "Pipenv dev exclusions leave omitted categories unresolved: %s",
  async (_label, origin, customFirst) => {
    const root = await realpath(
      await mkdtemp(join(tmpdir(), "sca-pipenv-exclusion-")),
    );
    temporaryDirectories.push(root);
    const repository = join(root, "repository");
    await mkdir(repository);
    const dependency = { "synthetic-lib": { version: "==1.2.0", ...origin } };
    const develop = { develop: dependency };
    const production = { production: dependency };
    const scanPipenv = async (includeProduction: boolean) => {
      await writeFile(
        join(repository, "Pipfile.lock"),
        JSON.stringify({
          _meta: {
            sources: [
              { name: "pypi", url: "https://pypi.org/simple" },
              {
                name: "synthetic-private",
                url: "https://index.example.test/simple",
              },
            ],
          },
          ...(includeProduction && customFirst ? production : {}),
          ...develop,
          ...(includeProduction && !customFirst ? production : {}),
        }),
      );
      return runOsvScan(
        { repositoryPath: repository, outputDir: join(root, "output") },
        {
          executable: process.execPath,
          runProcess: async (_executable, argv) =>
            argv[0] === "--version"
              ? {
                  stdout: "osv-scanner version: 2.6.0",
                  stderr: "",
                  exitCode: 0,
                }
              : {
                  stdout: JSON.stringify({ results: [] }),
                  stderr:
                    "Package PyPI/synthetic-lib/1.2.0 has been filtered out because: dev-only exclusion\n",
                  exitCode: 0,
                },
        },
      );
    };

    const omitted = await scanPipenv(true);
    expect(omitted.status).toBe("failed");
    expect(omitted.coverage.status).toBe("failed");
    expect(omitted.coverage.unresolvedPackages).toBe(1);
    expect(omitted.coverage.limitations.join("\n")).toContain(
      "group:production",
    );
    expect(omitted.coverage.limitations.join("\n")).toContain(
      "synthetic-lib@1.2.0",
    );
    if ("path" in origin)
      expect(omitted.coverage.limitations.join("\n")).toContain(origin.path);
    if ("index" in origin)
      expect(omitted.coverage.limitations.join("\n")).toContain(origin.index);

    const excluded = await scanPipenv(false);
    expect(excluded.status).toBe("completed");
    expect(excluded.coverage.status).toBe("complete");
    expect(excluded.coverage.unresolvedPackages).toBe(0);
  },
);

for (const [origin, resolution] of [
  ["local", "file:../synthetic-lib.tgz"],
  ["direct-url", "https://example.invalid/synthetic-lib.tgz"],
] as const) {
  for (const [layout, alias, packageKey, peer] of [
    ["named", "synthetic-lib", `synthetic-lib@${resolution}`, ""],
    [
      "scoped-alias-peer",
      "@synthetic/alias",
      `@synthetic/alias@${resolution}`,
      "(peer-lib@2.0.0)",
    ],
    ["bare-reference", "local-alias", resolution, ""],
  ] as const) {
    test.each([false, true])(
      `pnpm ${origin} ${layout} tarball uses the emitted identity while retained: %p`,
      async (retained) => {
        const root = await realpath(
          await mkdtemp(join(tmpdir(), "sca-pnpm-exclusion-")),
        );
        temporaryDirectories.push(root);
        const repository = join(root, "repository");
        await mkdir(repository);
        await writeFile(
          join(repository, "pnpm-lock.yaml"),
          JSON.stringify({
            lockfileVersion: "9.0",
            importers: {
              ".": {
                dependencies: {
                  [alias]: {
                    specifier: resolution,
                    version: resolution + peer,
                  },
                },
              },
            },
            packages: {
              [packageKey]: {
                ...(layout === "named" ? {} : { name: "synthetic-lib" }),
                version: "1.2.0",
                resolution: { tarball: resolution },
              },
              "synthetic-registry@2.0.0": {},
            },
            snapshots: {
              [packageKey + peer]: {},
              "synthetic-registry@2.0.0": {},
            },
          }),
        );
        await writeFile(
          join(repository, "osv-scanner.toml"),
          '[[PackageOverrides]]\nname="synthetic-lib"\nignore=true\n',
        );
        const result = await runOsvScan(
          { repositoryPath: repository, outputDir: join(root, "output") },
          {
            executable: process.execPath,
            runProcess: async (_executable, argv) =>
              argv[0] === "--version"
                ? {
                    stdout: "osv-scanner version: 2.6.0",
                    stderr: "",
                    exitCode: 0,
                  }
                : {
                    stdout: JSON.stringify({
                      results: [
                        {
                          source: { path: "pnpm-lock.yaml" },
                          packages: [
                            {
                              package: {
                                name: "synthetic-registry",
                                version: "2.0.0",
                                ecosystem: "npm",
                              },
                            },
                            ...(retained
                              ? [
                                  {
                                    package: {
                                      name: "synthetic-lib",
                                      version: "1.2.0",
                                      ecosystem: "npm",
                                    },
                                  },
                                ]
                              : []),
                          ],
                        },
                      ],
                    }),
                    stderr:
                      "Package npm/synthetic-lib/1.2.0 has been filtered out because: synthetic exclusion\n",
                    exitCode: 0,
                  },
          },
        );
        expect(result.status).toBe(retained ? "partial" : "completed");
        expect(result.coverage.unresolvedPackages).toBe(retained ? 1 : 0);
        expect(result.components).toHaveLength(retained ? 2 : 1);
        expect(
          result.coverage.limitations.some((line) => line.includes(resolution)),
        ).toBe(true);
      },
    );
  }
}

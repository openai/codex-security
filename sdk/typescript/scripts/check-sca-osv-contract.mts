/** Offline compatibility check: bun scripts/check-sca-osv-contract.mts /path/to/osv-scanner */
import assert from "node:assert/strict";
import {
  mkdir,
  mkdtemp,
  readFile,
  realpath,
  rm,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { strToU8, zipSync } from "fflate";
import {
  runOsvProcess,
  runOsvScan,
  type OsvScanResult,
} from "../src/sca-osv.js";
import {
  ecosystemAdvisoryId,
  ecosystemFixtures,
  localOriginFixtures,
  unsupportedEcosystemInputs,
  type EcosystemFixture,
} from "./sca-osv-ecosystem-fixtures.mjs";

const executable = process.argv[2];
if (!executable)
  throw new Error("Pass the path to an installed OSV-Scanner v2.6.0 binary.");
const root = await realpath(await mkdtemp(join(tmpdir(), "sca-osv-contract-")));
const database = join(root, "database");
const archiveDirectory = join(database, "osv-scalibr", "npm");
const results: {
  case: string;
  exitCode: number | null;
  status: string;
  components: number;
  matches: number;
}[] = [];
const syntheticAdvisory = {
  schema_version: "1.7.0",
  id: "SYNTHETIC-2026-001",
  aliases: ["CVE-2099-10001"],
  modified: "2026-01-01T00:00:00Z",
  published: "2026-01-01T00:00:00Z",
  summary: "Synthetic scanner contract fixture; not a real advisory.",
  affected: [
    {
      package: { name: "synthetic-lib", ecosystem: "npm" },
      ranges: [
        { type: "SEMVER", events: [{ introduced: "0" }, { fixed: "1.3.0" }] },
      ],
    },
  ],
};
const npmLock = (version: number, resolvedVersion = "1.2.0") =>
  JSON.stringify({
    name: "synthetic-app",
    lockfileVersion: version,
    packages: {
      "": { name: "synthetic-app", version: "1.0.0" },
      "node_modules/synthetic-lib": { version: resolvedVersion },
    },
  });
async function scan(
  name: string,
  files: Record<string, string>,
  missingDatabase = false,
  changeBeforeMatching?: (repository: string) => Promise<void>,
  prepareRepository?: (repository: string) => Promise<void>,
) {
  const repository = join(root, name, "repository with spaces");
  const output = join(root, name, "output");
  await mkdir(repository, { recursive: true });
  for (const [path, content] of Object.entries(files)) {
    await mkdir(join(repository, path, ".."), { recursive: true });
    await writeFile(join(repository, path), content);
  }
  await prepareRepository?.(repository);
  const result = await runOsvScan(
    { repositoryPath: repository, outputDir: output },
    {
      executable,
      runProcess: async (command, argv, options) => {
        if (argv[0] === "--version") {
          const version = await runOsvProcess(command, argv, options);
          assert.match(version.stdout, /osv-scanner version: 2\.6\.0\b/u);
          return version;
        }
        await changeBeforeMatching?.(repository);
        // Offline arguments belong only to this synthetic contract harness. Production keeps its documented arguments.
        return runOsvProcess(
          command,
          [
            ...argv.slice(0, argv.indexOf("--")),
            "--offline",
            `--local-db-path=${missingDatabase ? join(root, "missing-db") : database}`,
            ...argv.slice(argv.indexOf("--")),
          ],
          options,
        );
      },
    },
  );
  results.push({
    case: name,
    exitCode: result.scanner.exitCode,
    status: result.status,
    components: result.components.length,
    matches: result.matches.length,
  });
  return result;
}
function assertEcosystemFacts(
  result: OsvScanResult,
  fixture: EcosystemFixture,
  version: string,
  sourcePath = fixture.path,
) {
  const component = result.components.find(
    (item) => item.sourcePath === sourcePath && item.name === fixture.name,
  );
  assert.ok(component, `${sourcePath}: expected ${fixture.name} inventory`);
  assert.deepEqual(
    {
      ecosystem: component.ecosystem,
      name: component.name,
      version: component.version,
      sourcePath: component.sourcePath,
    },
    { ecosystem: fixture.ecosystem, name: fixture.name, version, sourcePath },
  );
  const matches = result.matches.filter(
    (match) => match.componentId === component.id,
  );
  assert.equal(matches.length, version === "1.2.0" ? 1 : 0);
  if (version === "1.2.0") {
    assert.deepEqual(matches[0]!.advisoryIds, [
      ecosystemAdvisoryId(fixture.ecosystem),
    ]);
    assert.deepEqual(matches[0]!.fixedVersions, ["1.3.0"]);
    assert.deepEqual(matches[0]!.sourceAdvisories[0]!["affected"], [
      {
        package: { name: fixture.name, ecosystem: fixture.ecosystem },
        ranges: [
          {
            type: ["Go", "crates.io"].includes(fixture.ecosystem)
              ? "SEMVER"
              : "ECOSYSTEM",
            events: [{ introduced: "0" }, { fixed: "1.3.0" }],
          },
        ],
      },
    ]);
  }
}
try {
  await mkdir(archiveDirectory, { recursive: true });
  await writeFile(
    join(archiveDirectory, "all.zip"),
    zipSync({
      "SYNTHETIC-2026-001.json": strToU8(JSON.stringify(syntheticAdvisory)),
    }),
  );
  const ecosystemAdvisories = new Map<string, EcosystemFixture>();
  for (const fixture of Object.values(ecosystemFixtures))
    ecosystemAdvisories.set(fixture.ecosystem, fixture);
  for (const [ecosystem, fixture] of ecosystemAdvisories) {
    const directory = join(database, "osv-scalibr", ecosystem);
    await mkdir(directory, { recursive: true });
    const advisory = {
      schema_version: "1.7.0",
      id: ecosystemAdvisoryId(ecosystem),
      modified: "2026-01-01T00:00:00Z",
      summary: "Synthetic scanner contract fixture; not a real advisory.",
      affected: [
        {
          package: { name: fixture.name, ecosystem },
          ranges: [
            {
              type: ["Go", "crates.io"].includes(ecosystem)
                ? "SEMVER"
                : "ECOSYSTEM",
              events: [{ introduced: "0" }, { fixed: "1.3.0" }],
            },
          ],
        },
      ],
    };
    await writeFile(
      join(directory, "all.zip"),
      zipSync({ [`${advisory.id}.json`]: strToU8(JSON.stringify(advisory)) }),
    );
  }
  for (const version of [2, 3]) {
    const match = await scan(`npm-v${version}`, {
      "package-lock.json": npmLock(version),
    });
    assert.equal(match.status, "completed");
    assert.equal(match.scanner.exitCode, 1);
    assert.deepEqual(match.matches[0]?.fixedVersions, ["1.3.0"]);
    assert.deepEqual(match.matches[0]?.aliases, [
      "CVE-2099-10001",
      "SYNTHETIC-2026-001",
    ]);
    assert.equal(match.components[0]?.sourcePath, "package-lock.json");
  }
  const commaPaths = await scan("repository,with,commas", {
    "nested,workspace/package-lock.json": npmLock(3),
    "-another,workspace/pnpm-lock.yaml":
      "lockfileVersion: '9.0'\npackages:\n  synthetic-lib@1.2.0: {}\nsnapshots:\n  synthetic-lib@1.2.0: {}\n",
  });
  assert.equal(commaPaths.status, "completed");
  assert.equal(commaPaths.matches.length, 2);
  assert.equal(commaPaths.scanner.invocations?.length, 2);
  for (const invocation of commaPaths.scanner.invocations!) {
    assert.equal(invocation.argv.at(-2), "--");
    assert.equal(
      JSON.parse(await readFile(invocation.rawOutputPath, "utf8")).results
        .length,
      1,
    );
  }
  const trackedIgnored = await scan(
    "git-tracked-ignored-input",
    {
      ".gitignore": "ignored/\n",
      "ignored/package-lock.json": npmLock(3),
      "ignored/untracked/package-lock.json": npmLock(3),
    },
    false,
    undefined,
    async (repository) => {
      const options = { cwd: repository, environment: process.env };
      assert.equal((await runOsvProcess("git", ["init"], options)).exitCode, 0);
      assert.equal(
        (
          await runOsvProcess(
            "git",
            ["add", "--force", "--", "ignored/package-lock.json"],
            options,
          )
        ).exitCode,
        0,
      );
    },
  );
  assert.equal(trackedIgnored.status, "completed");
  assert.equal(trackedIgnored.matches.length, 1);
  assert.deepEqual(
    trackedIgnored.coverage.inputs.map((input) => input.path),
    ["ignored/package-lock.json"],
  );
  assert.deepEqual(
    trackedIgnored.components.map((component) => component.sourcePath),
    ["ignored/package-lock.json"],
  );
  const submodule = await scan(
    "initialized-gitlink-coverage",
    {
      "package-lock.json": npmLock(3, "1.3.0"),
      "vendor/library/package-lock.json": npmLock(3),
    },
    false,
    undefined,
    async (repository) => {
      const git = async (cwd: string, args: string[]) => {
        const result = await runOsvProcess(
          "git",
          [
            "-c",
            `core.hooksPath=${join(repository, ".git", "empty-hooks")}`,
            "-c",
            "commit.gpgSign=false",
            "-c",
            "user.name=Synthetic",
            "-c",
            "user.email=synthetic@example.test",
            ...args,
          ],
          { cwd, environment: process.env },
        );
        assert.equal(result.exitCode, 0, result.stderr);
        return result.stdout.trim();
      };
      await git(repository, ["init", "--quiet"]);
      const nested = join(repository, "vendor/library");
      await git(nested, ["init", "--quiet"]);
      await git(nested, ["add", "package-lock.json"]);
      await git(nested, [
        "commit",
        "--quiet",
        "-m",
        "Synthetic dependency fixture",
      ]);
      const revision = await git(nested, ["rev-parse", "HEAD"]);
      await git(repository, [
        "update-index",
        "--add",
        "--cacheinfo",
        "160000",
        revision,
        "vendor/library",
      ]);
    },
  );
  assert.equal(submodule.status, "partial");
  assert.equal(submodule.coverage.status, "partial");
  assert.equal(submodule.matches.length, 0);
  assert.equal(submodule.components.length, 1);
  assert.deepEqual(
    submodule.coverage.inputs.map((input) => input.path),
    ["package-lock.json"],
  );
  assert.ok(
    submodule.diagnostics.some((message) =>
      message.includes("Git submodule vendor/library"),
    ),
  );
  const clean = await scan("fixed-version", {
    "package-lock.json": npmLock(3, "1.3.0"),
  });
  assert.equal(clean.status, "completed");
  assert.equal(clean.scanner.exitCode, 0);
  assert.equal(clean.components.length, 1);
  assert.equal(clean.matches.length, 0);
  const nestedConfig = await scan("nested-source-ignores-root-config", {
    "nested/package-lock.json": npmLock(3),
    "osv-scanner.toml": "invalid=[",
  });
  assert.equal(nestedConfig.status, "completed");
  assert.equal(nestedConfig.matches.length, 1);
  assert.deepEqual(nestedConfig.coverage.configFiles, []);
  // Bun 1.3.14 realpath rejects literal POSIX backslashes. Exercise this
  // filesystem case under Node; the normalization unit test runs on both.
  if (process.platform !== "win32" && process.versions["bun"] !== "1.3.14") {
    const literalBackslash = await scan("posix-literal-backslash", {
      "nested\\folder/package-lock.json": npmLock(3),
    });
    assert.equal(literalBackslash.status, "completed");
    assert.equal(literalBackslash.matches.length, 1);
    assert.equal(
      literalBackslash.components[0]?.sourcePath,
      "nested\\folder/package-lock.json",
    );
  }
  const malformedNestedConfig = await scan("malformed-nested-config", {
    "package-lock.json": npmLock(3),
    "nested/package-lock.json": npmLock(3),
    "nested/osv-scanner.toml": "IgnoredVulns = [",
  });
  assert.equal(malformedNestedConfig.status, "partial");
  assert.equal(malformedNestedConfig.scanner.exitCode, 130);
  assert.equal(malformedNestedConfig.matches.length, 2);
  assert.equal(malformedNestedConfig.coverage.inputs.length, 2);
  assert.equal(malformedNestedConfig.coverage.configFiles.length, 1);
  assert.ok(
    malformedNestedConfig.diagnostics.some((line) =>
      line.includes(
        "Unable to parse OSV configuration nested/osv-scanner.toml",
      ),
    ),
  );
  const shrink = await scan("shrinkwrap", {
    "package-lock.json": npmLock(3),
    "npm-shrinkwrap.json": npmLock(3, "1.3.0"),
  });
  assert.equal(shrink.status, "completed");
  assert.equal(shrink.components[0]?.sourcePath, "npm-shrinkwrap.json");
  assert.equal(shrink.matches.length, 0);
  assert.equal(
    shrink.coverage.inputs.find((item) => item.path === "package-lock.json")
      ?.status,
    "excluded",
  );
  const nestedShrinkwrap = await scan("nested-shrinkwrap", {
    "nested/package-lock.json": npmLock(3),
    "nested/npm-shrinkwrap.json": npmLock(3, "1.3.0"),
  });
  assert.equal(nestedShrinkwrap.status, "completed");
  assert.equal(nestedShrinkwrap.matches.length, 0);
  assert.deepEqual(
    nestedShrinkwrap.coverage.inputs.map((input) => [input.path, input.status]),
    [
      ["nested/npm-shrinkwrap.json", "scanned"],
      ["nested/package-lock.json", "excluded"],
    ],
  );
  for (const version of [2, 3]) {
    for (const origin of ["local", "direct-url", "registry"]) {
      const resolved =
        origin === "local"
          ? "file:../local-lib.tgz"
          : origin === "registry"
            ? "https://registry.npmjs.org/synthetic-lib/-/synthetic-lib-1.2.0.tgz"
            : "https://example.invalid/synthetic-lib.tgz";
      const tarball = await scan(`npm-v${version}-${origin}-tarball`, {
        "package-lock.json": JSON.stringify({
          lockfileVersion: version,
          packages: {
            "": {
              name: "synthetic-app",
              version: "1.0.0",
              dependencies: {
                "synthetic-lib": origin === "registry" ? "^1.2.0" : resolved,
              },
            },
            "node_modules/synthetic-lib": { version: "1.2.0", resolved },
          },
        }),
      });
      assert.equal(
        tarball.status,
        origin === "registry" ? "completed" : "partial",
      );
      assert.equal(
        tarball.coverage.unresolvedPackages,
        origin === "registry" ? 0 : 1,
      );
      assert.equal(tarball.components[0]?.version, "1.2.0");
      assert.equal(tarball.matches.length, 1);
    }
  }
  const workspaceLink = await scan("npm-workspace-link", {
    "package-lock.json": JSON.stringify({
      lockfileVersion: 3,
      packages: {
        "": { name: "synthetic-app", version: "1.0.0" },
        "node_modules/synthetic-lib": { version: "1.2.0" },
        "node_modules/linked-lib": {
          resolved: "packages/linked-lib",
          link: true,
        },
        "packages/linked-lib": { name: "linked-lib", version: "1.0.0" },
      },
    }),
  });
  assert.equal(workspaceLink.status, "partial");
  assert.equal(workspaceLink.coverage.unresolvedPackages, 1);
  assert.equal(workspaceLink.matches.length, 1);
  const pnpm = await scan("pnpm-v9-workspace-peer", {
    "workspace/pnpm-lock.yaml": `lockfileVersion: '9.0'
importers:
  .:
    dependencies:
      synthetic-lib:
        specifier: '1.2.0'
        version: '1.2.0(peer-lib@2.0.0)'
packages:
  synthetic-lib@1.2.0:
    resolution: {integrity: synthetic, tarball: https://registry.npmjs.org/synthetic-lib/-/synthetic-lib-1.2.0.tgz}
  peer-lib@2.0.0:
    resolution: {integrity: synthetic}
snapshots:
  synthetic-lib@1.2.0(peer-lib@2.0.0): {}
  peer-lib@2.0.0: {}
`,
  });
  assert.equal(pnpm.status, "completed");
  assert.equal(
    pnpm.components.find((item) => item.name === "synthetic-lib")?.version,
    "1.2.0",
  );
  assert.equal(pnpm.matches.length, 1);
  const pnpmLocal = await scan("pnpm-local-directory-and-link", {
    "pnpm-lock.yaml": `lockfileVersion: '9.0'
importers:
  .:
    dependencies:
      synthetic-lib: {specifier: '1.2.0', version: '1.2.0'}
      local-lib: {specifier: 'file:../local-lib', version: 'file:../local-lib'}
      url-lib: {specifier: 'https://example.invalid/url-lib.tgz', version: 'https://example.invalid/url-lib.tgz'}
    devDependencies:
      linked-lib: {specifier: 'link:../linked-lib', version: 'link:../linked-lib'}
packages:
  synthetic-lib@1.2.0: {resolution: {integrity: synthetic}}
  local-lib@file:../local-lib: {resolution: {directory: ../local-lib, type: directory}}
snapshots:
  synthetic-lib@1.2.0: {}
  local-lib@file:../local-lib: {}
`,
  });
  assert.equal(pnpmLocal.status, "partial");
  assert.equal(pnpmLocal.coverage.unresolvedPackages, 3);
  assert.equal(pnpmLocal.matches.length, 1);
  assert.equal(
    pnpmLocal.components.find((component) => component.name === "local-lib")
      ?.version,
    "file:../local-lib",
  );
  assert.ok(
    pnpmLocal.coverage.limitations.some((line) =>
      line.includes("linked-lib@link:../linked-lib"),
    ),
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
      for (const excluded of [false, true]) {
        const tarball = await scan(
          `pnpm-${origin}-tarball-${layout}-${excluded ? "excluded" : "retained"}`,
          {
            "pnpm-lock.yaml": JSON.stringify({
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
            ...(excluded
              ? {
                  "osv-scanner.toml":
                    '[[PackageOverrides]]\nname="synthetic-lib"\nignore=true\n',
                }
              : {}),
          },
        );
        assert.equal(tarball.status, excluded ? "completed" : "partial");
        assert.equal(tarball.coverage.unresolvedPackages, excluded ? 0 : 1);
        assert.equal(tarball.components.length, excluded ? 1 : 2);
        assert.equal(tarball.matches.length, excluded ? 0 : 1);
        if (!excluded)
          assert.equal(
            tarball.components.find(
              (component) => component.name === "synthetic-lib",
            )?.version,
            "1.2.0",
          );
      }
    }
  }
  const alias = await scan("npm-alias-scoped-multiple", {
    "package-lock.json": JSON.stringify({
      lockfileVersion: 3,
      packages: {
        "": { name: "synthetic-app" },
        "node_modules/alias-lib": {
          name: "synthetic-lib",
          version: "1.2.0",
          dev: true,
        },
        "node_modules/nested/node_modules/synthetic-lib": {
          version: "1.3.0",
          optional: true,
        },
        "node_modules/@synthetic/scoped": { version: "2.0.0" },
      },
    }),
  });
  assert.equal(alias.status, "completed");
  assert.equal(alias.components.length, 3);
  assert.equal(
    alias.components.find((item) => item.version === "1.2.0")?.name,
    "synthetic-lib",
  );
  assert.equal(alias.matches.length, 1);
  const emptyNested = await scan("empty-nested-lockfile", {
    "package-lock.json": npmLock(3),
    "nested/package-lock.json": JSON.stringify({
      lockfileVersion: 3,
      packages: {},
    }),
  });
  assert.equal(emptyNested.status, "completed");
  assert.equal(emptyNested.scanner.exitCode, 1);
  assert.deepEqual(
    emptyNested.scanner.invocations?.map((call) => call.exitCode),
    [128, 1],
  );
  assert.equal(emptyNested.matches.length, 1);
  assert.ok(
    emptyNested.coverage.inputs
      .find((input) => input.path === "nested/package-lock.json")
      ?.reason?.includes("no packages"),
  );
  const gitArchive = join(database, "osv-scalibr", "GIT");
  await mkdir(gitArchive, { recursive: true });
  await writeFile(join(gitArchive, "all.zip"), zipSync({}));
  const unresolved = await scan("local-and-git-references", {
    "package-lock.json": JSON.stringify({
      lockfileVersion: 3,
      packages: {
        "": { name: "synthetic-app" },
        "node_modules/local-lib": { resolved: "../local-lib", link: true },
        "node_modules/git-lib": {
          version: "1.0.0",
          resolved:
            "git+https://example.test/synthetic/lib.git#" + "a".repeat(40),
        },
        "node_modules/synthetic-lib": { version: "1.2.0" },
      },
    }),
  });
  assert.equal(unresolved.status, "partial");
  assert.equal(unresolved.coverage.unresolvedPackages, 2);
  assert.equal(unresolved.matches.length, 1);
  const excluded = await scan("package-exclusions", {
    "package-lock.json": npmLock(3),
    "osv-scanner.toml":
      '[[PackageOverrides]]\nname="synthetic-lib"\necosystem="npm"\nignore=true\n',
  });
  assert.equal(excluded.status, "completed");
  assert.equal(excluded.components.length, 0);
  assert.equal(excluded.coverage.configFiles.length, 1);
  assert.ok(
    excluded.coverage.limitations.some((line) =>
      line.includes("suppressed counts"),
    ),
  );
  const lowercaseExclusions = await scan(
    "case-insensitive-package-exclusions",
    {
      "package-lock.json": npmLock(3),
      "osv-scanner.toml":
        '[[packageoverrides]]\nName="synthetic-lib"\nEcosystem="npm"\nIgnore=true\n',
    },
  );
  assert.equal(lowercaseExclusions.status, "completed");
  assert.equal(lowercaseExclusions.scanner.exitCode, 0);
  assert.equal(lowercaseExclusions.components.length, 0);
  assert.ok(
    lowercaseExclusions.coverage.limitations.some((line) =>
      line.includes("suppressed counts"),
    ),
  );
  for (const [name, configuration, ignored] of [
    [
      "exact",
      '[[PackageOverrides]]\nname="synthetic-lib"\nignore=true\n',
      true,
    ],
    [
      "regex",
      '[[packageoverrides]]\nname="synthetic-.*"\nnameIsRegex=true\nignore=true\n',
      true,
    ],
    [
      "group",
      '[[PackageOverrides]]\nname="synthetic-lib"\ngroup="dev"\nignore=true\n',
      true,
    ],
    [
      "expired",
      '[[PackageOverrides]]\nname="synthetic-lib"\nignore=true\neffectiveUntil=2000-01-01T00:00:00Z\n',
      false,
    ],
    [
      "other-version",
      '[[PackageOverrides]]\nname="synthetic-lib"\nversion="1.3.0"\nignore=true\n',
      false,
    ],
    [
      "other-group",
      '[[PackageOverrides]]\nname="synthetic-lib"\ngroup="optional"\nignore=true\n',
      false,
    ],
    [
      "advisory-only",
      '[[IgnoredVulns]]\nid="SYNTHETIC-2026-001"\nreason="Synthetic exclusion"\n',
      false,
    ],
  ] as const) {
    const localExclusion = await scan(`local-exclusion-${name}`, {
      "package-lock.json": JSON.stringify({
        lockfileVersion: 3,
        packages: {
          "node_modules/synthetic-lib": {
            version: "1.2.0",
            resolved: "file:../local-lib.tgz",
            dev: true,
          },
          "node_modules/synthetic-registry": { version: "2.0.0" },
        },
      }),
      "osv-scanner.toml": configuration,
    });
    assert.equal(localExclusion.status, ignored ? "completed" : "partial");
    assert.equal(localExclusion.coverage.unresolvedPackages, ignored ? 0 : 1);
  }
  const allLocalExcluded = await scan("all-local-excluded", {
    "package-lock.json": JSON.stringify({
      lockfileVersion: 3,
      packages: {
        "node_modules/synthetic-lib": {
          version: "1.2.0",
          resolved: "file:../local-lib.tgz",
        },
      },
    }),
    "osv-scanner.toml":
      '[[PackageOverrides]]\nname="synthetic-lib"\nignore=true\n',
  });
  assert.equal(allLocalExcluded.status, "completed");
  assert.equal(allLocalExcluded.coverage.unresolvedPackages, 0);
  assert.equal(allLocalExcluded.components.length, 0);
  const localLock = JSON.stringify({
    lockfileVersion: 3,
    packages: {
      "node_modules/synthetic-lib": {
        version: "1.2.0",
        resolved: "file:../local-lib.tgz",
      },
    },
  });
  const scopedExclusion = await scan("local-exclusion-source-scope", {
    "a/package-lock.json": localLock,
    "a/osv-scanner.toml":
      '[[PackageOverrides]]\nname="synthetic-lib"\nignore=true\n',
    "b/package-lock.json": localLock,
  });
  assert.equal(scopedExclusion.status, "partial");
  assert.equal(scopedExclusion.coverage.unresolvedPackages, 1);
  assert.deepEqual(
    scopedExclusion.components.map((component) => component.sourcePath),
    ["b/package-lock.json"],
  );
  assert.equal(scopedExclusion.matches.length, 1);
  const ignored = await scan("advisory-exclusions", {
    "package-lock.json": npmLock(3),
    "osv-scanner.toml":
      '[[IgnoredVulns]]\nid="SYNTHETIC-2026-001"\nreason="Synthetic fixture"\n',
  });
  assert.equal(ignored.status, "completed");
  assert.equal(ignored.components.length, 1);
  assert.equal(ignored.matches.length, 0);
  const unavailable = await scan(
    "missing-offline-db",
    { "package-lock.json": npmLock(3) },
    true,
  );
  assert.equal(unavailable.status, "partial");
  assert.equal(unavailable.scanner.exitCode, 127);
  assert.equal(unavailable.components.length, 1);
  assert.ok(
    unavailable.diagnostics.some((line) =>
      line.includes("Error during extraction:"),
    ),
  );
  assert.ok(
    (await readFile(unavailable.scanner.rawOutputPath, "utf8")).includes(
      "synthetic-lib",
    ),
  );
  const invalidConfig = await scan("invalid-config", {
    "package-lock.json": npmLock(3),
    "osv-scanner.toml": "UnknownField=true\n",
  });
  assert.equal(invalidConfig.status, "partial");
  assert.equal(invalidConfig.scanner.exitCode, 130);
  assert.equal(invalidConfig.matches.length, 1);
  for (const changed of ["lockfile", "config"]) {
    const drift = await scan(
      `changed-${changed}-during-matching`,
      {
        "package-lock.json": npmLock(3),
      },
      false,
      async (repository) => {
        if (changed === "lockfile")
          await writeFile(
            join(repository, "package-lock.json"),
            npmLock(3, "1.3.0"),
          );
        else
          await writeFile(
            join(repository, "osv-scanner.toml"),
            '[[IgnoredVulns]]\nid="SYNTHETIC-2026-001"\nreason="Synthetic drift fixture"\n',
          );
      },
    );
    assert.equal(drift.status, "partial");
    assert.equal(drift.scanner.exitCode, 0);
    assert.equal(drift.components.length, 1);
    assert.equal(drift.matches.length, 0);
    assert.ok(
      drift.diagnostics.some((line) => line.includes("changed while matching")),
    );
  }
  const emptyWithExcluded = await scan("empty-with-excluded-inventory", {
    "package-lock.json": npmLock(3),
    "osv-scanner.toml":
      '[[PackageOverrides]]\nname="synthetic-lib"\nignore=true\n',
    "empty/package-lock.json": JSON.stringify({
      lockfileVersion: 3,
      packages: {},
    }),
  });
  assert.equal(emptyWithExcluded.status, "completed");
  assert.equal(emptyWithExcluded.scanner.exitCode, 0);
  assert.equal(emptyWithExcluded.components.length, 0);
  const empty = await scan("no-packages", {
    "package-lock.json": JSON.stringify({ lockfileVersion: 3, packages: {} }),
  });
  assert.equal(empty.status, "failed");
  assert.equal(empty.scanner.exitCode, 128);
  const malformed = await scan("malformed-package", {
    "package-lock.json": JSON.stringify({
      lockfileVersion: 3,
      packages: "invalid",
    }),
  });
  assert.equal(malformed.status, "failed");
  assert.equal(malformed.scanner.exitCode, 128);
  for (const [format, fixture] of Object.entries(ecosystemFixtures)) {
    for (const version of ["1.2.0", "1.3.0"]) {
      const result = await scan(
        `ecosystem-${format}-${version === "1.2.0" ? "vulnerable" : "fixed"}`,
        { [fixture.path]: fixture.content(version) },
      );
      assert.equal(
        result.status,
        fixture.declaration ? "partial" : "completed",
        `${format}: ${result.diagnostics.join("; ")}`,
      );
      assert.equal(
        result.coverage.status,
        fixture.declaration ? "partial" : "complete",
      );
      assert.equal(result.scanner.exitCode, version === "1.2.0" ? 1 : 0);
      assert.deepEqual(
        result.coverage.inputs.map((input) => [
          input.path,
          input.format,
          input.status,
        ]),
        [[fixture.path, format, "scanned"]],
      );
      assertEcosystemFacts(result, fixture, version);
    }
  }
  for (const [name, directive] of [
    ["legacy", "go 1.16\n"],
    ["unspecified", ""],
  ]) {
    const fixture = ecosystemFixtures.go;
    const result = await scan(`ecosystem-go-${name}-modern-toolchain`, {
      [fixture.path]: fixture
        .content("1.2.0")
        .replace("go 1.20\n", `${directive}toolchain go1.23.0\n`),
    });
    assert.equal(result.status, "partial");
    assert.equal(result.coverage.status, "partial");
    assert.equal(result.coverage.inputs[0]?.status, "scanned");
    assert.equal(result.scanner.exitCode, 1);
    assert.ok(
      result.diagnostics.some((message) =>
        message.includes("may omit transitive dependencies"),
      ),
    );
    assert.ok(
      result.coverage.limitations.some((message) =>
        message.includes("may omit transitive dependencies"),
      ),
    );
    assertEcosystemFacts(result, fixture, "1.2.0");
  }
  for (const [format, path] of [
    ["gradle", "buildscript-gradle.lockfile"],
    ["bundler", "gems.locked"],
  ] as const) {
    const fixture = ecosystemFixtures[format];
    const result = await scan(`ecosystem-${format}-alternate-filename`, {
      [path]: fixture.content("1.2.0"),
    });
    assert.equal(result.status, "completed");
    assertEcosystemFacts(result, fixture, "1.2.0", path);
  }
  for (const origin of localOriginFixtures) {
    const fixture = ecosystemFixtures[origin.format];
    const result = await scan(`ecosystem-${origin.format}-local-origin`, {
      [fixture.path]: origin.content,
    });
    assert.equal(
      result.status,
      "partial",
      `${origin.format}: ${result.diagnostics.join("; ")}`,
    );
    assert.equal(result.coverage.status, "partial");
    assert.equal(result.coverage.unresolvedPackages, 1);
    assert.equal(result.matches.length, origin.matches);
    for (const emitted of origin.emitted)
      assert.ok(
        result.components.some(
          (component) =>
            component.name === emitted.name &&
            component.version === emitted.version &&
            component.ecosystem === fixture.ecosystem &&
            component.sourcePath === fixture.path,
        ),
        `${origin.format}: missing retained ${emitted.name} tuple`,
      );
    for (const omitted of origin.omitted ?? [])
      assert.ok(
        !result.components.some((component) => component.name === omitted),
      );
    if (origin.matches) assertEcosystemFacts(result, fixture, "1.2.0");
  }
  for (const origin of localOriginFixtures.filter((item) =>
    ["uv", "poetry", "cargo", "bundler", "composer"].includes(item.format),
  )) {
    const fixture = ecosystemFixtures[origin.format];
    const excluded = await scan(`ecosystem-${origin.format}-local-excluded`, {
      [fixture.path]: origin.content,
      "osv-scanner.toml": `[[PackageOverrides]]\nname=${JSON.stringify(fixture.name)}\necosystem=${JSON.stringify(fixture.ecosystem)}\nversion="1.2.0"\nignore=true\nreason="Synthetic exclusion contract"\n`,
    });
    assert.equal(
      excluded.status,
      "completed",
      `${origin.format}: ${excluded.diagnostics.join("; ")}`,
    );
    assert.equal(excluded.coverage.unresolvedPackages, 0);
    assert.equal(excluded.components.length, 0);
    assert.equal(excluded.matches.length, 0);
    assert.ok(
      (await readFile(excluded.scanner.stderrPath, "utf8")).includes(
        `Package ${fixture.ecosystem}/${fixture.name}/1.2.0 has been filtered out because:`,
      ),
    );
  }
  for (const version of ["1.2.0", "9.0.0"]) {
    const sourceOnlyComposer = await scan(`composer-source-only-${version}`, {
      "composer.lock": JSON.stringify({
        packages: [
          {
            name: ecosystemFixtures.composer.name,
            version,
            source: {
              type: "git",
              url: "https://example.invalid/synthetic-fork.git",
              reference: "0123456789012345678901234567890123456789",
            },
          },
        ],
        "packages-dev": [],
      }),
    });
    assert.equal(sourceOnlyComposer.status, "partial");
    assert.equal(sourceOnlyComposer.coverage.status, "partial");
    assert.equal(sourceOnlyComposer.coverage.unresolvedPackages, 1);
    assertEcosystemFacts(
      sourceOnlyComposer,
      ecosystemFixtures.composer,
      version,
    );
  }
  const skippedComposer = await scan("ecosystem-composer-short-commit", {
    "composer.lock": JSON.stringify({
      packages: [
        {
          name: ecosystemFixtures.composer.name,
          version: "1.2.0",
          dist: {
            type: "zip",
            url: "https://example.invalid/synthetic.zip",
            reference: "abc1234",
          },
        },
      ],
      "packages-dev": [],
    }),
  });
  assert.equal(skippedComposer.status, "partial");
  assert.equal(skippedComposer.coverage.status, "partial");
  assert.equal(skippedComposer.coverage.inputs[0]?.status, "failed");
  assert.equal(skippedComposer.components.length, 1);
  assert.equal(skippedComposer.matches.length, 0);
  assert.ok(
    skippedComposer.diagnostics.some((line) =>
      line.includes('short commit hash "abc1234" cannot be queried;'),
    ),
  );
  const resolvedProjectContent = ecosystemFixtures.nuget
    .content("1.2.0")
    .replace('"type":"Direct"', '"type":"Project"');
  const resolvedProject = await scan("ecosystem-nuget-resolved-project", {
    "packages.lock.json": resolvedProjectContent,
  });
  assert.equal(resolvedProject.status, "partial");
  assert.equal(resolvedProject.coverage.unresolvedPackages, 1);
  assertEcosystemFacts(resolvedProject, ecosystemFixtures.nuget, "1.2.0");
  const excludedProject = await scan(
    "ecosystem-nuget-resolved-project-excluded",
    {
      "packages.lock.json": resolvedProjectContent,
      "osv-scanner.toml":
        '[[PackageOverrides]]\nname="Synthetic.Library"\necosystem="NuGet"\nversion="1.2.0"\nignore=true\nreason="Synthetic exclusion contract"\n',
    },
  );
  assert.equal(excludedProject.status, "completed");
  assert.equal(excludedProject.coverage.unresolvedPackages, 0);
  assert.equal(excludedProject.components.length, 0);
  assert.equal(excludedProject.matches.length, 0);
  assert.ok(
    (await readFile(excludedProject.scanner.stderrPath, "utf8")).includes(
      "Package NuGet/Synthetic.Library/1.2.0 has been filtered out because:",
    ),
  );
  for (const input of unsupportedEcosystemInputs) {
    const result = await scan(`ecosystem-unsupported-${input.name}`, {
      [input.path]: input.content,
    });
    assert.equal(result.status, "failed");
    assert.deepEqual(
      result.coverage.inputs.map((file) => [file.path, file.status]),
      [[input.path, "unsupported"]],
    );
    assert.equal(result.scanner.version, null);
    assert.deepEqual(result.scanner.invocations, []);
    assert.equal(result.matches.length, 0);
  }
  const resolvedFixtures = Object.entries(ecosystemFixtures).filter(
    ([, fixture]) => !fixture.declaration,
  );
  const mixedFiles: Record<string, string> = {
    "package-lock.json": npmLock(3),
  };
  for (const [format, fixture] of resolvedFixtures)
    mixedFiles[`${format}/${fixture.path}`] = fixture.content("1.2.0");
  const mixed = await scan("mixed-resolved-ecosystems", mixedFiles);
  assert.equal(mixed.status, "completed");
  assert.equal(mixed.coverage.status, "complete");
  assert.equal(mixed.matches.length, resolvedFixtures.length + 1);
  assert.equal(mixed.scanner.invocations!.length, resolvedFixtures.length + 1);
  for (const [format, fixture] of resolvedFixtures)
    assertEcosystemFacts(mixed, fixture, "1.2.0", `${format}/${fixture.path}`);
  const mixedDeclarations = await scan(
    "mixed-resolved-and-declaration-inventory",
    {
      "package-lock.json": npmLock(3),
      "python/requirements.txt":
        ecosystemFixtures.requirements.content("1.2.0"),
      "java/pom.xml": ecosystemFixtures.maven.content("1.2.0"),
    },
  );
  assert.equal(mixedDeclarations.status, "partial");
  assert.equal(mixedDeclarations.coverage.status, "partial");
  assert.equal(mixedDeclarations.matches.length, 3);
  assertEcosystemFacts(
    mixedDeclarations,
    ecosystemFixtures.requirements,
    "1.2.0",
    "python/requirements.txt",
  );
  assertEcosystemFacts(
    mixedDeclarations,
    ecosystemFixtures.maven,
    "1.2.0",
    "java/pom.xml",
  );
  console.log(
    JSON.stringify(
      { scanner: "OSV-Scanner v2.6.0", network: "disabled", cases: results },
      null,
      2,
    ),
  );
} finally {
  await rm(root, { recursive: true, force: true });
}

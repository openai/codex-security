import { afterEach, expect, test } from "bun:test";
import { execFileSync } from "node:child_process";
import {
  chmod,
  mkdir,
  realpath,
  rename,
  rm,
  symlink,
  writeFile,
} from "node:fs/promises";
import { dirname, join, relative } from "node:path";
import { dependencyPackageContexts } from "../src/sca-context.js";
import { discoverScaInputs, initialOsvScanResult } from "../src/sca-osv.js";
import { dependencyScanResult } from "../src/sca.js";
import {
  dependencyAssessmentSummary,
  dependencyInventorySummary,
  prioritizedDependencyMatches,
} from "../src/sca-summary.js";
import { renderScaReport } from "../src/sca-report.js";
import { createTemporaryDirectories } from "./support/temporary-directories.js";

const { create, cleanup } = createTemporaryDirectories();
afterEach(cleanup);

async function packageAt(
  path: string,
  name: string,
  version: string,
  dependencies: Record<string, string> = {},
) {
  await mkdir(path, { recursive: true });
  await writeFile(
    join(path, "package.json"),
    JSON.stringify({
      name,
      version,
      dependencies,
      main: "index.js",
      private: true,
    }),
  );
  await writeFile(
    join(path, "index.js"),
    "throw new Error('Package code must never execute during evidence collection');",
  );
}

async function fixture() {
  const root = await realpath(await create("dependency-context-"));
  const repository = join(root, "repository");
  await packageAt(repository, "synthetic-project", "1.0.0", {
    "synthetic-parent": "2.0.0",
  });
  const parent = join(
    repository,
    "node_modules/.pnpm/synthetic-parent@2.0.0/node_modules/synthetic-parent",
  );
  const leaf = join(
    repository,
    "node_modules/.pnpm/leaf@3.0.0/node_modules/@synthetic/leaf",
  );
  await packageAt(parent, "synthetic-parent", "2.0.0", {
    "@synthetic/leaf": "3.0.0",
  });
  await packageAt(leaf, "@synthetic/leaf", "3.0.0");
  await symlink(
    parent,
    join(repository, "node_modules/synthetic-parent"),
    process.platform === "win32" ? "junction" : "dir",
  );
  await mkdir(join(dirname(parent), "@synthetic"));
  await symlink(
    leaf,
    join(dirname(parent), "@synthetic/leaf"),
    process.platform === "win32" ? "junction" : "dir",
  );
  const result = dependencyScanResult(
    initialOsvScanResult(join(root, "output")),
    { path: repository, revision: "synthetic", dirty: false },
    join(root, "output"),
  );
  result.components = [
    {
      id: "leaf",
      name: "@synthetic/leaf",
      version: "3.0.0",
      ecosystem: "npm",
      sourcePath: "pnpm-lock.yaml",
      dependencyGroups: [],
    },
  ];
  result.matches = ["low", "critical", "high"].map((severity, index) => ({
    id: `match-${index}`,
    componentId: "leaf",
    advisoryIds: [`SYNTHETIC-${index}`],
    aliases: [],
    sourceAdvisories: [],
    severity,
    fixedVersions: ["3.0.1"],
    advisoryModifiedAt: [],
  }));
  return { root, repository, result, parent, leaf };
}

test("resolves exact pnpm transitive source and an introduction chain without executing package code", async () => {
  const { result, leaf } = await fixture();
  const contexts = await dependencyPackageContexts(result);
  expect(contexts[0]).toMatchObject({
    projectName: "synthetic-project",
    private: true,
    dependencyGroups: ["runtime"],
  });
  expect(join(result.repository.path, contexts[0]!.installedPath!)).toBe(leaf);
  expect(
    contexts[0]!.dependencyChain.map((item) => `${item.name}@${item.version}`),
  ).toEqual([
    "synthetic-project@1.0.0",
    "synthetic-parent@2.0.0",
    "@synthetic/leaf@3.0.0",
  ]);
  expect(contexts[0]!.limitations.join(" ")).toContain("not a complete graph");
  result.packageContexts = contexts;
  expect(dependencyInventorySummary(result).join("\n")).toContain(
    "Local chain:",
  );
});

test("does not attribute a different installed version to a scanner match", async () => {
  const { result } = await fixture();
  result.components[0]!.version = "0.1.0";
  expect(
    (await dependencyPackageContexts(result))[0]!.installedPath,
  ).toBeNull();
});

test.each(["npm", "pnpm", "pnpm-multidoc"] as const)(
  "%s workspace importer supplies the manifest, installed source, and introduction chain",
  async (manager) => {
    const { repository, result, leaf } = await fixture();
    await packageAt(repository, "synthetic-workspace", "1.0.0");
    const workspace = join(repository, "packages/app");
    await packageAt(workspace, "synthetic-app", "1.0.0");
    await writeFile(
      join(workspace, "package.json"),
      JSON.stringify({
        name: "synthetic-app",
        version: "1.0.0",
        private: true,
        devDependencies: { "synthetic-parent": "2.0.0" },
      }),
    );
    const lockfile = manager === "npm" ? "package-lock.json" : "pnpm-lock.yaml";
    result.components[0]!.sourcePath = lockfile;
    await writeFile(
      join(repository, lockfile),
      manager === "npm"
        ? JSON.stringify({
            lockfileVersion: 3,
            packages: {
              "": { name: "synthetic-workspace", version: "1.0.0" },
              "packages/app": {
                name: "synthetic-app",
                version: "1.0.0",
                devDependencies: { "synthetic-parent": "2.0.0" },
              },
              "node_modules/synthetic-parent": { version: "2.0.0" },
            },
          })
        : (manager === "pnpm-multidoc"
            ? "lockfileVersion: '9.0'\npackages: {}\n---\n"
            : "") +
            "lockfileVersion: '9.0'\nimporters:\n  .: {}\n  packages/app:\n    devDependencies:\n      synthetic-parent:\n        specifier: 2.0.0\n        version: 2.0.0\n",
    );
    const [context] = await dependencyPackageContexts(result);
    expect(context).toMatchObject({
      manifestPath: relative(repository, join(workspace, "package.json")),
      projectName: "synthetic-app",
      private: true,
      installedPath: relative(repository, leaf),
      dependencyGroups: ["dev"],
    });
    expect(context!.dependencyChain.map((item) => item.name)).toEqual([
      "synthetic-app",
      "synthetic-parent",
      "@synthetic/leaf",
    ]);
  },
);

test.each(["root", "workspace"] as const)(
  "%s peer-only seed supplies installed source and an introduction chain",
  async (kind) => {
    const { repository, result } = await fixture();
    await packageAt(repository, "synthetic-project", "1.0.0");
    const project =
      kind === "root" ? repository : join(repository, "packages/library");
    await packageAt(project, "synthetic-library", "1.0.0");
    await writeFile(
      join(project, "package.json"),
      JSON.stringify({
        name: "synthetic-library",
        version: "1.0.0",
        peerDependencies: { "@synthetic/leaf": "3.0.0" },
      }),
    );
    const peer = join(repository, "node_modules/@synthetic/leaf");
    await packageAt(peer, "@synthetic/leaf", "3.0.0");
    await writeFile(
      join(repository, "pnpm-lock.yaml"),
      `lockfileVersion: '9.0'\nimporters:\n  ${kind === "root" ? "." : "packages/library"}: {}\n`,
    );
    const [context] = await dependencyPackageContexts(result);
    expect(context).toMatchObject({
      manifestPath: relative(repository, join(project, "package.json")),
      projectName: "synthetic-library",
      installedPath: relative(repository, peer),
      dependencyGroups: ["runtime"],
    });
    expect(context!.dependencyChain.map((item) => item.name)).toEqual([
      "synthetic-library",
      "@synthetic/leaf",
    ]);
  },
);

test("unresolved workspace matches do not inherit an unrelated importer manifest", async () => {
  const { repository, result } = await fixture();
  await rm(join(repository, "package.json"));
  await rm(join(repository, "node_modules"), { recursive: true });
  await packageAt(
    join(repository, "packages/alpha"),
    "synthetic-alpha",
    "1.0.0",
  );
  await packageAt(
    join(repository, "packages/beta"),
    "synthetic-beta",
    "1.0.0",
    {
      "@synthetic/leaf": "3.0.0",
    },
  );
  await writeFile(
    join(repository, "pnpm-lock.yaml"),
    "lockfileVersion: '9.0'\nimporters:\n  packages/alpha: {}\n  packages/beta:\n    dependencies:\n      '@synthetic/leaf':\n        specifier: 3.0.0\n        version: 3.0.0\n",
  );
  const [context] = await dependencyPackageContexts(result);
  expect(context).toMatchObject({
    manifestPath: null,
    projectName: null,
    private: null,
    installedPath: null,
    dependencyChain: [],
  });
});

test("workspace peer seeds and incoming dependency chains remain available", async () => {
  const { repository, result } = await fixture();
  const workspace = join(repository, "packages/bridge");
  await packageAt(repository, "synthetic-project", "1.0.0", {
    "synthetic-bridge": "2.0.0",
  });
  await packageAt(workspace, "synthetic-bridge", "2.0.0");
  await writeFile(
    join(workspace, "package.json"),
    JSON.stringify({
      name: "synthetic-bridge",
      version: "2.0.0",
      peerDependencies: { "@synthetic/leaf": "3.0.0" },
    }),
  );
  const peer = join(repository, "node_modules/@synthetic/leaf");
  await packageAt(peer, "@synthetic/leaf", "3.0.0");
  await symlink(
    workspace,
    join(repository, "node_modules/synthetic-bridge"),
    process.platform === "win32" ? "junction" : "dir",
  );
  await writeFile(
    join(repository, "package-lock.json"),
    JSON.stringify({
      lockfileVersion: 3,
      packages: {
        "": { name: "synthetic-project", version: "1.0.0" },
        "packages/bridge": { name: "synthetic-bridge", version: "2.0.0" },
        "node_modules/synthetic-bridge": {
          resolved: "packages/bridge",
          link: true,
        },
        "node_modules/@synthetic/leaf": { version: "3.0.0" },
      },
    }),
  );
  result.components[0]!.sourcePath = "package-lock.json";
  result.components.push({
    ...result.components[0]!,
    id: "bridge",
    name: "synthetic-bridge",
    version: "2.0.0",
  });
  result.matches.push({
    ...result.matches[0]!,
    id: "bridge-match",
    componentId: "bridge",
  });
  const contexts = await dependencyPackageContexts(result);
  for (const [id, path, manifest, names] of [
    [
      "leaf",
      peer,
      relative(repository, join(workspace, "package.json")),
      ["synthetic-bridge", "@synthetic/leaf"],
    ],
    [
      "bridge",
      workspace,
      "package.json",
      ["synthetic-project", "synthetic-bridge"],
    ],
  ] as const) {
    const context = contexts.find((item) => item.componentId === id)!;
    expect(context.manifestPath).toBe(manifest);
    expect(context.installedPath).toBe(relative(repository, path));
    expect(context.dependencyChain.map((item) => item.name)).toEqual([
      ...names,
    ]);
  }
});

test.each(["project", "parent", "leaf"] as const)(
  "a linked %s manifest preserves installed source and transitive resolution",
  async (kind) => {
    const { repository, result, parent, leaf } = await fixture();
    const path = { project: repository, parent, leaf }[kind];
    const metadata = join(repository, "metadata");
    await mkdir(metadata);
    const manifest = join(path, "package.json");
    const target = join(metadata, `${kind}.json`);
    await rename(manifest, target);
    await symlink(target, manifest, "file");

    const [context] = await dependencyPackageContexts(result);
    expect(join(repository, context!.installedPath!)).toBe(leaf);
    expect(context!.manifestPath).toBe("package.json");
    expect(
      context!.dependencyChain.map((item) => join(repository, item.path)),
    ).toEqual([repository, parent, leaf]);
  },
);

test("repository package links do not authorize reading a dependency outside the target", async () => {
  const { root, repository, result } = await fixture();
  const external = join(root, "external");
  await packageAt(external, "external-package", "1.0.0");
  await symlink(
    external,
    join(repository, "node_modules/external-package"),
    process.platform === "win32" ? "junction" : "dir",
  );
  await packageAt(repository, "synthetic-project", "1.0.0", {
    "external-package": "1.0.0",
  });
  Object.assign(result.components[0]!, {
    name: "external-package",
    version: "1.0.0",
  });
  expect(
    (await dependencyPackageContexts(result))[0]!.installedPath,
  ).toBeNull();
});

test("orders advisories by severity while preserving their individual identities", async () => {
  const { result } = await fixture();
  expect(prioritizedDependencyMatches(result).map((match) => match.id)).toEqual(
    ["match-1", "match-2", "match-0"],
  );
  expect(result.matches.map((match) => match.id)).toEqual([
    "match-0",
    "match-1",
    "match-2",
  ]);
});

test("findings and next actions precede inventory and inconclusive results remain explicit", async () => {
  const { result } = await fixture();
  result.assessments = [
    {
      matchId: "match-1",
      status: "completed",
      verdict: "needs_review",
      triage: null,
      error: null,
    },
  ];
  expect(dependencyAssessmentSummary(result)).toBe(
    "0 confirmed, 0 not actionable, 1 inconclusive, 0 failed, 2 unfinished",
  );
  const report = renderScaReport(result);
  expect(report.indexOf("Candidate fixed versions")).toBeLessThan(
    report.indexOf("## Observed components"),
  );
  expect(report.indexOf("SYNTHETIC-1")).toBeLessThan(
    report.indexOf("SYNTHETIC-0"),
  );
});

test("identifies the local Cargo root without reclassifying an unresolved path dependency", async () => {
  const repository = await create("dependency-cargo-context-");
  await writeFile(
    join(repository, "Cargo.toml"),
    '[package]\nname="synthetic-root"\nversion="0.1.0"\n',
  );
  await writeFile(
    join(repository, "Cargo.lock"),
    'version=4\n[[package]]\nname="synthetic-root"\nversion="0.1.0"\n[[package]]\nname="external-path"\nversion="0.1.0"\n',
  );
  const discovered = await discoverScaInputs(repository);
  expect(discovered.firstPartyPackages).toEqual([
    {
      name: "synthetic-root",
      version: "0.1.0",
      sourcePath: "Cargo.lock",
      manifestPath: "Cargo.toml",
    },
  ]);
  expect(discovered.localReferences.map((item) => item.name)).toEqual([
    "external-path",
  ]);
  expect(discovered.limitations.join(" ")).toContain(
    "local first-party package",
  );
});

test("collects installed dependencies when the local project has no package name", async () => {
  const { repository, result } = await fixture();
  await writeFile(
    join(repository, "package.json"),
    JSON.stringify({
      private: true,
      dependencies: { "synthetic-parent": "2.0.0" },
    }),
  );
  const contexts = await dependencyPackageContexts(result);
  expect(contexts[0]!.projectName).toBeNull();
  expect(contexts[0]!.installedPath).not.toBeNull();
});

test("invalid optional Cargo metadata does not prevent lockfile matching", async () => {
  const repository = await create("dependency-cargo-context-");
  await writeFile(join(repository, "Cargo.toml"), "invalid manifest [");
  await writeFile(
    join(repository, "Cargo.lock"),
    'version=4\n[[package]]\nname="synthetic-root"\nversion="0.1.0"\n',
  );
  const discovered = await discoverScaInputs(repository);
  expect(discovered.inputs[0]!.status).toBe("scanned");
  expect(discovered.localReferences).toHaveLength(1);
  expect(discovered.firstPartyPackages).toHaveLength(0);
});

test.each(["directory", "cyclic link"] as const)(
  "unreadable optional npm manifest (%s) leaves matching evidence usable",
  async (kind) => {
    const { repository, result } = await fixture();
    const manifest = join(repository, "package.json");
    await rm(manifest);
    if (kind === "directory") await mkdir(manifest);
    else await symlink("package.json", manifest, "file");
    const contexts = await dependencyPackageContexts(result);
    expect(contexts[0]!.installedPath).toBeNull();
    expect(contexts[0]!.limitations).not.toHaveLength(0);
    expect(result.matches).toHaveLength(3);
  },
);

test.skipIf(process.platform === "win32")(
  "ignores a FIFO package manifest without waiting for a writer",
  async () => {
    const { leaf, result } = await fixture();
    const manifest = join(leaf, "package.json");
    await rm(manifest);
    execFileSync("mkfifo", [manifest]);
    const contexts = await dependencyPackageContexts(result);
    expect(contexts[0]!.installedPath).toBeNull();
    expect(contexts[0]!.limitations).not.toHaveLength(0);
  },
);

test("registry-only Cargo matching does not depend on optional manifest parsing", async () => {
  const repository = await create("dependency-cargo-context-");
  await writeFile(join(repository, "Cargo.toml"), "invalid manifest [");
  await writeFile(
    join(repository, "Cargo.lock"),
    'version=4\n[[package]]\nname="synthetic-registry-package"\nversion="0.1.0"\nsource="registry+https://github.com/rust-lang/crates.io-index"\n',
  );
  const discovered = await discoverScaInputs(repository);
  expect(discovered.inputs[0]!.status).toBe("scanned");
  expect(discovered.localReferences).toHaveLength(0);
  expect(discovered.diagnostics).toEqual([]);
});

test("an outside package link does not invent a chain through a hoisted copy", async () => {
  const { root, repository, result, parent, leaf } = await fixture();
  const external = join(root, "external-leaf");
  await packageAt(external, "@synthetic/leaf", "9.0.0");
  const nearerLink = join(dirname(parent), "@synthetic/leaf");
  await rm(nearerLink, { recursive: true });
  await symlink(
    external,
    nearerLink,
    process.platform === "win32" ? "junction" : "dir",
  );
  await mkdir(join(repository, "node_modules/@synthetic"));
  await symlink(
    leaf,
    join(repository, "node_modules/@synthetic/leaf"),
    process.platform === "win32" ? "junction" : "dir",
  );
  await packageAt(
    join(repository, "node_modules/synthetic-dev"),
    "synthetic-dev",
    "1.0.0",
    { "@synthetic/leaf": "3.0.0" },
  );
  await writeFile(
    join(repository, "package.json"),
    JSON.stringify({
      name: "synthetic-project",
      version: "1.0.0",
      dependencies: { "synthetic-parent": "2.0.0" },
      devDependencies: { "synthetic-dev": "1.0.0" },
    }),
  );
  const [context] = await dependencyPackageContexts(result);
  expect(context!.dependencyChain.map((item) => item.name)).toEqual([
    "synthetic-project",
    "synthetic-dev",
    "@synthetic/leaf",
  ]);
  expect(context!.dependencyGroups).toEqual(["dev"]);
});

test
  .skipIf(process.platform === "win32" || process.getuid?.() === 0)
  .each(["project", "installed"] as const)(
  "permission-denied optional %s manifest leaves advisory evidence usable",
  async (kind) => {
    const { repository, leaf, result } = await fixture();
    const manifest = join(
      kind === "project" ? repository : leaf,
      "package.json",
    );
    await chmod(manifest, 0o000);
    try {
      const [context] = await dependencyPackageContexts(result);
      expect(context!.installedPath).toBeNull();
      expect(context!.limitations).not.toHaveLength(0);
      expect(result.matches).toHaveLength(3);
    } finally {
      await chmod(manifest, 0o600);
    }
  },
);

test("resolves a project's published alias through its dependency edge", async () => {
  const { repository, result } = await fixture();
  await packageAt(repository, "synthetic-project", "1.0.0", {
    baseline: "npm:synthetic-project@1.0.0",
  });
  const installed = join(repository, "node_modules/baseline");
  await packageAt(installed, "synthetic-project", "1.0.0");
  Object.assign(result.components[0]!, {
    name: "synthetic-project",
    version: "1.0.0",
  });
  const [context] = await dependencyPackageContexts(result);
  expect(join(repository, context!.installedPath!)).toBe(installed);
  expect(context!.dependencyChain).toHaveLength(2);
  expect(context!.dependencyChain[0]!.path).toBe(".");
  expect(join(repository, context!.dependencyChain[1]!.path)).toBe(installed);
  expect(context!.dependencyGroups).toEqual(["runtime"]);
});

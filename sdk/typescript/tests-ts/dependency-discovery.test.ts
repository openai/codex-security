import { expect, test } from "bun:test";
import { execFileSync } from "node:child_process";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { reviewScopes } from "../src/exploitability/analyzers/repository/claims.js";
import {
  discoverDependencyRepository,
  readNpmManifests,
} from "../src/exploitability/analyzers/repository/discovery.js";
import { dependencyGraphCandidates } from "../src/exploitability/analyzers/repository/graph-candidates.js";

const pkg = { ecosystem: "npm", name: "sample-codec" };

test("caller ownership and installed versions come from the same committed workspace", async () => {
  const repo = await mkdtemp(join(tmpdir(), "dependency-workspace-"));
  const git = (...args: string[]) =>
    execFileSync("git", ["-C", repo, ...args], { encoding: "utf8" }).trim();
  try {
    const entries: Record<string, unknown> = { "": { workspaces: ["apps/*"] } };
    for (const [service, version] of [
      ["alpha", "1.0.0"],
      ["beta", "2.0.0"],
      ["inconsistent", "1.0.0"],
      ["unlocked", "3.0.0"],
    ] as const) {
      const dir = "apps/" + service;
      const manifest = {
        name: service,
        dependencies: { [pkg.name]: "^" + version },
      };
      await mkdir(join(repo, dir), { recursive: true });
      await writeFile(
        join(repo, dir, "package.json"),
        JSON.stringify(manifest),
      );
      await writeFile(
        join(repo, dir, "main.js"),
        "// entry point\nimport codec from 'sample-codec';\ncodec.decode('file');\n",
      );
      if (service !== "unlocked") {
        entries[dir] = manifest;
        entries[
          service === "alpha"
            ? "node_modules/sample-codec"
            : dir + "/node_modules/sample-codec"
        ] = { version: service === "inconsistent" ? "7.0.0" : version };
      }
    }
    await writeFile(
      join(repo, "package.json"),
      JSON.stringify({ private: true, workspaces: ["apps/*"] }),
    );
    await writeFile(
      join(repo, "package-lock.json"),
      JSON.stringify({ lockfileVersion: 3, packages: entries }, null, 2),
    );
    await writeFile(join(repo, "Dockerfile"), "FROM node:22\n");
    git("init", "--quiet");
    git("add", ".");
    git(
      "-c",
      "user.name=Fixture",
      "-c",
      "user.email=fixture@example.invalid",
      "commit",
      "--quiet",
      "-m",
      "Fixture",
    );
    const revision = git("rev-parse", "HEAD");
    await writeFile(
      join(repo, "apps/alpha/main.js"),
      "// dirty working copy\n",
    );
    await writeFile(join(repo, "package-lock.json"), "{}\n");
    // The database may have a local replacement object for the same tracked file.
    git(
      "replace",
      git("rev-parse", "HEAD:package-lock.json"),
      git("hash-object", "-w", "package-lock.json"),
    );
    const result = await discoverDependencyRepository({
      repository: repo,
      package: pkg,
      environment: { PATH: "" },
    });
    expect(result.revision).toBe(revision);
    expect(
      result.callers.map(({ path, line, version }) => [path, line, version]),
    ).toEqual([
      ["apps/alpha/main.js", 2, "1.0.0"],
      ["apps/beta/main.js", 2, "2.0.0"],
      ["apps/inconsistent/main.js", 2, undefined],
      ["apps/unlocked/main.js", 2, undefined],
    ]);
    expect(result.manifests.map((m) => m.selection?.packagePath)).toEqual([
      "node_modules/sample-codec",
      "apps/beta/node_modules/sample-codec",
      undefined,
      undefined,
    ]);
    const lockLines = git(
      "--no-replace-objects",
      "show",
      "HEAD:package-lock.json",
    ).split("\n");
    for (const m of result.manifests.filter((m) => m.selection)) {
      const selection = m.selection!;
      expect(lockLines[selection.line - 1]).toContain(
        '"version": "' + selection.version + '"',
      );
    }
    expect(result.buildFiles).toEqual(["Dockerfile"]);
    expect(result.runtime).toEqual([]);
    expect(result.coverage.status).toBe("partial");
    expect(result.coverage.gaps.join("\n")).toMatch(/OpenGrep is unavailable/);
    expect(result.coverage.gaps.join("\n")).toMatch(/unlocked/);
    expect(result.coverage.gaps).toContain(
      "No runtime observations were supplied.",
    );

    // Only beta owns its manifest. The shared lockfile alone cannot identify a copy.
    git("--no-replace-objects", "restore", "--", "package-lock.json");
    const scopes = reviewScopes([
      result,
      {
        ...result,
        package: { ...pkg, ecosystem: "GIT" },
        gitRepository: "https://example.invalid/sample-codec.git",
        manifests: [],
        callers: [],
      },
    ]);
    const dependency = {
      path: "apps/beta/package.json",
      line: 1,
      kind: "dependency" as const,
      package: pkg.name,
    };
    const routed = await dependencyGraphCandidates(
      scopes,
      [dependency, { ...dependency, path: "package-lock.json" }],
      repo,
      new AbortController().signal,
    );
    const beta = scopes.find((s) => s.manifest === dependency.path)!;
    expect([...routed]).toEqual([[beta.id, [dependency]]]);
  } finally {
    await rm(repo, { recursive: true, force: true });
  }
});

test("Python pins and module aliases require scoped source evidence", async () => {
  const repo = await mkdtemp(join(tmpdir(), "python-package-"));
  const git = (...args: string[]) =>
    execFileSync("git", ["-C", repo, ...args], { encoding: "utf8" }).trim();
  try {
    for (const [project, requirement] of [
      ["worker", "sample_image==2.3.4"],
      ["preview", 'sample-image==2.5.0; python_version < "3.12"'],
    ] as const) {
      await mkdir(join(repo, project));
      await writeFile(
        join(repo, project, "requirements.txt"),
        requirement + "\n",
      );
      await writeFile(
        join(repo, project, "main.py"),
        "from decoder import load\nload('sample')\n",
      );
    }
    git("init", "--quiet");
    git("add", ".");
    git(
      "-c",
      "user.name=Fixture",
      "-c",
      "user.email=fixture@example.invalid",
      "commit",
      "--quiet",
      "-m",
      "Fixture",
    );
    const args = {
      repository: repo,
      package: { ecosystem: "PyPI", name: "sample-image" },
      environment: { PATH: "" },
    };
    const evidence = await discoverDependencyRepository({
      ...args,
      symbols: ["decoder.load"],
    });
    expect(
      evidence.callers.map(({ path, version }) => [path, version]),
    ).toEqual([
      ["preview/main.py", undefined],
      ["worker/main.py", "2.3.4"],
    ]);
    expect(evidence.manifests[1]!.selection).toEqual({
      kind: "requirements-pin",
      version: "2.3.4",
      lockfile: "worker/requirements.txt",
      packagePath: "sample-image",
      line: 1,
    });
    const withoutAlias = await discoverDependencyRepository(args);
    expect(withoutAlias.callers).toEqual([]);
    expect(withoutAlias.coverage.gaps.join("\n")).toContain(
      "No direct importing caller",
    );
  } finally {
    await rm(repo, { recursive: true, force: true });
  }
});

test("reports a nested build-only package in the active caller boundary", async () => {
  const repo = await mkdtemp(join(tmpdir(), "dependency-docker-build-"));
  const git = (...args: string[]) =>
    execFileSync("git", ["-C", repo, ...args], { encoding: "utf8" });
  try {
    for (const directory of [
      "services/renderer",
      "tests/fixtures",
      "tests/owned",
    ]) {
      await mkdir(join(repo, directory), { recursive: true });
      await writeFile(
        join(repo, directory, "Dockerfile"),
        "FROM scratch\nRUN apt-get install -y libwebp7\n",
      );
    }
    await writeFile(
      join(repo, "tests/owned/SECURITY.md"),
      "This renderer is deployed.\n",
    );
    git("init", "--quiet");
    git("add", ".");
    git(
      "-c",
      "user.name=Test",
      "-c",
      "user.email=test@example.invalid",
      "commit",
      "-qm",
      "renderer builds",
    );
    const result = await discoverDependencyRepository({
      repository: repo,
      package: { ecosystem: "Debian", name: "libwebp7" },
      callerBoundary: { productionOnly: true, excludePaths: [] },
    });
    expect(result.coverage.status).toBe("unknown");
    expect(result.buildFiles.sort()).toEqual([
      "services/renderer/Dockerfile",
      "tests/owned/Dockerfile",
    ]);
  } finally {
    await rm(repo, { recursive: true, force: true });
  }
});

test("a wildcard npm request selects a locked prerelease like npm does", async () => {
  for (const [requested, selected] of [
    ["*", true],
    ["", true],
    ["^2.0.0-beta.1", true],
    [">=1.0.0", false],
    [">=0.0.0", false],
    ["x", false],
  ] as const) {
    const files: Record<string, string> = {
      "package.json": JSON.stringify({
        name: "app",
        dependencies: { lib: requested },
      }),
      "package-lock.json": JSON.stringify(
        {
          lockfileVersion: 3,
          packages: {
            "": { name: "app", dependencies: { lib: requested } },
            "node_modules/lib": { version: "2.0.0-beta.3" },
          },
        },
        null,
        2,
      ),
    };
    const gaps: string[] = [];
    const [manifest] = await readNpmManifests(
      new Map(Object.keys(files).map((path) => [path, path])),
      ["package.json"],
      "lib",
      async (path) => files[path]!,
      gaps,
    );
    expect(manifest?.selection?.version).toBe(
      selected ? "2.0.0-beta.3" : undefined,
    );
    expect(gaps.length).toBe(selected ? 0 : 1);
  }
});

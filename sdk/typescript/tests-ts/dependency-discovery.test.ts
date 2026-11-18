import { expect, test } from "bun:test";
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { discoverDependencyRepository } from "../src/dependency-discovery.js";

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
    const payload = JSON.stringify({
      service: "alpha",
      package: { ...pkg, version: "1.0.0" },
      revision,
      coverage: "partial",
      evidence: "One request was sampled.",
      access: {
        caller: "example client",
        evidence: "One client request reached this service.",
      },
    });
    const result = await discoverDependencyRepository({
      repository: repo,
      package: pkg,
      environment: { PATH: "" },
      runtimeReceipts: [
        { source: "sample", payload },
        { source: "opaque", payload: "{}" },
      ],
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
    expect(result.runtime[0]).toMatchObject({
      payload,
      sha256: createHash("sha256").update(payload).digest("hex"),
      observation: {
        service: "alpha",
        access: {
          caller: "example client",
          evidence: "One client request reached this service.",
        },
      },
    });
    expect(result.runtime[1]!.observation).toBeUndefined();
    expect(result.coverage.status).toBe("partial");
    expect(result.coverage.gaps.join("\n")).toMatch(/OpenGrep is unavailable/);
    expect(result.coverage.gaps.join("\n")).toMatch(/unlocked/);
    expect(result.coverage.gaps.join("\n")).toMatch(/opaque is unknown/);
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

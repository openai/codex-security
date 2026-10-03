import { describe, expect, test } from "bun:test";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import type { LoadedContract } from "../src/contract.js";
import { requireCloudScanEligibility } from "../src/cloud-scan-eligibility.js";
import { PLUGIN_ROOT } from "./plugin-root.js";
async function contract(): Promise<LoadedContract> {
  const root = join(PLUGIN_ROOT, "examples", "completed-scan");
  const [manifest, findings, coverage] = await Promise.all(
    ["scan-manifest.json", "findings.json", "coverage.json"].map(async (name) =>
      JSON.parse(await readFile(join(root, name), "utf8")),
    ),
  );
  manifest.scan.target.repositoryPath = ".";
  return { manifest, findings, coverage };
}
describe("native Cloud scope eligibility", () => {
  test.each([
    "https://github.com/example/repo.git/",
    "https://github.com/example/repo/",
    "ssh://github.com/example/repo.git/",
  ])("matches saved trailing-slash repository identity %s", async (remote) => {
    const input = await contract();
    input.manifest.scan.target.remote = remote;
    expect(requireCloudScanEligibility(input)).toBe("github.com/example/repo");
  });
  test.each(["git_diff", "directory_snapshot"] as const)(
    "rejects %s imports",
    async (kind) => {
      const input = await contract();
      input.manifest.scan.target.kind = kind;
      expect(() => requireCloudScanEligibility(input)).toThrow(
        "full-repository SCM",
      );
    },
  );
  test("permits a tracked dirty snapshot without pretending it is committed bytes", async () => {
    const input = await contract();
    input.manifest.scan.target.kind = "git_worktree";
    expect(requireCloudScanEligibility(input)).toBe("github.com/example/repo");
    delete input.manifest.scan.target.snapshotDigest;
    expect(() => requireCloudScanEligibility(input)).toThrow(
      "snapshot identity",
    );
  });
  test("checks both coverage and manifest scope", async () => {
    const input = await contract();
    input.coverage.excludePaths = ["src"];
    expect(() => requireCloudScanEligibility(input)).toThrow("scoped");
    input.coverage.excludePaths = [];
    input.manifest.scan.scope.includePaths = ["src"];
    expect(() => requireCloudScanEligibility(input)).toThrow("scoped");
  });
  test("accepts full deep repository coverage and SSH provenance", async () => {
    const input = await contract();
    input.coverage.mode = "deep_repository";
    input.manifest.scan.target.remote = "ssh://github.com/Example/Repo.git";
    expect(requireCloudScanEligibility(input)).toBe("github.com/example/repo");
  });
});

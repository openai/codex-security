import { afterEach, expect, mock, test } from "bun:test";
import { mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { ScanResult } from "../src/result.js";
import { writeScanOwnerSuggestions } from "../src/scan-owner-suggestions.js";
import { fakeResult } from "./cli-fixtures.js";
import { git } from "./git-fixture.js";
import { rejecting } from "./support/errors.js";
import { createApiTestFixtures } from "./support/temporary-directories.js";

const { cleanup, temporaryDirectory } = createApiTestFixtures("scan-owners-");
afterEach(cleanup);
const restoreMany = rejecting("Unexpected bulk artifact restore");

async function fixture() {
  const repository = await temporaryDirectory();
  await writeFile(join(repository, "handler.ts"), "export const value = 1;\n");
  await writeFile(join(repository, "CODEOWNERS"), "*.ts alex@example.test\n");
  git(repository, "init", "-q");
  git(repository, "add", ".");
  git(repository, "commit", "-qm", "Synthetic fixture");
  const source = fakeResult(["high"]);
  source.manifest.scan.target.kind = "git_revision";
  source.manifest.scan.target.revision = git(repository, "rev-parse", "HEAD");
  source.findings.findings[0]!.locations = [
    { path: "handler.ts", startLine: 1 },
  ];
  source.findings.findings[0]!.summary = "Synthetic finding summary.";
  source.findings.findings[0]!.title = "Synthetic ownership finding";
  source.findings.findings[0]!.findingId = "finding-one";
  source.findings.findings[0]!.occurrenceId = "occurrence-one";
  const result = new ScanResult({
    ...source,
    scanDir: await temporaryDirectory(),
  });
  return { repository, result };
}

test.each(["git_revision", "git_diff"] as const)(
  "writes a v2 owner artifact for %s beside unchanged sealed base artifacts",
  async (kind) => {
    const { repository, result } = await fixture();
    const target = result.manifest.scan.target;
    if (kind === "git_diff") {
      const baseRevision = target.revision!;
      await writeFile(
        join(repository, "handler.ts"),
        "export const value = 2;\n",
      );
      git(repository, "add", "handler.ts");
      git(repository, "commit", "-qm", "Synthetic source change");
      target.kind = kind;
      delete target.revision;
      target.baseRevision = baseRevision;
      target.headRevision = git(repository, "rev-parse", "HEAD");
    }
    const revision = target.revision ?? target.headRevision;
    const documents = {
      "scan-manifest.json": result.manifest,
      "findings.json": result.findings,
      "coverage.json": result.coverage,
    };
    for (const [name, document] of Object.entries(documents))
      await writeFile(join(result.scanDir, name), JSON.stringify(document));
    const inference = mock(() => {
      throw new Error("CODEOWNERS needs no inference");
    });
    const restore = mock(async (name: string, bytes: Uint8Array) => {
      await writeFile(join(result.scanDir, name), bytes);
    });
    const path = await writeScanOwnerSuggestions(
      repository,
      result,
      { restore, restoreMany },
      {
        codex: { startThread: inference },
      },
    );
    const report = JSON.parse(await readFile(path, "utf8"));
    expect(report).toMatchObject({
      schemaVersion: 2,
      revision,
      results: [
        {
          findingId: result.findings.findings[0]!.findingId,
          occurrenceId: result.findings.findings[0]!.occurrenceId,
          status: "identified",
          owner: { kind: "person", email: "alex@example.test" },
        },
      ],
    });
    expect(restore).toHaveBeenCalledTimes(1);
    expect(inference).not.toHaveBeenCalled();
    for (const [name, document] of Object.entries(documents))
      expect(await readFile(join(result.scanDir, name), "utf8")).toBe(
        JSON.stringify(document),
      );
  },
);

test.each(["directory_snapshot", "git_worktree"] as const)(
  "does not attribute %s findings to committed HEAD",
  async (kind) => {
    const { repository, result } = await fixture();
    result.manifest.scan.target.kind = kind;
    const restore = mock(async () => {});
    await expect(
      writeScanOwnerSuggestions(
        repository,
        result,
        { restore, restoreMany },
        {},
      ),
    ).rejects.toThrow("committed Git content");
    expect(restore).not.toHaveBeenCalled();
  },
);

test("rejects a changed checkout before starting owner inference", async () => {
  const { repository, result } = await fixture();
  result.manifest.scan.target.revision = "a".repeat(40);
  const restore = mock(async () => {});
  const inference = mock(() => {
    throw new Error("must not run");
  });
  await expect(
    writeScanOwnerSuggestions(
      repository,
      result,
      { restore, restoreMany },
      {
        codex: { startThread: inference },
      },
    ),
  ).rejects.toThrow("checkout does not match");
  expect(inference).not.toHaveBeenCalled();
  expect(restore).not.toHaveBeenCalled();
});

test.each([true, false])(
  "subdirectory owners use Git-root paths (root collision=%p)",
  async (collision) => {
    const { repository, result } = await fixture();
    const service = join(repository, "service");
    await mkdir(service);
    await writeFile(join(service, "handler.ts"), "export const service = 1;\n");
    await writeFile(
      join(repository, "CODEOWNERS"),
      "/handler.ts root@example.test\n/service/handler.ts service@example.test\n",
    );
    if (!collision) await rm(join(repository, "handler.ts"));
    git(repository, "add", ".");
    git(repository, "commit", "-qm", "Synthetic service");
    result.manifest.scan.target.revision = git(repository, "rev-parse", "HEAD");
    const inference = mock(() => {
      throw new Error("CODEOWNERS needs no inference");
    });
    const path = await writeScanOwnerSuggestions(
      service,
      result,
      {
        restoreMany,
        restore: async (name, bytes) => {
          await writeFile(join(result.scanDir, name), bytes);
        },
      },
      { codex: { startThread: inference } },
    );
    const report = JSON.parse(await readFile(path, "utf8"));
    expect(report.results[0]).toMatchObject({
      status: "identified",
      owner: { email: "service@example.test" },
    });
    expect(result.findings.findings[0]!.locations[0]!.path).toBe("handler.ts");
    expect(inference).not.toHaveBeenCalled();
  },
);

test.each([
  "identified",
  "missing",
  "invalid",
  "unknown",
  "wrong_commit",
] as const)(
  "finalizes an inline %s hint without inference and preserves sealed findings",
  async (outcome) => {
    const { repository, result } = await fixture();
    await rm(join(repository, "CODEOWNERS"));
    git(repository, "add", ".");
    git(repository, "commit", "-qm", "Remove declaration");
    const revision = git(repository, "rev-parse", "HEAD");
    const authorCommit = git(repository, "rev-parse", "HEAD^");
    result.manifest.scan.target.revision = revision;
    const finding = result.findings.findings[0]!;
    if (outcome !== "missing")
      finding.extensions = {
        ownerSuggestion:
          outcome === "invalid"
            ? "invalid"
            : {
                email:
                  outcome === "unknown"
                    ? "unobserved@example.test"
                    : git(
                        repository,
                        "show",
                        "-s",
                        "--format=%ae",
                        authorCommit,
                      ),
                commit:
                  outcome === "wrong_commit" ? "0".repeat(40) : authorCommit,
                reason: "Maintains the affected source.",
              },
      };
    const before = JSON.stringify(result.findings);
    const inference = mock(() => {
      throw new Error("No owner inference is allowed");
    });
    const path = await writeScanOwnerSuggestions(
      repository,
      result,
      {
        restore: async (name, bytes) => {
          await writeFile(join(result.scanDir, name), bytes);
        },
        restoreMany,
      },
      { codex: { startThread: inference } },
    );
    const report = JSON.parse(await readFile(path!, "utf8"));
    expect(report.results[0].status).toBe(
      outcome === "identified"
        ? "identified"
        : outcome === "missing"
          ? "abstained"
          : "error",
    );
    expect(JSON.stringify(result.findings)).toBe(before);
    expect(inference).not.toHaveBeenCalled();
  },
);

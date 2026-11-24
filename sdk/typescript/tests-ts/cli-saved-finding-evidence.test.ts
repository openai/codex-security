import { execFileSync } from "node:child_process";
import { mkdir, readFile, rename, rm, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { expect, spyOn, test } from "bun:test";
import { ContinuumValidationProvider } from "../src/continuum-validation-provider.js";
import { exportEnvironment, main } from "../src/cli.js";
import type { Finding, FindingsDocument, ScanManifest } from "../src/models.js";
import { resolvePluginPython } from "../src/runtime.js";
import { dependencies } from "./cli-fixtures.js";
import { copyCompletedScanFixture } from "./plugin-root.js";
import { createCliTest } from "./support/cli-run.js";
import {
  creation,
  registeredSource,
} from "./support/continuum-validation-fixtures.js";
import { setFindingIdentity } from "./support/finding-identity.js";
import { temporaryDirectory } from "./support/temporary-directories.js";
import {
  scanRegistrationArguments,
  workbenchCommand,
} from "./support/workbench-command.js";

function createRepository(repository: string, slug: string) {
  execFileSync("git", ["init", "-q", repository]);
  const git = (...args: string[]) =>
    execFileSync("git", args, { cwd: repository, encoding: "utf8" }).trim();
  git(
    "-c",
    "user.name=Fixture",
    "-c",
    "user.email=fixture@example.test",
    "commit",
    "--allow-empty",
    "-m",
    slug,
  );
  git("remote", "add", "origin", `https://github.com/${slug}`);
  return git("rev-parse", "HEAD");
}

async function savedEvidence(git = false) {
  const root = await temporaryDirectory("saved-finding-evidence-", true);
  const repository = join(root, "repository");
  const scanDir = join(root, "scan");
  const environment = {
    ...exportEnvironment(),
    CODEX_SECURITY_STATE_DIR: join(root, "state"),
  };
  const workbench = workbenchCommand(
    await resolvePluginPython(),
    () => environment,
  );
  try {
    await mkdir(repository);
    const revision = git
      ? createRepository(repository, "example/repo")
      : undefined;
    await mkdir(scanDir, { mode: 0o700 });
    const registered = await workbench(
      scanRegistrationArguments(repository, scanDir),
    );
    const scanId = registered["scanId"] as string;
    await copyCompletedScanFixture(scanDir);
    const manifest = JSON.parse(
      await readFile(join(scanDir, "scan-manifest.json"), "utf8"),
    ) as ScanManifest;
    manifest.scan.id = scanId;
    manifest.scan.target.kind = revision
      ? "git_worktree"
      : "directory_snapshot";
    if (revision) manifest.scan.target.revision = revision;
    manifest.scan.target.targetId = registered["targetId"] as string;
    Reflect.deleteProperty(manifest.scan, "sealedAt");
    Reflect.deleteProperty(manifest.scan, "artifacts");
    const document = JSON.parse(
      await readFile(join(scanDir, "findings.json"), "utf8"),
    ) as FindingsDocument;
    document.scanId = scanId;
    const finding = document.findings[0]!;
    const slug = "synthetic".repeat(28);
    const reportPath = `findings/${slug}/${slug}.md`;
    finding.codeEvidence = Array.from({ length: 9 }, (_, index) => ({
      id: `evidence-${index}`,
      label: `Synthetic evidence ${index}`,
      path: "src/extract.py",
      startLine: index + 1,
      code: `synthetic_source_${index}();\n`.repeat(200),
      explanation: "Synthetic source-to-sink evidence.",
    }));
    finding.validation = {
      summary: "Synthetic validation evidence.",
      counterEvidence: ["A mitigation remains unverified. ".repeat(300)],
    };
    finding.writeup = { reportPath };
    Object.assign(finding, {
      createdAt: "2000-01-01T00:00:00Z",
      remediationState: { status: "fixed" },
      continuumAssessment: { verdict: "EXPLOITABLE", provider: "continuum" },
      matches: [{ occurrenceId: "stale-occurrence" }],
      knownSince: "2000-01-01T00:00:00Z",
      knownScanIds: ["stale-scan"],
      related: [{ occurrenceId: "stale-related-occurrence" }],
      sourceExcerpt: "Stale source excerpt.",
      artifactPaths: ["stale-report.md"],
    });
    const closed = structuredClone(finding);
    closed.identity.anchor = "closed-synthetic-finding";
    delete closed.writeup;
    document.findings.push(closed);
    document.findings.forEach((item) =>
      setFindingIdentity(manifest.scan, item),
    );
    await mkdir(dirname(join(scanDir, reportPath)), { recursive: true });
    await writeFile(join(scanDir, reportPath), "# Synthetic finding report\n");
    const coverage = JSON.parse(
      await readFile(join(scanDir, "coverage.json"), "utf8"),
    );
    coverage.scanId = scanId;
    await Promise.all([
      writeFile(join(scanDir, "scan-manifest.json"), JSON.stringify(manifest)),
      writeFile(join(scanDir, "findings.json"), JSON.stringify(document)),
      writeFile(join(scanDir, "coverage.json"), JSON.stringify(coverage)),
    ]);
    await workbench(["complete-scan", "--scan-id", scanId]);
    const canonical = JSON.parse(
      await readFile(join(scanDir, "findings.json"), "utf8"),
    ) as FindingsDocument;
    expect(canonical.findings).toHaveLength(2);
    await workbench([
      "set-finding-triage",
      "--occurrence-id",
      canonical.findings[1]!.occurrenceId,
      "--status",
      "closed",
      "--close-reason",
      "false_positive",
      "--note",
      "Synthetic closed finding retained for selection coverage.",
    ]);
    return {
      root,
      repository,
      scanDir,
      scanId,
      workbench,
      canonical,
      async [Symbol.asyncDispose]() {
        await rm(root, { recursive: true, force: true });
      },
    };
  } catch (error) {
    await rm(root, { recursive: true, force: true });
    throw error;
  }
}

test("saved validation polls receipts after edits but cannot upload for a replacement checkout", async () => {
  await using fixture = await savedEvidence(true);
  const config = join(fixture.root, "project.json");
  const validation = {
    provider: "continuum",
    continuum: { environment_id: "example" },
  };
  await writeFile(config, JSON.stringify({ scan: { validation } }));
  let source = "example/repo";
  const calls: string[] = [];
  const receipt = creation("f", "example");
  const provider = new ContinuumValidationProvider({
    environmentId: "example",
    launcher: async (op) => {
      const setup = registeredSource(op, "example", source);
      if (setup) return setup;
      calls.push(op);
      if (op === "create-code-finding") return receipt;
      if (op === "get-code-finding") return { ...receipt, status: "DISCARDED" };
      throw new Error(`Unexpected operation ${op}`);
    },
  });
  const run = provider.validateBatch.bind(provider);
  using _batch = spyOn(
    ContinuumValidationProvider.prototype,
    "validateBatch",
  ).mockImplementation(run);
  const state = join(fixture.root, "state");
  const current = dependencies({
    onWorkbench: fixture.workbench,
    environment: { CODEX_SECURITY_STATE_DIR: state },
  });
  delete current.readSavedFindings;
  const args = ["validate", "--scan", fixture.scanId, "-c", config, "--json"];
  const previous = process.env["CODEX_SECURITY_STATE_DIR"];
  process.env["CODEX_SECURITY_STATE_DIR"] = state;
  try {
    const first = createCliTest(main);
    expect(await first.runCli(args, current), first.stderr.text()).toBe(0);
    await writeFile(join(fixture.repository, "changed.txt"), "local edit");
    const poll = createCliTest(main);
    expect(await poll.runCli(args, current), poll.stderr.text()).toBe(0);
    expect(calls).toEqual([
      "create-code-finding",
      "get-code-finding",
      "get-code-finding",
    ]);

    await rename(fixture.repository, join(fixture.root, "original"));
    source = "example/replacement";
    createRepository(fixture.repository, source);
    calls.length = 0;
    const swapped = createCliTest(main);
    expect(await swapped.runCli(args, current), swapped.stderr.text()).toBe(1);
    expect(JSON.parse(swapped.stdout.text()).items[0].unavailable).toMatch(
      /checkout path was replaced/,
    );
    expect(calls).toEqual([]);
  } finally {
    if (previous === undefined) delete process.env["CODEX_SECURITY_STATE_DIR"];
    else process.env["CODEX_SECURITY_STATE_DIR"] = previous;
  }
});

test("saved patch and verification tasks receive complete sealed evidence and live workbench state", async () => {
  await using fixture = await savedEvidence();
  const full = fixture.canonical.findings[0]!;
  expect(full.codeEvidence).toHaveLength(9);
  const preview = await fixture.workbench([
    "get-scan",
    "--scan-id",
    fixture.scanId,
  ]);
  const previewFinding = (preview["scan"] as { findings: Finding[] })
    .findings[0]!;
  expect(previewFinding.codeEvidence).toHaveLength(4);
  expect(previewFinding.writeup?.reportPath).not.toBe(full.writeup!.reportPath);

  const state = join(fixture.root, "state");
  const config = join(fixture.root, "project.json");
  const validation = {
    provider: "continuum",
    continuum: { environment_id: "synthetic" },
  };
  await writeFile(config, JSON.stringify({ scan: { validation } }));
  const assessment = {
    provider: "continuum",
    itemId: full.occurrenceId,
    ...creation("f", "synthetic"),
    submittedAt: "2026-01-01T00:00:00Z",
    verdict: "DISCARDED",
    statusMessage: "Synthetic provider declined validation",
    severityBefore: "high",
    severityAfter: "high",
    reasons: [],
    claimMatch: "unknown" as const,
    freshness: { stale: false, reasons: [] },
  };
  using batch = spyOn(
    ContinuumValidationProvider.prototype,
    "validateBatch",
  ).mockResolvedValue([
    {
      disposition: "not_applicable",
      report: "Synthetic decline",
      provenance: { provider: "continuum", providerVersion: "1" },
      record: assessment,
    },
  ]);
  // A failed save reports the error and still returns the provider result.
  const args = ["validate", "--scan", fixture.scanId, "-c", config, "--json"];
  for (const directory of [fixture.repository, state]) {
    const cli = createCliTest(main);
    const current = dependencies({
      onWorkbench: fixture.workbench,
      environment: { CODEX_SECURITY_STATE_DIR: directory },
    });
    delete current.readSavedFindings;
    expect(await cli.runCli(args, current), cli.stderr.text()).toBe(0);
    expect(JSON.parse(cli.stdout.text()).items).toEqual([assessment]);
    expect(cli.stderr.text().includes("Could not save validation")).toBe(
      directory === fixture.repository,
    );
    expect(batch.mock.calls.at(-1)![0][0]).not.toHaveProperty(
      "continuumAssessment",
    );
  }
  // A model-writable projection cannot replace the host conclusion.
  await writeFile(
    join(fixture.scanDir, "validation.json"),
    JSON.stringify({
      schemaVersion: 1,
      items: [{ ...assessment, verdict: "EXPLOITABLE" }],
    }),
  );
  for (const command of ["patch", "verify-fix"]) {
    const { runCli, stderr } = createCliTest(main);
    const received: Finding[] = [];
    const current = dependencies({
      environment: { CODEX_SECURITY_STATE_DIR: state },
      onWorkbench: fixture.workbench,
      onRepositoryCommand: (_command, args) =>
        args.includes("--name-only") ? "src/extract.py\0" : "",
      onCodex: (_args, output) => {
        const findings = JSON.parse(
          output!.appServer!.prompt.split("\n").at(-1)!,
        ) as Finding[];
        received.push(...findings);
        output!.stdout.write(
          JSON.stringify(
            command === "patch"
              ? {
                  patches: findings.map(({ occurrenceId }) => ({
                    occurrenceId,
                    status: "verified",
                    files: ["src/extract.py"],
                    verification: "Synthetic regression passed.",
                  })),
                }
              : {
                  results: findings.map(({ occurrenceId }) => ({
                    id: occurrenceId,
                    status: "fixed",
                    evidence: "Synthetic regression passed.",
                  })),
                },
          ),
        );
        return 0;
      },
    });
    delete current.readSavedFindings;
    expect(
      await runCli([command, "--scan", fixture.scanId, "--json"], current),
      stderr.text(),
    ).toBe(0);
    expect(received).toHaveLength(1);
    expect(received[0]!.codeEvidence).toHaveLength(9);
    expect(received[0]!["continuumAssessment"]).toEqual({
      itemId: full.occurrenceId,
      provider: "continuum",
      verdict: assessment.verdict,
      claimMatch: "unknown",
      freshness: { stale: false },
    });
    expect(received[0]).toMatchObject({
      occurrenceId: full.occurrenceId,
      findingId: full.findingId,
      remediationTests: full.remediationTests,
      codeEvidence: full.codeEvidence,
      validation: full.validation,
      writeup: full.writeup,
      triage: { status: "open" },
    });
    for (const key of [
      "createdAt",
      "remediationState",
      "matches",
      "knownSince",
      "knownScanIds",
      "related",
      "sourceExcerpt",
      "artifactPaths",
    ]) {
      expect(received[0]![key]).toEqual(previewFinding[key]);
    }
  }
});

test.each(["missing findings", "changed manifest", "wrong scan"])(
  "saved patch tasks stop before Codex when canonical evidence has %s",
  async (failure) => {
    await using fixture = await savedEvidence();
    const { runCli, stderr } = createCliTest(main);
    let calls = 0;
    const current = dependencies({
      onWorkbench: async (args) => {
        if (failure === "wrong scan" && args[0] === "get-scan") {
          const result = await fixture.workbench(args);
          (result["scan"] as { scanId: string }).scanId = "another-scan";
          return result;
        }
        if (failure === "wrong scan" && args[0] === "export-findings") {
          return { scan: { scanDir: fixture.scanDir } };
        }
        return fixture.workbench(args);
      },
      onCodex: () => {
        calls++;
        return 0;
      },
    });
    delete current.readSavedFindings;
    if (failure === "missing findings")
      await rm(join(fixture.scanDir, "findings.json"));
    if (failure === "changed manifest")
      await writeFile(join(fixture.scanDir, "scan-manifest.json"), "{}\n");
    expect(
      await runCli(["patch", "--scan", fixture.scanId], current),
      stderr.text(),
    ).toBe(2);
    expect(calls).toBe(0);
    expect(stderr.text()).toContain(
      failure === "missing findings"
        ? "findings.json"
        : failure === "changed manifest"
          ? "manifest changed"
          : "do not match selected scan",
    );
  },
);

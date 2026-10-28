import { mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { expect, test } from "bun:test";
import { exportEnvironment, main } from "../src/cli.js";
import type { Finding, FindingsDocument, ScanManifest } from "../src/models.js";
import { resolvePluginPython } from "../src/runtime.js";
import { dependencies } from "./cli-fixtures.js";
import {
  readCompletedFindingsFixture,
  copyCompletedScanFixture,
} from "./plugin-root.js";
import { createCliTest } from "./support/cli-run.js";
import { setFindingIdentity } from "./support/finding-identity.js";
import { temporaryDirectory } from "./support/temporary-directories.js";
import {
  scanRegistrationArguments,
  workbenchCommand,
} from "./support/workbench-command.js";

async function savedEvidence() {
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
    manifest.scan.target.kind = "directory_snapshot";
    manifest.scan.target.targetId = registered["targetId"] as string;
    Reflect.deleteProperty(manifest.scan, "sealedAt");
    Reflect.deleteProperty(manifest.scan, "artifacts");
    const document = await readCompletedFindingsFixture();
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
      method: "synthetic fixture",
      evidenceRefs: ["evidence-0"],
      summary: "Synthetic validation evidence.",
      counterEvidence: ["A mitigation remains unverified. ".repeat(300)],
    };
    finding.writeup = { reportPath };
    Object.assign(finding, {
      createdAt: "2000-01-01T00:00:00Z",
      remediationState: { status: "fixed" },
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

  for (const command of ["patch", "verify-fix"]) {
    const { runCli, stderr } = createCliTest(main);
    const received: Finding[] = [];
    const current = dependencies({
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
    expect(received[0]).toMatchObject({
      occurrenceId: full.occurrenceId,
      findingId: full.findingId,
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

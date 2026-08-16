import { createHash } from "node:crypto";
import { chmod, cp, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, test } from "bun:test";
import { prepareScanPublication } from "../src/publication.js";
import type {
  CoverageDocument,
  FindingsDocument,
  ScanManifest,
  SeverityLevel,
} from "../src/models.js";
import { PLUGIN_ROOT } from "./plugin-root.js";

const EXAMPLE = join(PLUGIN_ROOT, "examples", "completed-scan");
const temporaryDirectories: string[] = [];
const DESTINATION = {
  destination: "linear",
  teamId: "team_example",
  projectId: "project_example",
  uploadedAt: "2026-06-01T10:30:00Z",
} as const;

afterEach(async () => {
  await Promise.all(
    temporaryDirectories
      .splice(0)
      .map((directory) => rm(directory, { recursive: true, force: true })),
  );
});

async function copyExample(): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), "codex-security-publication-"));
  temporaryDirectories.push(root);
  const scanDirectory = join(root, "scan");
  await cp(EXAMPLE, scanDirectory, { recursive: true });
  if (process.platform !== "win32") await chmod(scanDirectory, 0o700);
  return scanDirectory;
}

async function readJson<T>(path: string): Promise<T> {
  return JSON.parse(await readFile(path, "utf8")) as T;
}

async function writeJson(path: string, value: unknown): Promise<void> {
  await writeFile(path, `${JSON.stringify(value, null, 2)}\n`);
}

async function reseal(scanDirectory: string): Promise<void> {
  const manifestPath = join(scanDirectory, "scan-manifest.json");
  const manifest = await readJson<ScanManifest>(manifestPath);
  for (const artifact of manifest.scan.artifacts) {
    artifact.sha256 = createHash("sha256")
      .update(await readFile(join(scanDirectory, artifact.path)))
      .digest("hex");
  }
  await writeJson(manifestPath, manifest);
}

describe("scan publication preparation", () => {
  test("prepares sealed findings with scan-based upload IDs and full traceability", async () => {
    const scanDirectory = await copyExample();
    const publication = await prepareScanPublication(
      scanDirectory,
      DESTINATION,
    );

    expect(publication).toMatchObject({
      scanId: "scan_example_001",
      uploadId: "scan_example_001",
      scanDirectory,
      destination: {
        type: "linear",
        teamId: "team_example",
        projectId: "project_example",
      },
      issues: [
        {
          findingId: "csf_852f90d6e1177502ff113d4a",
          occurrenceId: "occ_e79cb19591e696572a1c22be",
          title:
            "[Codex Security][HIGH] Unsafe archive extraction can escape the output directory",
          priority: 2,
        },
      ],
    });

    const issue = publication.issues[0]!;
    expect(issue.title).not.toContain(publication.scanId);
    expect(issue.title).not.toContain("example/repo");
    expect(issue.description).toContain("**Scan ID:** scan_example_001");
    expect(issue.description).not.toContain("**Upload ID:**");
    expect(issue.description).toContain(issue.findingId);
    expect(issue.description).toContain(issue.occurrenceId);
    expect(issue.description).toContain("**Repository:** example/repo");
    expect(issue.description).toContain("https://github.com/example/repo");
    expect(issue.description).toContain("**Base revision:** deadbeef");
    expect(issue.description).toContain(
      "**Snapshot digest:** codex-security-snapshot/v1:sha256:",
    );
    expect(issue.description).toContain("**Scanned scope:** .");
    expect(issue.description).toContain("**Coverage:** complete");
    expect(issue.description).toContain("**Scan mode:** standard");
    expect(issue.description).toContain("**CWE:** CWE-22");
    expect(issue.description).toContain("**Sink:** `src/extract.py:41-44`");
    expect(issue.description).toContain("**Uploaded:** 2026-06-01T10:30:00Z");
    expect(issue.description).toContain("without containment validation");
    expect(issue.description).toContain("Normalize destinations");
    expect(issue.description).not.toContain("/blob/deadbeef/");
  });

  test.each([
    ["repository", "standard"],
    ["scoped_path", "scoped_path"],
    ["diff", "diff"],
    ["commit", "commit"],
    ["branch_diff", "branch_diff"],
    ["working_tree", "working_tree"],
    ["deep_repository", "deep"],
  ] as const)(
    "preserves truthful scan provenance for %s coverage",
    async (mode, expectedMode) => {
      const scanDirectory = await copyExample();
      const coveragePath = join(scanDirectory, "coverage.json");
      const coverage = await readJson<CoverageDocument>(coveragePath);
      coverage.mode = mode;
      await writeJson(coveragePath, coverage);
      await reseal(scanDirectory);

      const { description } = (
        await prepareScanPublication(scanDirectory, DESTINATION)
      ).issues[0]!;

      expect(description).toContain(`**Coverage mode:** ${mode}`);
      expect(description).toContain(`**Scan mode:** ${expectedMode}`);
      expect(description).not.toContain("**Scan mode:** unknown");
    },
  );

  test("prepares sealed findings for a Linear team without a project", async () => {
    const scanDirectory = await copyExample();
    const publication = await prepareScanPublication(scanDirectory, {
      destination: "linear",
      teamId: "team_example",
      uploadedAt: "2026-06-01T10:30:00Z",
    });

    expect(publication.destination).toEqual({
      type: "linear",
      teamId: "team_example",
    });
    expect(publication.destination).not.toHaveProperty("projectId");
    expect(publication.issues[0]).toMatchObject({
      findingId: "csf_852f90d6e1177502ff113d4a",
      occurrenceId: "occ_e79cb19591e696572a1c22be",
    });
  });

  test("includes every canonical source snippet, location role, and root-cause code", async () => {
    const scanDirectory = await copyExample();
    const findingsPath = join(scanDirectory, "findings.json");
    const findings = await readJson<FindingsDocument>(findingsPath);
    const finding = findings.findings[0]!;
    finding.locations.push({
      path: "src/archive.py",
      startLine: 12,
      role: "root_control",
    });
    finding.codeEvidence = [
      {
        id: "untrusted-source",
        label: "Untrusted archive entry",
        path: "src/archive.py",
        startLine: 12,
        language: "python",
        role: "source",
        code: "entry = archive.read(request.path)",
        explanation: "An attacker controls the selected entry.",
      },
      {
        id: "filesystem-sink",
        label: "Filesystem write",
        path: "src/extract.py",
        startLine: 41,
        endLine: 44,
        language: "python",
        role: "sink",
        code: "destination.write_bytes(entry.read())",
        explanation: "No containment validation runs before the write.",
      },
      {
        id: "markdown-fence",
        label: "Literal Markdown delimiter",
        path: "src/extract.py",
        startLine: 43,
        language: "python\n## unexpected-heading",
        code: "````\nprint('literal fence')",
        explanation: "Source text can contain Markdown fence characters.",
      },
    ];
    finding.rootCause = {
      summary: "Archive paths bypass containment validation.",
      language: "python",
      code: "destination = output / entry.name",
    };
    await writeJson(findingsPath, findings);
    await reseal(scanDirectory);

    const { description } = (
      await prepareScanPublication(scanDirectory, DESTINATION)
    ).issues[0]!;

    expect(description).toContain("**Root control:** `src/archive.py:12`");
    expect(description).toContain(
      "Archive paths bypass containment validation.",
    );
    expect(description).toContain(
      "```python\ndestination = output / entry.name\n```",
    );
    expect(description).toContain("### Untrusted archive entry");
    expect(description).toContain("**Source:** `src/archive.py:12`");
    expect(description).toContain(
      "```python\nentry = archive.read(request.path)\n```",
    );
    expect(description).toContain("An attacker controls the selected entry.");
    expect(description).toContain("### Filesystem write");
    expect(description).toContain(
      "```python\ndestination.write_bytes(entry.read())\n```",
    );
    expect(description).toContain(
      "No containment validation runs before the write.",
    );
    expect(description).toContain("`````\n````\nprint('literal fence')\n`````");
    expect(description).not.toContain("unexpected-heading");
  });

  test("only links source locations for a full immutable GitHub revision", async () => {
    const scanDirectory = await copyExample();
    const manifestPath = join(scanDirectory, "scan-manifest.json");
    const manifest = await readJson<ScanManifest>(manifestPath);
    manifest.scan.target.kind = "git_revision";
    manifest.scan.target.revision = "0123456789abcdef0123456789abcdef01234567";
    delete manifest.scan.target.snapshotDigest;
    await writeJson(manifestPath, manifest);

    const { description } = (
      await prepareScanPublication(scanDirectory, DESTINATION)
    ).issues[0]!;

    expect(description).toContain(
      "https://github.com/example/repo/blob/0123456789abcdef0123456789abcdef01234567/src/extract.py#L41-L44",
    );
    expect(description).toContain(
      "**Revision:** 0123456789abcdef0123456789abcdef01234567",
    );
    expect(description).not.toContain("Snapshot digest");
  });

  test("does not turn non-HTTPS repository remotes into source links", async () => {
    const scanDirectory = await copyExample();
    const manifestPath = join(scanDirectory, "scan-manifest.json");
    const manifest = await readJson<ScanManifest>(manifestPath);
    manifest.scan.target.kind = "git_revision";
    manifest.scan.target.revision = "0123456789abcdef0123456789abcdef01234567";
    manifest.scan.target.remote = "ssh://github.com/example/repo";
    delete manifest.scan.target.snapshotDigest;
    await writeJson(manifestPath, manifest);

    const { description } = (
      await prepareScanPublication(scanDirectory, DESTINATION)
    ).issues[0]!;

    expect(description).toContain("**Remote:** ssh://github.com/example/repo");
    expect(description).toContain("**Sink:** `src/extract.py:41-44`");
    expect(description).not.toContain("/blob/");
  });

  test("preserves unsafe evidence snippets without generating escaping source links", async () => {
    const scanDirectory = await copyExample();
    const manifestPath = join(scanDirectory, "scan-manifest.json");
    const manifest = await readJson<ScanManifest>(manifestPath);
    manifest.scan.target.kind = "git_revision";
    manifest.scan.target.revision = "0123456789abcdef0123456789abcdef01234567";
    delete manifest.scan.target.snapshotDigest;
    await writeJson(manifestPath, manifest);

    const findingsPath = join(scanDirectory, "findings.json");
    const findings = await readJson<FindingsDocument>(findingsPath);
    const paths = [
      "../outside.py",
      "src/../outside.py",
      "src/./outside.py",
      "src//outside.py",
      "/outside.py",
      "src\\outside.py",
      "C:/outside.py",
      "src/%2e%2e/outside.py",
      "src/%2foutside.py",
      "src/%5coutside.py",
    ];
    findings.findings[0]!.codeEvidence = paths.map((path, index) => ({
      id: `unsafe-path-${index}`,
      label: `Unsafe path ${index}`,
      path,
      startLine: 41,
      role: "source",
      code: `preserved_snippet_${index}()`,
      explanation:
        "Preserve canonical evidence even without a safe source link.",
    }));
    await writeJson(findingsPath, findings);
    await reseal(scanDirectory);

    const { description } = (
      await prepareScanPublication(scanDirectory, DESTINATION)
    ).issues[0]!;

    expect(description).toContain(
      "https://github.com/example/repo/blob/0123456789abcdef0123456789abcdef01234567/src/extract.py#L41-L44",
    );
    for (const [index, path] of paths.entries()) {
      expect(description).toContain(`**Source:** \`${path}:41\``);
      expect(description).toContain(`preserved_snippet_${index}()`);
      expect(description).not.toContain(`[\`${path}:41\`](`);
    }
  });

  test.each([
    ["critical", 1],
    ["high", 2],
    ["medium", 3],
    ["low", 4],
    ["informational", undefined],
  ] as const)(
    "maps %s severity to Linear priority %s",
    async (severity, priority) => {
      const scanDirectory = await copyExample();
      const findingsPath = join(scanDirectory, "findings.json");
      const findings = await readJson<FindingsDocument>(findingsPath);
      findings.findings[0]!.severity.level = severity satisfies SeverityLevel;
      await writeJson(findingsPath, findings);
      await reseal(scanDirectory);

      const issue = (await prepareScanPublication(scanDirectory, DESTINATION))
        .issues[0]!;
      expect(issue.title).toStartWith(
        `[Codex Security][${severity.toUpperCase()}] `,
      );
      expect(issue.priority).toBe(priority);
      if (priority === undefined) expect(issue).not.toHaveProperty("priority");
    },
  );

  test("preserves an empty sealed finding set", async () => {
    const scanDirectory = await copyExample();
    const findingsPath = join(scanDirectory, "findings.json");
    const findings = await readJson<FindingsDocument>(findingsPath);
    findings.findings = [];
    await writeJson(findingsPath, findings);
    await reseal(scanDirectory);

    expect(
      (await prepareScanPublication(scanDirectory, DESTINATION)).issues,
    ).toEqual([]);
  });

  test("rejects findings whose sealed artifact has been modified", async () => {
    const scanDirectory = await copyExample();
    const findingsPath = join(scanDirectory, "findings.json");
    const findings = await readJson<FindingsDocument>(findingsPath);
    findings.findings[0]!.summary = "Modified after the scan was sealed.";
    await writeJson(findingsPath, findings);

    await expect(
      prepareScanPublication(scanDirectory, DESTINATION),
    ).rejects.toThrow();
  });
});

import { createHash } from "node:crypto";
import { chmod, mkdir, readFile, realpath, symlink } from "node:fs/promises";
import { dirname, join } from "node:path";
import { afterEach, describe, expect, test } from "bun:test";
import { prepareScanPublication } from "../src/publication.js";
import type {
  CoverageDocument,
  FindingsDocument,
  ScanManifest,
  SeverityLevel,
} from "../src/models.js";
import { copyCompletedScanFixture } from "./plugin-root.js";
import { createApiTestFixtures } from "./support/temporary-directories.js";
import { readJson, writeJson } from "./support/json.js";

const { temporaryDirectory, cleanup } = createApiTestFixtures(
  "codex-security-publication-",
  false,
);
function publicationOptions(scanDirectory: string) {
  return {
    destination: "linear",
    teamId: "team_example",
    projectId: "project_example",
    uploadedAt: "2026-06-01T10:30:00Z",
    environment: {
      CODEX_SECURITY_STATE_DIR: join(dirname(scanDirectory), "state"),
    },
  } as const;
}

afterEach(cleanup);

async function copyExample(): Promise<string> {
  const root = await temporaryDirectory();
  const scanDirectory = join(root, "scan");
  await copyCompletedScanFixture(scanDirectory);
  if (process.platform !== "win32") await chmod(scanDirectory, 0o700);
  return scanDirectory;
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
  test("preserves cancellation while loading the sealed scan", async () => {
    const scanDirectory = await copyExample();
    const controller = new AbortController();
    const reason = new Error("Publication preparation canceled.");
    controller.abort(reason);

    await expect(
      prepareScanPublication(scanDirectory, {
        ...publicationOptions(scanDirectory),
        signal: controller.signal,
      }),
    ).rejects.toBe(reason);
  });

  test("requires artifacts to match the selected saved scan", async () => {
    const scanDirectory = await copyExample();
    await expect(
      prepareScanPublication(scanDirectory, {
        ...publicationOptions(scanDirectory),
        expectedScanId: "another-scan",
      }),
    ).rejects.toThrow(
      "Scan artifacts do not match selected scan another-scan.",
    );
    expect(
      (
        await prepareScanPublication(scanDirectory, {
          ...publicationOptions(scanDirectory),
          expectedScanId: "scan_example_001",
        })
      ).scanId,
    ).toBe("scan_example_001");
  });

  test("prepares sealed findings with full traceability", async () => {
    const scanDirectory = await copyExample();
    const publication = await prepareScanPublication(
      scanDirectory,
      publicationOptions(scanDirectory),
    );

    expect(publication).toMatchObject({
      scanId: "scan_example_001",
      scanDirectory: await realpath(scanDirectory),
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
    expect(issue.description).not.toContain("**Coverage:**");
    expect(issue.description).toContain("**Scan mode:** standard");
    expect(issue.description).toContain("**CWE:** CWE-22");
    expect(issue.description).toContain("**Sink:** `src/extract.py:41-44`");
    expect(issue.description).toContain("**Uploaded:** 2026-06-01T10:30:00Z");
    expect(issue.description).toContain("without containment validation");
    expect(issue.description).toContain("Normalize destinations");
    expect(
      issue.description.indexOf("without containment validation"),
    ).toBeLessThan(issue.description.indexOf("**Scan ID:**"));
    expect(issue.description.indexOf("Normalize destinations")).toBeLessThan(
      issue.description.indexOf("**Scan ID:**"),
    );
    expect(issue.description).not.toContain("/blob/deadbeef/");
  });

  test("keeps the reproduction and validation limits ahead of scan metadata", async () => {
    const scanDirectory = await copyExample();
    const findingsPath = join(scanDirectory, "findings.json");
    const findings = await readJson<FindingsDocument>(findingsPath);
    const finding = findings.findings[0]!;
    const reproduction =
      "Import an archive containing ../escape.txt. The importer should reject it; source review shows it writing outside the selected directory. This was not run.";
    const unrun = "No runtime reproduction was run.";
    const attackPath = {
      summary: reproduction,
      limitations: [unrun, "Files must be writable by the importing process."],
    };
    const validation = {
      method: "Source review",
      summary: "The importer passes the entry name to the filesystem write.",
      limitations: [unrun],
      counterEvidence: ["The user must first choose to import the archive."],
    };
    finding.attackPath = attackPath;
    finding.validation = validation;
    await writeJson(findingsPath, findings);
    await reseal(scanDirectory);

    const { description } = (
      await prepareScanPublication(
        scanDirectory,
        publicationOptions(scanDirectory),
      )
    ).issues[0]!;

    const metadata = description.indexOf("**Scan ID:**");
    for (const text of [
      finding.summary,
      reproduction,
      validation.summary,
      validation.method,
      ...validation.limitations,
      ...validation.counterEvidence,
      ...attackPath.limitations,
    ]) {
      expect(description).toContain(text);
      expect(description.indexOf(text)).toBeLessThan(metadata);
    }
    expect(description.split(unrun)).toHaveLength(2);
  });

  test("uses the canonical scan directory beneath an aliased parent", async () => {
    const root = await temporaryDirectory("codex-security-publication-alias-");
    const parent = join(root, "actual-parent");
    const alias = join(root, "aliased-parent");
    const scanDirectory = join(parent, "scan");
    await mkdir(parent, { mode: 0o700 });
    await copyCompletedScanFixture(scanDirectory);
    if (process.platform !== "win32") await chmod(scanDirectory, 0o700);
    await symlink(
      parent,
      alias,
      process.platform === "win32" ? "junction" : "dir",
    );

    const publication = await prepareScanPublication(
      join(alias, "scan"),
      publicationOptions(scanDirectory),
    );

    expect(publication.scanDirectory).toBe(await realpath(scanDirectory));
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
        await prepareScanPublication(
          scanDirectory,
          publicationOptions(scanDirectory),
        )
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
      environment: publicationOptions(scanDirectory).environment,
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
      await prepareScanPublication(
        scanDirectory,
        publicationOptions(scanDirectory),
      )
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
      await prepareScanPublication(
        scanDirectory,
        publicationOptions(scanDirectory),
      )
    ).issues[0]!;

    expect(description).toContain(
      "https://github.com/example/repo/blob/0123456789abcdef0123456789abcdef01234567/src/extract.py#L41-L44",
    );
    expect(description).toContain(
      "**Revision:** 0123456789abcdef0123456789abcdef01234567",
    );
    expect(description).not.toContain("Snapshot digest");
  });

  test.each([
    ["string", undefined, "Legacy root summary.", ["Legacy root summary."], []],
    [
      "code only",
      undefined,
      { code: "legacy_control()", language: "python" },
      ["```python\nlegacy_control()\n```"],
      ["undefined"],
    ],
    [
      "complementary",
      { summary: "Canonical root summary.", language: "javascript" },
      {
        summary: "Shadow summary.",
        code: "legacy_control()",
        language: "python",
      },
      ["Canonical root summary.", "```python\nlegacy_control()\n```"],
      ["Shadow summary.", "```javascript"],
    ],
    [
      "conflicting",
      {
        summary: "Canonical root summary.",
        code: "canonical_control()",
        language: "python",
      },
      {
        summary: "Shadow summary.",
        code: "legacy_control()",
        language: "javascript",
      },
      ["Canonical root summary.", "```python\ncanonical_control()\n```"],
      ["Shadow summary.", "legacy_control()"],
    ],
    [
      "different code without canonical language",
      { summary: "Canonical root summary.", code: "canonical_control()" },
      { code: "legacy_control()", language: "python" },
      ["```\ncanonical_control()\n```"],
      ["```python", "legacy_control()"],
    ],
    [
      "string with complementary code",
      "Canonical root summary.",
      { code: "legacy_control()", language: "python" },
      ["Canonical root summary.", "```python\nlegacy_control()\n```"],
      [],
    ],
    [
      "same code",
      { summary: "Canonical root summary.", code: "same_control()" },
      { code: "same_control()", language: "python" },
      ["```python\nsame_control()\n```"],
      [],
    ],
    [
      "blank canonical",
      { summary: " ", code: "\t", language: "javascript" },
      {
        summary: "Legacy root summary.",
        code: "legacy_control()",
        language: "python",
      },
      ["Legacy root summary.", "```python\nlegacy_control()\n```"],
      ["```javascript"],
    ],
    ["null", undefined, null, [], ["## Root cause"]],
    ["empty object", undefined, {}, [], ["## Root cause"]],
  ] as const)(
    "preserves %s historical root details",
    async (_name, canonical, legacy, present, absent) => {
      const scanDirectory = await copyExample();
      const findingsPath = join(scanDirectory, "findings.json");
      const findings = await readJson<FindingsDocument>(findingsPath);
      findings.findings[0]!.rootCause = canonical;
      findings.findings[0]!.root_cause = legacy;
      await writeJson(findingsPath, findings);
      await reseal(scanDirectory);
      const saved = await readFile(findingsPath, "utf8");
      const { description } = (
        await prepareScanPublication(
          scanDirectory,
          publicationOptions(scanDirectory),
        )
      ).issues[0]!;
      for (const text of present) expect(description).toContain(text);
      for (const text of absent) expect(description).not.toContain(text);
      expect(await readFile(findingsPath, "utf8")).toBe(saved);
    },
  );

  test("preserves historical evidence with missing or invalid optional metadata", async () => {
    const scanDirectory = await copyExample();
    const findingsPath = join(scanDirectory, "findings.json");
    const findings = await readJson<FindingsDocument>(findingsPath);
    const finding = findings.findings[0]!;
    const canonical = {
      id: "shared",
      label: "Canonical source",
      path: "src/canonical.py",
      startLine: 12,
      code: "canonical_source()",
      explanation: "Canonical explanation.",
    };
    finding.codeEvidence = [
      canonical,
      { ...canonical, code: "second_canonical_source()" },
      { ...canonical, id: "canonical-whitespace", code: " \t " },
    ];
    finding.code_evidence = [
      { id: "shared", code: "shadow_source()" },
      {
        id: "minimal",
        code: "````\nlegacy_minimal()",
        language: "text\n## injected-language",
      },
      { id: "minimal", code: "duplicate_legacy_source()" },
      {
        id: "invalid",
        code: "legacy_invalid_metadata()",
        label: 42,
        path: false,
        role: {},
        language: [],
        explanation: true,
      },
      { id: "whitespace", code: " \t " },
      { id: "whitespace", code: "legacy_whitespace_evidence()" },
      { id: "canonical-whitespace", code: "canonical_whitespace_evidence()" },
      {
        id: "path-only",
        code: "legacy_path_only()",
        path: "src/path-only.py",
        startLine: true,
        endLine: 42,
      },
      {
        id: "range",
        code: "legacy_range()",
        path: "src/range.py",
        startLine: 12,
        endLine: 8,
        label: "Legacy range",
        explanation: "Legacy explanation.",
        role: "source",
        language: "python",
      },
    ];
    await writeJson(findingsPath, findings);
    const manifestPath = join(scanDirectory, "scan-manifest.json");
    const manifest = await readJson<ScanManifest>(manifestPath);
    manifest.scan.target.kind = "git_revision";
    manifest.scan.target.revision = "0123456789abcdef0123456789abcdef01234567";
    delete manifest.scan.target.snapshotDigest;
    await writeJson(manifestPath, manifest);
    await reseal(scanDirectory);
    const saved = await readFile(findingsPath, "utf8");
    const { description } = (
      await prepareScanPublication(
        scanDirectory,
        publicationOptions(scanDirectory),
      )
    ).issues[0]!;
    for (const snippet of [
      "canonical_source()",
      "second_canonical_source()",
      "legacy_minimal()",
      "legacy_invalid_metadata()",
      "legacy_path_only()",
      "legacy_range()",
      "legacy_whitespace_evidence()",
      "canonical_whitespace_evidence()",
    ])
      expect(description).toContain(snippet);
    expect(description.indexOf("canonical_source()")).toBeLessThan(
      description.indexOf("second_canonical_source()"),
    );
    expect(description.indexOf("second_canonical_source()")).toBeLessThan(
      description.indexOf("legacy_minimal()"),
    );
    expect(description.indexOf("legacy_minimal()")).toBeLessThan(
      description.indexOf("legacy_invalid_metadata()"),
    );
    for (const omitted of [
      "shadow_source()",
      "duplicate_legacy_source()",
      "injected-language",
      "undefined",
      "[object Object]",
    ])
      expect(description).not.toContain(omitted);
    expect(description).toContain("`````\n````\nlegacy_minimal()\n`````");
    expect(description.split("```\n \t \n```")).toHaveLength(3);
    expect(description).toContain("`src/path-only.py`");
    expect(description).not.toContain("[`src/path-only.py");
    expect(description).toContain("src/range.py#L12)");
    expect(description).not.toContain("#L12-L8");
    expect(description).toContain("Legacy explanation.");
    expect(await readFile(findingsPath, "utf8")).toBe(saved);
  });

  test("preserves embedded root-cause evidence across historical aliases", async () => {
    const scanDirectory = await copyExample();
    const findingsPath = join(scanDirectory, "findings.json");
    const findings = await readJson<FindingsDocument>(findingsPath);
    const finding = findings.findings[0]!;
    const canonical = {
      id: "shared",
      label: "Canonical source",
      path: "src/canonical.py",
      startLine: 12,
      code: "canonical_source()",
      explanation: "Canonical explanation.",
    };
    finding.codeEvidence = [canonical, canonical];
    finding.code_evidence = [{ id: "top-level", code: "top_level_legacy()" }];
    finding.rootCause = {
      summary: "Canonical root summary.",
      codeEvidence: [
        { id: "shared", code: "embedded_canonical()" },
        { code: "anonymous_first()" },
        { code: "anonymous_second()" },
        { code: "anonymous_first()" },
        null,
        "not an evidence object",
        {},
        { code: false },
        { code: " \t " },
      ],
      code_evidence: [
        { id: "canonical-alias", code: "embedded_canonical_alias()" },
      ],
    };
    finding.root_cause = {
      codeEvidence: [
        { id: "shared", code: "embedded_canonical()" },
        { id: "shared", code: "embedded_legacy()" },
      ],
      code_evidence: [{ id: "legacy-alias", code: "embedded_legacy_alias()" }],
    };
    await writeJson(findingsPath, findings);
    await reseal(scanDirectory);
    const saved = await readFile(findingsPath, "utf8");

    const { description } = (
      await prepareScanPublication(
        scanDirectory,
        publicationOptions(scanDirectory),
      )
    ).issues[0]!;

    const snippets = [
      "canonical_source()",
      "top_level_legacy()",
      "embedded_canonical()",
      "anonymous_first()",
      "anonymous_second()",
      "embedded_canonical_alias()",
      "embedded_legacy()",
      "embedded_legacy_alias()",
    ];
    for (const snippet of snippets) expect(description).toContain(snippet);
    for (let index = 1; index < snippets.length; index++)
      expect(description.lastIndexOf(snippets[index - 1]!)).toBeLessThan(
        description.indexOf(snippets[index]!),
      );
    expect(description.split("canonical_source()")).toHaveLength(3);
    expect(description.split("embedded_canonical()")).toHaveLength(2);
    expect(description.split("anonymous_first()")).toHaveLength(2);
    expect(await readFile(findingsPath, "utf8")).toBe(saved);
  });

  test("preserves nested historical evidence coordinates and source-link rules", async () => {
    const scanDirectory = await copyExample();
    const findingsPath = join(scanDirectory, "findings.json");
    const findings = await readJson<FindingsDocument>(findingsPath);
    const finding = findings.findings[0]!;
    finding.codeEvidence = [
      {
        id: "canonical-nested",
        label: "Canonical nested location",
        path: "src/shadow-canonical.py",
        startLine: 1,
        code: "canonical_nested_location()",
        explanation: "Canonical explanation.",
        location: {
          path: "src/canonical-nested.py",
          startLine: 20,
          endLine: 24,
        },
      },
      {
        id: "canonical-backticks",
        label: "Canonical backtick path",
        path: "app/api/`id`/route.ts",
        startLine: 7,
        code: "canonical_backtick_path()",
        explanation: "Canonical backtick explanation.",
      },
    ];
    finding.code_evidence = [
      {
        id: "nested-range",
        code: "nested_range()",
        path: "src/shadow.py",
        startLine: 1,
        endLine: 2,
        location: { path: "src/nested.py", startLine: 12, endLine: 15 },
      },
      {
        id: "reversed-range",
        code: "reversed_range()",
        location: { path: "src/reversed.py", startLine: 48, endLine: 47 },
      },
      {
        id: "path-only",
        code: "nested_path_only()",
        location: { path: "src/path-only.py", startLine: true, endLine: 42 },
      },
      {
        id: "backtick-path-only",
        code: "backtick_path_only()",
        location: { path: "`route`.ts" },
      },
      {
        id: "unsafe-path",
        code: "unsafe_path()",
        location: { path: "../outside.py", startLine: 10 },
      },
    ];
    await writeJson(findingsPath, findings);
    const manifestPath = join(scanDirectory, "scan-manifest.json");
    const manifest = await readJson<ScanManifest>(manifestPath);
    manifest.scan.target.kind = "git_revision";
    manifest.scan.target.revision = "0123456789abcdef0123456789abcdef01234567";
    delete manifest.scan.target.snapshotDigest;
    await writeJson(manifestPath, manifest);
    await reseal(scanDirectory);
    const saved = await readFile(findingsPath, "utf8");

    const { description } = (
      await prepareScanPublication(
        scanDirectory,
        publicationOptions(scanDirectory),
      )
    ).issues[0]!;

    expect(description).toContain("src/canonical-nested.py#L20-L24)");
    expect(description).toContain("[``app/api/`id`/route.ts:7``]");
    expect(description).toContain("app/api/%60id%60/route.ts#L7)");
    expect(description).toContain("`` `route`.ts ``");
    expect(description).not.toContain("src/shadow-canonical.py");
    expect(description).toContain("src/nested.py:12-15");
    expect(description).toContain("src/nested.py#L12-L15)");
    expect(description).not.toContain("src/shadow.py");
    expect(description).toContain("src/reversed.py#L48)");
    expect(description).not.toContain("#L48-L47");
    expect(description).toContain("`src/path-only.py`");
    expect(description).not.toContain("[`src/path-only.py");
    expect(description).toContain("`../outside.py:10`");
    expect(description).not.toContain("/../outside.py#");
    expect(await readFile(findingsPath, "utf8")).toBe(saved);
  });

  test("preserves embedded validation and attack-path evidence catalogs", async () => {
    const scanDirectory = await copyExample();
    const findingsPath = join(scanDirectory, "findings.json");
    const findings = await readJson<FindingsDocument>(findingsPath);
    const finding = findings.findings[0]!;
    const embedded = (name: string) => ({
      codeEvidence: [{ code: `${name}_canonical()` }],
      code_evidence: [{ code: `${name}_legacy()` }],
    });
    finding.validation = embedded("validation");
    finding.attackPath = {
      ...embedded("attack"),
      dataFlow: embedded("data_flow_camel"),
      dataflow: embedded("data_flow_lower"),
      data_flow: embedded("data_flow_snake"),
      reachability: embedded("reachability"),
    };
    await writeJson(findingsPath, findings);
    await reseal(scanDirectory);
    const saved = await readFile(findingsPath, "utf8");

    const { description } = (
      await prepareScanPublication(
        scanDirectory,
        publicationOptions(scanDirectory),
      )
    ).issues[0]!;

    let previous = -1;
    for (const section of [
      "validation",
      "attack",
      "data_flow_camel",
      "data_flow_lower",
      "data_flow_snake",
      "reachability",
    ]) {
      for (const alias of ["canonical", "legacy"]) {
        const snippet = `${section}_${alias}()`;
        expect(description).toContain(snippet);
        expect(description.indexOf(snippet)).toBeGreaterThan(previous);
        previous = description.indexOf(snippet);
      }
    }
    expect(await readFile(findingsPath, "utf8")).toBe(saved);
  });

  test("preserves string evidence locations as literal labels in both catalogs", async () => {
    const scanDirectory = await copyExample();
    const findingsPath = join(scanDirectory, "findings.json");
    const findings = await readJson<FindingsDocument>(findingsPath);
    const finding = findings.findings[0]!;
    finding.codeEvidence = [
      {
        id: "canonical-string",
        label: "Canonical string location",
        path: "src/shadow-canonical.py",
        startLine: 1,
        code: "canonical_string_location()",
        explanation: "Canonical explanation.",
        location: "  src/string.py:12 \n  additional context  ",
      },
    ];
    finding.code_evidence = [
      {
        id: "legacy-string",
        code: "legacy_string_location()",
        path: "src/shadow-legacy.py",
        startLine: 2,
        location: "  `src/quoted.py:12` \n ",
      },
      {
        id: "legacy-backticks",
        code: "legacy_backtick_location()",
        location: "src/with``ticks.py:12",
      },
    ];
    await writeJson(findingsPath, findings);
    const manifestPath = join(scanDirectory, "scan-manifest.json");
    const manifest = await readJson<ScanManifest>(manifestPath);
    manifest.scan.target.kind = "git_revision";
    manifest.scan.target.revision = "0123456789abcdef0123456789abcdef01234567";
    delete manifest.scan.target.snapshotDigest;
    await writeJson(manifestPath, manifest);
    await reseal(scanDirectory);
    const saved = await readFile(findingsPath, "utf8");

    const { description } = (
      await prepareScanPublication(
        scanDirectory,
        publicationOptions(scanDirectory),
      )
    ).issues[0]!;

    expect(description).toContain("`src/string.py:12 additional context`");
    expect(description).toContain("`` `src/quoted.py:12` ``");
    expect(description).toContain("```src/with``ticks.py:12```");
    expect(description).not.toContain("src/shadow-");
    for (const path of ["src/string.py", "src/quoted.py", "src/with``ticks.py"])
      expect(description).not.toContain(`${path}#L`);
    expect(await readFile(findingsPath, "utf8")).toBe(saved);
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
      await prepareScanPublication(
        scanDirectory,
        publicationOptions(scanDirectory),
      )
    ).issues[0]!;

    expect(description).toContain("**Remote:** ssh://github.com/example/repo");
    expect(description).toContain("**Sink:** `src/extract.py:41-44`");
    expect(description).not.toContain("/blob/");
  });

  test("rejects publication with a traversal in an evidence path", async () => {
    const scanDirectory = await copyExample();
    const findingsPath = join(scanDirectory, "findings.json");
    const findings = await readJson<FindingsDocument>(findingsPath);
    findings.findings[0]!.codeEvidence = [
      {
        id: "unsafe-path",
        label: "Unsafe path",
        path: "src/../outside.py",
        startLine: 41,
        code: "preserved_snippet()",
        explanation:
          "An unsafe path cannot be published as canonical evidence.",
      },
    ];
    await writeJson(findingsPath, findings);
    await reseal(scanDirectory);

    await expect(
      prepareScanPublication(scanDirectory, publicationOptions(scanDirectory)),
    ).rejects.toThrow(
      "findings.findings[0].codeEvidence[0].path: expected a safe repository-relative POSIX path.",
    );
  });

  test("preserves evidence snippets for valid paths without safe source links", async () => {
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
      "src/./outside.py",
      "src//outside.py",
      "src/%2e%2e/outside.py",
      "src/%2foutside.py",
      "src/%5coutside.py",
    ];
    findings.findings[0]!.codeEvidence = paths.map((path, index) => ({
      id: `unlinked-path-${index}`,
      label: `Unlinked path ${index}`,
      path,
      startLine: 41,
      role: "source",
      code: `preserved_snippet_${index}()`,
      explanation:
        "Preserve canonical evidence even without a safe source link.",
    }));
    findings.findings[0]!.code_evidence = paths.map((path, index) => ({
      id: `legacy-path-${index}`,
      path,
      startLine: 41,
      code: `legacy_preserved_snippet_${index}()`,
    }));
    await writeJson(findingsPath, findings);
    await reseal(scanDirectory);

    const { description } = (
      await prepareScanPublication(
        scanDirectory,
        publicationOptions(scanDirectory),
      )
    ).issues[0]!;

    expect(description).toContain(
      "https://github.com/example/repo/blob/0123456789abcdef0123456789abcdef01234567/src/extract.py#L41-L44",
    );
    for (const [index, path] of paths.entries()) {
      expect(description).toContain(`**Source:** \`${path}:41\``);
      expect(description).toContain(`preserved_snippet_${index}()`);
      expect(description).toContain(`legacy_preserved_snippet_${index}()`);
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

      const issue = (
        await prepareScanPublication(
          scanDirectory,
          publicationOptions(scanDirectory),
        )
      ).issues[0]!;
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
      (
        await prepareScanPublication(
          scanDirectory,
          publicationOptions(scanDirectory),
        )
      ).issues,
    ).toEqual([]);
  });

  test("rejects findings whose sealed artifact has been modified", async () => {
    const scanDirectory = await copyExample();
    const findingsPath = join(scanDirectory, "findings.json");
    const findings = await readJson<FindingsDocument>(findingsPath);
    findings.findings[0]!.summary = "Modified after the scan was sealed.";
    await writeJson(findingsPath, findings);

    await expect(
      prepareScanPublication(scanDirectory, publicationOptions(scanDirectory)),
    ).rejects.toThrow();
  });
});

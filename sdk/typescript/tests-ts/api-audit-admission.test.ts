import { mkdir, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { afterEach, describe, expect, test } from "bun:test";
import { build } from "esbuild";
import { createApiTestFixtures } from "./support/temporary-directories.js";
import { runScanEvents } from "../src/api.js";
import { loadContract } from "../src/contract.js";
import { PLUGIN_ROOT, copyCompletedScan } from "./plugin-root.js";
import { completedEvents } from "./support/api-events.js";
import { sha256 } from "./support/finding-identity.js";

const { temporaryDirectory, cleanup } = createApiTestFixtures();
afterEach(cleanup);

const bundle = await build({
  stdin: {
    resolveDir: fileURLToPath(
      new URL("../../../plugins/codex-security/mcp-app/", import.meta.url),
    ),
    contents: `export * from "./src/artifact-scan-draft.ts";`,
  },
  bundle: true,
  format: "esm",
  platform: "node",
  loader: { ".md": "text" },
  write: false,
});
const bundlePath = join(await temporaryDirectory(), "deep-admission.mjs");
await writeFile(bundlePath, bundle.outputFiles[0]!.contents);
const { recordCodexSecurityScanDraftViaWorkbench, parseCanonicalScanDraft } =
  await import(pathToFileURL(bundlePath).href);

interface DraftFixture {
  scanId: string;
  complete?: boolean;
  scope?: Record<string, unknown>;
  threatModel?: Record<string, unknown>;
  findings: Record<string, unknown>[];
  coverage: Record<string, unknown>;
}

const scanId = "811aef98-3709-4c2d-8b7a-742977521865";
type Mutation =
  | "missing-findings"
  | "inverted-lines"
  | "wrong-scan"
  | "legacy-details"
  | "legacy-surface";
const cases: {
  name: string;
  legacyCompleteness?: string;
  complete?: boolean;
  mutation?: Mutation;
  accepted: boolean;
}[] = [
  { name: "scope notes", complete: true, accepted: true },
  {
    name: "legacy completeness metadata",
    legacyCompleteness: "partial",
    complete: true,
    accepted: true,
  },
  { name: "omitted completion marker", accepted: true },
  {
    name: "legacy finding details",
    mutation: "legacy-details",
    accepted: false,
  },
  { name: "legacy surface ID", mutation: "legacy-surface", accepted: false },
  { name: "unfinished checkpoint", complete: false, accepted: false },
  { name: "missing findings", mutation: "missing-findings", accepted: false },
  {
    name: "inverted finding lines",
    mutation: "inverted-lines",
    accepted: false,
  },
  {
    name: "mismatched canonical scan ID",
    mutation: "wrong-scan",
    accepted: false,
  },
];

describe.each(["standard", "deep"] as const)(
  "%s canonical admission",
  (mode) => {
    for (const scenario of cases) {
      test(`ordinary scan production admission: ${scenario.name}`, async () => {
        const root = await temporaryDirectory();
        const repository = join(root, "repository");
        const standardRoot = join(root, mode);
        await Promise.all([
          mkdir(repository),
          mkdir(standardRoot, { mode: 0o700 }),
        ]);
        const semantic: DraftFixture = {
          scanId,
          ...(scenario.complete === undefined
            ? {}
            : { complete: scenario.complete }),
          scope: { summary: "Archive extraction." },
          threatModel: {
            summary: "An untrusted caller supplies archive entries.",
          },
          findings: [
            {
              ruleId: "path-traversal.archive",
              title: "Unsafe archive extraction",
              summary: "An archive entry reaches a filesystem write.",
              severity: { level: "high" },
              confidence: { level: "high", rationale: "Source review." },
              taxonomy: { category: "path-traversal", cwe: ["CWE-22"] },
              locations: [{ path: "extract.py", startLine: 4, endLine: 7 }],
              remediation: "Validate the resolved output path before writing.",
              provenance: {
                source: "local_plugin",
                candidateId: "archive-entry",
              },
            },
          ],
          coverage: {
            ...(scenario.legacyCompleteness === undefined
              ? {}
              : { completeness: scenario.legacyCompleteness }),
            surfaces: [
              {
                label: "Archive extraction",
                disposition: "reported",
              },
            ],
            explicitExclusions: [],
            deferred: [{ reason: "Deployment controls remain unverified." }],
          },
        };
        await recordCodexSecurityScanDraftViaWorkbench(
          {
            root: standardRoot,
            repoRoot: repository,
            layout: "scan",
            scanId,
            mode,
            status: "running",
            scope: ".",
            targetContract: {
              target: {
                allowedKinds: ["directory_snapshot"],
                targetId: "target_example",
                displayName: "example",
                requiredSnapshotDigest: `codex-security-snapshot/v1:sha256:${"a".repeat(64)}`,
              },
              scope: { requiredIncludePaths: ["."], requiredExcludePaths: [] },
              diffTarget: null,
            },
          },
          semantic,
          async (args: string[]) => {
            const draft = JSON.parse(
              await readFile(args[args.indexOf("--draft-path") + 1]!, "utf8"),
            );
            await Promise.all(
              [
                ["manifest", "scan-manifest.json"],
                ["findings", "findings.json"],
                ["coverage", "coverage.json"],
              ].map(([key, name]) =>
                writeFile(
                  join(standardRoot, name!),
                  JSON.stringify(draft[key!]),
                ),
              ),
            );
          },
        );
        const submitted = mutateDraft(semantic, scenario.mutation);
        const findings = {
          scanId: submitted.scanId,
          findings: submitted.findings?.map((finding) => ({
            ...finding,
            findingId: "finding_example",
            occurrenceId: "occurrence_example",
            fingerprints: { identity: "synthetic" },
          })),
        };
        const coverage = JSON.parse(
          await readFile(join(standardRoot, "coverage.json"), "utf8"),
        );
        Object.assign(coverage, submitted.coverage);
        await Promise.all([
          writeFile(
            join(standardRoot, "findings.json"),
            JSON.stringify(findings),
          ),
          writeFile(
            join(standardRoot, "coverage.json"),
            JSON.stringify(coverage),
          ),
        ]);
        const standard = await observeAdmission(
          repository,
          standardRoot,
          scanId,
        );

        if (scenario.accepted) {
          expect(standard.error).toBe(standard.finalization);
          expect(standard.finalizations).toBe(1);
          const canonicalDraft = parseCanonicalScanDraft({
            scanId,
            manifest: JSON.parse(
              await readFile(join(standardRoot, "scan-manifest.json"), "utf8"),
            ),
            findings,
            coverage,
          });
          expect(canonicalDraft.coverage).not.toHaveProperty("completeness");
          expect(canonicalDraft.scope).toEqual(semantic.scope);
          expect(canonicalDraft.threatModel).toEqual(semantic.threatModel);
          if (scenario.mutation === "legacy-details") {
            expect(canonicalDraft.findings[0]!["validation"]).toEqual({
              limitations: ["Legacy persisted limitation."],
            });
          }
        } else {
          expect(standard.error).toBeInstanceOf(Error);
          expect(standard.error).not.toBe(standard.finalization);
          expect(standard.finalizations).toBe(0);
        }
        const manifest = JSON.parse(
          await readFile(join(standardRoot, "scan-manifest.json"), "utf8"),
        );
        expect(manifest.scan.sealedAt).toBeUndefined();
        await expect(
          readFile(join(standardRoot, "report.md")),
        ).rejects.toThrow();
      });
    }

    test("preserves existing canonical scan IDs", async () => {
      const root = await temporaryDirectory();
      const repository = join(root, "repository");
      await mkdir(repository);
      const scanDir = await copyAdmissionScan(root);
      const manifest = JSON.parse(
        await readFile(join(scanDir, "scan-manifest.json"), "utf8"),
      );
      const standard = await observeAdmission(repository, scanDir);
      expect(manifest.scan.id).toBe("scan_example_001");
      expect(standard.error).toBe(standard.finalization);
      expect(standard.finalizations).toBe(1);
    });

    test.each(["scan-manifest.json", "findings.json", "coverage.json"])(
      "preserves BOM-prefixed %s bytes",
      async (name) => {
        const root = await temporaryDirectory();
        const repository = join(root, "repository");
        await mkdir(repository);
        const scanDir = await copyAdmissionScan(root);
        const file = join(scanDir, name);
        const bytes = Buffer.concat([
          Buffer.from([0xef, 0xbb, 0xbf]),
          await readFile(file),
        ]);
        await writeFile(file, bytes);
        const standard = await observeAdmission(repository, scanDir);
        expect(standard.error).toBe(standard.finalization);
        expect(standard.finalizations).toBe(1);
        expect(await readFile(file)).toEqual(bytes);
      },
    );

    test.each(["HTTP API", "ArchiveSurface", "", 17])(
      "new drafts reject unsupported coverage IDs: %j",
      async (id) => {
        const root = await temporaryDirectory();
        const repository = join(root, "repository");
        await mkdir(repository);
        const scanDir = await copyAdmissionScan(root);
        const [manifest, findings, coverage] = await Promise.all(
          ["scan-manifest.json", "findings.json", "coverage.json"].map(
            async (name) =>
              JSON.parse(await readFile(join(scanDir, name), "utf8")),
          ),
        );
        coverage.surfaces[0].id = id;
        await writeFile(
          join(scanDir, "coverage.json"),
          JSON.stringify(coverage),
        );
        expect(() =>
          parseCanonicalScanDraft({
            scanId: manifest.scan.id,
            manifest,
            findings,
            coverage,
          }),
        ).toThrow();
        const admission = await observeAdmission(repository, scanDir);
        expect(admission.error).toBeInstanceOf(Error);
        expect(admission.finalizations).toBe(0);
      },
    );

    test.each([
      { path: "src/./extract.py", notes: " " },
      { path: "src//extract.py", notes: " " },
      { path: "src/extract.py/", notes: " " },
      { path: "../extract.py", notes: "Checked" },
      { path: "/src/extract.py", notes: "Checked" },
      { path: "C:/extract.py", notes: "Checked" },
      { path: "src\\extract.py", notes: "Checked" },
      { path: "src/\u0000extract.py", notes: "Checked" },
      { path: "src/\ud800extract.py", notes: "Checked" },
      { path: ".", notes: "Checked" },
      { path: "src/extract.py", notes: "" },
      { path: "src/extract.py", notes: 17 },
      {
        path: "src/extract.py",
        notes: "Checked",
        questions: [17],
      },
    ])(
      "new drafts reject legacy canonical fields: %j",
      async ({ path, notes, questions }) => {
        const root = await temporaryDirectory();
        const repository = join(root, "repository");
        await mkdir(repository);
        const scanDir = await copyAdmissionScan(root);
        const [manifest, findings, coverage] = await Promise.all(
          ["scan-manifest.json", "findings.json", "coverage.json"].map(
            async (name) =>
              JSON.parse(await readFile(join(scanDir, name), "utf8")),
          ),
        );
        manifest.scan.scope.context = " ";
        manifest.scan.threatModel = {
          summary: "Archive input",
          assumptions: [" "],
        };
        const finding = findings.findings[0];
        finding.locations[0].path = path;
        finding.locations[0].role = " ";
        finding.severity.vector = " ";
        finding.codeEvidence = [
          {
            id: "archive-write",
            label: "Filesystem write",
            path,
            startLine: 41,
            code: "write(entry)",
            explanation: "Archive entry reaches a write.",
          },
        ];
        coverage.surfaces[0].notes = notes;
        coverage.surfaces[0].riskArea = " ";
        coverage.openQuestions = questions ?? [
          "What deployment controls apply?",
          { question: "Which controls apply?", followUpPrompt: " " },
        ];
        await Promise.all([
          writeFile(
            join(scanDir, "scan-manifest.json"),
            JSON.stringify(manifest),
          ),
          writeFile(join(scanDir, "findings.json"), JSON.stringify(findings)),
          writeFile(join(scanDir, "coverage.json"), JSON.stringify(coverage)),
        ]);
        const canonical = {
          scanId: manifest.scan.id,
          manifest,
          findings,
          coverage,
        };
        const standard = await observeAdmission(repository, scanDir);

        expect(() => parseCanonicalScanDraft(canonical)).toThrow();
        expect(standard.error).toBeInstanceOf(Error);
        expect(standard.error).not.toBe(standard.finalization);
        expect(standard.finalizations).toBe(0);
      },
    );

    test("sealed legacy evidence stays readable but is not admitted as a new draft", async () => {
      const scanDir = await copyCompletedScan(await temporaryDirectory());
      const file = join(scanDir, "findings.json");
      const findings = JSON.parse(await readFile(file, "utf8"));
      const evidence = {
        id: "legacy-reversed-end",
        code: "read(input)",
        path: "src/legacy.py",
        startLine: 48,
        endLine: 47,
      };
      findings.findings[0].code_evidence = [evidence];
      const saved = JSON.stringify(findings);
      await writeFile(file, saved);
      const manifestFile = join(scanDir, "scan-manifest.json");
      const manifest = JSON.parse(await readFile(manifestFile, "utf8"));
      manifest.scan.artifacts.find(
        (artifact: { path: string }) => artifact.path === "findings.json",
      ).sha256 = sha256(saved);
      await writeFile(manifestFile, JSON.stringify(manifest));
      const expectation = {
        repository: "/repository",
        repositoryRevision: "deadbeef",
        target: { kind: "repository" as const, paths: [] },
        mode: "standard" as const,
        pluginVersion: "0.1.0",
      };
      const contract = await loadContract(scanDir, {
        pluginRoot: PLUGIN_ROOT,
        expectation,
        workbenchValidated: true,
      });
      expect(contract.findings.findings[0]?.["code_evidence"]).toEqual([
        evidence,
      ]);
      expect(await readFile(file, "utf8")).toBe(saved);

      const coverage = JSON.parse(
        await readFile(join(scanDir, "coverage.json"), "utf8"),
      );
      expect(() =>
        parseCanonicalScanDraft({
          scanId: manifest.scan.id,
          manifest,
          findings,
          coverage,
        }),
      ).toThrow();
    });

    test("canonical admission still rejects reversed typed evidence bounds", async () => {
      const scanDir = await copyAdmissionScan(await temporaryDirectory());
      const file = join(scanDir, "findings.json");
      const findings = JSON.parse(await readFile(file, "utf8"));
      findings.findings[0].codeEvidence = [
        {
          id: "typed-reversed-end",
          label: "Source read",
          code: "read(input)",
          explanation: "The input reaches a read.",
          path: "src/typed.py",
          startLine: 48,
          endLine: 47,
        },
      ];
      await writeFile(file, JSON.stringify(findings));
      const outcome = await observeAdmission("/repository", scanDir);
      expect(outcome.error).toMatchObject({
        message: expect.stringContaining(
          "codeEvidence[0].endLine must not precede startLine",
        ),
      });
      expect(outcome.finalizations).toBe(0);
    });

    async function copyAdmissionScan(root: string) {
      const scanDir = await copyCompletedScan(root);
      if (mode === "deep") {
        const coveragePath = join(scanDir, "coverage.json");
        const coverage = JSON.parse(await readFile(coveragePath, "utf8"));
        coverage.mode = "deep_repository";
        const saved = JSON.stringify(coverage);
        await writeFile(coveragePath, saved);
        const manifestPath = join(scanDir, "scan-manifest.json");
        const manifest = JSON.parse(await readFile(manifestPath, "utf8"));
        manifest.scan.artifacts.find(
          (artifact: { path: string }) => artifact.path === "coverage.json",
        ).sha256 = sha256(saved);
        await writeFile(manifestPath, JSON.stringify(manifest));
      }
      return scanDir;
    }

    async function observeAdmission(
      repository: string,
      scanDir: string,
      scanId?: string,
    ) {
      const finalization = new Error(
        "The enclosing finalizer owns the next step.",
      );
      let finalizations = 0;
      const thread = {
        id: `${mode}-thread`,
        async runStreamed() {
          return { events: completedEvents(`${mode}-thread`) };
        },
      };
      const error = await runScanEvents({
        scanId,
        thread,
        events: completedEvents(`${mode}-thread`),
        signal: new AbortController().signal,
        scanDir,
        pluginRoot: PLUGIN_ROOT,
        expectation: {
          repository,
          repositoryRevision: null,
          target: { kind: "repository", paths: [] },
          mode,
          pluginVersion: "0.1.0",
        },
        onFinalize: async () => {
          finalizations++;
          throw finalization;
        },
      }).catch((error: unknown) => error);
      return {
        error,
        finalization,
        finalizations,
      };
    }
  },
);

function mutateDraft(input: DraftFixture, mutation?: Mutation): DraftFixture {
  const draft = structuredClone(input);
  if (mutation === "missing-findings")
    return { ...draft, findings: undefined } as unknown as DraftFixture;
  if (mutation === "wrong-scan")
    draft.scanId = "553a0c18-dcdf-4a3b-8e39-2751a8187bce";
  if (mutation === "inverted-lines") {
    const locations = draft.findings[0]!["locations"] as Record<
      string,
      unknown
    >[];
    locations[0]!["endLine"] = 1;
  }
  if (mutation === "legacy-surface")
    (draft.coverage["surfaces"] as Record<string, unknown>[])[0]!["id"] =
      "HTTP API";
  if (mutation === "legacy-details")
    draft.findings[0]!["validation"] = {
      method: null,
      limitations: "Legacy persisted limitation.",
    };
  return draft;
}

import { execFileSync } from "node:child_process";
import { randomUUID } from "node:crypto";
import { mkdirSync, renameSync, writeFileSync } from "node:fs";
import {
  chmod,
  cp,
  mkdir,
  readFile,
  rm,
  stat,
  symlink,
  writeFile,
} from "node:fs/promises";
import { join, resolve } from "node:path";
import type { ScanReadFile } from "../../../plugins/codex-security/native/scan-read-binding.mjs";
import type { ThreadEvent } from "@openai/codex-sdk";
import type { ScanActivity } from "../src/scan-activity.js";
import Ajv2020 from "ajv/dist/2020.js";
import { afterEach, describe, expect, mock, spyOn, test } from "bun:test";
import {
  runCustomValidation,
  type CustomValidationResult,
} from "../src/custom-validation.js";
import {
  customDiscoveryPrompt,
  customValidationConfig,
} from "../src/custom-validation-prompt.js";
import {
  ContractValidationError,
  DiffTarget,
  type CoverageDocument,
  type FindingsDocument,
  type ScanManifest,
  type ScanProgress,
} from "../src/index.js";
import { createMarketplace, resolveCodexCommand } from "../src/runtime.js";
import { copyCompletedScanFixture, PLUGIN_ROOT } from "./plugin-root.js";
import { runWorkbench } from "../src/runtime.js";
import { TestClient } from "./support/api-client.js";
import { completedEvents, preparedRuntime } from "./support/api-events.js";
import { createApiTestFixtures } from "./support/temporary-directories.js";
import { readJson as json, jsonLines } from "./support/json.js";
import { rejecting } from "./support/errors.js";
import { runTestInSubprocess } from "./support/test-subprocess.js";
import { scanReadBinding } from "./support/scan-read-binding.js";
import { readReviewState } from "./support/review-state.js";

const { cleanup, temporaryDirectory } = createApiTestFixtures();
const resultName = "artifacts/custom-validation/results.json";
afterEach(cleanup);

async function save(path: string, value: unknown) {
  await writeFile(path, JSON.stringify(value));
}

async function draft(scanDir: string, scanId: string, count = 1, diff = false) {
  await copyCompletedScanFixture(scanDir);
  const manifest = await json<ScanManifest>(
    join(scanDir, "scan-manifest.json"),
  );
  const { sealedAt: _sealed, artifacts: _artifacts, ...scan } = manifest.scan;
  scan.id = scanId;
  scan.target.kind = diff ? "git_diff" : "directory_snapshot";
  scan.scope.validationMode = "custom_pending";
  await save(join(scanDir, "scan-manifest.json"), { ...manifest, scan });
  const findings = await json<FindingsDocument>(join(scanDir, "findings.json"));
  const original = findings.findings[0]!;
  findings.scanId = scanId;
  findings.findings = Array.from({ length: count }, (_, index) => ({
    ...structuredClone(original),
    identity: { anchor: `fixture-${index}` },
    title: `Fixture ${index}`,
    extensions: { customValidationSurfaceIds: [`surface-${index}`] },
  }));
  await save(join(scanDir, "findings.json"), findings);
  const coverage = await json<CoverageDocument>(join(scanDir, "coverage.json"));
  coverage.scanId = scanId;
  coverage.mode = diff ? "diff" : "repository";
  coverage.inventoryStrategy = diff ? "diff" : "directory";
  coverage.surfaces = findings.findings.map((finding, index) => ({
    id: `surface-${index}`,
    label: finding.title,
    disposition: "reported",
    receiptRefs: [],
  }));
  if (count === 0)
    coverage.surfaces.push({
      id: "reviewed",
      label: "Reviewed source",
      disposition: "no_issue_found",
      receiptRefs: [],
    });
  await save(join(scanDir, "coverage.json"), coverage);
  await rm(join(scanDir, "report.md"), { force: true });
  return findings;
}

async function publishDraft(
  scanDir: string,
  scanId: string,
  workbench: (args: readonly string[]) => Promise<Record<string, unknown>>,
  complete?: boolean,
) {
  const manifest = await json<ScanManifest>(
    join(scanDir, "scan-manifest.json"),
  );
  const findings = await json<FindingsDocument>(join(scanDir, "findings.json"));
  const coverage = await json<CoverageDocument>(join(scanDir, "coverage.json"));
  const staged = {
    manifest: {
      scan: {
        target: manifest.scan.target,
        scope: manifest.scan.scope,
        ...(complete === undefined ? {} : { complete }),
      },
    },
    findings: {
      findings: findings.findings.map(
        ({
          findingId: _id,
          occurrenceId: _occurrence,
          fingerprints: _fingerprints,
          ...finding
        }) => finding,
      ),
    },
    coverage: {
      inventoryStrategy: coverage.inventoryStrategy,
      surfaces: coverage.surfaces,
      explicitExclusions: coverage.explicitExclusions,
      deferred: coverage.deferred,
    },
  };
  await mkdir(join(scanDir, "drafts"), { recursive: true });
  const draftPath = join(scanDir, "drafts", `${scanId}.json`);
  await save(draftPath, staged);
  expect(
    await workbench([
      "write-scan-draft",
      "--scan-id",
      scanId,
      "--draft-path",
      draftPath,
    ]),
  ).toMatchObject({ scanId, status: "draft_written" });
}

function result(
  ...dispositions: CustomValidationResult["validations"][number]["validation"]["disposition"][]
): CustomValidationResult {
  return {
    status: "complete",
    reason: null,
    validations: dispositions.map((disposition, index) => ({
      candidateId: `candidate-${index + 1}`,
      validation: {
        disposition,
        method: "integration test",
        confidence: "medium",
        confidence_rationale: "The test exercised the selected path.",
        rubric: "Check the protected operation.",
        evidence: ["The test returned the observed result."],
        counterevidence_or_proof_gap:
          disposition === "deferred"
            ? "The required service was unavailable."
            : "",
        remaining_uncertainty: "",
        artifact_paths: [],
      },
      severity: null,
      impact: null,
    })),
  };
}

async function fixture(count = 1) {
  const root = await temporaryDirectory();
  const scanDir = join(root, "scan");
  await mkdir(scanDir, { mode: 0o700 });
  const scanId = randomUUID();
  const findings = await draft(scanDir, scanId, count);
  return {
    root,
    repository: root,
    target: { kind: "repository" as const, paths: [] },
    scanDir,
    scanId,
    findings,
    pluginRoot: PLUGIN_ROOT,
    prompt: "Run the selected fixture workflow.",
    signal: new AbortController().signal,
  };
}

async function* responseEvents(
  value: unknown,
  activity?: string,
): AsyncGenerator<ThreadEvent> {
  for await (const event of completedEvents("validation-thread")) {
    if (
      event.type === "item.completed" &&
      event.item.type === "agent_message"
    ) {
      if (activity !== undefined)
        yield { ...event, item: { ...event.item, text: activity } };
      yield { ...event, item: { ...event.item, text: JSON.stringify(value) } };
    } else yield event;
  }
}

describe("custom validation", () => {
  test.each(["scan-manifest.json", "findings.json", "coverage.json"])(
    "rejects %s replaced by a directory before opening the provisional document",
    async (name) => {
      const title = `rejects ${name} replaced by a directory before opening the provisional document`;
      if (runTestInSubprocess(import.meta.path, title)) return;
      const f = await fixture();
      const path = join(f.scanDir, name);
      const native = scanReadBinding();
      const original = native.openScanReadRoot;
      let replaced = false;
      const opening = spyOn(native, "openScanReadRoot").mockImplementation(
        (...args) => {
          const root = original(...args);
          const open = root.openFile.bind(root);
          spyOn(root, "openFile").mockImplementation((relativePath) => {
            if (relativePath === name && !replaced) {
              renameSync(path, `${path}.original`);
              mkdirSync(path);
              replaced = true;
            }
            return open(relativePath);
          });
          return root;
        },
      );
      const run = mock(async () => JSON.stringify(result("reportable")));
      try {
        const pending = runCustomValidation({ ...f, run });
        await expect(pending).rejects.toBeInstanceOf(ContractValidationError);
        await expect(pending).rejects.toThrow(
          name === "coverage.json" ? "legacy review state" : name,
        );
        await expect(pending).rejects.toThrow(/regular.*file/i);
        expect(replaced).toBe(true);
        expect(run).not.toHaveBeenCalled();
      } finally {
        opening.mockRestore();
      }
    },
  );

  test.each(["scan-manifest.json", "findings.json", "coverage.json"])(
    "reads and closes held %s after a pathname replacement attempt",
    async (name) => {
      const title = `reads and closes held ${name} after a pathname replacement attempt`;
      if (runTestInSubprocess(import.meta.path, title)) return;
      const f = await fixture();
      const path = join(f.scanDir, name);
      const native = scanReadBinding();
      const original = native.openScanReadRoot;
      let checked: ScanReadFile | undefined;
      let attempted = false;
      const originalBytes = await readFile(path);
      const chunks: Buffer[] = [];
      const opening = spyOn(native, "openScanReadRoot").mockImplementation(
        (...args) => {
          const root = original(...args);
          const open = root.openFile.bind(root);
          spyOn(root, "openFile").mockImplementation((relativePath) => {
            const file = open(relativePath);
            if (relativePath === name && file !== null) {
              checked = file;
              const read = file.read.bind(file);
              spyOn(file, "read").mockImplementation((size) => {
                if (!attempted) {
                  attempted = true;
                  if (process.platform === "win32") {
                    expect(() =>
                      renameSync(path, `${path}.original`),
                    ).toThrow();
                  } else {
                    renameSync(path, `${path}.original`);
                    writeFileSync(path, "not JSON");
                  }
                }
                const chunk = read(size);
                chunks.push(chunk);
                return chunk;
              });
            }
            return file;
          });
          return root;
        },
      );
      const run = mock(async () => JSON.stringify(result("reportable")));
      try {
        await runCustomValidation({ ...f, run });
        expect(run).toHaveBeenCalledTimes(1);
        expect(attempted).toBe(true);
        expect(Buffer.concat(chunks)).toEqual(originalBytes);
        expect(checked).toBeDefined();
        expect(() => checked!.read(1)).toThrow("Scan file is closed");
      } finally {
        opening.mockRestore();
      }
    },
  );

  test.each(["malformed", "directory"])(
    "rejects a %s provisional document before invoking validation",
    async (kind) => {
      const f = await fixture();
      const path = join(f.scanDir, "findings.json");
      if (kind === "malformed") await writeFile(path, "not JSON");
      else {
        await rm(path);
        await mkdir(path);
      }
      const run = mock(async () => JSON.stringify(result("reportable")));
      const pending = runCustomValidation({ ...f, run });
      if (kind === "malformed") {
        await expect(pending).rejects.toThrow(/JSON/);
      } else {
        await expect(pending).rejects.toBeInstanceOf(ContractValidationError);
        await expect(pending).rejects.toThrow("findings.json");
        await expect(pending).rejects.toThrow(/regular.*file/i);
      }
      expect(run).not.toHaveBeenCalled();
    },
  );

  test.skipIf(process.platform === "win32")(
    "rejects provisional documents from a scan owned by another user",
    async () => {
      const title =
        "rejects provisional documents from a scan owned by another user";
      if (runTestInSubprocess(import.meta.path, title)) return;
      const f = await fixture();
      const files = await import("node:fs/promises");
      const original = files.lstat;
      const inspecting = spyOn(files, "lstat").mockImplementation((async (
        ...args: Parameters<typeof original>
      ) => {
        const metadata = await original(...args);
        if (
          args[0] === f.scanDir ||
          (Buffer.isBuffer(args[0]) && args[0].equals(Buffer.from(f.scanDir)))
        )
          Object.defineProperty(metadata, "uid", {
            value: process.geteuid!() + 1,
          });
        return metadata;
      }) as typeof original);
      const run = mock(async () => JSON.stringify(result("reportable")));
      try {
        await expect(runCustomValidation({ ...f, run })).rejects.toThrow(
          "must be owned by the current user",
        );
        expect(run).not.toHaveBeenCalled();
      } finally {
        inspecting.mockRestore();
      }
    },
  );

  test("applies dispositions and assessments without changing source identity or output permissions", async () => {
    const f = await fixture(4);
    if (process.platform !== "win32") await chmod(f.scanDir, 0o755);
    const output = result(
      "reportable",
      "suppressed",
      "not_applicable",
      "deferred",
    );
    const counterEvidence =
      "The protected caller checks a separate precondition.";
    const limitations = "The alternate configuration was not exercised.";
    output.validations[0]!.validation.counterevidence_or_proof_gap =
      counterEvidence;
    output.validations[0]!.validation.remaining_uncertainty = limitations;
    output.validations[0]!.severity = {
      level: "medium",
      rationale: "Requires an uncommon configuration.",
    };
    output.validations[0]!.impact = {
      level: "high",
      rationale: "Can modify protected files.",
    };
    output.validations[0]!.validation.artifact_paths = [
      "artifacts/custom-validation/proof.txt",
    ];
    await runCustomValidation({
      ...f,
      run: async (prompt, schema) => {
        expect(prompt).toContain(JSON.stringify(f.target));
        await writeFile(
          join(f.scanDir, "artifacts/custom-validation/proof.txt"),
          "Synthetic proof.\n",
        );
        expect(prompt).toContain(f.prompt);
        // Structured outputs cannot resolve plugin URIs or use regex lookaround.
        expect(JSON.stringify(schema)).not.toContain("codex-security://");
        expect(JSON.stringify(schema)).not.toMatch(/\(\?[=!<]/);
        const common = await json<object>(
          join(PLUGIN_ROOT, "schemas/definitions/artifact-common.schema.json"),
        );
        const existing = await json<object>(
          join(PLUGIN_ROOT, "schemas/tools/candidate-validations.schema.json"),
        );
        const ajv = new Ajv2020({ strict: false, validateFormats: false });
        ajv.addSchema(common);
        expect(
          ajv.validate(existing, {
            scanId: f.scanId,
            validations: output.validations.map(
              ({ candidateId, validation }) => ({ candidateId, validation }),
            ),
          }),
        ).toBe(true);
        return JSON.stringify(output);
      },
    });
    if (process.platform !== "win32")
      expect((await stat(f.scanDir)).mode & 0o777).toBe(0o755);
    const findings = await json<FindingsDocument>(
      join(f.scanDir, "findings.json"),
    );
    expect(findings.findings).toHaveLength(1);
    expect(findings.findings[0]).toMatchObject({
      identity: f.findings.findings[0]!.identity,
      locations: f.findings.findings[0]!.locations,
      severity: output.validations[0]!.severity,
      confidence: { level: "medium" },
      attackPath: { impact: output.validations[0]!.impact },
      validation: {
        disposition: "reportable",
        counterEvidence: [counterEvidence],
        limitations: [limitations],
      },
    });
    const coverage = await json<CoverageDocument>(
      join(f.scanDir, "coverage.json"),
    );
    expect(coverage.surfaces.map((surface) => surface.disposition)).toEqual([
      "reported",
      "rejected",
      "not_applicable",
      "needs_follow_up",
    ]);
    expect(coverage).not.toHaveProperty("completeness");
    expect(coverage.surfaces[0]!.receiptRefs).toContain(
      "artifacts/custom-validation/proof.txt",
    );
    expect(coverage.deferred).toHaveLength(1);
    expect(await json(join(f.scanDir, resultName))).toMatchObject({
      scanId: f.scanId,
      ...output,
    });
    expect(
      await json(
        join(f.scanDir, "artifacts/custom-validation/candidates.json"),
      ),
    ).toMatchObject({
      target: f.target,
      candidates: f.findings.findings.map((finding, index) => ({
        candidateId: `candidate-${index + 1}`,
        finding,
      })),
    });
  });

  test.each([{ artifacts: [] }, { artifacts: null }])(
    "validates an unfinished draft with %j",
    async ({ artifacts }) => {
      const f = await fixture();
      const manifest = await json<{ scan: Record<string, unknown> }>(
        join(f.scanDir, "scan-manifest.json"),
      );
      manifest.scan["artifacts"] = artifacts;
      manifest.scan["sealedAt"] = null;
      await save(join(f.scanDir, "scan-manifest.json"), manifest);
      const run = mock(async () => JSON.stringify(result("reportable")));
      await runCustomValidation({ ...f, run });
      expect(run).toHaveBeenCalledTimes(1);
      const findings = await json<FindingsDocument>(
        join(f.scanDir, "findings.json"),
      );
      expect(findings.findings).toHaveLength(1);
      expect(findings.findings[0]).toMatchObject({
        identity: f.findings.findings[0]!.identity,
        validation: { disposition: "reportable" },
      });
    },
  );

  test.each([
    "sealedAt",
    "artifacts",
    "manifest ID",
    "findings ID",
    "coverage ID",
  ])("rejects an invalid discovery handoff: %s", async (kind) => {
    const f = await fixture();
    const manifest = await json<ScanManifest>(
      join(f.scanDir, "scan-manifest.json"),
    );
    if (kind === "sealedAt") manifest.scan.sealedAt = "2026-01-01T00:00:00Z";
    if (kind === "artifacts")
      manifest.scan.artifacts = [
        {
          path: "findings.json",
          sha256: "0".repeat(64),
          mediaType: "application/json",
        },
      ];
    if (kind === "manifest ID") manifest.scan.id = randomUUID();
    if (kind === "findings ID" || kind === "coverage ID") {
      const name = kind === "findings ID" ? "findings.json" : "coverage.json";
      const document = await json<{ scanId: string }>(join(f.scanDir, name));
      document.scanId = randomUUID();
      await save(join(f.scanDir, name), document);
    }
    await save(join(f.scanDir, "scan-manifest.json"), manifest);
    await expect(
      runCustomValidation({
        ...f,
        run: unexpectedValidation,
      }),
    ).rejects.toThrow("unsealed custom-validation draft");
  });

  test.each([
    ["empty title", { title: "" }],
    ["empty optional detail", { attackPath: { dataflow: { sink: "" } } }],
    ["legacy field", { root_cause: "Synthetic legacy detail." }],
  ])(
    "rejects %s before validation without changing the draft",
    async (_name, fields) => {
      const f = await fixture(2);
      Object.assign(f.findings.findings[1]!, fields);
      await save(join(f.scanDir, "findings.json"), f.findings);
      await expect(
        runCustomValidation({
          ...f,
          run: unexpectedValidation,
        }),
      ).rejects.toThrow(/valid provisional finding set.*findings\[1\]/);
      expect(
        await json<FindingsDocument>(join(f.scanDir, "findings.json")),
      ).toEqual(f.findings);
    },
  );

  test.each([
    ["bundled", ""],
    ["unmarked oneOf", "coverage/deferred/0/paths/1"],
    ["additional pattern", "coverage/deferred/0/paths/1"],
    ["referenced array", "coverage/checkedPaths"],
    ["conditional", "must have required property 'reviewReceipt'"],
    ["referenced predicate", "must have required property 'reviewReceipt'"],
  ])(
    "honors %s deferred path rules before custom validation",
    async (rules, expectedError) => {
      const f = await fixture();
      const path = join(f.scanDir, "coverage.json");
      const coverage = await json<CoverageDocument>(path);
      coverage.deferred = [
        {
          id: "pending",
          reason: "Review pending.",
          paths: ["src/valid", "../outside"],
        },
      ];
      await save(path, coverage);
      const run = mock(async () => JSON.stringify(result("reportable")));
      if (rules === "bundled") {
        await runCustomValidation({ ...f, run });
        expect(run).toHaveBeenCalledTimes(1);
        expect((await json<CoverageDocument>(path)).deferred).toEqual(
          coverage.deferred,
        );
        return;
      }
      const pluginRoot = join(f.root, "plugin");
      await cp(join(f.pluginRoot, "schemas"), join(pluginRoot, "schemas"), {
        recursive: true,
      });
      const schemaPath = join(pluginRoot, "schemas", "coverage.schema.json");
      const schema = JSON.parse(await readFile(schemaPath, "utf8"));
      const deferred = schema.properties.deferred.items;
      const paths = deferred.properties.paths;
      if (rules === "unmarked oneOf") delete paths.items.oneOf[1].$comment;
      if (rules === "additional pattern") paths.items.pattern = "^src/";
      if (rules === "referenced array") {
        schema.$id = "relative/coverage.json";
        paths.$id = "deferred-paths.json";
        schema.$defs = { ...schema.$defs, sharedPaths: paths };
        schema.properties.deferred.items.properties.paths = {
          $ref: "#/$defs/sharedPaths",
        };
        schema.properties.checkedPaths = {
          anyOf: [{ $ref: "#/$defs/sharedPaths" }, { type: "null" }],
        };
        await save(path, {
          ...coverage,
          checkedPaths: ["src/other", "../outside"],
        });
      }
      if (rules === "conditional") {
        schema.if = {
          properties: { deferred: { $ref: "#/properties/deferred" } },
        };
        schema.then = { required: ["reviewReceipt"] };
      }
      if (rules === "referenced predicate") {
        deferred.properties.reviewReceipt = { type: "boolean" };
        deferred.if = {
          properties: {
            paths: {
              contains: {
                $ref: "#/properties/deferred/items/properties/paths/items/oneOf/1",
              },
            },
          },
        };
        deferred.then = { required: ["reviewReceipt"] };
      }
      await save(schemaPath, schema);
      await expect(
        runCustomValidation({ ...f, pluginRoot, run }),
      ).rejects.toThrow(expectedError);
      expect(run).not.toHaveBeenCalled();
      if (rules === "referenced array" || rules === "referenced predicate") {
        if (rules === "referenced array")
          Object.assign(coverage, { checkedPaths: ["src/other"] });
        else Object.assign(coverage.deferred[0]!, { reviewReceipt: true });
        await save(path, coverage);
        await runCustomValidation({ ...f, pluginRoot, run });
        expect(run).toHaveBeenCalledTimes(1);
        expect((await json<CoverageDocument>(path)).deferred).toEqual(
          coverage.deferred,
        );
      }
    },
  );

  test("identifies invalid provisional coverage before validation", async () => {
    const f = await fixture();
    const path = join(f.scanDir, "coverage.json");
    const coverage = await json<CoverageDocument>(path);
    coverage.surfaces[0]!.label = "";
    await save(path, coverage);
    await expect(
      runCustomValidation({
        ...f,
        run: unexpectedValidation,
      }),
    ).rejects.toThrow("coverage/surfaces/0/label");
    expect(await json<CoverageDocument>(path)).toEqual(coverage);
  });

  test.each([
    "missing",
    "duplicate",
    "unknown",
    "malformed",
    "incomplete",
    "unsafe artifact",
  ])("rejects %s results without losing the draft", async (kind) => {
    const f = await fixture();
    const original = await readFile(join(f.scanDir, "findings.json"), "utf8");
    const output = result("reportable");
    if (kind === "missing") output.validations = [];
    if (kind === "duplicate") output.validations.push(output.validations[0]!);
    if (kind === "unknown") output.validations[0]!.candidateId = "unknown";
    if (kind === "unsafe artifact")
      output.validations[0]!.validation.artifact_paths = ["../outside.txt"];
    if (kind === "incomplete") {
      output.status = "incomplete";
      output.reason = "Setup failed.";
    }
    await expect(
      runCustomValidation({
        ...f,
        run: async () => {
          await writeFile(join(f.scanDir, "findings.json"), "{}");
          return kind === "malformed" ? "not JSON" : JSON.stringify(output);
        },
      }),
    ).rejects.toThrow("Custom validation is incomplete");
    expect(await json(join(f.scanDir, "findings.json"))).toEqual(
      JSON.parse(original),
    );
  });

  test("rejects output directories linked outside the scan", async () => {
    const f = await fixture();
    const outside = join(f.root, "outside");
    await mkdir(outside);
    await mkdir(join(f.scanDir, "artifacts"), { recursive: true });
    await symlink(
      outside,
      join(f.scanDir, "artifacts/custom-validation"),
      process.platform === "win32" ? "junction" : "dir",
    );
    await expect(
      runCustomValidation({
        ...f,
        run: async () => JSON.stringify(result("reportable")),
      }),
    ).rejects.toThrow("inside the scan directory");
    await expect(readFile(join(outside, "candidates.json"))).rejects.toThrow();
  });

  const completionScenarios = [
    "standard",
    "progress",
    "diff",
    "empty",
    "incomplete",
    "dismissed",
    "unfinished-source",
  ];
  test.each(completionScenarios)(
    "SDK owns real workbench completion: %s",
    async (scenario) => {
      const diff = scenario === "diff";
      const maxTimeMinutes = scenario === "standard" || diff ? 5 : undefined;
      const count = scenario === "empty" ? 0 : 1;
      const root = await temporaryDirectory();
      const repository = join(root, "repository");
      const scanDir = join(root, "scan");
      const codexHome = join(root, "codex-home");
      const stateDir = join(root, "state");
      const python = Bun.which("python3") ?? Bun.which("python");
      expect(python).not.toBeNull();
      await mkdir(join(repository, "src"), { recursive: true });
      await writeFile(join(repository, "src/extract.py"), "# source fixture\n");
      await mkdir(scanDir, { mode: 0o700 });
      await mkdir(codexHome);
      if (diff) {
        const git = (...args: string[]) =>
          execFileSync("git", [
            "-C",
            repository,
            "-c",
            "user.name=Fixture",
            "-c",
            "user.email=fixture@example.test",
            ...args,
          ]);
        git("init", "-q");
        git("config", "--local", "core.autocrlf", "false");
        git("add", ".");
        git("commit", "-qm", "base");
        await writeFile(
          join(repository, "src/extract.py"),
          "# changed fixture\n",
        );
      }
      const workflow = "Run the synthetic validation script, then clean up.";
      const workflowFile = join(root, "validation.md");
      if (scenario === "standard") await writeFile(workflowFile, workflow);
      const falsePositive = {
        reason: "The fixture is not included in the deployed application.",
      };
      let scanId = "";
      let turns = 0;
      const workingDirectories: Array<string | undefined> = [];
      const commands: string[] = [];
      const activities: ScanActivity[] = [];
      const progress: ScanProgress[] = [];
      const validationActivity = "Synthetic validation activity.";
      const profileDisabledTools =
        scenario === "standard"
          ? []
          : diff
            ? ["profile_disabled_tool"]
            : undefined;
      const workbench = (args: readonly string[], input?: string) =>
        runWorkbench(
          {
            python: python!,
            pluginRoot: PLUGIN_ROOT,
            environment: {
              PATH: process.env["PATH"],
              CODEX_SECURITY_STATE_DIR: stateDir,
            },
          },
          args,
          input,
        );
      const client = new TestClient(
        profileDisabledTools === undefined
          ? {}
          : {
              codexOverrides: {
                profile: "synthetic.validation",
                profiles: {
                  "synthetic.validation": {
                    mcp_servers: {
                      "codex-security": {
                        disabled_tools: profileDisabledTools,
                      },
                    },
                  },
                },
              },
            },
        {
          environment: { CODEX_SECURITY_STATE_DIR: stateDir },
          now: () => Date.UTC(2026, 0, 1),
          prepareRuntime: async () => {
            const runtime = preparedRuntime(codexHome);
            runtime.plugin.version = (
              await json<{ version: string }>(
                join(PLUGIN_ROOT, ".codex-plugin/plugin.json"),
              )
            ).version;
            return runtime;
          },
          resolvePluginPython: async () => python!,
          prepareOutputDir: async () => scanDir,
          createCodex: (options) => {
            expect(options.config?.["mcp_servers"]).toMatchObject({
              "codex-security": {
                disabled_tools: expect.arrayContaining([
                  "start_codex_security_standard_scan",
                  "start_codex_security_prompt_only_scan",
                  "start_codex_security_deep_scan",
                  "complete_codex_security_scan",
                  "record_codex_security_candidate_validations",
                  "record_candidate_attack_paths",
                  ...(profileDisabledTools ?? []),
                ]),
              },
            });
            return {
              startThread: (threadOptions) => {
                expect(threadOptions.threadSource).toBe("security_scan");
                workingDirectories.push(threadOptions.workingDirectory);
                return {
                  id:
                    workingDirectories.length === 1
                      ? "thread-1"
                      : "validation-thread",
                  async runStreamed(prompt, turnOptions) {
                    expect(turnOptions.cyberAccessProgram).toBe(
                      "daybreak_blue",
                    );
                    turns += 1;
                    if (turns === 1) {
                      expect(prompt.includes("2026-01-01T00:05:00.000Z")).toBe(
                        maxTimeMinutes !== undefined,
                      );
                      expect(prompt).not.toContain(workflow);
                      expect(prompt).toContain("SDK-owned discovery workflow");
                      expect(prompt).not.toContain(
                        "Independently validate each unique finding",
                      );
                      expect(prompt).not.toContain("run `$validation` once");
                      expect(turnOptions.outputSchema).toBeUndefined();
                      await draft(scanDir, scanId, 0, diff);
                      await publishDraft(scanDir, scanId, workbench, false);
                      await draft(scanDir, scanId, count, diff);
                      if (scenario === "unfinished-source") {
                        const coverage = await json<CoverageDocument>(
                          join(scanDir, "coverage.json"),
                        );
                        coverage.deferred = [
                          {
                            id: "unfinished-source",
                            reason:
                              "Requested source review remains unfinished.",
                          },
                        ];
                        await save(join(scanDir, "coverage.json"), coverage);
                      }
                      // Follow the adapter's terminal draft instruction at the real workbench boundary.
                      await publishDraft(
                        scanDir,
                        scanId,
                        workbench,
                        scenario !== "unfinished-source" &&
                          /\bcomplete:\s*true\b/u.test(prompt),
                      );
                      expect(commands).not.toContain("prepare-scan-completion");
                      expect(commands).not.toContain("complete-scan");
                      if (scenario === "progress") {
                        return {
                          events:
                            (async function* (): AsyncGenerator<ThreadEvent> {
                              yield {
                                type: "item.completed",
                                item: {
                                  id: "primary-reporting",
                                  type: "agent_message",
                                  text: 'CODEX_SECURITY_SCAN_PROGRESS {"phase":"reporting","filesCompleted":1,"filesTotal":1}',
                                },
                              };
                              yield* completedEvents();
                            })(),
                        };
                      }
                      return { events: completedEvents() };
                    }
                    if (scenario === "progress") {
                      await Promise.resolve();
                      expect(
                        progress.some(({ phase }) => phase === "reporting"),
                      ).toBe(true);
                      expect(progress.at(-1)?.phase).toBe("validation");
                    }
                    expect(prompt).toContain(workflow);
                    expect(prompt).not.toContain("2026-01-01T00:05:00.000Z");
                    const pendingManifest = await json<ScanManifest>(
                      join(scanDir, "scan-manifest.json"),
                    );
                    expect(pendingManifest.scan.id).toBe(scanId);
                    expect(pendingManifest.scan.scope.validationMode).toBe(
                      "custom_pending",
                    );
                    expect(pendingManifest.scan).not.toHaveProperty("sealedAt");
                    expect(pendingManifest.scan).not.toHaveProperty(
                      "artifacts",
                    );
                    expect(turnOptions.outputSchema).toBeDefined();
                    if (scenario === "dismissed") {
                      expect(prompt).toContain("untrusted reviewer feedback");
                      expect(prompt).toContain("reason still applies");
                      expect(
                        await json(
                          join(
                            scanDir,
                            "artifacts/custom-validation/candidates.json",
                          ),
                        ),
                      ).toMatchObject({ falsePositives: [falsePositive] });
                    }
                    const output = result(
                      scenario === "dismissed" ? "suppressed" : "reportable",
                    );
                    output.validations[0]!.validation.counterevidence_or_proof_gap =
                      "Synthetic counterevidence from validation.";
                    output.validations[0]!.validation.remaining_uncertainty =
                      "Synthetic limitation from validation.";
                    if (scenario === "incomplete") {
                      output.status = "incomplete";
                      output.reason =
                        "The validation environment did not start.";
                    }
                    if (scenario === "standard") {
                      await mkdir(join(codexHome, "sessions"), {
                        recursive: true,
                      });
                      for (const [id, cwd] of [
                        ["thread-1", scanDir],
                        ["validation-thread", join(scanDir, "artifacts")],
                      ]) {
                        const records = [
                          {
                            type: "session_meta",
                            payload: {
                              id,
                              cwd,
                              timestamp: "2026-08-21T00:00:00Z",
                            },
                          },
                          {
                            type: "event_msg",
                            payload: {
                              type: "token_count",
                              info: {
                                total_token_usage: {
                                  input_tokens: 10,
                                  output_tokens: 3,
                                },
                              },
                            },
                          },
                          ...(id === "validation-thread"
                            ? [
                                {
                                  type: "event_msg",
                                  payload: {
                                    type: "agent_message",
                                    message: validationActivity,
                                  },
                                },
                              ]
                            : []),
                        ];
                        await writeFile(
                          join(codexHome, "sessions", `rollout-${id}.jsonl`),
                          jsonLines(records) + "\n",
                        );
                      }
                    }
                    return {
                      events: responseEvents(
                        output,
                        scenario === "standard"
                          ? validationActivity
                          : undefined,
                      ),
                    };
                  },
                };
              },
            };
          },
          runWorkbench: async (_options, args, input) => {
            commands.push(args[0]!);
            const value = await workbench(args, input);
            if (args[0] === "register-cli-scan")
              scanId = String(value["scanId"]);
            if (args[0] === "get-scan-feedback" && scenario === "dismissed")
              value["falsePositives"] = [falsePositive];
            return value;
          },
        },
      );
      try {
        const pending = client.run(repository, {
          cyberAccessProgram: "daybreak_blue",
          maxTimeMinutes,
          ...(scenario === "standard"
            ? { validationPromptFile: workflowFile }
            : { validationPrompt: workflow }),
          onActivity: (activity) => activities.push(activity),
          ...(scenario === "progress"
            ? { onProgress: (update: ScanProgress) => progress.push(update) }
            : {}),
          ...(diff ? { target: DiffTarget.workingTree({}) } : {}),
        });
        if (scenario === "unfinished-source") {
          await expect(pending).rejects.toThrow(
            "The latest saved scan draft is incomplete",
          );
          expect(turns).toBe(2);
          expect(commands).not.toContain("complete-scan");
          expect(commands).toContain("fail-scan");
          expect(await json(join(scanDir, resultName))).toMatchObject({
            status: "complete",
          });
          expect(await readReviewState(scanDir)).toMatchObject({
            deferred: expect.arrayContaining([
              expect.objectContaining({ id: "unfinished-source" }),
            ]),
          });
          return;
        }
        if (scenario === "incomplete") {
          await expect(pending).rejects.toThrow(
            "The validation environment did not start",
          );
          expect(turns).toBe(2);
          expect(commands).not.toContain("prepare-scan-completion");
          expect(commands).not.toContain("complete-scan");
          expect(commands).toContain("fail-scan");
          expect(await json(join(scanDir, resultName))).toMatchObject({
            status: "incomplete",
          });
          expect(
            (await json<FindingsDocument>(join(scanDir, "findings.json")))
              .findings,
          ).toHaveLength(1);
          expect(
            (
              await json<{ scan: { status: string } }>(
                join(scanDir, "scan-manifest.json"),
              )
            ).scan.status,
          ).toBe("failed");
          expect(await readFile(join(scanDir, "report.md"), "utf8")).toContain(
            "Fixture 0",
          );
          return;
        }
        const completed = await pending;
        if (scenario === "standard") {
          const report = await readFile(join(scanDir, "report.md"), "utf8");
          expect(report).toContain(
            "Synthetic counterevidence from validation.",
          );
          expect(report).toContain("Synthetic limitation from validation.");
          expect(
            activities.filter(
              ({ description }) => description === validationActivity,
            ),
          ).toHaveLength(1);
          expect(completed.cost?.inputTokens).toBe(20);
        }
        expect(turns).toBe(count === 0 ? 1 : 2);
        expect(workingDirectories).toEqual(
          count === 0 ? [scanDir] : [scanDir, join(scanDir, "artifacts")],
        );
        expect(commands.indexOf("prepare-scan-completion")).toBeLessThan(
          commands.indexOf("complete-scan"),
        );
        expect(completed.findings.findings).toHaveLength(
          scenario === "dismissed" ? 0 : count,
        );
        const receipt = await json<CustomValidationResult>(
          join(scanDir, resultName),
        );
        expect(receipt.status).toBe("complete");
        expect(receipt.validations).toHaveLength(count);
        if (count > 0 && scenario !== "dismissed")
          expect(completed.findings.findings[0]?.validation?.disposition).toBe(
            "reportable",
          );
        expect(completed.manifest.scan.scope.validationMode).toBe("custom");
        expect(
          completed.manifest.scan.artifacts.map((artifact) => artifact.path),
        ).toContain(resultName);
        expect(
          completed.manifest.scan.artifacts.map((artifact) => artifact.path),
        ).toContain("artifacts/custom-validation/candidates.json");
        expect(completed.turnResult.usage).toMatchObject({
          input_tokens: count === 0 ? 10 : 20,
          output_tokens: count === 0 ? 3 : 6,
        });
        expect(await readFile(join(scanDir, "report.md"), "utf8")).toContain(
          count === 0 || scenario === "dismissed" ? "No findings" : "Fixture 0",
        );
      } finally {
        await client.close();
      }
    },
  );

  test("rejects Deep and empty prompts before starting Codex", async () => {
    const root = await temporaryDirectory();
    const client = TestClient.withDependencies({});
    await expect(
      client.run(root, { mode: "deep", validationPrompt: "Validate." }),
    ).rejects.toThrow("not supported for Deep");
    await expect(client.run(root, { validationPrompt: " \n" })).rejects.toThrow(
      "must not be empty",
    );
    await client.close();
  });

  test("renders only the discovery portion of the shipped workflows", async () => {
    const standard = await customDiscoveryPrompt(PLUGIN_ROOT, "security-scan");
    const diff = await customDiscoveryPrompt(PLUGIN_ROOT, "security-diff-scan");
    expect(standard.match(/^1\. .+$/mu)?.[0]).toContain(
      "make-hosted-repo-scope-input",
    );
    expect(standard).toContain("## Baseline Auditor Prompt");
    expect(standard).toContain("## Focused Investigator Prompt");
    expect(standard).toContain("<plugin_dir>/references/scan-prologue.md");
    expect(diff).toContain("<plugin_dir>/references/scan-runtime.md");
    expect(standard).toContain("`complete: false` checkpoint");
    expect(standard).toContain("retain the model in an early");
    expect(standard).toContain("`followup_task`");
    expect(standard).toContain("`send_message`");
    expect(standard).not.toContain("undefined");
    expect(standard).not.toContain(
      "Independently validate each unique finding",
    );
    expect(diff).toContain("Run `$finding-discovery`");
    expect(diff).toContain(
      "Immediately save a `complete: false` semantic draft",
    );
    expect(diff).toContain('"format": "markdown", "content": "<model text>"');
    expect(diff).not.toContain("run `$validation` once");
    expect(diff).not.toContain("Call `complete_codex_security_scan` once");
    for (const prompt of [standard, diff]) {
      expect(prompt).toContain("custom_pending");
      expect(prompt).toContain("extensions.customValidationSurfaceIds");
      expect(prompt).not.toContain("finalize_scan_contract.py");
    }
    const changed = await temporaryDirectory();
    await mkdir(join(changed, "skills/security-diff-scan"), {
      recursive: true,
    });
    await writeFile(
      join(changed, "skills/security-diff-scan/SKILL.md"),
      "Changed workflow\n",
    );
    await expect(
      customDiscoveryPrompt(changed, "security-diff-scan"),
    ).rejects.toThrow("incompatible");
  });

  test("the bundled Codex honors the invocation-only completion restriction", async () => {
    const home = await temporaryDirectory();
    const marketplace = await createMarketplace(home, PLUGIN_ROOT);
    const command = resolveCodexCommand({}).command;
    const run = (args: string[]) =>
      execFileSync(command, args, {
        env: {
          PATH: process.env["PATH"],
          SystemRoot: process.env["SystemRoot"],
          TEMP: process.env["TEMP"],
          TMP: process.env["TMP"],
          CODEX_HOME: home,
        },
        encoding: "utf8",
        windowsHide: true,
      });
    run(["plugin", "marketplace", "add", marketplace]);
    run(["plugin", "add", "--json", "codex-security@codex-security-sdk"]);
    const config = await customValidationConfig(
      {
        mcp_servers: {
          "codex-security": { disabled_tools: ["user_disabled_tool"] },
        },
      },
      PLUGIN_ROOT,
    );
    const server = (config["mcp_servers"] as Record<string, unknown>)[
      "codex-security"
    ] as Record<string, unknown>;
    const overrides = Object.entries(server).flatMap(([key, value]) => [
      "-c",
      `mcp_servers.codex-security.${key}=${JSON.stringify(value)}`,
    ]);
    const effective = JSON.parse(
      run([...overrides, "mcp", "get", "codex-security", "--json"]),
    );
    expect(effective.disabled_tools).toContain("complete_codex_security_scan");
    expect(effective.disabled_tools).toContain("user_disabled_tool");
    expect(effective.transport.cwd).toBe(resolve(PLUGIN_ROOT));
    const ordinary = JSON.parse(
      run(["mcp", "get", "codex-security", "--json"]),
    );
    expect(ordinary.disabled_tools).toBeNull();
  });
});

const unexpectedValidation = rejecting("unexpected validation");

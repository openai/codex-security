import { execFileSync } from "node:child_process";
import { createHash, randomUUID } from "node:crypto";
import { cp, mkdir, readFile, rm, symlink, writeFile } from "node:fs/promises";
import { join, resolve } from "node:path";
import type { ThreadEvent } from "@openai/codex-sdk";
import type { ScanActivity } from "../src/scan-activity.js";
import Ajv2020 from "ajv/dist/2020.js";
import { afterEach, describe, expect, spyOn, test } from "bun:test";
import * as fileSystem from "node:fs/promises";
import {
  runCustomValidation,
  type CustomValidationResult,
} from "../src/custom-validation.js";
import {
  customDiscoveryPrompt,
  customValidationConfig,
} from "../src/custom-validation-prompt.js";
import {
  DiffTarget,
  type CoverageDocument,
  type FindingsDocument,
  type ScanManifest,
} from "../src/index.js";
import {
  createMarketplace,
  resolveCodexCommand,
  runWorkbench,
} from "../src/runtime.js";
import { PLUGIN_ROOT } from "./plugin-root.js";
import { TestClient } from "./support/api-client.js";
import { main } from "../src/cli.js";
import { capture, dependencies } from "./cli-fixtures.js";
import {
  completedEvents,
  createApiTestFixtures,
  preparedRuntime,
} from "./support/api-events.js";

const { cleanup, temporaryDirectory } = createApiTestFixtures();
const resultName = "artifacts/custom-validation/results.json";
afterEach(cleanup);

async function json<T>(path: string): Promise<T> {
  return JSON.parse(await readFile(path, "utf8")) as T;
}

async function save(path: string, value: unknown) {
  await writeFile(path, JSON.stringify(value));
}

async function draft(scanDir: string, scanId: string, count = 1, diff = false) {
  await cp(join(PLUGIN_ROOT, "examples/completed-scan"), scanDir, {
    recursive: true,
  });
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

async function addCollidingSurfaceIds(scanDir: string) {
  const coverage = await json<CoverageDocument>(join(scanDir, "coverage.json"));
  const findings = await json<FindingsDocument>(join(scanDir, "findings.json"));
  const ids = [
    "custom-validation-candidate-1",
    "custom-validation-candidate-1-2",
    "custom-validation-candidate-1-3",
  ];
  coverage.surfaces[0]!.id = ids[0]!;
  findings.findings[0]!.extensions!["customValidationSurfaceIds"] = [ids[0]!];
  for (const id of ids.slice(1))
    coverage.surfaces.push({
      id,
      label: "Reviewed source",
      disposition: "no_issue_found",
      receiptRefs: [],
    });
  await save(join(scanDir, "coverage.json"), coverage);
  await save(join(scanDir, "findings.json"), findings);
  return ids;
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
  test("surface ID collisions preserve deferred validation evidence", async () => {
    const f = await fixture();
    const retainedIds = await addCollidingSurfaceIds(f.scanDir);
    await runCustomValidation({
      ...f,
      run: async () => JSON.stringify(result("deferred")),
    });
    const coverage = await json<CoverageDocument>(
      join(f.scanDir, "coverage.json"),
    );
    expect(coverage.surfaces.slice(0, 3).map((surface) => surface.id)).toEqual(
      retainedIds,
    );
    expect(new Set(coverage.surfaces.map((surface) => surface.id)).size).toBe(
      4,
    );
    const added = coverage.surfaces[3]!;
    expect(added.disposition).toBe("needs_follow_up");
    expect(added["previousFindings"]).toHaveLength(1);
    expect(coverage.deferred).toHaveLength(1);
    expect(coverage.deferred[0]!["id"]).toBe(added.id);
    expect(coverage.deferred[0]!["surfaceIds"]).toEqual([retainedIds[0]!]);
  });

  test("applies dispositions and assessments without changing source identity", async () => {
    const f = await fixture(4);
    const output = result(
      "reportable",
      "suppressed",
      "not_applicable",
      "deferred",
    );
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
      checkpoint: async (path) => {
        const modulePath = new URL(
          "../../../plugins/codex-security/mcp-app/src/artifact-scan-draft.ts",
          import.meta.url,
        ).href;
        const { parseScanDraft } = await import(modulePath);
        const { coverage } = await json<{ coverage: CoverageDocument }>(path);
        expect(
          parseScanDraft({
            scanId: f.scanId,
            findings: [],
            coverage: {
              completeness: coverage.completeness,
              surfaces: coverage.surfaces,
              deferred: coverage.deferred,
              explicitExclusions: coverage.explicitExclusions,
            },
          }),
        ).toBeDefined();
      },
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
      validation: { disposition: "reportable" },
    });
    const coverage = await json<CoverageDocument>(
      join(f.scanDir, "coverage.json"),
    );
    expect(
      coverage.surfaces.slice(0, 4).map((surface) => surface.disposition),
    ).toEqual(["reported", "rejected", "not_applicable", "needs_follow_up"]);
    expect(
      coverage.surfaces.slice(4).map((surface) => surface["previousFindings"]),
    ).toEqual(f.findings.findings.map((finding) => [finding]));
    expect(coverage.completeness).toBe("partial");
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

  test("rejects a prematurely sealed discovery draft", async () => {
    const f = await fixture();
    const manifest = await json<ScanManifest>(
      join(f.scanDir, "scan-manifest.json"),
    );
    manifest.scan.sealedAt = "2026-01-01T00:00:00Z";
    await save(join(f.scanDir, "scan-manifest.json"), manifest);
    await expect(
      runCustomValidation({
        ...f,
        run: async () => {
          throw new Error("unexpected validation");
        },
      }),
    ).rejects.toThrow("unsealed custom-validation draft");
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

  test.each([false, true])(
    "does not publish canonical files when checkpointing fails: validated=%s",
    async (validated) => {
      const f = await fixture();
      const original = await readFile(join(f.scanDir, "findings.json"));
      let turns = 0;
      await expect(
        runCustomValidation({
          ...f,
          run: async () => {
            turns++;
            return JSON.stringify(result("reportable"));
          },
          checkpoint: async (_path, complete) => {
            if (complete === validated)
              throw new Error("Synthetic checkpoint failure");
          },
        }),
      ).rejects.toThrow("Synthetic checkpoint failure");
      expect(turns).toBe(validated ? 1 : 0);
      expect(await readFile(join(f.scanDir, "findings.json"))).toEqual(
        original,
      );
      expect(
        (await json<ScanManifest>(join(f.scanDir, "scan-manifest.json"))).scan
          .scope.validationMode,
      ).toBe("custom_pending");
    },
  );

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

  test.each([
    "standard",
    "surface-id-collision",
    "diff",
    "empty",
    "incomplete",
    "dismissed",
    "interrupted-reportable",
    "interrupted-suppressed",
    "interrupted-no-id-suppressed",
    "interrupted-no-id-stopped",
    "interrupted-no-id-diff-stopped",
    "interrupted-missing-artifact",
    "interrupted-unreviewed",
    "interrupted-custom-turn",
  ])(
    // Keep interruption recovery on the same real workbench path as completion.
    "SDK owns real workbench completion: %s",
    async (scenario) => {
      const diff = scenario === "diff" || scenario.includes("-diff-");
      const interrupted = scenario.startsWith("interrupted-");
      const suppressed =
        scenario.includes("suppressed") || scenario.endsWith("-stopped");
      const rename = fileSystem.rename;
      const publication = scenario.endsWith("-stopped")
        ? spyOn(fileSystem, "rename").mockImplementation(
            async (source, destination) => {
              if (
                String(destination).endsWith("scan-manifest.json") &&
                (await json<ScanManifest>(String(source))).scan.scope
                  .validationMode === "custom"
              )
                throw new Error("Synthetic process stopped before sealing");
              return rename(source, destination);
            },
          )
        : undefined;
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
      if (scenario === "interrupted-unreviewed")
        await writeFile(join(repository, "pending.ts"), "// Not reviewed.\n");
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
        git("add", ".");
        git("commit", "-qm", "base");
        await writeFile(
          join(repository, "src/extract.py"),
          "# changed fixture\n",
        );
      }
      const workflow = "Run the synthetic validation script, then clean up.";
      const falsePositive = {
        reason: "The fixture is not included in the deployed application.",
      };
      let scanId = "";
      let turns = 0;
      const workingDirectories: Array<string | undefined> = [];
      const commands: string[] = [];
      const activities: ScanActivity[] = [];
      const validationActivity = "Synthetic validation activity.";
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
        {},
        {
          environment: { CODEX_SECURITY_STATE_DIR: stateDir },
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
                  "complete_codex_security_scan",
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
                    turns += 1;
                    if (turns === 1) {
                      expect(prompt).not.toContain(workflow);
                      expect(prompt).toContain("SDK-owned discovery workflow");
                      expect(prompt).not.toContain(
                        "Independently validate each unique finding",
                      );
                      expect(prompt).not.toContain("run `$validation` once");
                      expect(turnOptions.outputSchema).toBeUndefined();
                      await draft(scanDir, scanId, count, diff);
                      if (scenario === "surface-id-collision")
                        await addCollidingSurfaceIds(scanDir);
                      if (interrupted) {
                        const findings = await json<FindingsDocument>(
                          join(scanDir, "findings.json"),
                        );
                        const coverage = await json<CoverageDocument>(
                          join(scanDir, "coverage.json"),
                        );
                        if (!scenario.includes("no-id"))
                          findings.findings[0]!.provenance["candidateId"] =
                            "discovered-1";
                        await save(join(scanDir, "findings.json"), findings);
                        const raw =
                          JSON.stringify({
                            scanId,
                            complete: false,
                            findings: findings.findings,
                            coverage: { ...coverage, reviewedFiles: [] },
                          }) + "\n";
                        await mkdir(join(scanDir, "checkpoints"), {
                          recursive: true,
                        });
                        if (scenario !== "interrupted-custom-turn")
                          await writeFile(
                            join(
                              scanDir,
                              "checkpoints",
                              `${createHash("sha256").update(raw).digest("hex")}.json`,
                            ),
                            raw,
                          );
                        const checkpoint =
                          JSON.stringify({
                            scanId,
                            complete: false,
                            findings:
                              scenario === "interrupted-custom-turn"
                                ? []
                                : findings.findings,
                            coverage: {
                              ...coverage,
                              reviewedFiles: diff ? [] : ["src/extract.py"],
                            },
                            scope: { validationMode: "custom_pending" },
                          }) + "\n";
                        const path = join(
                          scanDir,
                          "checkpoints",
                          `${createHash("sha256").update(checkpoint).digest("hex")}.json`,
                        );
                        await mkdir(join(scanDir, "checkpoints"), {
                          recursive: true,
                        });
                        await writeFile(path, checkpoint);
                        await workbench([
                          "record-scan-checkpoint",
                          "--scan-id",
                          scanId,
                          "--checkpoint-path",
                          path,
                        ]);
                        if (scenario === "interrupted-unreviewed") {
                          coverage["reviewedFiles"] = [
                            "src/extract.py",
                            "pending.ts",
                          ];
                          await save(join(scanDir, "coverage.json"), coverage);
                        }
                      }
                      expect(commands).not.toContain("prepare-scan-completion");
                      expect(commands).not.toContain("complete-scan");
                      return { events: completedEvents() };
                    }
                    expect(prompt).toContain(workflow);
                    if (scenario === "interrupted-custom-turn")
                      throw new Error(
                        "Synthetic process stopped before sealing",
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
                      scenario === "dismissed" || suppressed
                        ? "suppressed"
                        : "reportable",
                    );
                    if (interrupted) {
                      output.validations[0]!.validation.artifact_paths = [
                        "artifacts/custom-validation/proof.txt",
                      ];
                      await writeFile(
                        join(scanDir, "artifacts/custom-validation/proof.txt"),
                        "Validated synthetic evidence.\n",
                      );
                    }
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
                          records
                            .map((record) => JSON.stringify(record))
                            .join("\n") + "\n",
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
            if (
              interrupted &&
              !scenario.endsWith("-stopped") &&
              ["prepare-scan-completion", "fail-scan"].includes(args[0]!)
            )
              throw new Error("Synthetic process stopped before sealing");
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
          validationPrompt: workflow,
          onActivity: (activity) => activities.push(activity),
          ...(diff ? { target: DiffTarget.workingTree({}) } : {}),
        });
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
        if (interrupted) {
          await expect(pending).rejects.toThrow(
            "Synthetic process stopped before sealing",
          );
          publication?.mockRestore();
          expect(turns).toBe(2);
          if (scenario.endsWith("-stopped"))
            expect(
              (await json<FindingsDocument>(join(scanDir, "findings.json")))
                .findings,
            ).toHaveLength(0);
          // Diff checkpoints preserve decisions without repository-wide review credit.
          if (diff) return;
          const context = await workbench([
            "get-cli-scan-resume",
            "--scan-id",
            scanId,
          ]);
          const checkpoint = context["checkpoint"] as {
            reviewedFiles: string[];
            sources: Array<{
              scope: { validationMode: string };
              findings: FindingsDocument["findings"];
            }>;
          };
          expect(checkpoint.sources[0]!.scope.validationMode).toBe(
            scenario === "interrupted-custom-turn"
              ? "custom_pending"
              : "custom",
          );
          if (scenario === "interrupted-custom-turn")
            expect(checkpoint.sources[0]!.findings).toHaveLength(1);
          expect(checkpoint.reviewedFiles).toEqual(["src/extract.py"]);
          const parentEvidence = await readFile(join(scanDir, resultName));
          if (scenario === "interrupted-missing-artifact")
            await rm(join(scanDir, "artifacts/custom-validation/proof.txt"));
          const childDir = join(root, "continued");
          const resumed = new TestClient(
            {},
            {
              environment: { CODEX_SECURITY_STATE_DIR: stateDir },
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
              prepareOutputDir: async () => {
                await mkdir(childDir, { mode: 0o700 });
                return childDir;
              },
              runWorkbench: async (_options, args, input) =>
                workbench(args, input),
            },
          );
          try {
            const stdout = capture();
            const stderr = capture();
            const code = await main(
              ["scans", "resume", scanId, "--json"],
              stdout.stream,
              stderr.stream,
              {
                ...dependencies({
                  environment: { CODEX_SECURITY_STATE_DIR: stateDir },
                  currentDirectory: repository,
                }),
                runWorkbench: workbench,
                createSecurity: () => resumed,
              },
            );
            if (
              [
                "interrupted-unreviewed",
                "interrupted-custom-turn",
                "interrupted-missing-artifact",
              ].includes(scenario)
            ) {
              expect(code).toBe(2);
              expect(stderr.text()).toContain("--validation-prompt-file");
              return;
            }
            expect({ code, stderr: stderr.text() }).toMatchObject({ code: 0 });
            const completed = {
              manifest: await json<ScanManifest>(
                join(childDir, "scan-manifest.json"),
              ),
              findings: await json<FindingsDocument>(
                join(childDir, "findings.json"),
              ),
            };
            expect(completed.manifest.scan.scope.validationMode).toBe("custom");
            expect(completed.findings.findings).toHaveLength(
              suppressed ? 0 : 1,
            );
            if (scenario === "interrupted-reportable") {
              expect(
                completed.findings.findings[0]!.provenance["previousFindings"],
              ).toEqual(
                expect.arrayContaining([
                  expect.objectContaining({
                    validation: null,
                    confidence: expect.objectContaining({ level: "high" }),
                  }),
                ]),
              );
              expect(completed.findings.findings[0]!.validation).toMatchObject({
                method: "integration test",
                artifact_paths: ["artifacts/custom-validation/proof.txt"],
              });
            }
            expect(await readFile(join(childDir, resultName))).toEqual(
              parentEvidence,
            );
            expect(
              await readFile(
                join(childDir, "artifacts/custom-validation/proof.txt"),
                "utf8",
              ),
            ).toBe("Validated synthetic evidence.\n");
            expect(
              (
                await workbench([
                  "get-scan-recipe",
                  "--scan-id",
                  completed.manifest.scan.id,
                ])
              )["recipe"],
            ).toMatchObject({ validationMode: "custom" });
          } finally {
            await resumed.close();
          }
          expect(await readFile(join(scanDir, resultName))).toEqual(
            parentEvidence,
          );
          return;
        }
        const completed = await pending;
        if (scenario === "surface-id-collision") {
          expect(completed.coverage.completeness).toBe("complete");
          const rows = completed.coverage.surfaces;
          expect(rows).toHaveLength(4);
          expect(new Set(rows.map((row) => row.id)).size).toBe(4);
          expect(rows.slice(0, 3).map((row) => row.id)).toEqual([
            "custom-validation-candidate-1",
            "custom-validation-candidate-1-2",
            "custom-validation-candidate-1-3",
          ]);
          expect(rows[3]!["previousFindings"]).toHaveLength(1);
          expect(rows[3]!.receiptRefs).toContain(resultName);
        }
        if (scenario === "standard") {
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
          count === 0 ? "No findings" : "Fixture 0",
        );
      } finally {
        publication?.mockRestore();
        await client.close();
      }
    },
  );

  test("rejects Deep and empty prompts before starting Codex", async () => {
    const root = await temporaryDirectory();
    const client = new TestClient({}, {});
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
    expect(standard).toContain("bind-repo-scopes");
    expect(standard).toContain("## Baseline Auditor Prompt");
    expect(standard).toContain("## Focused Investigator Prompt");
    expect(standard).toContain("security_scan` capability preflight");
    expect(standard).not.toContain(
      "Independently validate each unique finding",
    );
    expect(diff).toContain("Run `$finding-discovery`");
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

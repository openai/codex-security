import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { ThreadOptions, TurnOptions } from "@openai/codex-sdk";
import Ajv2020 from "ajv/dist/2020.js";
import { afterEach, expect, test } from "bun:test";
import {
  classifySeverity,
  validateSeverityClassification,
  type ClassifySeverityOptions,
  type SeverityClassificationFinding,
} from "../src/classify-severity.js";

const directories: string[] = [];
afterEach(async () => {
  await Promise.all(
    directories
      .splice(0)
      .map((path) => rm(path, { recursive: true, force: true })),
  );
});

async function document(contents: string): Promise<string> {
  const directory = await mkdtemp(join(tmpdir(), "severity-policy-"));
  directories.push(directory);
  const path = join(directory, "policy.md");
  await writeFile(path, contents);
  return path;
}

const finding: SeverityClassificationFinding = {
  findingId: "finding-example",
  occurrenceId: "occurrence-example",
  title: "Example boundary violation",
  summary:
    "A documented lower-trust caller can read bounded operational metadata.",
  severity: { level: "high", rationale: "Original assessment" },
  evidence: "The response contains counters and no protected content.",
};
const assessed = {
  findingId: finding.findingId,
  decision: "assessed",
  level: "medium",
  rubricLabel: "MEDIUM",
  rationale:
    "The demonstrated read crosses a boundary but exposes only bounded metadata.",
  confidence: "high",
  reviewTrigger: "Protected content in the response would increase severity.",
};

function fakeCodex(response: unknown) {
  const calls: { prompt: string; thread: ThreadOptions; turn: TurnOptions }[] =
    [];
  const codex: NonNullable<ClassifySeverityOptions["codex"]> = {
    startThread(thread) {
      return {
        async run(prompt, turn) {
          calls.push({ prompt, thread, turn });
          return {
            finalResponse:
              typeof response === "string"
                ? response
                : JSON.stringify(response),
          };
        },
      };
    },
  };
  return { codex, calls };
}

test("without a rubric reuses severity without authentication or a model call", async () => {
  const { codex, calls } = fakeCodex("must not run");
  const original = structuredClone(finding);
  const result = await classifySeverity([finding], { codex, environment: {} });
  expect(calls).toHaveLength(0);
  expect(result.rubricSha256).toBeNull();
  expect(result.assessments[0]).toMatchObject({
    findingId: finding.findingId,
    occurrenceId: finding.occurrenceId,
    decision: "assessed",
    level: "high",
    source: "existing-severity",
    rationale: "Original assessment",
  });
  expect(finding).toEqual(original);
  expect(
    validateSeverityClassification(JSON.parse(JSON.stringify(result)), [
      finding,
    ]),
  ).toEqual(result);
});

test("supplies complete evidence and separate policy/context to a restricted structured Codex turn", async () => {
  const rubricPath = await document(
    "Assign MEDIUM to bounded unauthorized metadata reads.",
  );
  const knowledge = await document("The counters contain no customer data.");
  const { codex, calls } = fakeCodex(assessed);
  const signal = new AbortController().signal;
  const result = await classifySeverity([finding], {
    rubricPath,
    knowledgeBasePaths: [knowledge],
    codex,
    signal,
    model: "synthetic-model",
    reasoningEffort: "high",
  });
  expect(result.assessments[0]).toMatchObject({
    ...assessed,
    source: "rubric",
  });
  expect(result.rubricSha256).toMatch(/^[a-f0-9]{64}$/u);
  expect(result.knowledgeBaseSha256).toMatch(/^[a-f0-9]{64}$/u);
  expect(calls).toHaveLength(1);
  expect(calls[0]!.prompt).toContain(String(finding["evidence"]));
  expect(calls[0]!.prompt).toContain("The counters contain no customer data.");
  expect(calls[0]!.thread).toMatchObject({
    threadSource: "security_severity_classification",
    model: "synthetic-model",
    modelReasoningEffort: "high",
    sandboxMode: "read-only",
    approvalPolicy: "never",
    networkAccessEnabled: false,
    webSearchMode: "disabled",
  });
  expect(calls[0]!.turn.signal).toBe(signal);
  expect(calls[0]!.turn.outputSchema).toMatchObject({
    type: "object",
    additionalProperties: false,
  });
  expect(finding.severity!.level).toBe("high");
});

test("represents policy exclusions independently from Low", async () => {
  const rubricPath = await document("Exclude administrative records.");
  const excluded = {
    ...assessed,
    decision: "excluded",
    level: null,
    rubricLabel: null,
    rationale: "This record is an administrative tracker.",
    confidence: null,
    reviewTrigger: null,
  };
  const { codex, calls } = fakeCodex(excluded);
  const result = await classifySeverity([finding], { rubricPath, codex });
  // Codex consumes JSON Schema, without OpenAPI's nullable extension.
  const validate = new Ajv2020()
    .removeKeyword("nullable")
    .compile(calls[0]!.turn.outputSchema as object);
  expect(validate(excluded)).toBe(true);
  expect(validate(assessed)).toBe(true);
  expect(validate({ ...assessed, level: "severe" })).toBe(false);
  expect(result.assessments[0]).toMatchObject({
    decision: "excluded",
    level: null,
  });
  expect(validateSeverityClassification(result, [finding])).toEqual(result);
});

test("classifies imported reports without severity when a rubric is supplied", async () => {
  const {
    severity: _severity,
    occurrenceId: _occurrenceId,
    ...imported
  } = finding;
  await expect(classifySeverity([imported])).rejects.toThrow("supply a rubric");
  const rubricPath = await document(
    "Classify bounded metadata reads as medium.",
  );
  const { codex } = fakeCodex(assessed);
  expect(
    (await classifySeverity([imported], { rubricPath, codex })).assessments[0]!
      .occurrenceId,
  ).toBeNull();
});

test("rejects malformed, misbound, and contradictory model assessments", async () => {
  const rubricPath = await document("Apply the supplied policy.");
  for (const response of [
    "not json",
    { ...assessed, findingId: "another-finding" },
    { ...assessed, level: "severe" },
    { ...assessed, level: null },
    { ...assessed, decision: "excluded" },
    { ...assessed, rubricLabel: null },
  ]) {
    const { codex } = fakeCodex(response);
    await expect(
      classifySeverity([finding], { rubricPath, codex }),
    ).rejects.toThrow("invalid assessment");
  }
});

test("binds assessments to evidence and tracks policy and context changes", async () => {
  const rubricPath = await document("First policy.");
  const context = await document("First context.");
  const options = {
    rubricPath,
    knowledgeBasePaths: [context],
    ...fakeCodex(assessed),
  };
  const first = await classifySeverity([finding], options);
  await writeFile(rubricPath, "Second policy.");
  const second = await classifySeverity([finding], options);
  expect(second.rubricSha256).not.toBe(first.rubricSha256);
  expect(second.knowledgeBaseSha256).toBe(first.knowledgeBaseSha256);
  await writeFile(context, "Second context.");
  const third = await classifySeverity([finding], options);
  expect(third.knowledgeBaseSha256).not.toBe(second.knowledgeBaseSha256);
  expect(() =>
    validateSeverityClassification(first, [
      { ...finding, summary: "Different evidence" },
    ]),
  ).toThrow("does not match");
  expect(() =>
    validateSeverityClassification(
      { ...first, assessments: [...first.assessments, ...first.assessments] },
      [finding],
    ),
  ).toThrow("does not match");
});

test("cancellation and invalid inputs cannot produce a successful classification", async () => {
  const controller = new AbortController();
  const reason = new Error("Canceled classification");
  controller.abort(reason);
  await expect(
    classifySeverity([finding], { signal: controller.signal }),
  ).rejects.toBe(reason);
  await expect(classifySeverity([finding, finding])).rejects.toThrow(
    "unique finding IDs",
  );
  const rubricPath = await document(" ");
  await expect(classifySeverity([finding], { rubricPath })).rejects.toThrow(
    "must not be empty",
  );
  expect((await classifySeverity([])).assessments).toEqual([]);
});

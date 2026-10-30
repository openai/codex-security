import { createHash } from "node:crypto";
import { defaultSeverityRubric } from "../src/default-severity-rubric.js";
import { workflowDigest } from "../src/finding-workflow.js";
import { modelResponseText } from "./support/model-response-text.js";
import { writeFile } from "node:fs/promises";
import { join } from "node:path";
import type { ThreadOptions, TurnOptions } from "@openai/codex-sdk";
import Ajv2020 from "ajv/dist/2020.js";
import { afterEach, expect, mock, spyOn, test } from "bun:test";
import * as rubricSource from "../src/severity-rubric.js";
import {
  classifySeverity,
  validateSeverityClassification,
  type ClassifySeverityOptions,
  type SeverityClassificationFinding,
} from "../src/classify-severity.js";
import { rubricConfigResponse } from "./support/rubric-config.js";
import { createApiTestFixtures } from "./support/temporary-directories.js";

const { temporaryDirectory, cleanup } = createApiTestFixtures(
  "severity-policy-",
  false,
);
afterEach(cleanup);
afterEach(() => mock.restore());

async function document(contents: string): Promise<string> {
  const directory = await temporaryDirectory();
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
            finalResponse: modelResponseText(
              typeof response === "function"
                ? response(calls.length)
                : response,
            ),
          };
        },
      };
    },
  };
  return { codex, calls };
}

test.each([
  { optIn: undefined, custom: false },
  { optIn: "0", custom: false },
  { optIn: "1", custom: false },
  { optIn: "1", custom: true },
])(
  "classification honors the selected environment and explicit policy: %j",
  async ({ optIn, custom }) => {
    const config = { markdown: "# Remote classification policy", revision: 9 };
    const request = spyOn(globalThis, "fetch").mockResolvedValue(
      rubricConfigResponse(config),
    );
    const customPolicy = "Use this explicit classification policy.";
    const { codex, calls } = fakeCodex(assessed);
    const result = await classifySeverity([finding], {
      codex,
      environment: { CODEX_SECURITY_ENABLE_REMOTE_SEVERITY_RUBRIC: optIn },
      ...(custom ? { rubricPath: await document(customPolicy) } : {}),
    });
    const markdown = custom
      ? customPolicy
      : optIn === "1"
        ? config.markdown
        : defaultSeverityRubric;
    expect(request).toHaveBeenCalledTimes(optIn === "1" && !custom ? 1 : 0);
    expect(result.rubricSha256).toBe(
      createHash("sha256").update(markdown).digest("hex"),
    );
    expect(result.rubricRevision).toBe(
      custom
        ? undefined
        : optIn === "1"
          ? config.revision
          : rubricSource.bundledSeverityRubric.revision,
    );
    for (const call of calls)
      expect(JSON.parse(call.prompt.split("\n\n").at(-1)!).rubric).toEqual([
        markdown,
      ]);
  },
);

test("rubric directories retain the ordered document digest without a revision", async () => {
  const directory = await temporaryDirectory();
  await writeFile(join(directory, "01.md"), "First policy");
  await writeFile(join(directory, "02.md"), "Second policy");
  const result = await classifySeverity([], { rubricPath: directory });
  expect(result.rubricSha256).toBe(
    workflowDigest(["First policy", "Second policy"]),
  );
  expect(result.rubricRevision).toBeUndefined();
});

test("without a rubric runs three independent reviews with the bundled fallback policy", async () => {
  const { codex, calls } = fakeCodex(assessed);
  const original = structuredClone(finding);
  const result = await classifySeverity([finding], { codex, environment: {} });
  expect(calls).toHaveLength(3);
  expect(new Set(calls.map((call) => call.thread)).size).toBe(3);
  expect(JSON.parse(calls[0]!.prompt.split("\n\n").at(-1)!).rubric).toEqual([
    defaultSeverityRubric,
  ]);
  expect(result.rubricSha256).toBe(rubricSource.bundledSeverityRubric.sha256);
  expect(result.rubricRevision).toBe(
    rubricSource.bundledSeverityRubric.revision,
  );
  expect(result.assessments[0]).toMatchObject({
    findingId: finding.findingId,
    occurrenceId: finding.occurrenceId,
    decision: "assessed",
    level: "medium",
    source: "rubric",
    rationale: assessed.rationale,
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
    reasoningEffort: "future-effort",
  });
  expect(result.assessments[0]).toMatchObject({
    ...assessed,
    source: "rubric",
  });
  expect(result.rubricSha256).toMatch(/^[a-f0-9]{64}$/u);
  expect(result.knowledgeBaseSha256).toMatch(/^[a-f0-9]{64}$/u);
  expect(calls).toHaveLength(3);
  expect(new Set(calls.map((call) => call.thread)).size).toBe(3);
  expect(new Set(calls.map((call) => call.prompt)).size).toBe(1);
  expect(JSON.parse(calls[0]!.prompt.split("\n\n").at(-1)!).rubric).toEqual([
    "Assign MEDIUM to bounded unauthorized metadata reads.",
  ]);
  expect(calls[0]!.prompt).not.toContain(defaultSeverityRubric);
  expect(calls[0]!.prompt).toContain(String(finding["evidence"]));
  expect(calls[0]!.prompt).toContain("The counters contain no customer data.");
  expect(calls[0]!.thread).toMatchObject({
    threadSource: "security_severity_classification",
    model: "synthetic-model",
    modelReasoningEffort: "future-effort",
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

test("classifies imported reports without severity using the default rubric", async () => {
  const {
    severity: _severity,
    occurrenceId: _occurrenceId,
    ...imported
  } = finding;
  const { codex } = fakeCodex(assessed);
  expect(
    (await classifySeverity([imported], { codex })).assessments[0]!
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

test("votes independently for each imported report and retains the winning answer", async () => {
  const rubricPath = await document("Classify using the supplied evidence.");
  const second = { ...finding, findingId: "second-finding" };
  const responses = [
    { ...assessed, level: "low", rationale: "First low answer" },
    { ...assessed, level: "high" },
    { ...assessed, level: "low", rationale: "Second low answer" },
    ...["medium", "critical", "high"].map((level) => ({
      ...assessed,
      findingId: second.findingId,
      level,
    })),
  ];
  const { codex, calls } = fakeCodex((call: number) => responses[call - 1]);
  const result = await classifySeverity([finding, second], {
    rubricPath,
    codex,
  });
  expect(calls).toHaveLength(6);
  expect(result.assessments).toMatchObject([
    { level: "low", rationale: "First low answer" },
    { level: "critical", findingId: second.findingId },
  ]);
  expect(
    calls.map(
      ({ prompt }) =>
        JSON.parse(prompt.split("\n\n").at(-1)!).finding.findingId,
    ),
  ).toEqual([
    finding.findingId,
    finding.findingId,
    finding.findingId,
    second.findingId,
    second.findingId,
    second.findingId,
  ]);
});

test.each([2, 3, 10])(
  "does not return a partial vote when review %p fails or is invalid",
  async (failedRun) => {
    for (const invalid of [false, true]) {
      const { codex, calls } = fakeCodex((call: number) => {
        if (call !== failedRun) return assessed;
        if (invalid) return { ...assessed, findingId: "wrong-finding" };
        throw new Error("Review failed");
      });
      await expect(
        classifySeverity([finding], {
          codex,
          classificationRuns: Math.max(3, failedRun),
        }),
      ).rejects.toThrow(invalid ? "invalid assessment" : "Review failed");
      expect(calls).toHaveLength(failedRun);
    }
  },
);

test.each([1, 2, 3])(
  "cancellation after review %p stops classification",
  async (canceledRun) => {
    const controller = new AbortController();
    const { codex, calls } = fakeCodex((call: number) => {
      if (call === canceledRun) controller.abort(new Error("Stopped"));
      return assessed;
    });
    await expect(
      classifySeverity([finding], {
        codex,
        signal: controller.signal,
      }),
    ).rejects.toThrow("Stopped");
    expect(calls).toHaveLength(canceledRun);
  },
);

test.each([1, 2, 4, 10])(
  "runs %i independent local reviews",
  async (classificationRuns) => {
    const { codex, calls } = fakeCodex(assessed);
    const result = await classifySeverity([finding], {
      codex,
      classificationRuns,
    });
    expect(calls).toHaveLength(classificationRuns);
    expect(result.classificationRuns).toBe(classificationRuns);
    expect(result.assessments[0]!.level).toBe("medium");
  },
);

test.each([0, -1, 11, 1.5, NaN, Infinity])(
  "rejects invalid local run count %p before model work",
  async (classificationRuns) => {
    const { codex, calls } = fakeCodex(assessed);
    await expect(
      classifySeverity([finding], { codex, classificationRuns }),
    ).rejects.toThrow();
    expect(calls).toHaveLength(0);
  },
);

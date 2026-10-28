import { defaultSeverityRubric } from "../src/default-severity-rubric.js";
import { expect, test } from "bun:test";
import { createHash } from "node:crypto";
import { PassThrough, Writable } from "node:stream";
import {
  classifySeverityRecords,
  type ClassifySeverityRecordsInput,
  type SeverityClassificationReviewRequest,
} from "../src/classify-severity-records.js";
import { main } from "../src/cli.js";
import { capture, dependencies } from "./cli-fixtures.js";

const hash = (value: string) =>
  createHash("sha256").update(value, "utf8").digest("hex");
function input(): ClassifySeverityRecordsInput & {
  rubric: NonNullable<ClassifySeverityRecordsInput["rubric"]>;
} {
  const markdown =
    "# Severity\nHigh: unauthorized access to private records.\n";
  const findingJson =
    '{"findingId":"canonical-one","title":"Accès non autorisé","summary":"A missing authorization check exposes a private record.","severity":{"level":"low"},"evidence":{"number":9007199254740993}}';
  return {
    version: 1,
    rubric: { revision: 4, markdown, sha256: hash(markdown) },
    model: "synthetic-model",
    effort: "high",
    records: [
      {
        id: "canonical-one",
        revision: 7,
        findingJson,
        inputSha256: hash(findingJson),
      },
    ],
  };
}
function answer(request: SeverityClassificationReviewRequest) {
  return {
    findingId: JSON.parse(request.prompt).finding.findingId,
    decision: "assessed",
    level: "high",
    rubricLabel: "High",
    rationale: "Unauthorized access is evidenced in the supplied report.",
    confidence: "high",
    reviewTrigger: null,
  };
}

test("binds assessments to exact UTF-8 snapshots without rewriting the original report", async () => {
  const original = input();
  const before = structuredClone(original);
  const requests: SeverityClassificationReviewRequest[] = [];
  const result = await classifySeverityRecords(original, {
    reviewRunner: {
      async run(request) {
        requests.push(request);
        expect(request.model).toBe(original.model);
        expect(request.effort).toBe("high");
        expect(JSON.parse(request.prompt).rubric).toEqual([
          original.rubric.markdown,
        ]);
        expect(request.trustedInstructions).toContain("Do not use tools");
        expect(request.schema).toHaveProperty("required");
        expect(request.prompt).toContain(original.records[0]!.findingJson);
        expect(JSON.parse(request.prompt).finding.severity.level).toBe("low");
        return answer(request);
      },
    },
  });
  expect(result).toMatchObject({
    version: 1,
    status: "completed",
    rubric: { revision: 4, sha256: original.rubric.sha256 },
    assessments: [
      {
        id: "canonical-one",
        revision: 7,
        inputSha256: original.records[0]!.inputSha256,
        decision: "assessed",
        level: "high",
      },
    ],
  });
  expect(original).toEqual(before);
  expect(requests).toHaveLength(3);
  expect(new Set(requests.map(({ requestId }) => requestId)).size).toBe(3);
  expect(new Set(requests.map(({ prompt }) => prompt)).size).toBe(1);
  expect(result.assessments[0]).not.toHaveProperty("findingId");
});

test.each([
  "rubric-hash",
  "finding-hash",
  "duplicate",
  "identity",
  "missing-title",
  "null-summary",
  "version",
  "unsafe-revision",
])("rejects %s before any host work", async (scenario) => {
  const data = input();
  if (scenario === "rubric-hash") data.rubric.markdown += " ";
  if (scenario === "finding-hash") data.records[0]!.findingJson += " ";
  if (scenario === "duplicate") data.records.push(data.records[0]!);
  if (scenario === "version") (data as { version: number }).version = 2;
  if (scenario === "unsafe-revision")
    data.records[0]!.revision = Number.MAX_SAFE_INTEGER + 1;
  if (["identity", "missing-title", "null-summary"].includes(scenario)) {
    const report = JSON.parse(data.records[0]!.findingJson);
    if (scenario === "identity") report.findingId = "another-record";
    if (scenario === "missing-title") delete report.title;
    if (scenario === "null-summary") report.summary = null;
    data.records[0]!.findingJson = JSON.stringify(report);
    data.records[0]!.inputSha256 = hash(data.records[0]!.findingJson);
  }
  let calls = 0;
  await expect(
    classifySeverityRecords(data, {
      reviewRunner: {
        async run() {
          calls++;
          return {};
        },
      },
    }),
  ).rejects.toThrow();
  expect(calls).toBe(0);
});

test.each([
  "wrong-id",
  "missing",
  "extra",
  "assessed-null",
  "excluded-level",
  "host-failure",
])("does not return persistable partial results after %s", async (scenario) => {
  const data = input();
  const report = JSON.parse(data.records[0]!.findingJson);
  report.findingId = "canonical-two";
  const findingJson = JSON.stringify(report);
  data.records.push({
    id: report.findingId,
    revision: 8,
    findingJson,
    inputSha256: hash(findingJson),
  });
  let calls = 0;
  const result = await classifySeverityRecords(data, {
    reviewRunner: {
      async run(request) {
        calls++;
        const result: Record<string, unknown> = answer(request);
        if (calls <= 3) return result;
        if (scenario === "host-failure")
          throw new Error("Host could not complete review");
        if (scenario === "wrong-id") result["findingId"] = "canonical-one";
        if (scenario === "missing") delete result["rationale"];
        if (scenario === "extra") result["extra"] = true;
        if (scenario === "assessed-null") result["level"] = null;
        if (scenario === "excluded-level") result["decision"] = "excluded";
        return result;
      },
    },
  });
  expect(result).toMatchObject({
    status: "unresolved",
    assessments: [],
    error: {
      recordId: "canonical-two",
      code:
        scenario === "host-failure" ? "review_failed" : "invalid_assessment",
    },
  });
  expect(calls).toBe(4);
});

test("exclusion is distinct from low severity", async () => {
  const result = await classifySeverityRecords(input(), {
    reviewRunner: {
      async run(request) {
        return {
          ...answer(request),
          decision: "excluded",
          level: null,
          rubricLabel: null,
        };
      },
    },
  });
  expect(result.assessments[0]).toMatchObject({
    decision: "excluded",
    level: null,
    rubricLabel: null,
  });
});

test("snapshots mutable caller input before the first host request", async () => {
  const data = input();
  const digest = data.rubric.sha256;
  const result = await classifySeverityRecords(data, {
    reviewRunner: {
      async run(request) {
        data.rubric.revision = 99;
        data.rubric.markdown = "changed";
        data.records[0]!.revision = 99;
        data.records.push(data.records[0]!);
        return answer(request);
      },
    },
  });
  expect(result).toMatchObject({
    rubric: { revision: 4, sha256: digest },
    assessments: [{ revision: 7 }],
  });
  expect(result.assessments).toHaveLength(1);
});

test("cancellation rejects even when the host review does not settle", async () => {
  const controller = new AbortController();
  const result = classifySeverityRecords(input(), {
    signal: controller.signal,
    reviewRunner: {
      async run() {
        controller.abort(new Error("Stopped"));
        return new Promise(() => {});
      },
    },
  });
  await expect(result).rejects.toThrow("Stopped");
});

test.each([
  "completed",
  "default-rubric",
  "one-run",
  "ten-runs",
  "persistent-effort",
  "provider-effort",
  "provider-effort-host-error",
  "host-error",
  "wrong-response",
  "disconnect",
  "cancel",
])(
  "CLI records protocol handles %s without local execution",
  async (scenario) => {
    const effort =
      scenario === "persistent-effort"
        ? "persistent"
        : scenario.startsWith("provider-effort")
          ? "provider-defined-effort"
          : "high";
    const stream = new PassThrough();
    const messages: any[] = [];
    const output = new Writable({
      write(chunk, _encoding, callback) {
        const message = JSON.parse(chunk.toString());
        messages.push(message);
        if (message.method === "review.run") {
          expect(message.params.effort).toBe(effort);
          queueMicrotask(() => {
            if (scenario === "disconnect") {
              stream.end();
              return;
            }
            const response =
              scenario === "cancel"
                ? {
                    jsonrpc: "2.0",
                    method: "cancel",
                    params: { id: "run-one" },
                  }
                : scenario === "host-error" ||
                    scenario === "provider-effort-host-error"
                  ? {
                      jsonrpc: "2.0",
                      id: message.id,
                      error: { code: -32001, message: "Host unavailable" },
                    }
                  : {
                      jsonrpc: "2.0",
                      id: scenario === "wrong-response" ? "wrong" : message.id,
                      result: answer(message.params),
                    };
            stream.write(`${JSON.stringify(response)}\n`);
          });
        }
        callback();
      },
    });
    const deps = dependencies();
    deps.recordsInput = stream;
    deps.classifyScanSeverity = async () => {
      throw new Error("Local scan execution is forbidden");
    };
    const result = main(
      [
        "classify-severity",
        "--records",
        ...(scenario === "one-run"
          ? ["--runs", "1"]
          : scenario === "ten-runs"
            ? ["--runs=10"]
            : []),
      ],
      output,
      capture().stream,
      deps,
    );
    const params: ClassifySeverityRecordsInput = input();
    params.effort = effort;
    if (scenario === "default-rubric") delete params.rubric;
    const completed = [
      "completed",
      "default-rubric",
      "one-run",
      "ten-runs",
      "persistent-effort",
      "provider-effort",
    ].includes(scenario);
    stream.write(
      `${JSON.stringify({ jsonrpc: "2.0", id: "run-one", method: "run", params })}\n`,
    );
    expect(await result).toBe(
      completed
        ? 0
        : scenario === "host-error" || scenario === "provider-effort-host-error"
          ? 1
          : 2,
    );
    expect(
      messages.filter((message) => message.method === "review.run"),
    ).toHaveLength(
      completed
        ? scenario === "one-run"
          ? 1
          : scenario === "ten-runs"
            ? 10
            : 3
        : 1,
    );
    const final = messages.at(-1);
    expect(final.id).toBe("run-one");
    if (completed)
      expect(final.result.assessments[0]).toHaveProperty("id", "canonical-one");
    else if (
      scenario === "host-error" ||
      scenario === "provider-effort-host-error"
    )
      expect(final.result).toMatchObject({
        status: "unresolved",
        assessments: [],
      });
    else expect(final.error).toBeDefined();
    stream.destroy();
  },
);

test("records mode is discoverable and rejects saved-scan flags", async () => {
  const output = capture();
  expect(
    await main(
      ["classify-severity", "--help"],
      output.stream,
      capture().stream,
      dependencies(),
    ),
  ).toBe(0);
  expect(output.text()).toContain("--records");
  expect(
    await main(
      ["classify-severity", "--records", "--scan", "latest"],
      capture().stream,
      capture().stream,
      dependencies(),
    ),
  ).toBe(2);
});

test("empty records probe version 1 without host execution", async () => {
  const data = input();
  data.records = [];
  let calls = 0;
  expect(
    await classifySeverityRecords(data, {
      reviewRunner: {
        async run() {
          calls++;
          return {};
        },
      },
    }),
  ).toEqual({
    version: 1,
    classificationRuns: 3,
    status: "completed",
    rubric: { revision: data.rubric.revision, sha256: data.rubric.sha256 },
    assessments: [],
  });
  expect(calls).toBe(0);
});

test("immediate SDK cancellation never starts a queued host review", async () => {
  const controller = new AbortController();
  let calls = 0;
  const result = classifySeverityRecords(input(), {
    signal: controller.signal,
    reviewRunner: {
      async run(request) {
        calls++;
        return answer(request);
      },
    },
  });
  controller.abort(new Error("Stopped before review"));
  await expect(result).rejects.toThrow("Stopped before review");
  expect(calls).toBe(0);
});

test("canonical records use majority voting and highest severity for a three-way tie", async () => {
  for (const [levels, expected] of [
    [["low", "high", "low"], "low"],
    [["medium", "critical", "high"], "critical"],
  ] as const) {
    let calls = 0;
    const result = await classifySeverityRecords(input(), {
      reviewRunner: {
        async run(request) {
          return { ...answer(request), level: levels[calls++] };
        },
      },
    });
    expect(calls).toBe(3);
    expect(result.assessments[0]?.level).toBe(expected);
  }
});

test.each([2, 3, 10])(
  "canonical review %p must succeed before returning any assessment",
  async (failedRun) => {
    for (const invalid of [false, true]) {
      let calls = 0;
      const data: ClassifySeverityRecordsInput = input();
      delete data.rubric;
      const result = await classifySeverityRecords(data, {
        classificationRuns: Math.max(3, failedRun),
        reviewRunner: {
          async run(request) {
            if (++calls !== failedRun) return answer(request);
            if (invalid)
              return { ...answer(request), findingId: "wrong-finding" };
            throw new Error("Host review failed");
          },
        },
      });
      expect(result).toMatchObject({
        status: "unresolved",
        assessments: [],
        error: {
          recordId: "canonical-one",
          code: invalid ? "invalid_assessment" : "review_failed",
        },
      });
      expect(calls).toBe(failedRun);
    }
  },
);

test.each([2, 3])(
  "canonical cancellation during review %p never returns a partial vote",
  async (canceledRun) => {
    const controller = new AbortController();
    let calls = 0;
    await expect(
      classifySeverityRecords(input(), {
        signal: controller.signal,
        reviewRunner: {
          async run(request) {
            if (++calls === canceledRun) controller.abort(new Error("Stopped"));
            return answer(request);
          },
        },
      }),
    ).rejects.toThrow("Stopped");
    expect(calls).toBe(canceledRun);
  },
);

test("omitted canonical rubric uses the bundled policy and returns its exact binding", async () => {
  const data: ClassifySeverityRecordsInput = input();
  delete data.rubric;
  const requests: SeverityClassificationReviewRequest[] = [];
  const result = await classifySeverityRecords(data, {
    reviewRunner: {
      async run(request) {
        requests.push(request);
        expect(JSON.parse(request.prompt).rubric).toEqual([
          defaultSeverityRubric,
        ]);
        return answer(request);
      },
    },
  });
  expect(requests).toHaveLength(3);
  expect(new Set(requests.map(({ requestId }) => requestId)).size).toBe(3);
  expect(result).toMatchObject({
    status: "completed",
    rubric: { revision: 1, sha256: hash(defaultSeverityRubric) },
    assessments: [{ level: "high" }],
  });
  expect(data.rubric).toBeUndefined();
});

test.each([1, 2, 4, 10])(
  "runs %i independent canonical reviews",
  async (classificationRuns) => {
    let calls = 0;
    const result = await classifySeverityRecords(input(), {
      classificationRuns,
      reviewRunner: {
        async run(request) {
          calls++;
          return answer(request);
        },
      },
    });
    expect(calls).toBe(classificationRuns);
    expect(result.classificationRuns).toBe(classificationRuns);
    expect(result.status).toBe("completed");
  },
);

test.each([0, -1, 11, 1.5, NaN, Infinity])(
  "rejects invalid canonical run count %p before host work",
  async (classificationRuns) => {
    let calls = 0;
    await expect(
      classifySeverityRecords(input(), {
        classificationRuns,
        reviewRunner: {
          async run(request) {
            calls++;
            return answer(request);
          },
        },
      }),
    ).rejects.toThrow();
    expect(calls).toBe(0);
  },
);

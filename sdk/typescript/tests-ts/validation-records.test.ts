import { expect, mock, test } from "bun:test";
import { PassThrough } from "node:stream";
import { standaloneValidationPrompt } from "../src/standalone-validation-prompt.js";
import { bundledPluginRoot } from "../src/runtime.js";
import { main } from "../src/cli.js";
import { DEFAULT_CODEX_CONFIG, scanModelConfiguration } from "../src/config.js";
import {
  validateRecords,
  type ValidateRecordsInput,
  type ValidationReviewRequest,
} from "../src/validation-records.js";
import { capture, dependencies } from "./cli-fixtures.js";
import { throwing } from "./support/errors.js";

const input: ValidateRecordsInput = {
  version: 1,
  findings: [{ id: "finding-1", finding: { title: "Synthetic unsafe URL" } }],
  context: "Only authenticated tenants can configure URLs.",
  knowledgeBasePath: "/validation/context",
  outputSchema: {
    type: "object",
    properties: { rationale: { type: "string", minLength: 1 } },
    required: ["rationale"],
    additionalProperties: false,
  },
};
const result = {
  rationale: "Authentication does not restrict the destination.",
};

test("rejects invalid input and duplicate host identities before execution", async () => {
  const run = mock(async () => result);
  for (const invalid of [
    { ...input, findings: [] },
    { ...input, findings: [...input.findings, ...input.findings] },
    { ...input, outputSchema: { type: "not-a-json-schema-type" } },
    { ...input, outputSchema: { ...input.outputSchema, $async: true } },
  ]) {
    await expect(
      validateRecords(invalid, { reviewRunner: { run } }),
    ).rejects.toThrow();
  }
  expect(run).not.toHaveBeenCalled();
});

test("rejects malformed results and propagates operational failures", async () => {
  await expect(
    validateRecords(input, {
      reviewRunner: {
        async run() {
          return { rationale: 7 };
        },
      },
    }),
  ).rejects.toThrow("does not match");
  await expect(
    validateRecords(input, {
      reviewRunner: {
        async run() {
          throw new Error("Source unavailable");
        },
      },
    }),
  ).rejects.toThrow("Source unavailable");
});

test("aborts a stuck host review and passes cancellation to the host", async () => {
  const controller = new AbortController();
  await expect(
    validateRecords(input, {
      signal: controller.signal,
      reviewRunner: {
        async run(_request, options) {
          expect(options?.signal).toBe(controller.signal);
          controller.abort(new Error("Host canceled"));
          return await new Promise(() => {});
        },
      },
    }),
  ).rejects.toThrow("Host canceled");
});

test.each([undefined, "", "\t", " synthetic-effort "])(
  "validate --records sends effort %p and source context to one host review",
  async (effort) => {
    const stdin = new PassThrough();
    const send = (message: unknown) =>
      stdin.write(JSON.stringify(message) + "\n");
    const reviews: ValidationReviewRequest[] = [];
    const replies: unknown[] = [];
    const stdout = new PassThrough();
    stdout.on("data", (chunk: Buffer) => {
      const message = JSON.parse(chunk.toString());
      if (message.method === "review.run") {
        expect(message.id).toBe(message.params.requestId);
        reviews.push(message.params);
        queueMicrotask(() => send({ jsonrpc: "2.0", id: message.id, result }));
      } else replies.push(message);
    });
    const deps = dependencies();
    deps.recordsInput = stdin;
    deps.runCodex = mock(throwing("Local execution is forbidden"));
    const stderr = capture(true);
    const completion = main(
      ["validate", "--records"],
      stdout,
      stderr.stream,
      deps,
    );
    send({
      jsonrpc: "2.0",
      id: "validation",
      method: "run",
      params: { ...input, model: "example-model", effort },
    });
    expect(await completion).toBe(0);
    expect(reviews).toHaveLength(1);
    const review = reviews[0]!;
    expect(review).toMatchObject({
      model: "example-model",
      effort:
        effort ?? scanModelConfiguration(DEFAULT_CODEX_CONFIG).reasoningEffort,
      schema: input.outputSchema,
      trustedInstructions: await standaloneValidationPrompt(
        await bundledPluginRoot(),
      ),
    });
    for (const value of [
      input.findings,
      input.context,
      input.knowledgeBasePath,
    ])
      expect(review.prompt).toContain(JSON.stringify(value));
    expect(replies).toEqual([
      {
        jsonrpc: "2.0",
        id: "validation",
        result: { status: "completed", result },
      },
    ]);
    expect(deps.runCodex).not.toHaveBeenCalled();
    expect(stderr.text()).toBe("");
    stdin.destroy();
  },
);

test("records mode rejects local validation flags", async () => {
  const stderr = capture(true);
  expect(
    await main(
      ["validate", "--records", "--context", "example"],
      capture().stream,
      stderr.stream,
      dependencies(),
    ),
  ).toBe(2);
  expect(stderr.text()).toContain("must be used alone with validate");
});

test("alternate records flag syntax cannot start local validation", async () => {
  const deps = dependencies();
  deps.runCodex = mock(async () => {
    throw new Error("Local execution is forbidden");
  });
  const stderr = capture(true);
  expect(
    await main(
      ["validate", "example candidate", "--records=true"],
      capture().stream,
      stderr.stream,
      deps,
    ),
  ).toBe(2);
  expect(stderr.text()).toContain("Use validate --records alone");
  expect(deps.runCodex).not.toHaveBeenCalled();
});

test.each([
  ["const", "drop"],
  ["const", "keep"],
  ["enum", "drop"],
  ["enum", "keep"],
] as const)(
  "keeps the admitted %s schema when a host mutates it and returns %s",
  async (keyword, verdict) => {
    const admitted = { verdict: { value: "keep" } };
    const outputSchema = {
      [keyword]: keyword === "const" ? admitted : [admitted],
    };
    const original = structuredClone(outputSchema);
    const run = mock(async (request: ValidationReviewRequest) => {
      const value = request.schema[keyword];
      const constraint = (Array.isArray(value) ? value[0] : value) as {
        verdict: { value: string };
      };
      expect(constraint.verdict.value).toBe("keep");
      constraint.verdict.value = "drop";
      return { verdict: { value: verdict } };
    });
    const pending = validateRecords(
      { ...input, outputSchema },
      { reviewRunner: { run } },
    );
    if (verdict === "drop")
      await expect(pending).rejects.toThrow("does not match");
    else await expect(pending).resolves.toEqual(admitted);
    expect(run).toHaveBeenCalledTimes(1);
    expect(outputSchema).toEqual(original);
  },
);

import { expect, mock, test } from "bun:test";
import { PassThrough, Writable } from "node:stream";
import { standaloneValidationPrompt } from "../src/standalone-validation-prompt.js";
import { bundledPluginRoot } from "../src/runtime.js";
import { main } from "../src/cli.js";
import {
  validateRecords,
  type ValidateRecordsInput,
  type ValidationReviewRequest,
} from "../src/validation-records.js";
import { capture, dependencies } from "./cli-fixtures.js";

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

test("passes source-only instructions and context to one host review", async () => {
  const run = mock(async (request: ValidationReviewRequest) => {
    expect(request.trustedInstructions).toBe(
      await standaloneValidationPrompt(await bundledPluginRoot()),
    );
    expect(request.prompt).toContain(JSON.stringify(input.findings));
    expect(request.prompt).toContain(JSON.stringify(input.context));
    expect(request.prompt).toContain(JSON.stringify(input.knowledgeBasePath));
    expect(request.schema).toEqual(input.outputSchema);
    expect(request.model).toBe("example-model");
    expect(request.effort).toBe("high");
    return result;
  });
  expect(
    await validateRecords(
      { ...input, model: "example-model", effort: "high" },
      {
        reviewRunner: { run },
      },
    ),
  ).toEqual(result);
  expect(run).toHaveBeenCalledTimes(1);
});

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

test("CLI records exchange returns schema-checked results without local Codex", async () => {
  const stdin = new PassThrough();
  const messages: Record<string, unknown>[] = [];
  const stdout = new Writable({
    write(chunk, _encoding, done) {
      const message = JSON.parse(chunk.toString());
      messages.push(message);
      if (message.method === "review.run") {
        expect(message.id).toBe(message.params.requestId);
        queueMicrotask(() =>
          stdin.write(
            JSON.stringify({
              jsonrpc: "2.0",
              id: message.id,
              result,
            }) + "\n",
          ),
        );
      }
      done();
    },
  });
  const deps = dependencies();
  deps.recordsInput = stdin;
  deps.runCodex = mock(async () => {
    throw new Error("Local execution is forbidden");
  });
  const stderr = capture(true);
  const completion = main(
    ["validate", "--records"],
    stdout,
    stderr.stream,
    deps,
  );
  stdin.write(
    JSON.stringify({
      jsonrpc: "2.0",
      id: "validation",
      method: "run",
      params: input,
    }) + "\n",
  );
  expect(await completion).toBe(0);
  expect(messages.at(-1)).toEqual({
    jsonrpc: "2.0",
    id: "validation",
    result: { status: "completed", result },
  });
  expect(deps.runCodex).not.toHaveBeenCalled();
  expect(stderr.text()).toBe("");
  stdin.destroy();
});

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

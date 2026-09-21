import { expect, test } from "bun:test";
import { DeduplicationReviewError } from "../src/errors.js";
import { mkdtemp, readFile, readdir, rm } from "node:fs/promises";
import { spawn } from "node:child_process";
import { createInterface } from "node:readline";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";
import { join } from "node:path";
import { PassThrough, Writable } from "node:stream";
import type { Finding, FindingsDocument } from "../src/models.js";
import {
  deduplicateRecords,
  type DeduplicateRecordsInput,
} from "../src/deduplication/records.js";
import type { DeduplicationReviewRequest } from "../src/deduplication/review.js";
import { runRecordsProtocol } from "../src/deduplication/records-protocol.js";
import { main } from "../src/cli.js";
import { capture, dependencies, FakeSignals } from "./cli-fixtures.js";
import { PLUGIN_ROOT } from "./plugin-root.js";

const document: FindingsDocument = JSON.parse(
  await readFile(
    join(PLUGIN_ROOT, "examples/completed-scan/findings.json"),
    "utf8",
  ),
);
function record(id: string, title = id) {
  const finding = structuredClone(document.findings[0]!);
  finding.title = title;
  finding.provenance = {
    source: `synthetic/${id}`,
    revision: "synthetic-revision",
  };
  return { id, finding };
}
function input(): DeduplicateRecordsInput {
  return {
    version: 1,
    observations: [
      record("a", "shared"),
      record("b", "shared"),
      record("c", "existing"),
      record("d", "unique"),
      record("neighbor", "existing"),
    ],
    candidateRelationships: ["a", "b", "c", "d"].map((observationId) => ({
      observationId,
      candidateObservationIds: ["a", "b", "c", "d", "neighbor"].filter(
        (id) => id !== observationId,
      ),
    })),
  };
}
function assigned(review: DeduplicationReviewRequest): Finding[] {
  return JSON.parse(
    review.prompt.slice(review.prompt.lastIndexOf('\n{"findings":')),
  ).findings;
}
function decision(findings: Finding[]) {
  return findings[0]!.title === findings[1]!.title
    ? {
        decision: "SAME",
        rationale: "Synthetic shared correction.",
        canonicalFindingId: findings[0]!.findingId,
        mergedFinding: { ...findings[0]!, extensions: { originals: findings } },
      }
    : { decision: "DISTINCT", rationale: "Synthetic independent corrections." };
}
function answer(review: DeduplicationReviewRequest): unknown {
  const findings = assigned(review);
  return review.stage === "pair-review"
    ? decision(findings)
    : {
        decisions: Object.fromEntries(
          findings.slice(1).map((finding, index) => [
            `pair-${index + 1}`,
            {
              decision: decision([findings[0]!, finding]).decision,
              rationale: "Synthetic pair recommendation.",
            },
          ]),
        ),
      };
}

test("records groups original observations and retrieved neighbors with unique representatives", async () => {
  const original = input();
  const requests: DeduplicationReviewRequest[] = [];
  const result = await deduplicateRecords(original, {
    reviewRunner: {
      async run(review) {
        requests.push(review);
        expect(review.trustedInstructions).toContain("approved repository");
        expect(review.findingSchema).toHaveProperty("required");
        expect(review).not.toHaveProperty("validate");
        for (const finding of assigned(review))
          expect(finding.provenance).toHaveProperty(
            "revision",
            "synthetic-revision",
          );
        return answer(review);
      },
    },
  });
  expect(result.status).toBe("completed");
  expect(
    result.groups.map((group) => [...group.observationIds].sort()).sort(),
  ).toEqual([["a", "b"], ["c", "neighbor"], ["d"]]);
  for (const group of result.groups)
    expect(group.observationIds).toContain(group.representativeObservationId);
  expect(result.unresolved).toEqual([]);
  expect(new Set(requests.map(({ requestId }) => requestId)).size).toBe(
    requests.length,
  );
  expect(requests.filter(({ stage }) => stage === "pair-review")).toHaveLength(
    2,
  );
  expect(original).toEqual(input());
});

test("records honors explicit observation neighborhoods and handles empty/isolated inputs without reviews", async () => {
  for (const observations of [[], [record("a")]]) {
    const result = await deduplicateRecords(
      {
        version: 1,
        observations: [...observations, record("unused")],
        candidateRelationships: observations.map(({ id }) => ({
          observationId: id,
          candidateObservationIds: [],
        })),
      },
      {
        reviewRunner: {
          async run() {
            throw new Error("No model call expected");
          },
        },
      },
    );
    expect(result.status).toBe("completed");
    expect(result.groups).toHaveLength(observations.length);
  }
});

test("candidate-only observations are grouped without becoming additional anchors", async () => {
  const data: DeduplicateRecordsInput = {
    version: 1,
    observations: [
      record("a", "same"),
      record("b", "same"),
      record("c", "same"),
    ],
    candidateRelationships: [
      { observationId: "a", candidateObservationIds: ["b"] },
    ],
  };
  const requests: DeduplicationReviewRequest[] = [];
  const result = await deduplicateRecords(data, {
    reviewRunner: {
      async run(review) {
        requests.push(review);
        return answer(review);
      },
    },
  });
  expect(result.status).toBe("completed");
  expect(
    result.groups.map(({ observationIds }) => observationIds.sort()),
  ).toEqual([["a", "b"]]);
  expect(requests.map(({ stage }) => stage)).toEqual([
    "screening",
    "pair-review",
  ]);
});

test.each([
  "malformed",
  "unknown-slot",
  "unknown-canonical",
  "missing-pair",
  "inconclusive",
  "failed",
  "pair-failed",
])(
  "%s review never becomes a unique disposition or retries",
  async (scenario) => {
    let calls = 0;
    const result = await deduplicateRecords(input(), {
      reviewRunner: {
        async run(review) {
          calls++;
          if (scenario === "pair-failed" && review.stage !== "pair-review")
            return answer(review);
          if (scenario === "failed" || scenario === "pair-failed")
            throw new Error("Remote execution may already have been accepted");
          if (scenario === "malformed") return "not an object";
          if (scenario === "inconclusive") return { decision: "INCONCLUSIVE" };
          if (scenario === "unknown-canonical") {
            if (review.stage === "screening") return answer(review);
            return {
              ...decision(assigned(review)),
              canonicalFindingId: "unknown",
            };
          }
          const valid = answer(review) as {
            decisions: Record<string, unknown>;
          };
          if (scenario === "missing-pair") delete valid.decisions["pair-1"];
          if (scenario === "unknown-slot") {
            valid.decisions["unknown"] = valid.decisions["pair-1"];
            delete valid.decisions["pair-1"];
          }
          return valid;
        },
      },
    });
    expect(result.status).toBe("unresolved");
    expect(result.groups).toEqual([]);
    expect(result.unresolved.map(({ observationId }) => observationId)).toEqual(
      ["a", "b", "c", "d"],
    );
    expect(calls).toBe(
      ["pair-failed", "unknown-canonical"].includes(scenario) ? 3 : 1,
    );
  },
);

test("rejects invalid inputs before calling the host", async () => {
  const cases = [
    { ...input(), version: 2 },
    { ...input(), observations: [record("a"), record("a")] },
    { ...input(), observations: [{ id: "a", finding: {} }] },
    { ...input(), canonicals: [] },
    {
      ...input(),
      candidateRelationships: [{ observationId: "a", canonicalIds: [] }],
    },
    {
      ...input(),
      candidateRelationships: [
        { observationId: "a", candidateObservationIds: ["a"] },
      ],
    },
    {
      ...input(),
      candidateRelationships: [
        { observationId: "a", candidateObservationIds: ["b", "b"] },
      ],
    },
    {
      ...input(),
      candidateRelationships: [
        input().candidateRelationships[0],
        input().candidateRelationships[0],
      ],
    },
    {
      ...input(),
      candidateRelationships: [
        { observationId: "unknown", candidateObservationIds: [] },
      ],
    },
    {
      ...input(),
      candidateRelationships: [
        { observationId: "a", candidateObservationIds: ["unknown"] },
      ],
    },
  ];
  for (const data of cases)
    await expect(
      deduplicateRecords(data as DeduplicateRecordsInput, {
        reviewRunner: {
          async run() {
            throw new Error("Host must not be called");
          },
        },
      }),
    ).rejects.toThrow();
});

test("SDK aborts even while a host runner is stuck", async () => {
  const controller = new AbortController();
  await expect(
    deduplicateRecords(input(), {
      signal: controller.signal,
      reviewRunner: {
        async run(_review, options) {
          expect(options?.signal).toBe(controller.signal);
          controller.abort(new Error("Canceled by host"));
          return await new Promise(() => {});
        },
      },
    }),
  ).rejects.toThrow("Canceled by host");
});

type Message = {
  jsonrpc: string;
  id: string | number | null;
  method?: string;
  params: DeduplicationReviewRequest;
  result?: unknown;
  error?: { code: number };
};
function fakeHost(
  onReview: (
    message: Message,
    send: (value: unknown) => void,
    input: PassThrough,
  ) => void,
) {
  const stream = new PassThrough();
  const messages: Message[] = [];
  const send = (value: unknown) => stream.write(`${JSON.stringify(value)}\n`);
  const output = new Writable({
    write(chunk, _encoding, callback) {
      const message = JSON.parse(chunk.toString()) as Message;
      messages.push(message);
      if (message.method === "review.run")
        queueMicrotask(() => onReview(message, send, stream));
      callback();
    },
  });
  return { stream, output, messages, send };
}
const run = { jsonrpc: "2.0", id: "run-1", method: "run", params: input() };

test("CLI records mode uses only the fake host, bypassing saved scans, persistence, auth, and updates", async () => {
  const host = fakeHost((message, send) =>
    send({ jsonrpc: "2.0", id: message.id, result: answer(message.params) }),
  );
  const deps = dependencies();
  for (const key of Object.keys(deps)) {
    if (typeof deps[key as keyof typeof deps] === "function")
      Object.assign(deps, {
        [key]: () => {
          throw new Error(`Unexpected dependency: ${key}`);
        },
      });
  }
  deps.addSignalListener = () => {};
  deps.removeSignalListener = () => {};
  deps.recordsInput = host.stream;
  const stderr = capture(true);
  const done = main(["dedupe", "--records"], host.output, stderr.stream, deps);
  host.send(run);
  expect(await done).toBe(0);
  expect(stderr.text()).toBe("");
  expect(host.messages.at(-1)).toMatchObject({
    jsonrpc: "2.0",
    id: "run-1",
    result: { status: "completed" },
  });
  expect(
    host.messages.filter((message) => message.method === "review.run"),
  ).toHaveLength(6);
  host.stream.destroy();
});

test.each([
  "wrong-id",
  "wrong-type",
  "duplicate",
  "malformed",
  "both",
  "no-result",
  "second-run",
  "unknown-cancel",
  "disconnect",
  "stream-error",
  "cancel",
  "host-error",
])("protocol handles %s without further reviews", async (scenario) => {
  const host = fakeHost((message, send, stream) => {
    if (scenario === "wrong-id")
      send({ jsonrpc: "2.0", id: "wrong", result: answer(message.params) });
    if (scenario === "wrong-type")
      send({ jsonrpc: "2.0", id: 1, result: answer(message.params) });
    if (scenario === "duplicate") {
      send({ jsonrpc: "2.0", id: message.id, result: answer(message.params) });
      send({ jsonrpc: "2.0", id: message.id, result: answer(message.params) });
    }
    if (scenario === "malformed") stream.write("not-json\n");
    if (scenario === "both")
      send({
        jsonrpc: "2.0",
        id: message.id,
        result: {},
        error: { code: -1, message: "failed" },
      });
    if (scenario === "no-result") send({ jsonrpc: "2.0", id: message.id });
    if (scenario === "second-run") send(run);
    if (scenario === "unknown-cancel")
      send({ jsonrpc: "2.0", method: "cancel", params: { id: "unknown" } });
    if (scenario === "disconnect") stream.end();
    if (scenario === "stream-error")
      stream.destroy(new Error("Host read failed"));
    if (scenario === "cancel")
      send({ jsonrpc: "2.0", method: "cancel", params: { id: "run-1" } });
    if (scenario === "host-error")
      send({
        jsonrpc: "2.0",
        id: message.id,
        error: {
          code: -32001,
          message: "Inconclusive",
          data: { executionMayHaveBeenAccepted: true },
        },
      });
  });
  const done = runRecordsProtocol(host.stream, host.output);
  host.send(run);
  expect(await done).toBe(scenario === "host-error" ? 1 : 2);
  expect(
    host.messages.filter((message) => message.method === "review.run"),
  ).toHaveLength(1);
  const final = host.messages.at(-1)!;
  expect(final.id).toBe("run-1");
  if (scenario === "host-error")
    expect(final.result).toMatchObject({
      status: "unresolved",
      groups: [],
    });
  else expect(final.error).toBeDefined();
  host.stream.destroy();
});

test.each(["SIGINT", "SIGTERM"] as const)(
  "records mode handles %s and removes handlers",
  async (signal) => {
    const signals = new FakeSignals();
    const host = fakeHost(() => signals.emit(signal));
    const deps = dependencies();
    deps.recordsInput = host.stream;
    deps.addSignalListener = (name, listener) => signals.add(name, listener);
    deps.removeSignalListener = (name, listener) =>
      signals.remove(name, listener);
    const done = main(
      ["dedupe", "--records"],
      host.output,
      capture().stream,
      deps,
    );
    host.send(run);
    expect(await done).toBe(signal === "SIGINT" ? 130 : 143);
    expect(host.messages.at(-1)?.error?.code).toBe(-32800);
    expect(signals.listeners.get(signal)?.size).toBe(0);
    host.stream.destroy();
  },
);

test("real CLI pipes exit after a fake-host run without local Codex or state writes", async () => {
  const directory = await mkdtemp(join(tmpdir(), "records-cli-"));
  const child = spawn(
    process.execPath,
    [
      fileURLToPath(new URL("../src/cli.ts", import.meta.url)),
      "dedupe",
      "--records",
    ],
    {
      cwd: directory,
      env: {
        ...process.env,
        CODEX_CLI_PATH: join(directory, "no-local-codex"),
        CODEX_SECURITY_STATE_DIR: join(directory, "state"),
        CODEX_HOME: join(directory, "home"),
      },
      stdio: ["pipe", "pipe", "pipe"],
    },
  );
  const closed = new Promise<number | null>((resolve, reject) => {
    child.on("error", reject);
    child.on("close", resolve);
  });
  let stderr = "";
  child.stderr.setEncoding("utf8").on("data", (value) => {
    stderr += value;
  });
  child.stdin.on("error", () => {});
  try {
    child.stdin.write(`${JSON.stringify(run)}\n`);
    let final: Message | undefined;
    for await (const line of createInterface({ input: child.stdout })) {
      const message = JSON.parse(line) as Message;
      if (message.method === "review.run")
        child.stdin.write(
          `${JSON.stringify({ jsonrpc: "2.0", id: message.id, result: answer(message.params) })}\n`,
        );
      else final = message;
    }
    expect(await closed).toBe(0);
    expect(stderr).toBe("");
    expect(final).toMatchObject({
      id: "run-1",
      result: {
        status: "completed",
        groups: expect.arrayContaining([
          {
            representativeObservationId: expect.any(String),
            observationIds: expect.arrayContaining(["c", "neighbor"]),
          },
        ]),
      },
    });
    expect(await readdir(directory)).toEqual([]);
  } finally {
    child.stdin.end();
    if (child.exitCode === null) child.kill();
    await closed;
    await rm(directory, { recursive: true, force: true });
  }
});

test("disconnect before run and a broken output pipe terminate cleanly", async () => {
  const host = fakeHost(() => {});
  const disconnected = runRecordsProtocol(host.stream, host.output);
  host.stream.end();
  expect(await disconnected).toBe(2);
  expect(host.messages).toMatchObject([{ id: null, error: { code: -32000 } }]);
  const input = new PassThrough();
  const output = new Writable({
    write(_chunk, _encoding, callback) {
      callback(new Error("Broken pipe"));
    },
  });
  const failed = runRecordsProtocol(input, output);
  input.write(`${JSON.stringify(run)}\n`);
  expect(await failed).toBe(2);
  input.destroy();
});

test("a disconnect while flushing the final result does not send a second response", async () => {
  const inputStream = new PassThrough();
  const messages: Message[] = [];
  const output = new Writable({
    write(chunk, _encoding, callback) {
      messages.push(JSON.parse(chunk.toString()));
      inputStream.end();
      setImmediate(callback);
    },
  });
  const done = runRecordsProtocol(inputStream, output);
  inputStream.write(
    `${JSON.stringify({
      ...run,
      params: {
        version: 1,
        observations: [],
        candidateRelationships: [],
      },
    })}\n`,
  );
  expect(await done).toBe(0);
  expect(messages).toMatchObject([
    { id: "run-1", result: { status: "completed" } },
  ]);
  expect(messages).toHaveLength(1);
});

test.each(["screening", "pair-review"] as const)(
  "%s refusal leaves records unresolved when the shared algorithm continues",
  async (stage) => {
    const result = await deduplicateRecords(input(), {
      reviewRunner: {
        async run(review) {
          if (review.stage === stage)
            throw new DeduplicationReviewError({
              stage,
              model: review.model,
              category: "refusal",
              attempts: 1,
              reason: "Synthetic review refusal.",
            });
          return answer(review);
        },
      },
    });
    expect(result.status).toBe("unresolved");
    expect(result.groups).toEqual([]);
    expect(result.unresolved.map(({ observationId }) => observationId)).toEqual(
      ["a", "b", "c", "d"],
    );
    expect(
      result.unresolved.every(({ reason }) => reason === "review_failed"),
    ).toBe(true);
  },
);

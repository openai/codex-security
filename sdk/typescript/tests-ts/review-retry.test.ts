import { expect, test } from "bun:test";
import {
  classifyReviewFailure,
  type DeduplicationReviewFailureCode,
  type DeduplicationReviewFailureObservation,
  type DeduplicationReviewFailurePolicy,
} from "../src/deduplication/review-failure.js";
import { runReviewSessions } from "../src/deduplication/retry.js";

class SyntheticReviewFailure extends Error {
  constructor(public readonly failurePolicy: DeduplicationReviewFailurePolicy) {
    super(failurePolicy.failureCode);
  }
}

const policyFor = (error: unknown) =>
  error instanceof SyntheticReviewFailure ? error.failurePolicy : undefined;

test("a temporary approval reviewer failure recovers in session two", async () => {
  const sessions: number[] = [];
  const delays: number[] = [];
  const result = await runReviewSessions(
    async (session) => {
      sessions.push(session);
      if (session === 1)
        throw new SyntheticReviewFailure(
          classifyReviewFailure({
            kind: "approval-reviewer",
            outcome: "unavailable",
          }),
        );
      return "accepted";
    },
    policyFor,
    {
      random: () => 0.5,
      wait: async (delay) => {
        delays.push(delay);
      },
    },
  );
  expect(result).toBe("accepted");
  expect(sessions).toEqual([1, 2]);
  expect(delays).toEqual([1500]);
});

test("a temporary transport failure exhausts exactly three sessions", async () => {
  const failure = new SyntheticReviewFailure(
    classifyReviewFailure({ kind: "transport", outcome: "unavailable" }),
  );
  const sessions: number[] = [];
  const delays: number[] = [];
  const result = runReviewSessions(
    async (session) => {
      sessions.push(session);
      throw failure;
    },
    policyFor,
    {
      random: () => 0,
      wait: async (delay) => {
        delays.push(delay);
      },
    },
  );
  await expect(result).rejects.toBe(failure);
  expect(sessions).toEqual([1, 2, 3]);
  expect(delays).toEqual([1000, 2000]);
  expect(failure.failurePolicy).toEqual({
    failureCode: "review_transport_unavailable",
    retryable: true,
  });
});

test.each<
  [
    string,
    DeduplicationReviewFailureObservation | object,
    DeduplicationReviewFailureCode,
  ]
>([
  [
    "genuine authorization 403",
    { kind: "transport", outcome: "forbidden" },
    "review_request_forbidden",
  ],
  [
    "source EACCES",
    { kind: "source", outcome: "access-unavailable" },
    "review_source_access_unavailable",
  ],
  [
    "missing source revision",
    { kind: "source", outcome: "revision-unavailable" },
    "review_source_revision_unavailable",
  ],
  [
    "model refusal",
    { kind: "model", outcome: "refused" },
    "review_model_refused",
  ],
  [
    "cost limit",
    { kind: "lifecycle", outcome: "cost-limit-exceeded" },
    "review_cost_limit_exceeded",
  ],
  ["bare HTTP 403", { httpStatusCode: 403 }, "review_unknown"],
  [
    "model-reported approval outage",
    { reason: "Approval reviewer unavailable" },
    "review_unknown",
  ],
])("does not retry terminal %s", async (_name, observation, failureCode) => {
  const failure = new SyntheticReviewFailure(
    classifyReviewFailure(observation),
  );
  let sessions = 0;
  const result = runReviewSessions(
    async () => {
      sessions++;
      throw failure;
    },
    policyFor,
    {
      wait: async () => {
        throw new Error("Terminal failures must not wait");
      },
    },
  );
  await expect(result).rejects.toBe(failure);
  expect(sessions).toBe(1);
  expect(failure.failurePolicy).toEqual({ failureCode, retryable: false });
});

test("cancellation during an injected retry wait stops before session two", async () => {
  const controller = new AbortController();
  const cancellation = "synthetic retry cancellation";
  let sessions = 0;
  let waits = 0;
  const result = runReviewSessions(
    async () => {
      sessions++;
      throw new SyntheticReviewFailure(
        classifyReviewFailure({
          kind: "approval-reviewer",
          outcome: "unavailable",
        }),
      );
    },
    policyFor,
    {
      signal: controller.signal,
      wait: async (_delay, signal) => {
        waits++;
        expect(signal).toBe(controller.signal);
        controller.abort(cancellation);
      },
    },
  );
  await expect(result).rejects.toBe(cancellation);
  expect(sessions).toBe(1);
  expect(waits).toBe(1);
});

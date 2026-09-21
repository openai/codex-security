import { expect, test } from "bun:test";
import {
  classifyReviewFailure,
  type DeduplicationReviewFailureCode,
  type DeduplicationReviewFailureObservation,
} from "../src/deduplication/review-failure.js";
import { DeduplicationReviewError } from "../src/errors.js";

test.each<
  [
    string,
    DeduplicationReviewFailureObservation,
    DeduplicationReviewFailureCode,
    boolean,
  ]
>([
  [
    "temporary approval reviewer outage",
    { kind: "approval-reviewer", outcome: "unavailable" },
    "approval_reviewer_unavailable",
    true,
  ],
  [
    "approval reviewer authorization failure",
    { kind: "approval-reviewer", outcome: "forbidden" },
    "review_request_forbidden",
    false,
  ],
  [
    "temporary review transport outage",
    { kind: "transport", outcome: "unavailable" },
    "review_transport_unavailable",
    true,
  ],
  [
    "review transport authorization failure",
    { kind: "transport", outcome: "forbidden" },
    "review_request_forbidden",
    false,
  ],
  [
    "source access failure",
    { kind: "source", outcome: "access-unavailable" },
    "review_source_access_unavailable",
    false,
  ],
  [
    "source revision failure",
    { kind: "source", outcome: "revision-unavailable" },
    "review_source_revision_unavailable",
    false,
  ],
  [
    "model refusal",
    { kind: "model", outcome: "refused" },
    "review_model_refused",
    false,
  ],
  [
    "validation exhaustion",
    { kind: "validation", outcome: "exhausted" },
    "review_validation_exhausted",
    true,
  ],
  [
    "cancellation",
    { kind: "lifecycle", outcome: "cancelled" },
    "review_cancelled",
    false,
  ],
  [
    "cost limit",
    { kind: "lifecycle", outcome: "cost-limit-exceeded" },
    "review_cost_limit_exceeded",
    false,
  ],
])(
  "classifies host-observed %s",
  (_name, observation, failureCode, retryable) => {
    expect(classifyReviewFailure(observation)).toEqual({
      failureCode,
      retryable,
    });
  },
);

test.each([
  null,
  "approval reviewer unavailable",
  { reason: "approval reviewer unavailable" },
  { kind: "transport", httpStatusCode: 503 },
  { kind: "transport", outcome: "http-error", httpStatusCode: 403 },
  {
    kind: "approval-reviewer",
    outcome: "unavailable",
    retryable: false,
  },
])(
  "fails closed for unstructured or inconsistent observations: %p",
  (value) => {
    expect(classifyReviewFailure(value)).toEqual({
      failureCode: "review_unknown",
      retryable: false,
    });
  },
);

test("legacy and inconsistent error metadata fail closed", () => {
  const metadata = {
    stage: "screening" as const,
    model: "synthetic-review-model",
    category: "transport" as const,
    attempts: 1,
    reason: "Review failed.",
  };
  expect(new DeduplicationReviewError(metadata).metadata).toEqual({
    ...metadata,
    failureCode: "review_unknown",
    retryable: false,
  });
  expect(
    new DeduplicationReviewError({
      ...metadata,
      failureCode: "approval_reviewer_unavailable",
      retryable: false,
    }).metadata,
  ).toEqual({
    ...metadata,
    failureCode: "review_unknown",
    retryable: false,
  });
});

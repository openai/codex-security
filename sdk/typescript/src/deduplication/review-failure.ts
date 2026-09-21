export type DeduplicationReviewFailureCode =
  | "approval_reviewer_unavailable"
  | "review_transport_unavailable"
  | "review_source_access_unavailable"
  | "review_source_revision_unavailable"
  | "review_request_forbidden"
  | "review_model_refused"
  | "review_validation_exhausted"
  | "review_cancelled"
  | "review_cost_limit_exceeded"
  | "review_unknown";

export interface DeduplicationReviewFailurePolicy {
  failureCode: DeduplicationReviewFailureCode;
  retryable: boolean;
}

export type DeduplicationReviewFailureObservation =
  | {
      kind: "approval-reviewer";
      outcome: "unavailable" | "forbidden";
    }
  | {
      kind: "transport";
      outcome: "unavailable" | "forbidden";
    }
  | {
      kind: "source";
      outcome: "access-unavailable" | "revision-unavailable";
    }
  | { kind: "model"; outcome: "refused" }
  | { kind: "validation"; outcome: "exhausted" }
  | { kind: "lifecycle"; outcome: "cancelled" | "cost-limit-exceeded" }
  | { kind: "unknown" };

const policies = {
  approval_reviewer_unavailable: true,
  review_transport_unavailable: true,
  review_source_access_unavailable: false,
  review_source_revision_unavailable: false,
  review_request_forbidden: false,
  review_model_refused: false,
  review_validation_exhausted: true,
  review_cancelled: false,
  review_cost_limit_exceeded: false,
  review_unknown: false,
} as const satisfies Record<DeduplicationReviewFailureCode, boolean>;

const unknownPolicy: DeduplicationReviewFailurePolicy = {
  failureCode: "review_unknown",
  retryable: false,
};

function policy(
  failureCode: DeduplicationReviewFailureCode,
): DeduplicationReviewFailurePolicy {
  return { failureCode, retryable: policies[failureCode] };
}

function exactObservation(
  value: Record<string, unknown>,
  kind: string,
  outcomes: readonly string[],
): value is Record<"kind" | "outcome", string> {
  return (
    value["kind"] === kind &&
    typeof value["outcome"] === "string" &&
    outcomes.includes(value["outcome"]) &&
    Object.keys(value).length === 2
  );
}

/** Classifies host-observed review failures without consulting diagnostic prose. */
export function classifyReviewFailure(
  observation: unknown,
): DeduplicationReviewFailurePolicy {
  if (
    observation === null ||
    typeof observation !== "object" ||
    Array.isArray(observation)
  )
    return { ...unknownPolicy };
  const value = observation as Record<string, unknown>;
  if (value["kind"] === "unknown" && Object.keys(value).length === 1)
    return { ...unknownPolicy };
  if (
    exactObservation(value, "approval-reviewer", ["unavailable", "forbidden"])
  )
    return policy(
      value.outcome === "unavailable"
        ? "approval_reviewer_unavailable"
        : "review_request_forbidden",
    );
  if (exactObservation(value, "transport", ["unavailable", "forbidden"]))
    return policy(
      value.outcome === "unavailable"
        ? "review_transport_unavailable"
        : "review_request_forbidden",
    );
  if (
    exactObservation(value, "source", [
      "access-unavailable",
      "revision-unavailable",
    ])
  )
    return policy(
      value.outcome === "access-unavailable"
        ? "review_source_access_unavailable"
        : "review_source_revision_unavailable",
    );
  if (exactObservation(value, "model", ["refused"]))
    return policy("review_model_refused");
  if (exactObservation(value, "validation", ["exhausted"]))
    return policy("review_validation_exhausted");
  if (
    exactObservation(value, "lifecycle", ["cancelled", "cost-limit-exceeded"])
  )
    return policy(
      value.outcome === "cancelled"
        ? "review_cancelled"
        : "review_cost_limit_exceeded",
    );
  return { ...unknownPolicy };
}

export function validatedReviewFailurePolicy(
  failureCode: unknown,
  retryable: unknown,
): DeduplicationReviewFailurePolicy {
  if (
    typeof failureCode === "string" &&
    Object.hasOwn(policies, failureCode) &&
    policies[failureCode as DeduplicationReviewFailureCode] === retryable
  )
    return policy(failureCode as DeduplicationReviewFailureCode);
  return { ...unknownPolicy };
}

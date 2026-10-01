import { isDeepStrictEqual } from "node:util";

export const CODEX_SANDBOX_STATE_META_CAPABILITY = "codex/sandbox-state-meta";

export function trustedSandboxState(extra: unknown): Record<string, unknown> {
  const request = record(extra);
  const direct = record(request?._meta)?.[CODEX_SANDBOX_STATE_META_CAPABILITY];
  const requestInfo = record(request?.requestInfo);
  const forwarded = record(requestInfo?._meta)?.[
    CODEX_SANDBOX_STATE_META_CAPABILITY
  ];

  if (
    direct !== undefined &&
    forwarded !== undefined &&
    !isDeepStrictEqual(direct, forwarded)
  ) {
    throw new Error("the parent supplied conflicting sandbox metadata");
  }

  const state = record(direct ?? forwarded);
  if (!state) {
    throw new Error("the host did not provide trusted parent sandbox metadata");
  }
  return state;
}

function record(value: unknown): Record<string, unknown> | undefined {
  return typeof value === "object" && value !== null && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : undefined;
}

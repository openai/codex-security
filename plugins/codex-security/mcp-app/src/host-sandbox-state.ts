import { isDeepStrictEqual } from "node:util";
import { asRecord as record } from "./record.js";

export const CODEX_SANDBOX_STATE_META_CAPABILITY = "codex/sandbox-state-meta";

export function trustedSandboxState(
  extra: unknown,
  error: (reason: string) => Error = (reason) => new Error(reason),
): Record<string, unknown> {
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
    throw error("the parent supplied conflicting sandbox metadata");
  }

  const state = record(direct ?? forwarded);
  if (!state) {
    throw error("the host did not provide trusted parent sandbox metadata");
  }
  return state;
}

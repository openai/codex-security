import { workflowDigest } from "../finding-workflow.js";
import type { CodexReview } from "./codex-review.js";

/** Persist a validated review before acknowledging completion to its caller. */
export interface DeduplicationCheckpointStore {
  getReview(key: string): Promise<unknown | null>;
  /** Acknowledge this exact result durably; reject conflicting writes for a key. */
  saveReview(key: string, binding: object, result: unknown): Promise<void>;
}

/** @internal */
export async function runCheckpointedReview<T>(options: {
  review: CodexReview<T>;
  binding: object;
  store?: DeduplicationCheckpointStore;
  run(): Promise<unknown>;
  assertSourceUnchanged(): Promise<void>;
}): Promise<T> {
  const key = workflowDigest(options.binding);
  if (options.store) {
    const saved = await options.store.getReview(key);
    if (saved !== null) return options.review.validate(saved);
  }
  const result = options.review.validate(await options.run());
  await options.assertSourceUnchanged();
  await options.store?.saveReview(key, options.binding, result);
  return result;
}

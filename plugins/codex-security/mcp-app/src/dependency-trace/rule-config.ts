import { createHash } from "node:crypto";
import type { RuleExecution, TraceScope } from "./types.ts";

export function configIdentity(config: unknown) {
  const text = JSON.stringify(config);
  return { text, sha256: createHash("sha256").update(text).digest("hex") };
}

export function scopeSummary({ rules, ...scope }: TraceScope) {
  return {
    ...scope,
    ...(rules === undefined
      ? {}
      : { ruleConfigSha256: configIdentity({ rules }).sha256 }),
  };
}

export function executionSummary({ config, ...execution }: RuleExecution) {
  return { ...execution, ruleIds: config.rules.map((rule) => rule.id) };
}

import { boundGraphResponse } from "./graph.ts";
import { executionSummary, scopeSummary } from "./rule-config.ts";
import type {
  TraceEntity,
  TraceResult,
  TraceStep,
  RuleExecution,
  TextMatch,
  NativeMatch,
} from "./types.ts";

function entityKey({ kind, name, scope }: TraceEntity) {
  return [kind, name, scope];
}

// Keep the graph and the CLI candidate registry independent of the model view.
export function boundTraceResponse<T extends object>(result: T) {
  const view = { ...result };
  const executions = (view as Record<string, unknown>).ruleExecutions;
  if (Array.isArray(executions))
    Object.assign(view, {
      ruleExecutions: executions.map((entry) =>
        entry.config === undefined
          ? entry
          : executionSummary(entry as RuleExecution),
      ),
    });
  for (const key of ["trace", "candidates", "textMatches"] as const) {
    const items = (view as Record<string, unknown>)[key];
    if (!Array.isArray(items) || items.length <= 128) continue;
    Object.assign(view, {
      [key]: items.slice(0, 128),
      [key + "_omitted"]: items.length - 128,
      truncated: true,
    });
  }
  return boundGraphResponse(view);
}

export function traceResponse(result: TraceResult) {
  const steps = new Map<
    string,
    {
      step: TraceStep;
      sources: Map<
        string,
        { lines: Set<number>; matches: Map<string, NativeMatch> }
      >;
    }
  >();
  const textMatches = new Map<
    string,
    Omit<TextMatch, "line"> & { lines: Set<number> }
  >();
  const searched = new Set<string>();
  const partial = [];
  const batches = result.scopes.filter(
    ({ scope }) => scope.kind === "source_batch",
  );
  for (const {
    scope,
    evidence,
    textMatches: hits,
    complete,
    reason,
    hops,
  } of result.scopes) {
    if (
      complete &&
      (scope.kind === "search" || scope.kind === "manifests") &&
      scope.path !== undefined
    )
      searched.add(scope.path);
    if (!complete)
      partial.push({
        ...scopeSummary(scope),
        hops,
        reason: reason ?? "Lookup did not finish.",
      });
    for (const { step, source, line, match } of evidence) {
      const key = JSON.stringify([
        entityKey(step.from),
        step.relation,
        step.to && entityKey(step.to),
        step.calleeText,
        step.sourceText,
      ]);
      let entry = steps.get(key);
      if (!entry) {
        entry = { step, sources: new Map() };
        steps.set(key, entry);
      }
      let cited = entry.sources.get(source);
      if (!cited) {
        cited = { lines: new Set(), matches: new Map() };
        entry.sources.set(source, cited);
      }
      if (line !== undefined) cited.lines.add(line);
      if (match) cited.matches.set(JSON.stringify(match), match);
    }
    for (const { source, text, line, ruleExecutionId, nativeRuleId } of hits ??
      []) {
      const provenance = {
        ...(ruleExecutionId === undefined ? {} : { ruleExecutionId }),
        ...(nativeRuleId === undefined ? {} : { nativeRuleId }),
      };
      const key = JSON.stringify([
        source,
        text,
        ...(ruleExecutionId === undefined
          ? []
          : [ruleExecutionId, nativeRuleId]),
      ]);
      let match = textMatches.get(key);
      if (!match) {
        match = { source, text, lines: new Set(), ...provenance };
        textMatches.set(key, match);
      }
      if (line !== undefined) match.lines.add(line);
    }
  }
  const trace = Array.from(steps.values(), ({ step, sources }) => ({
    ...step,
    evidence: Array.from(sources, ([source, { lines, matches }]) => ({
      source,
      ...(lines.size > 0 && { lines: [...lines].sort((a, b) => a - b) }),
      ...(matches.size > 0 && { matches: [...matches.values()] }),
    })),
  }));
  const executions = new Map(
    result.scopes.flatMap(({ ruleExecution }) =>
      ruleExecution ? [[ruleExecution.id, ruleExecution] as const] : [],
    ),
  );
  return {
    ...(executions.size > 0 && { ruleExecutions: [...executions.values()] }),
    trace,
    textMatches: Array.from(
      textMatches.values(),
      ({ source, text, lines, ...provenance }) => ({
        source,
        text,
        ...provenance,
        lines: [...lines].sort((a, b) => a - b),
      }),
    ),
    coverage: {
      complete: result.complete,
      limits: result.limits,
      searched_paths: [...searched].sort(),
      partial,
      ...(batches.length > 0 && {
        source_batches: {
          scheduled: batches.length,
          completed: batches.filter(({ complete }) => complete).length,
          files: batches.reduce(
            (total, { scope }) => total + scope.files!.length,
            0,
          ),
        },
      }),
      frontier: result.frontier.map(scopeSummary),
    },
  };
}

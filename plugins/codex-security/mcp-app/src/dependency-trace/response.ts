import type { TraceEntity, TraceResult, TraceStep } from "./types.ts";

function entityKey({ kind, name, scope }: TraceEntity) {
  return [kind, name, scope];
}

export function traceResponse(result: TraceResult) {
  const steps = new Map<
    string,
    { step: TraceStep; sources: Map<string, Set<number>> }
  >();
  const textMatches = new Map<
    string,
    { source: string; text: string; lines: Set<number> }
  >();
  const searched = new Set<string>();
  const partial = [];
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
        ...scope,
        hops,
        reason: reason ?? "Lookup did not finish.",
      });
    for (const { step, source, line } of evidence) {
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
      let lines = entry.sources.get(source);
      if (!lines) {
        lines = new Set();
        entry.sources.set(source, lines);
      }
      if (line !== undefined) lines.add(line);
    }
    for (const { source, text, line } of hits ?? []) {
      const key = JSON.stringify([source, text]);
      let match = textMatches.get(key);
      if (!match) {
        match = { source, text, lines: new Set() };
        textMatches.set(key, match);
      }
      if (line !== undefined) match.lines.add(line);
    }
  }
  const trace = Array.from(steps.values(), ({ step, sources }) => ({
    ...step,
    evidence: Array.from(sources, ([source, lines]) => ({
      source,
      ...(lines.size > 0 && { lines: [...lines].sort((a, b) => a - b) }),
    })),
  }));
  return {
    trace,
    textMatches: Array.from(
      textMatches.values(),
      ({ source, text, lines }) => ({
        source,
        text,
        lines: [...lines].sort((a, b) => a - b),
      }),
    ),
    coverage: {
      complete: result.complete,
      limits: result.limits,
      searched_paths: [...searched].sort(),
      partial,
      frontier: result.frontier,
    },
  };
}

{{REDUCER_ROLE}}

Use this exact reducer configuration:

```json
{{DEDUP_CONTEXT_JSON}}
```

Read the assigned, previously accepted Standard findings and the previous aggregate with `get_codex_security_deep_reducer_inputs({ maxBytes, cursor? })`. Choose a small `maxBytes` that fits comfortably in a tool response. The budget counts serialized response bytes, including JSON escaping. Even one large finding can span pages.

Each tool response has one text content block containing `{ json, nextCursor? }`. Its `json` is a fragment that may end inside a field. Follow `nextCursor` until absent and read the fragments in order as one document. The assigned document contains `{ discoveries, previous }`. Keep pages from different `findingRef` requests separate.

Without code mode, call `get_codex_security_deep_reducer_inputs` directly for each page. Keep the fragments in conversation order and submit the complete aggregate directly with `record_codex_security_deep_reduction`.

With code mode, use the helper below to assemble the document inside a cell and return only the fields you need. It saves the fragments, next unread cursor, and completion together after each successful page. The terminal cursor is `null` because `store` cannot save `undefined`.

```javascript
async function readReducerDocument(maxBytes, findingRef = null) {
  const key = "deep-reducer-pages:" + (findingRef ?? "assigned");
  let state = load(key) ?? { json: "", cursor: null, done: false };
  while (!state.done) {
    const response =
      await tools.mcp__cs_artifacts__get_codex_security_deep_reducer_inputs({
        maxBytes,
        ...(state.cursor === null ? {} : { cursor: state.cursor }),
        ...(findingRef === null ? {} : { findingRef }),
      });
    const body = response.content.find((item) => item.type === "text").text;
    if (response.isError) throw new Error(body);
    const page = JSON.parse(body);
    state = {
      json: state.json + page.json,
      cursor: page.nextCursor ?? null,
      done: page.nextCursor == null,
    };
    store(key, state);
  }
  return JSON.parse(state.json);
}
```

Use the exact exposed tool name if the host uses a different MCP namespace. Code mode has only its documented globals; use `load`/`store` for state between cells and ordinary JSON operations for JSON data, rather than assuming Node.js globals or `structuredClone` are available.

The input view omits the retained `provenance.sourceFindings`, `previousFindings`, and `originalCandidates` bodies. The host preserves those bodies when saving the aggregate. Fetch full details when needed with the same paged tool and `findingRef`: use `source:<sourceFindingId>` for an original source, or `previous:N` for the previous aggregate's zero-based finding index, including its synthesized history. Never copy those retained bodies into your submission; submit the semantic finding and its source refs.

If a response is truncated or exceeds the IPC frame limit, retry the failed page with a smaller `maxBytes` (halve the budget used for that request), keeping its cursor and findingRef. Preserve already-read fragments and continue from the failed page. If the budget is too small to hold even one character and the page envelope, increase it as directed by the tool's diagnostic.

Read every finding and the previous aggregate. Merge only the same actionable root issue using remediation-subsumption: fixing the retained finding must also fix every absorbed finding. Preserve distinct reachable vulnerable instances, proof tuples, useful evidence, uncertainty, locations, provenance, severity, validation, attack paths, and remediation.

Do not merge findings merely because they share a subsystem, CWE, route or file family, sink family, or attack language. Keep them separate whenever any source/control/sink/impact tuple or independently reachable instance would remain after the proposed common fix. Related findings may be cross-referenced without being collapsed.

For a valid merge, synthesize one stronger finding while preserving every materially useful non-redundant detail: narrower exploit framings, affected subpaths, preconditions, distinct source/control/sink nuances, contradictory or strengthening evidence, affected locations, and remediation-relevant subcases. Omit only genuinely duplicate or superseded detail. Preserve the identity of each independently retained finding. Semantically equivalent previous aliases may consolidate under one retained or synthesized identity when each complete prior source group maps to that single recipient; never split a prior source group across output findings.

Account for every input finding using the host-supplied `provenance.sourceFindingIds`. Copy the refs for retained findings; union them for a valid merge, preserving previous refs. Never invent, omit, or reuse a ref across independent output findings. The host retains original source payloads and rejects unaccounted input. Identity collisions do not establish that findings are duplicates.

Carry unchanged previous findings forward with `retainedFindingRefs: ["previous:0", "previous:1", ...]`, using their zero-based indices in the previous aggregate. The host copies their full bodies, identities, source refs, and retained history. Omit those findings from `findings`; submit only new or synthesized findings there. Never replace descriptive text with placeholders to fit a submission. When code mode is available, build the submission object and call the record tool inside a cell without printing the complete aggregate.

Preserve the threat-model context and scope as needed, omitting scope `includePaths` and `excludePaths`. Do not resolve or reject source findings during reduction.

Call `record_codex_security_deep_reduction({ scanId, findings, retainedFindingRefs?, threatModel?, scope? })` until it succeeds; correct a reported validation error and retry in the same conversation. After the first successful call, do not call it again. The host derives convergence and worker attribution from its existing state.

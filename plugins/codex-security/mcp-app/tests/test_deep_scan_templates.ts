import { join } from "node:path";
import { readFile } from "node:fs/promises";
import assert from "node:assert/strict";
import { importSource } from "./import-module.ts";

const { renderDedupPrompt, renderDiscoveryPrompt } = await importSource(
  join(import.meta.dirname, "../src/deep-scan/templates.ts"),
  { loader: { ".md": "text" } },
);

for (const name of ["discovery", "dedup"]) {
  const template = await readFile(
    new URL(`../templates/deep-scan/${name}.md`, import.meta.url),
    "utf8",
  );
  for (const key of template.match(/\{\{[A-Z0-9_]+\}\}/g) ?? []) {
    assert.equal(key, `{{${name.toUpperCase()}_CONTEXT_JSON}}`);
  }
}

const discoveryInput = {
  scanId: "a0d89285-66b7-4e4f-b51a-e21b93b7081b",
  pluginRoot: "/fixture/plugins/codex-security",
  targetPath: "/fixture/repository",
  scope: ".",
  userContext:
    "preserve literal {{DISCOVERY_CONTEXT_JSON}} text and https://security.example.test/callback",
  workerLabel: "discovery-0001",
  subagents: 3,
};

const rendered = renderDiscoveryPrompt({ ...discoveryInput });
assert.doesNotMatch(rendered, /false_positive_feedback\.json/);
assert.match(rendered, /preserve literal \{\{DISCOVERY_CONTEXT_JSON\}\} text/);
assert.match(rendered, /record_codex_security_scan_draft/);
assert.match(rendered, /coverage\.deferred/);
const discoveryContext = firstJsonBlock(rendered);
const { scope, ...expectedContext } = discoveryInput;
assert.deepEqual(discoveryContext, {
  ...expectedContext,
  includePaths: [scope],
});

const scopedPaths = ["src/api", "background jobs/worker.py"];
assert.deepEqual(
  firstJsonBlock(
    renderDiscoveryPrompt({ ...discoveryInput, includePaths: scopedPaths }),
  ).includePaths,
  scopedPaths,
);

const feedbackPath =
  "/fixture/scans/run/artifacts/01_context/false_positive_feedback.json";
const withFeedback = renderDiscoveryPrompt({ ...discoveryInput }, feedbackPath);
assert.deepEqual(firstJsonBlock(withFeedback), discoveryContext);
assert.equal(withFeedback.includes(JSON.stringify(feedbackPath)), true);

const dedup = renderDedupPrompt("dedup-0001", ["worker-001"]);
const dedupContext = firstJsonBlock(dedup);
assert.doesNotMatch(dedup, /\bcoverage\b/i);
assert.match(
  dedup,
  /record_codex_security_deep_reduction\(\{ scanId, findings, threatModel\?, scope\? \}\)/,
);
assert.deepEqual(dedupContext, {
  reducerLabel: "dedup-0001",
  claimedWorkerIds: ["worker-001"],
});

const previousReduction = firstJsonBlock(renderDedupPrompt("dedup-0002", []));
assert.deepEqual(previousReduction, {
  reducerLabel: "dedup-0002",
  claimedWorkerIds: [],
});

// Execute the documented pager across a failed page and fresh code-mode cells.
// Its stored terminal state must never replay a successfully committed tail.
const pagerExample = dedup.match(/```javascript\n([\s\S]*?)\n```/);
assert.ok(pagerExample);
const values = new Map<string, unknown>();
const requests: { maxBytes: number; cursor?: string; findingRef?: string }[] =
  [];
const assigned = { discoveries: [{ workerId: "worker-001" }], previous: null };
const fullFinding = { title: "Original source finding" };
let failNextAssignedTail = true;
const tools = {
  async mcp__cs_artifacts__get_codex_security_deep_reducer_inputs(input: {
    maxBytes: number;
    cursor?: string;
    findingRef?: string;
  }) {
    requests.push(input);
    if (input.cursor && !input.findingRef && failNextAssignedTail) {
      failNextAssignedTail = false;
      return {
        isError: true,
        content: [
          { type: "text", text: "Retry this page with a smaller byte budget." },
        ],
      };
    }
    const json = JSON.stringify(input.findingRef ? fullFinding : assigned);
    const offset = Number(input.cursor ?? 0);
    const end = Math.min(offset + 20, json.length);
    return {
      content: [
        {
          type: "text",
          text: JSON.stringify({
            json: json.slice(offset, end),
            ...(end < json.length ? { nextCursor: String(end) } : {}),
          }),
        },
      ],
    };
  },
};
function freshPager() {
  return new Function(
    "tools",
    "load",
    "store",
    `${pagerExample![1]}\nreturn readReducerDocument;`,
  )(
    tools,
    (key: string) => values.get(key),
    (key: string, value: unknown) => {
      const persisted = JSON.parse(JSON.stringify(value));
      assert.deepEqual(
        persisted,
        value,
        "stored paging state must not contain undefined fields",
      );
      values.set(key, persisted);
    },
  );
}
await assert.rejects(freshPager()(1000), /smaller byte budget/);
assert.deepEqual(values.get("deep-reducer-pages:assigned"), {
  json: JSON.stringify(assigned).slice(0, 20),
  cursor: "20",
  done: false,
});
assert.deepEqual(await freshPager()(500), assigned);
assert.equal(requests[1].cursor, requests[2].cursor, "retry the unread page");
assert.ok(requests[2].maxBytes < requests[1].maxBytes);
const afterCompletion = requests.length;
assert.deepEqual(await freshPager()(500), assigned);
assert.equal(
  requests.length,
  afterCompletion,
  "a new cell must not append the terminal page again",
);
assert.deepEqual(await freshPager()(500, "source:worker-001:0"), fullFinding);
assert.deepEqual(
  await freshPager()(500),
  assigned,
  "findingRef reads use separate paging state",
);

function firstJsonBlock(prompt: string) {
  const match = prompt.match(/```json\n([\s\S]*?)\n```/);
  assert.ok(match, "prompt should contain a JSON context block");
  return JSON.parse(match[1]);
}

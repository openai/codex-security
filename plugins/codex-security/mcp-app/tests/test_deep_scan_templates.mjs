import assert from "node:assert/strict";
import { build } from "esbuild";

const bundle = await build({
  bundle: true,
  entryPoints: [new URL("../src/deep-scan/templates.ts", import.meta.url).pathname],
  format: "esm",
  loader: { ".md": "text" },
  platform: "node",
  write: false
});
const { renderDedupPrompt, renderDiscoveryPrompt } = await import(
  `data:text/javascript;base64,${Buffer.from(bundle.outputFiles[0].contents).toString("base64")}`
);

const rendered = renderDiscoveryPrompt({
  scanId: "a0d89285-66b7-4e4f-b51a-e21b93b7081b",
  pluginRoot: "/fixture/plugins/codex-security",
  targetPath: "/fixture/repository",
  scope: ".",
  userContext: "preserve literal {{DISCOVERY_CONTEXT_JSON}} text and https://security.example.test/callback",
  workerLabel: "discovery-0001",
  subagents: 3
});
assert.doesNotMatch(rendered, /false_positive_feedback\.json/);
assert.match(rendered, /preserve literal \{\{DISCOVERY_CONTEXT_JSON\}\} text/);
assert.match(rendered, /record_codex_security_scan_draft/);
const discoveryContext = firstJsonBlock(rendered);
assert.deepEqual(discoveryContext, {
  scanId: "a0d89285-66b7-4e4f-b51a-e21b93b7081b",
  pluginRoot: "/fixture/plugins/codex-security",
  targetPath: "/fixture/repository",
  scope: ".",
  userContext: "preserve literal {{DISCOVERY_CONTEXT_JSON}} text and https://security.example.test/callback",
  workerLabel: "discovery-0001",
  subagents: 3
});
for (const field of [
  "artifactDir",
  "threatModelPath",
  "inScopeFilesPath",
  "candidateLedgerPath",
  "artifactSchemas",
  "rankInputPath",
  "deepReviewInputPath"
]) {
  assert.equal(Object.hasOwn(discoveryContext, field), false);
}

const feedbackPath = "/fixture/scans/run/artifacts/01_context/false_positive_feedback.json";
const withFeedback = renderDiscoveryPrompt({
  scanId: "a0d89285-66b7-4e4f-b51a-e21b93b7081b",
  pluginRoot: "/fixture/plugins/codex-security",
  targetPath: "/fixture/repository",
  scope: ".",
  userContext: "preserve literal {{DISCOVERY_CONTEXT_JSON}} text and https://security.example.test/callback",
  workerLabel: "discovery-0001",
  subagents: 3
}, feedbackPath);
assert.deepEqual(firstJsonBlock(withFeedback), discoveryContext);
assert.equal(withFeedback.includes(JSON.stringify(feedbackPath)), true);

const dedup = renderDedupPrompt({
  reducerLabel: "dedup-0001",
  discoveries: [{
    workerId: "worker-001",
    resultPath: "/fixture/worker/result.json"
  }]
});
const dedupContext = firstJsonBlock(dedup);
assert.deepEqual(dedupContext, {
  reducerLabel: "dedup-0001",
  claimedWorkerIds: ["worker-001"]
});
for (const field of [
  "artifactDir",
  "previousCandidateLedgerPath",
  "previousReducerResultPath",
  "discoveries",
  "canonicalOutputs",
  "resultPath",
  "rawCandidatesPath",
  "previousInventoryPath",
  "artifactSchemas"
]) {
  assert.equal(Object.hasOwn(dedupContext, field), false);
}

const previousReduction = firstJsonBlock(renderDedupPrompt({
  reducerLabel: "dedup-0002",
  discoveries: []
}));
assert.deepEqual(previousReduction, {
  reducerLabel: "dedup-0002",
  claimedWorkerIds: []
});

function firstJsonBlock(prompt) {
  const match = prompt.match(/```json\n([\s\S]*?)\n```/);
  assert.ok(match, "prompt should contain a JSON context block");
  return JSON.parse(match[1]);
}

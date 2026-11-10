import { join } from "node:path";
import { readFile } from "node:fs/promises";
import assert from "node:assert/strict";
import { importSource } from "./import-module.ts";

const { renderDiscoveryPrompt } = await importSource(
  join(import.meta.dirname, "../src/deep-scan/templates.ts"),
  { loader: { ".md": "text" } },
);

const template = await readFile(
  new URL("../templates/deep-scan/discovery.md", import.meta.url),
  "utf8",
);
for (const key of template.match(/\{\{[A-Z0-9_]+\}\}/g) ?? [])
  assert.equal(key, "{{DISCOVERY_CONTEXT_JSON}}");

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
assert.match(rendered, /reviewState\.deferred/);
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

function firstJsonBlock(prompt: string) {
  const match = prompt.match(/```json\n([\s\S]*?)\n```/);
  assert.ok(match, "prompt should contain a JSON context block");
  return JSON.parse(match[1]);
}

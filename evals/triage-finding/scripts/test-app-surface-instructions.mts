import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";

const pluginRoot = path.resolve(
  import.meta.dirname,
  "../../../plugins/codex-security",
);
function readPluginFile(relativePath: string) {
  return fs.readFileSync(path.join(pluginRoot, relativePath), "utf8");
}
const skillRoot = "skills/triage-finding";
const skill = readPluginFile(`${skillRoot}/SKILL.md`);
const ticketIntake = readPluginFile(`${skillRoot}/references/ticket-intake.md`);
const agent = readPluginFile(`${skillRoot}/agents/openai.yaml`);
const plugin = JSON.parse(readPluginFile(".codex-plugin/plugin.json"));

assert.match(skill, /references\/ticket-intake\.md/);
assert.match(
  ticketIntake,
  /\bsearchJiraIssuesUsingJql`?\s+for\s+collections\b|\bfor\s+collections,\s+use\s+`?searchJiraIssuesUsingJql\b/i,
);
assert.match(ticketIntake, /natural-language search[\s\S]*discover[\s\S]*JQL/);
assert.match(ticketIntake, /exhaust[\s\S]*pag(?:es|ination)/i);
assert.match(ticketIntake, /workitem search .*--fields "\$fields" --paginate/);
assert.match(ticketIntake, /workitem view .*--fields "\$fields"/);
assert.match(ticketIntake, /missing connector|connector.*unavailable/i);
assert.match(ticketIntake, /authentication|reauthorize/i);
assert.match(ticketIntake, /insufficient permission|request access/i);
assert.match(ticketIntake, /not found|inaccessible/i);
assert.match(ticketIntake, /transient/i);
const provenance =
  ticketIntake
    .split(/\n\s*\n/u)
    .find((paragraph) => paragraph.includes("normalized_input.references")) ??
  "";
for (const field of [
  "issue key",
  "URL",
  "project",
  "status",
  "labels",
  "components",
  "priority",
]) {
  assert.ok(provenance.includes(field), field);
}
const sentences = ticketIntake
  .split(/[.!?]|\n\s*\n|^#{1,6}[ \t]+.*$/m)
  .map((sentence) => sentence.trim().replace(/\s+/g, " "));
assert.ok(
  sentences.some((sentence) =>
    sentence.startsWith("Default to read-only import and triage"),
  ),
);
assert.ok(
  sentences.some(
    (sentence) =>
      sentence.startsWith(
        "Do not add comments, transition or close issues, assign owners, or change labels",
      ) &&
      /\b(?:without|unless)\b.*\bexplicit(?:ly)?\b.*\brequest(?:ed|s)?\b/i.test(
        sentence,
      ),
  ),
);
assert.match(agent, /default_prompt:.*Use \$triage-finding/);
assert.ok(plugin.interface.defaultPrompt.length <= 3);
assert(
  plugin.interface.defaultPrompt.every(
    (prompt: string) => [...prompt].length <= 128,
  ),
);
assert(
  plugin.interface.defaultPrompt.some(
    (prompt: string) =>
      /\btriage\b/i.test(prompt) && /\bfindings?\b/i.test(prompt),
  ),
);

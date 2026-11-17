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
const paragraphs = ticketIntake.split(/\n\s*\n/u);
const paragraphWords = paragraphs.map(
  (paragraph) => new Set(paragraph.match(/\w+/g)),
);
for (const [tool, ...fields] of [
  ["searchJiraIssuesUsingJql", "nextPageToken", "isLast"],
  ["listJiraIssueComments", "startAt", "isLast"],
  ["list_issues", "parentId"],
]) {
  assert.ok(
    paragraphWords.some(
      (words) => words.has(tool) && fields.every((field) => words.has(field)),
    ),
    `Expected the ${tool} instructions to include ${fields.join(", ")}`,
  );
}
assert.match(ticketIntake, /natural-language search[\s\S]*discover[\s\S]*JQL/);
const searchArgs =
  ticketIntake.match(/`acli jira workitem search ([^`]+)`/u)?.[1] ?? "";
const viewArgs =
  ticketIntake.match(/`acli jira workitem view ([^`]+)`/u)?.[1] ?? "";
assert.match(searchArgs, /(?:^|\s)--jql\s+"\$jql"(?=\s|$)/u);
assert.match(searchArgs, /(?:^|\s)--paginate(?=\s|$)/u);
assert.match(viewArgs, /(?:^|\s)"\$key"(?=\s|$)/u);
for (const args of [searchArgs, viewArgs]) {
  assert.match(args, /(?:^|\s)--fields\s+"\$fields"(?=\s|$)/u);
  assert.match(args, /(?:^|\s)--json(?=\s|$)/u);
}
assert.match(ticketIntake, /missing connector|connector.*unavailable/i);
assert.match(ticketIntake, /authentication|reauthorize/i);
assert.match(ticketIntake, /insufficient permission|request access/i);
assert.match(ticketIntake, /not found|inaccessible/i);
assert.match(ticketIntake, /transient/i);
const provenance =
  paragraphs.find((paragraph) =>
    paragraph.includes("normalized_input.references"),
  ) ?? "";
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

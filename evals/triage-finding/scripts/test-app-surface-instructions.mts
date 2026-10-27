import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";

const pluginRoot = path.resolve(
  import.meta.dirname,
  "..",
  "..",
  "..",
  "plugins",
  "codex-security",
);
const skillRoot = path.join(pluginRoot, "skills", "triage-finding");
const skillPath = path.join(skillRoot, "SKILL.md");
const skill = fs.readFileSync(skillPath, "utf8");
const ticketIntakePath = path.join(skillRoot, "references", "ticket-intake.md");
const ticketIntake = fs.readFileSync(ticketIntakePath, "utf8");
const agentPath = path.join(skillRoot, "agents", "openai.yaml");
const agent = fs.readFileSync(agentPath, "utf8");
const pluginPath = path.join(pluginRoot, ".codex-plugin", "plugin.json");
const plugin = JSON.parse(fs.readFileSync(pluginPath, "utf8"));

assert.match(skill, /references\/ticket-intake\.md/);
assert.match(
  ticketIntake,
  /\bsearchJiraIssuesUsingJql`?\s+for\s+collections\b|\bfor\s+collections,\s+use\s+`?searchJiraIssuesUsingJql\b/i,
);
assert.match(ticketIntake, /natural-language search[\s\S]*discover[\s\S]*JQL/);
assert.match(ticketIntake, /exhaust[\s\S]*pag(?:es|ination)/i);
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
  plugin.interface.defaultPrompt.some((prompt: string) =>
    /\btriage\b/i.test(prompt),
  ),
);

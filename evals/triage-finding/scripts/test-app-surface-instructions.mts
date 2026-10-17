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

assert.match(skill, /### Jira and Linear intake/);
assert.match(skill, /references\/ticket-intake\.md/);
assert.match(ticketIntake, /Atlassian[\s\S]*JQL/);
assert.match(ticketIntake, /natural-language search[\s\S]*discover[\s\S]*JQL/);
assert.match(skill, /security or vulnerability Jira\/Linear tickets/);
assert.match(skill, /Atlassian and Linear mentions are connector hints/);
assert.match(skill, /generic ticket or duplicate triage/);
assert.match(
  ticketIntake,
  /Normalize Jira and Linear vulnerability tickets as `source_type: "scanner_ticket"`/,
);
assert.match(
  ticketIntake,
  /issue key[\s\S]*URL[\s\S]*project[\s\S]*status[\s\S]*labels[\s\S]*components[\s\S]*priority/,
);
assert.match(
  ticketIntake,
  /Default to read-only import and triage[\s\S]*Do not add comments, transition or close issues, assign owners, or change labels/,
);
assert.match(agent, /default_prompt:.*Use \$triage-finding/);
assert.match(ticketIntake, /missing connector|connector.*unavailable/i);
assert.match(ticketIntake, /authentication|reauthorize/i);
assert.match(ticketIntake, /insufficient permission|request access/i);
assert.match(ticketIntake, /not found|inaccessible/i);
assert.match(ticketIntake, /transient/i);
assert.match(ticketIntake, /retry the identical read once/i);
assert.match(ticketIntake, /do not inspect the repository/i);
assert.match(ticketIntake, /do not[\s\S]*emit[\s\S]*triage-finding\/v0/i);
assert.match(ticketIntake, /list[\s\S]*direct children[\s\S]*parent/i);
assert.match(ticketIntake, /exhaust[\s\S]*pag(?:es|ination)/i);
assert.match(ticketIntake, /identifiers?[\s\S]*titles?[\s\S]*count/i);
assert.match(ticketIntake, /ask[\s\S]*before[\s\S]*full[\s\S]*content/i);
assert.match(ticketIntake, /repeat[\s\S]*next depth/i);
assert.match(ticketIntake, /independent vulnerability claim/i);
assert.match(ticketIntake, /ambiguous[\s\S]*ask/i);
assert.match(ticketIntake, /deterministic[\s\S]*tree order/i);
assert.equal(plugin.interface.defaultPrompt.length, 3);
assert(
  plugin.interface.defaultPrompt.every(
    (prompt: string) => [...prompt].length <= 128,
  ),
);
assert(
  plugin.interface.defaultPrompt.includes(
    "Triage existing security findings against this repository.",
  ),
);

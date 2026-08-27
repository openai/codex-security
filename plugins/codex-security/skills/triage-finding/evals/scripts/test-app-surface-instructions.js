const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const skillPath = path.join(__dirname, "..", "..", "SKILL.md");
const skill = fs.readFileSync(skillPath, "utf8");
const ticketIntakePath = path.join(__dirname, "..", "..", "references", "ticket-intake.md");
const ticketIntake = fs.readFileSync(ticketIntakePath, "utf8");
const agentPath = path.join(__dirname, "..", "..", "agents", "openai.yaml");
const agent = fs.readFileSync(agentPath, "utf8");
const pluginPath = path.join(__dirname, "..", "..", "..", "..", ".codex-plugin", "plugin.json");
const plugin = JSON.parse(fs.readFileSync(pluginPath, "utf8"));

assert.match(skill, /## Jira and Linear Intake/);
assert.match(skill, /references\/ticket-intake\.md/);
assert.match(ticketIntake, /Atlassian Rovo[\s\S]*JQL/);
assert.match(ticketIntake, /natural-language search[\s\S]*discover[\s\S]*JQL/);
assert.match(skill, /security or vulnerability Jira\/Linear tickets/);
assert.match(skill, /Atlassian Rovo and Linear mentions\s+as connector hints/);
assert.match(skill, /not as a reason to switch to\s+Atlassian Rovo's `triage-issue` skill/);
assert.match(skill, /Do not run duplicate-bug triage instead of security-impact triage/);
assert.match(ticketIntake, /Normalize Jira and Linear vulnerability tickets as `source_type: "scanner_ticket"`/);
assert.match(ticketIntake, /issue key[\s\S]*URL[\s\S]*project[\s\S]*status[\s\S]*labels[\s\S]*components[\s\S]*priority/);
assert.match(
  ticketIntake,
  /Default to read-only import and triage[\s\S]*Do not add comments, transition issues,\s+close issues, assign owners, or change labels/,
);
assert.match(agent, /Import security or vulnerability tickets from Jira\/Linear, scanners, advisories, or GitHub/);
assert.match(agent, /security or vulnerability tickets/);
assert.match(agent, /import Jira issues matching <JQL or project\/search>/);
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
assert.match(ticketIntake, /250[\s\S]*do not truncate/i);
assert.equal(plugin.interface.defaultPrompt.length, 3);
assert(
  plugin.interface.defaultPrompt.every((prompt) => [...prompt].length <= 128),
);
assert(plugin.interface.defaultPrompt.includes("Triage existing security findings against this repository."));

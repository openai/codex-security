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

const githubIntake = require("../assertions/github-rest-intake.js");
const connectorContext = {
  vars: {
    expected_github_rest_behavior: "explicit_connector",
    target_repo: "https://github.com/promptfoo/promptfoo",
  },
};
const connectorDecision = {
  schema_version: "github-transport-decision/v0",
  transport: "github_connector",
  access: "read_only",
  unavailable_endpoint: "explain_limitation",
  rest_fallback: "only_if_endpoint_unavailable",
  rest_approval: "before_use",
  rest_account: "specified_account",
  rest_repository: "promptfoo/promptfoo",
};
for (const answer of [
  JSON.stringify(connectorDecision),
  `Decision for /repos/{owner}/{repo}/code-scanning/alerts:\n\`\`\`json\n${JSON.stringify(connectorDecision, null, 2)}\n\`\`\``,
]) {
  const result = githubIntake(answer, connectorContext);
  assert.equal(result.pass, true, result.reason);
}
for (const wrongDecision of [
  { transport: "rest" },
  { access: "read_write" },
  { unavailable_endpoint: "ignore" },
  { rest_fallback: "always_after_approval" },
  { rest_fallback: undefined },
  { rest_approval: "not_required" },
  { rest_approval: "after_use" },
  { rest_account: "any_available_account" },
  { rest_repository: "example/other-repo" },
]) {
  const answer = JSON.stringify({ ...connectorDecision, ...wrongDecision });
  assert.equal(githubIntake(answer, connectorContext).pass, false, answer);
}
assert.equal(githubIntake("{invalid JSON}", connectorContext).pass, false);
for (const fenced of [[true, true], [true, false], [false, true]]) {
  const conflictingDecisions = [connectorDecision, { ...connectorDecision, transport: "rest" }]
    .map((decision, index) => fenced[index]
      ? `\`\`\`json\n${JSON.stringify(decision)}\n\`\`\``
      : JSON.stringify(decision))
    .join("\n");
  assert.equal(githubIntake(`Endpoint: /repos/{owner}/{repo}/code-scanning/alerts\n${conflictingDecisions}`, connectorContext).pass, false);
}

const intakeCases = fs.readFileSync(path.join(__dirname, "../tests/github-rest-intake.yaml"), "utf8");
const connectorCase = intakeCases.match(/case_id: github-explicit-connector[\s\S]*?(?=\n- description:|$)/)[0];
assert.match(connectorCase, /finding_input:.*code scanning/i);

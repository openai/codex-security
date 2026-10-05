#!/usr/bin/env node
"use strict";

const assert = require("node:assert/strict");
const { hasTriageJson } = require("../assertions/output");
const github = require("../assertions/github-rest-intake");
const missingInput = require("../assertions/missing-input");
const ticket = require("../assertions/ticket-intake");

function expectPass(grader, text, context, pass = true) {
  const result = grader(text, context);
  assert.equal(result.pass, pass, `${text}\n${result.reason}`);
}

const request = "Please provide a SARIF, CVE, advisory, or scanner ticket.";
const triage = JSON.stringify({ schema_version: "triage-finding/v0", findings: [] });
for (const text of [
  "```sh\ncat finding.sarif\n```",
  '```json\n{"findings": "paste the findings here"}\n```',
  '```json\n{"schema_version": "example/v0", "findings": []}\n```',
  '{"findings":[{"message":"Paste the scanner finding here"}]}',
  '{"input_id":"example","message":"Paste the scanner finding here"}',
  JSON.stringify({ example: '"schema_version": "triage-finding/v0"' }),
  JSON.stringify({ example: '"verdict": "confirmed"' }),
  '{"verdict":"unknown"}',
  'The result later uses schema_version: "triage-finding/v0".',
]) {
  assert.equal(hasTriageJson(text), false, text);
  expectPass(missingInput, `${request}\n${text}`);
}
for (const text of [
  triage,
  `\`\`\`json\n${triage}\n\`\`\``,
  `\`\`\`sh\ncat finding.sarif\n\`\`\`\n${triage}`,
  `Response: {"error":"forbidden"}\n${triage}`,
  `\`\`\`json\n{"error":"access denied"}\n\`\`\`\n${triage}`,
  `GET /repos/{owner}/{repo}/code-scanning/alerts\n${triage}`,
  `\`\`\`json\n${triage.replace("triage-finding/v0", "triage-finding\\/v0")}\n\`\`\``,
  `Response: {"error":"forbidden"}\n${triage.replace("triage-finding/v0", "triage-finding\\u002fv0")}`,
  '{"findings":[{"input_id":"SEC-293","verdict":"not_actionable"}]}',
  '{"input_id":"SEC-293","verdict":"not_actionable"}',
  '{"triage_item_id":"triage-001","verdict":"needs_review"}',
  '{"verdict":"confirmed"}',
  '{"verdict":"needs_review"}',
  '{"verdict":"not_actionable"}',
  "```json\n{'verdict': 'confirmed'}\n```",
  "{'schema_version': 'triage-finding/v0', 'findings': []}",
  '{"ver\\u0064ict":"needs\\u005freview"}',
]) {
  assert.equal(hasTriageJson(text), true, text);
  expectPass(missingInput, `${request}\n${text}`, undefined, false);
  expectPass(ticket, `Request access or paste the content. ${text}`, { vars: { expected_ticket_failure: "permission" } }, false);
}

const childContext = { vars: { expected_linear_subissues: "direct_confirmation" } };
for (const count of ["2 direct children", "two direct children", "2 direct sub-issues", "two sub-issues"]) {
  expectPass(ticket, `There are ${count}: SEC-294 and SEC-295. Would you like to include them?`, childContext);
}
expectPass(ticket, "There are 2 direct children: SEC-294 and SEC-295. Importing them now.", childContext, false);
for (const vars of [
  {},
  { expected_ticket_failure: "permisson" },
  { expected_ticket_failur: "permission" },
  { expected_linear_subissues: "direct_confirmaton" },
  { expected_ticket_failure: "constructor" },
]) {
  expectPass(ticket, "arbitrary text", { vars }, false);
}
for (const [behavior, text] of [
  ["unavailable", "Connect or authenticate the unavailable Linear connector, or paste the content."],
  ["permission", "Request access or paste the content."],
  ["not_found", "The identifier was not found. Check it or paste the content."],
  ["transient", "The retry failed after trying once. Paste the content."],
]) {
  expectPass(ticket, text, { vars: { expected_ticket_failure: behavior } });
}

const githubContext = (behavior) => ({
  vars: { expected_github_rest_behavior: behavior, target_repo: "https://github.com/example/project" },
});
for (const repository of ["{owner}/{repo}", "example/project"]) {
  for (const sourceType of ["source_type: advisory", '`source_type: "advisory"`', '"source_type": "advisory"', "normalize as `advisory`", '(source_type: advisory)', '[source_type: advisory]', 'source_type: advisory\n', 'source_type: advisory.', 'source_type: advisory!']) {
    expectPass(github, `GET /repos/${repository}/dependabot/alerts?classification=malware&state=open&per_page=100. ${sourceType}`, githubContext("dependabot_malware"));
    expectPass(github, `GET /repos/${repository}/security-advisories?per_page=100, with separate state=triage, state=draft, state=published, state=closed requests. Triage is for private vulnerability reports. ${sourceType}`, githubContext("advisories_private_reports"));
  }
  for (const alert of ["{alert_number}", "42"]) {
    expectPass(github, `GET /repos/${repository}/code-scanning/alerts?state=open&per_page=100 and code-scanning/alerts/${alert}/instances. source_type: "sarif"`, githubContext("code_scanning"));
  }
}
expectPass(github, 'GitHub Issues require an explicit issue and are not included in all sources. source_type: "freeform"', githubContext("explicit_issue"));
for (const text of [
  'GET /repos/example/other/dependabot/alerts?classification=malware&state=open&per_page=100. source_type: "advisory"',
  'GET /repos/example/project/dependabot/alerts?classification=malware&state=open&per_page=100. source_type: "sarif"',
  'GET /repos/example/project/dependabot/alerts?classification=malware&state=open. source_type: "advisory"',
  'GET /repos/example/project/dependabot/alerts?classification=malware&state=open&per_page=100. {"incorrect_source_type":"advisory"}',
  'GET /repos/example/project/dependabot/alerts?classification=malware&state=open&per_page=100. {"incorrect source_type":"advisory"}',
  'GET /repos/example/project/dependabot/alerts?classification=malware&state=open&per_page=100. {"source_type":"advisory-other"}',
  'GET /repos/example/project/dependabot/alerts?classification=malware&state=open&per_page=100. {"source_type":"advisory/other"}',
  'GET /repos/example/project/dependabot/alerts?classification=malware&state=open&per_page=100. {"source_type":"advisory other"}',
  'GET /repos/example/project/dependabot/alerts?classification=malware&state=open&per_page=100. {"source_type_suffix":"advisory"}',
  'GET /repos/example/project/dependabot/alerts?classification=malware&state=open&per_page=100. source_type: advisory_other',
]) {
  expectPass(github, text, githubContext("dependabot_malware"), false);
}

for (const emphasis of ["**", "*", "__", "_", "***"]) {
  for (const normalization of ["source_type: advisory", "source_type: `advisory`", '"source_type": "advisory"', "normalize as advisory", "normalize as `advisory`", "`source_type: advisory`", "`normalize as advisory`", "Normalize as advisory.", "Normalize as advisory: preserve the identifier", "Normalization: source_type: advisory"]) {
    expectPass(github, `GET /repos/example/project/dependabot/alerts?classification=malware&state=open&per_page=100. ${emphasis}${normalization}${emphasis}.`, githubContext("dependabot_malware"));
  }
  expectPass(github, `GET /repos/example/project/dependabot/alerts?classification=malware&state=open&per_page=100. ${emphasis}source_type: advisory_other${emphasis}`, githubContext("dependabot_malware"), false);
}

const decision = {
  transport: "github_connector_read_only",
  fallback: "explain_and_request_rest_approval",
  scope: { account: "user_specified_or_approved", repository: "example/project" },
};
const connectorJson = JSON.stringify(decision);
for (const text of [connectorJson, `\`\`\`json\n${connectorJson}\n\`\`\``]) {
  expectPass(github, text, githubContext("explicit_connector"));
}
for (const invalid of [
  null, [], {},
  ...["transport", "fallback", "scope"].map((key) => ({ ...decision, [key]: undefined })),
  ...["rest", "other", "unknown"].map((transport) => ({ ...decision, transport })),
  ...["automatic_rest", "stop", "unknown"].map((fallback) => ({ ...decision, fallback })),
  { ...decision, scope: { ...decision.scope, account: "any" } },
  { ...decision, scope: { ...decision.scope, repository: "example/other" } },
  { ...decision, explanation: "additional field" },
  { ...decision, scope: { ...decision.scope, extra: true } },
]) {
  expectPass(github, JSON.stringify(invalid), githubContext("explicit_connector"), false);
}
for (const text of ["not JSON", `\`\`\`json\n${connectorJson}\n\`\`\`\n\`\`\`json\n{}\n\`\`\``]) {
  expectPass(github, text, githubContext("explicit_connector"), false);
}
for (const behavior of ["", "code_scaning", "constructor"]) {
  expectPass(github, "arbitrary text", githubContext(behavior), false);
}

for (const repository of [
  "example/project", "https://github.com/example/project/",
  "https://github.com/example/project.git", "git@github.com:example/project.git",
  "ssh://git@github.com/example/project.git",
]) {
  const context = githubContext("explicit_connector");
  context.vars.target_repo = repository;
  expectPass(github, connectorJson, context);
  context.vars.expected_github_rest_behavior = "dependabot_malware";
  expectPass(github, 'GET /repos/example/project/dependabot/alerts?classification=malware&state=open&per_page=100. {"source_type":"advisory"}', context);
}

console.log("intake assertion tests passed");

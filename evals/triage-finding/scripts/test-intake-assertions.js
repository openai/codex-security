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
  for (const sourceType of ["source_type: advisory", '`source_type: "advisory"`', '"source_type": "advisory"', "normalize as `advisory`"]) {
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
]) {
  expectPass(github, text, githubContext("dependabot_malware"), false);
}

const connectorAnswer = "Use the GitHub Connector read-only to retrieve code scanning alerts. If it cannot retrieve the selected findings, explain the limitation and ask before switching to REST with the specified GitHub account and the exact repository. Never silently switch transports.";
expectPass(github, connectorAnswer, githubContext("explicit_connector"));
for (const restriction of ["modify or close alerts", "modify alerts or post comments"]) {
  expectPass(github, `${connectorAnswer} Do not use the GitHub Connector to ${restriction}.`, githubContext("explicit_connector"));
}
expectPass(github, "Retrieve alerts with the GitHub Connector using read only access. If the endpoint is unavailable, describe the limitation. REST is an option only with prior approval for the selected account and the same repository.", githubContext("explicit_connector"));
for (const text of [
  "Use the GitHub Connector only as an auth token source. Finding retrieval uses REST. Do not use the GitHub Connector to fetch findings.",
  connectorAnswer.replace("read-only", "read-write"),
  connectorAnswer.replace("ask before switching to REST", "switch to REST automatically"),
  connectorAnswer.replace("ask before switching to REST", "do not ask before switching to REST"),
  connectorAnswer.replace("ask before switching to REST", "no need to ask before switching to REST"),
  `${connectorAnswer} Do not use the GitHub Connector to fetch findings.`,
  `${connectorAnswer} Never retrieve alerts with the GitHub Connector.`,
  connectorAnswer.replace("specified GitHub account and the exact repository", "any account and repository"),
]) {
  expectPass(github, text, githubContext("explicit_connector"), false);
}
for (const behavior of ["", "code_scaning", "constructor"]) {
  expectPass(github, "arbitrary text", githubContext(behavior), false);
}

console.log("intake assertion tests passed");

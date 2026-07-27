# Security Policy

## Report a vulnerability in Codex Security

Report vulnerabilities in the Codex Security CLI, SDK, bundled plugin, or
release artifacts privately through
[OpenAI's Bugcrowd program](https://bugcrowd.com/engagements/openai).

Include the affected version, security impact, and the smallest safe
reproduction. Remove API keys, access tokens, private source code, and customer
data from the report unless a private submission requires that material and you
have permission to share it. Use the latest published version when confirming a
finding.

Public GitHub issues are for ordinary bugs, documentation problems, and feature
requests. Keep unpatched vulnerabilities and sensitive scan artifacts out of
public issues and pull requests.

## Report a finding in a scanned repository

A vulnerability found in another repository belongs to that repository's
owner. Follow its security policy or coordinated disclosure process, and share
the finding only with people authorized to receive it. OpenAI's Bugcrowd program
is for vulnerabilities in OpenAI products and services, not for findings in
unrelated projects.

## Run scans safely

- Scan only code you own or have explicit permission to assess.
- Treat repository files, instructions, build scripts, and findings as
  untrusted. Scans and validation may inspect code and run commands inside the
  Codex sandbox.
- Store credentials in an approved secret manager or environment variable.
  Keep your Codex home directory outside the repository being scanned.
- Store results outside the enclosing Git worktree. Findings, reports, logs,
  and SARIF can contain private source code, vulnerability details, and
  reproduction steps.
- Restrict access to scan artifacts, apply a suitable retention period, and
  review them before sharing or uploading them to another service.
- Review proposed patches before applying or merging them.

For more about Codex sandboxing, approvals, and network controls, see
[Agent approvals and security](https://developers.openai.com/codex/agent-approvals-security).

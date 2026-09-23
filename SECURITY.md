# Security policy

Report vulnerabilities privately through
[OpenAI's Bugcrowd program](https://bugcrowd.com/engagements/openai).
The **Codex** section defines the scope, supported configurations, and reward
eligibility. That policy takes precedence over this summary. Keep vulnerability
details out of public issues and pull requests.

## What qualifies

A report must show a software flaw that lets a less-privileged attacker bypass
an enforced security restriction in a current, supported release and
configuration. Examples include bypassing a filesystem or network restriction,
a required approval, or an administrator-enforced control.

Prompt injection or a model misusing access it already has does not qualify
by itself, even if it leaks data or performs an unwanted action. A report must
identify a separate flaw in an enforced security control. Model-behavior
reports may qualify under the separate
[Safety Bug Bounty](https://bugcrowd.com/engagements/openai-safety).

Missed findings, false positives, incorrect scan results, and performance issues
are ordinary bugs unless they also demonstrate such a flaw. Report ordinary
bugs through GitHub issues.

## Scan permissions

Codex Security runs under your local account. Scan only repositories you trust
and have permission to assess.

Deep-scan workers use read-only execution to prevent concurrent workspace
writes. This does not make the worker an isolated, offline environment or
disable inherited MCP servers. Workers must stay within the parent session's
permissions. Use of an inherited tool's existing access is not, by itself, a
security-boundary bypass; enforced restrictions that apply to that tool or
operation still matter.

## What to report

Include the product version, operating system, active configuration, attacker's
starting permissions, control that fails, and steps that reproduce the security
impact. Remove credentials and unrelated private data from examples and logs.

For vulnerabilities found in a repository you scan, follow that project's
security policy.

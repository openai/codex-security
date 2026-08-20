# Security policy

Codex Security is a local tool for reviewing repositories you trust and have
permission to assess. This policy explains which security issues are in scope
and how to report them.

## Report a vulnerability in Codex Security

Report vulnerabilities in the CLI, SDK, bundled plugin, scan runtime, or
published release artifacts privately through
[OpenAI's Bugcrowd program](https://bugcrowd.com/engagements/openai).

Do not post unpatched vulnerabilities, exploits, credentials, sensitive scan
results, or proofs of concept in GitHub issues or pull requests. Use public
issues for ordinary bugs, documentation, and feature requests.

OpenAI's
[coordinated vulnerability disclosure policy](https://openai.com/policies/coordinated-vulnerability-disclosure-policy/)
explains the reporting process, confidentiality, and program eligibility.

## Scope and supported versions

This policy applies to:

- The published `@openai/codex-security` package and `codex-security` CLI.
- The TypeScript SDK, including target selection, authentication,
  configuration, execution, and result validation.
- The Codex Security plugin, interpreter, and Codex runtime bundled with an
  official release.
- Scan output, including manifests, findings, coverage, reports, SARIF, and
  scan history.
- Official package, build, and release integrity.

Check that the issue affects the latest published package or the current default
branch. Include the package version and, when relevant, the commit, plugin
version, and operating system. If you found the issue in an older version,
explain whether a supported release is also affected.

## Threat model

Codex Security runs under your local operating-system account. Scan only
repositories you trust and either own or have explicit permission to assess.
Permission to assess a repository does not mean you can trust it.

The repository you select, your Git installation, and the tools and
configuration you choose run with your existing local permissions. Normal Git
operations can use repository configuration, hooks, filters, attributes,
credential helpers, worktrees, and executables on your `PATH`. These are not
separate security boundaries.

### Local trust and attacker prerequisites

The product does not isolate users, tasks, repositories, or scan jobs that
share the same operating-system account, credentials, or local state. Do not
treat shared local state as a multi-user or multi-tenant system.

Private Codex state, workbench databases, output directories, and resume
receipts are not separate security boundaries from your operating-system
account. A report that depends on changing them must show how an
attacker-controlled input reaches them through a supported workflow and
crosses a security boundary.

Trusting a repository does not authorize unrelated actions. Repository
contents, filenames, symlinks, model output, patches, service responses, and
imported artifacts are data. They do not authorize another target, a broader
scope, a different credential, an unrelated read or write, an unapproved
patch or network destination, a bypassed restriction, or a passing result for
incomplete coverage.

### How scans run

Each scan uses the product's `codex_security_scan` filesystem profile and
automatic approval review. Its baseline profile allows reads of the local
filesystem and writes to workspace roots and the selected scan state directory.
Requests are reviewed automatically without an interactive prompt; approved
requests can grant additional permissions for a specific operation. Set
`approval_policy="never"` to deny all requests instead.

Setting `approval_policy`, `approvals_reviewer`, `sandbox_mode`, or permissions
through `--codex` or SDK `codexOverrides` cannot replace the automatic reviewer
or baseline filesystem profile. A strict `approval_policy="never"` override,
including one in the selected profile, is preserved. Saved scans retain their
effective approval policy, and older scans remain deny-all when rerun.
Separately enforced host and network restrictions still apply.

Scan and workbench subprocesses can inherit your environment. The workbench
removes `OPENAI_API_KEY` and `CODEX_API_KEY`, but it does not remove every
credential. Other variables, such as `GITHUB_TOKEN` or `AWS_SECRET_ACCESS_KEY`,
can remain available to local subprocesses. Run a scan with only the
environment credentials it needs.

### Security boundaries

A security issue must cross a boundary the product actually provides:

- Scan only the selected target and requested scope; write only to authorized
  output paths.
- Honor explicitly selected credentials and documented cost controls.
- Keep credentials, private source, and scan results out of model requests,
  logs, reports, and network destinations the operator did not authorize.
- Apply the scan's actual filesystem and execution profile and respect host or
  network restrictions enforced independently of the scan.
- Do not follow a symlink or replaced file into an unauthorized read or write.
- Mark a scan complete only when its results match the reviewed scope,
  documented mode, and stated exclusions.
- Protect official packages, bundled runtimes, dependencies, build artifacts,
  and release credentials from unauthorized changes.

## In-scope reports

Report reproducible issues in an official release, such as:

- Credentials, private source, or scan results sent to another security
  principal, model request, or network destination without authorization.
- Model or remote input that bypasses the scan's effective permissions or an
  independently enforced host, execution, filesystem, or network restriction.
- A scan, patch, file write, or network request outside the action you
  authorized.
- Ignoring the target, path scope, credential, or documented cost limit you
  explicitly selected.
- Path traversal, a symlink, an archive, or a file-replacement race that writes
  outside the approved output or sends an unrelated local file to a model.
- An incomplete, forged, or incorrectly scoped scan accepted as complete or as
  a passing CI result.
- GitHub, package, update, dependency, or model-service input that causes an
  unauthorized local action or compromises a release.
- A reachable vulnerability in the published package, bundled runtime, build,
  or release process.
- Resource exhaustion that reaches a supported service, CI process, or other
  actual availability boundary.

## Usually out of scope

The following are not security vulnerabilities by themselves:

- Reading selected repository files, resolving worktrees, running Git, or
  using configured hooks, filters, credential helpers, and executables within
  the authority you granted.
- An attack that assumes prior control of your operating-system account,
  trusted local Git settings, private Codex state, or private scan outputs
  without showing how a supported input gains that control.
- A claim that depends on you deliberately granting a plugin, interpreter, or
  executable the authority your account already has.
- Access, cancellation, or changes to private scan state, workbench databases,
  results, resume receipts, or scan history by a process that already shares
  your account and local state.
- Prompt injection, unexpected model output, missed findings, false positives,
  or unsigned review receipts that do not cross a boundary or cause a supported
  security gate to accept incomplete or misrepresented coverage.
- A documented exclusion, ignore rule, estimate, or Git behavior accurately
  reflected in the scan and its results.
- Disclosed estimation uncertainty or unavoidable in-flight cost overruns
  when an explicitly requested limit is still enforced as documented.
- Terminal formatting or control characters without a demonstrated security
  impact in a supported terminal.
- A hypothetical compromise of a trusted release runner, registry, or
  dependency supplier without a path from untrusted input to a protected
  release or a bypass of its integrity controls.
- A dependency advisory, theoretical attack, or old package version without a
  reproducible impact on a supported release.
- Slow processing of a file, document, or repository you deliberately selected.
- Vulnerabilities in a third-party repository being scanned.
- Documentation, tests, fixtures, or development code that a published runtime
  or release process cannot reach.

Hosted services, multi-user installations, pull-request CI, and imported
third-party artifacts can have different trust boundaries. For those cases,
identify the deployment, attacker-controlled input, affected component, and
actual boundary. Storing multiple local scans does not make the CLI a
multi-tenant system.

If you are not sure whether a finding is in scope, report it privately.

## What to include in a report

Include:

- The affected component, package version, plugin version, and commit.
- Your platform, authentication method, scan mode, and target type.
- The attacker's starting permissions and the security boundary crossed.
- Minimal steps to reproduce the issue in a supported release or the default
  branch.
- The expected and actual behavior, impact, and any known mitigation.
- Sanitized logs or scan artifacts if they are needed to reproduce the issue.

Remove API keys, access tokens, customer data, and private source unless the
private report requires them and you are authorized to share them. Never
include a live credential in a proof of concept.

## Report a finding in a scanned repository

If a scan finds a vulnerability in someone else's repository, follow that
project's security policy and share the finding only with authorized people.
OpenAI's Bugcrowd program covers OpenAI products and services, not
vulnerabilities in other projects.

## Run scans safely

- Scan only repositories you trust and either own or have explicit permission
  to assess.
- Review repository instructions and inspect a patch before you apply or merge
  it.
- Pass only the credentials the scan needs. Local subprocesses can inherit
  other environment variables.
- Keep your credentials and Codex home outside the repository.
- Store scan state, findings, reports, logs, and SARIF outside the enclosing
  Git worktree.
- Limit access to results, set a retention period, and review them before you
  share or upload them.
- Keep the package, runtime, and dependencies up to date.

For details on Codex sandboxing, approvals, and network controls, see
[Agent approvals and security](https://developers.openai.com/codex/agent-approvals-security/).
For information about vulnerability identifiers and disclosure timelines, see
[OpenAI's CVE assignment policy](https://openai.com/policies/openai-cve-assignment-policy/).

# GitHub Draft Security Advisories

Read this reference only for the `github-advisory` destination.

## Contract

- Create one maintainer-owned private draft for one validated finding. Do not batch advisories.
- Use authenticated `gh api --hostname github.com` on every API request, and pin the selected identity and repository for the run. Never rely on ambient `GH_HOST` or inferred repository context.
- Require a sealed `git_revision` target, its verified public canonical non-fork source repository, a default branch, and `ADMIN` viewer permission. Verify the exact revision and every selected finding path. Do not use an external tracker.

Run repository metadata checks as `GH_HOST=github.com gh repo view github.com/{owner}/{repo}`. Keep `owner` and `repo` as separately validated path segments, and use their exact values in every API endpoint.

Use these headers on every request:

```text
Accept: application/vnd.github+json
X-GitHub-Api-Version: 2026-03-10
```

Use only:

- `GET /repos/{owner}/{repo}/security-advisories?state={triage|draft|published|closed}`
- `POST /repos/{owner}/{repo}/security-advisories`
- `GET /repos/{owner}/{repo}/security-advisories/{ghsa_id}`

Do not use `PATCH`, `/cve`, `/forks`, `/reports`, collaborator or credit workflows, temporary forks, publish or close transitions, or updates to existing advisories.

## Payload

The create payload requires `summary`, `description`, and `vulnerabilities`. Each vulnerability needs a verified ecosystem, canonical package name, and evidence-backed vulnerable version range. Do not infer affected releases from a scanned commit. Include `patched_versions` only when that release exists.

Provide exactly one of a validated `cvss_vector_string` or GitHub `severity`. Do not derive a vector from a score or prose, and do not map informational severity. Include only high-confidence CWE root-cause mappings. Leave `cve_id`, `credits`, and `start_private_fork` unset.

Treat the description as eventually public. Include impact, affected versions, prerequisites, safe technical and validation detail, remediation or workarounds, verified source context, role-aware locations, and labeled finding-id and fingerprint bindings. Warn that the bindings become public if the advisory is published. Exclude credentials, signed URLs, internal-only evidence, and unnecessary exploit payloads.

`git_worktree`, `directory_snapshot`, and `git_diff` targets cannot satisfy this advisory source contract. Block instead of using plain locations, substituting a base or head revision, or claiming those revisions represent the scanned bytes.

## Duplicates

The API has no idempotency key or full-text advisory search. Paginate `triage`, `draft`, `published`, and `closed` without printing unrelated advisory bodies. Match exact finding-id and fingerprint bindings first, then narrowly review same-package candidates.

Pass `--hostname github.com` on every duplicate request. A request that inherits its host from the environment is not a valid duplicate check.

Reuse one exact `draft` or `published` match. Block on a `triage` or `closed` match, multiple matches, or semantic ambiguity. Never update an existing advisory.

## Create And Verify

Preview the complete structured payload, CLI identity, repository, source context, package metadata, severity or CVSS choice, duplicate outcome, and warnings. Get explicit approval.

Immediately before creating, rerun source validation and recheck auth, repository identity and permission, source context, package metadata, and duplicates. If anything changes, preview again.

Write the approved JSON to a mode-`0600` temporary file outside the repository and scan directory, inspect it for secrets, and send it once with `gh api --hostname github.com --input`. Never blindly retry an uncertain create; search exact bindings and stop.

Read the returned `ghsa_id` through the allowed `GET` endpoint with `gh api --hostname github.com`. Compare normalized structured readback with the approved payload and require `state: draft` before reporting success.

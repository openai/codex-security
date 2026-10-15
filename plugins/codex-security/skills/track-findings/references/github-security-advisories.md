# GitHub draft security advisories

Use this reference for `github-advisory`.

## Access and source

Create one maintainer-owned private draft for one validated finding. Use the selected GitHub CLI identity and `github.com` repository throughout the run.

Require a sealed `git_revision`, its verified public canonical non-fork source repository, a default branch, and `ADMIN` viewer permission. Other target types cannot satisfy this contract. Verify the exact revision and every finding path through the main skill's source checks.

Run metadata checks as `gh repo view https://github.com/{owner}/{repo}`. Validate `owner` and `repo` as separate path segments. Use authenticated `gh api --hostname github.com` with these headers on every request:

```text
Accept: application/vnd.github+json
X-GitHub-Api-Version: 2026-03-10
```

Use only:

- `GET /repos/{owner}/{repo}/security-advisories?state={triage|draft|published|closed}`
- `POST /repos/{owner}/{repo}/security-advisories`
- `GET /repos/{owner}/{repo}/security-advisories/{ghsa_id}`

Do not update, publish, or close advisories, request CVEs, create forks, or manage collaborators or credits.

## Payload

Require `summary`, `description`, and `vulnerabilities`. Each vulnerability needs a verified ecosystem, canonical package name, and evidence-backed vulnerable version range. A scanned commit does not establish affected releases. Include `patched_versions` only when the release exists.

Provide exactly one of a validated `cvss_vector_string` or GitHub `severity`. Do not derive a vector from a score or prose or map informational severity. Include only high-confidence root-cause CWEs. Leave `cve_id`, `credits`, and `start_private_fork` unset.

The description is eventually public. Include impact, affected versions, prerequisites, safe technical and validation evidence, remediation or workarounds, and the main skill's verified source details and bindings. Warn that the bindings become public if published. Exclude credentials, signed URLs, internal-only evidence, and unnecessary exploit payloads.

## Duplicates

The API has no idempotency key or full-text advisory search. Paginate all four states without printing unrelated bodies. Match exact finding-id and fingerprint bindings first, then review same-package candidates.

Reuse one exact `draft` or `published` match. A `triage` or `closed` match, multiple matches, or semantic ambiguity blocks the run. Existing advisories are not updated.

## Create and verify

Use the main skill's preview and approval flow, including package metadata, the severity or CVSS choice, and disclosure warnings. Before creating, revalidate source, active identity, repository access, and duplicates. Refresh package or source metadata if evidence changed; preview changes before writing.

Write the approved JSON to a mode-`0600` temporary file outside the repository and scan directory. Review it for sensitive content and send it once with `gh api --hostname github.com --input`; remove it on every exit. Reconcile uncertain creates by exact bindings before considering another mutation.

Read the returned `ghsa_id` through the allowed endpoint. Compare normalized structured readback with the approved payload and require `state: draft` before reporting success.

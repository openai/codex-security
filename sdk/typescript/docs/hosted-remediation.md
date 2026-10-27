# Hosted patching and fix verification

`runHostedRemediation(input, { executor, signal, onEvent })` runs one patch or
verification using the same skills, prompts, and result schemas as the local
CLI. It requires a host executor and never starts local inference. This API is
separate from the Standard scan API and does not create scan/workbench state.

The host prepares an isolated checkout, freezes its HEAD, supplies the original
finding evidence and repository instructions, and enforces the requested
sandbox. For verification, the host must first apply the exact candidate patch
to its recorded base. The API does not apply a patch or infer a branch from the
finding. It checks HEAD before and after execution; the host owns checking the
candidate's bytes/digest and verifying that verification did not change them.

```ts
const result = await runHostedRemediation(
  {
    version: 1,
    operation: "verify", // or "patch"
    repository: "/workspace/repository",
    revision: "0123456789012345678901234567890123456789",
    finding: {
      id: "finding-1",
      context:
        "Original vulnerability, source evidence, reproducer, and controls.",
    },
    instructions: "Preserve existing repository conventions.",
    validationInstructions:
      "Run the focused reproduction and legitimate control.",
    model: "your-model",
    reasoningEffort: "high",
    identity: {
      runId: "run-1",
      attemptId: "attempt-1",
      buildId: "runtime-build",
    },
  },
  { executor },
);
```

Both instruction fields are optional and are distinct from finding data.
Reasoning effort is passed through unchanged so the selected model and provider
determine which values they support.
Verification remains read-only even when validation instructions request setup:
a required check that cannot run without repository changes is a proof gap,
not permission to edit. Generation's ordinary skill checks and standalone
verification are separate operations.

Set `verificationMode: "static"` to review attack paths, bypasses, and legitimate
behavior from source and diffs, without installing dependencies or executing
builds, tests, reproducers, or the application. Select it for both `patch` and
`verify` requests when both stages should be static. Omitted or `"standard"`
retains the existing behavior.

Static mode treats validation instructions as source-review questions. Missing
runtime tooling alone is not a blocker; material proof gaps still produce
`blocked` or `inconclusive`. Results must cite source evidence and state that
runtime checks were not performed. Hosts should retain and display the selected
mode with each attempt. This is an assessment policy; sandbox permissions remain
unchanged and do not enforce the static scope.

The executor receives one request with a unique `requestId`, operation,
repository/revision, identity, finding ID, prompt, model, reasoning effort,
`sandbox` (`workspace-write` for patch, `read-only` for verify), and
`runtime: { pluginRoot, pluginVersion }`. Its receipt contains the same
`requestId`, `status` (`completed`, `failed`, `canceled`, or
`acceptance_unknown`), `sessionId` (required for completed execution), and
optional `finalResponse`, opaque `usage`, `message`, and `error`.

The returned result retains that receipt, runtime provenance and request
identity even when parsing fails. `status: "completed"` means execution and
result validation finished; it does not imply that a patch fixed the finding:

- `patch` contains `occurrenceId`, `status` (`verified`, `no_change`, `blocked`,
  or `failed`), `files`, and optional `verification`/`reason`. Verified and
  no-change outcomes require verification evidence; blocked and failed outcomes
  require a reason. The host must inspect the actual changes, collect the
  canonical diff, and run separate verification.
- `verification` contains `id`, `status` (`fixed`, `still_vulnerable`, or
  `inconclusive`), and nonempty `evidence`, the same fields used by local
  `verify-fix`. The finding ID must match the request. A `fixed` verdict needs
  evidence that the original exploit path is closed and legitimate behavior
  still works. If the selected mode cannot establish that, use `inconclusive`
  unless the evidence shows the finding is still vulnerable.

Hosted and local verification use the same verdict parser and do not require
`checks`. At the hosted boundary, a `fixed` verdict is rejected if a nonempty
`checks` array matches the SDK 0.6.0 check format and reports a `failed` or
`not_run` required check. Other extra fields are ignored.

When upgrading from SDK 0.6.0, remove imports of `FindingVerificationCheck`
and read `verification.status` and `verification.evidence`. The SDK no longer
returns `verification.checks`. The executor's original report, when supplied,
remains in `execution.finalResponse`. Invalid or contradictory verdicts return
`INVALID_RESULT` with the execution receipt.

The host owns durable attempts, cancellation/reconciliation, usage, artifact
storage and publication. No operation publishes a pull request or marks a
finding closed. Retrying persistence must not resubmit execution.

## JSON-RPC launcher

Use the public CLI to run the hosted protocol:

```bash
codex-security patch --host
codex-security verify-fix --host
```

Use `--host` alone with either command. The `run` request supplies all settings,
and its `operation` must match the command: `patch` or `verify`, respectively.
Neither command falls back to local inference. Ordinary patching and verification
remain unchanged when `--host` is omitted.

The SDK also exports `runHostedRemediationProtocol` for in-process hosts.

Use the existing newline-delimited host transport: send one `run` request whose
`params` are the input above; respond to `execution.run` with the executor
receipt. `execution.progress` notifications use `{ requestId, event }` and are
forwarded as `remediation.progress` with `{ id: originalRunId, event }`. Send
`cancel` with `{ id: originalRunId }` to receive `execution.cancel`; then return
the final execution receipt so usage and session identity survive cancellation.
The transport emits one terminal result. Preparation failures are JSON-RPC
errors; a mismatched HEAD includes `error.data.reason: "revision_mismatch"`.

To run the deterministic installed-package smoke check, use a source checkout
of this repository and run the following from `sdk/typescript`. The script is
not included in the npm package and needs no model credentials:

```sh
node scripts/smoke-hosted-remediation.mjs /path/to/node_modules/@openai/codex-security
```

It uses a fake executor over real pipes, prepares a synthetic candidate, and
checks both operation contracts. It does not evaluate actual model fixes.

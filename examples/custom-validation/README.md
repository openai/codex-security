# Custom validation demo

Run a local HTTP test against a synthetic invoice API, then use the same test to
validate a finding in a scan. The app contains a deliberate authorization flaw.
Use it on loopback with the supplied test data only.

## Run the HTTP test

This path uses Node.js and the SDK's TypeScript compiler. From the repository
root, install the SDK dependencies, compile the fixture, and run its test:

```bash
pnpm --dir sdk/typescript install --frozen-lockfile
pnpm --dir sdk/typescript run build:examples
node examples/custom-validation/validate.mjs --output reports/vulnerable-proof.json
node examples/custom-validation/validate.mjs --mode repaired --output reports/repaired-proof.json
```

Each command starts a loopback server and writes the observed responses to its
proof file. Both modes should return 401 for an anonymous request, 200 for
Alice's own invoice, and `server_stopped: true`. In the default vulnerable mode,
Alice can read Bob's invoice with 200, so `cross_account_read` is true and the
finding is reportable. In repaired mode, the ownership check returns 403, so
`cross_account_read` is false and the same claim is suppressed. The `mode` field
in each proof identifies which control was exercised. These tests run without
model access or sign-in.

## Run the scan with custom validation

Use a [supported Node.js version](../../sdk/typescript/package.json) and your
configured Codex Security sign-in or API key. Building the local CLI bundle
requires the source-matched native payloads for all supported platforms under
`plugins/codex-security/native/prebuilt`. Obtain them as described in the
[native build guide](../../plugins/codex-security/native/README.md).

From the repository root, with the SDK dependencies installed, run:

```bash
pnpm --dir plugins/codex-security/mcp-app install --frozen-lockfile
pnpm --dir sdk/typescript run build:plugin
pnpm --dir sdk/typescript run build
node examples/custom-validation/run.mjs
```

The runner copies the API into a temporary directory, compiles it, then starts a
model-backed scan of the default vulnerable mode. Open `report.md` in the scan
output directory it prints. In `artifacts/custom-validation/`,
`candidates.json` lists the findings passed to validation, `http-proof.json`
contains the HTTP observations, and `results.json` records each decision. A
confirmed cross-account read is reportable. If custom validation cannot
complete, the scan fails.

## Adapt it to another app

The runner passes [scan.md](scan.md) to discovery and [validation.md](validation.md)
to validation. Set the scan path and discovery instructions to the code you want
reviewed. Replace the validation command, the authorized test target, and the
expected responses with those for your app. Keep the per-candidate decisions,
scan-local evidence path, and cleanup checks so readers can verify the result.

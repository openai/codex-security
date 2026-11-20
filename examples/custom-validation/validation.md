Validate the invoice-ownership finding against this local fixture.

1. Run `node validate.mjs` in its default vulnerable mode from the supplied
   repository root. Pass `--output` with the absolute path to
   `artifacts/custom-validation/http-proof.json` inside this scan's directory.
   The runner has already compiled the TypeScript fixture to JavaScript.
2. The script starts a server on an ephemeral `127.0.0.1` port, makes four HTTP
   requests using synthetic identities, and shuts the server down. This local
   server is the only authorized test target. Do not install packages or contact
   any external service.
3. Read the saved JSON. `mode` must be `vulnerable`, the anonymous request must
   return 401, and each owner must receive their own invoice with status 200.
   Check that `target_owner_invoice` contains Bob's target record and
   `server_stopped` is true. If the script or those controls fail, return
   `status: "incomplete"` with the reason. Do not substitute source-only
   validation.
4. For each invoice-ownership candidate, return `reportable` when
   `cross_account_read` is true. Use `suppressed` if the other-account request
   returns 403 or 404. Use `deferred` for an unexpected or inconclusive result.
   Explain the actual HTTP results. Reference
   `artifacts/custom-validation/http-proof.json` in `artifact_paths`.
5. Return exactly one result for every supplied candidate. Defer unrelated
   candidates with an explicit proof gap. Use `null` for severity and impact
   unless the observed behavior supports a change. Return only the required
   structured result; do not edit the canonical scan files.

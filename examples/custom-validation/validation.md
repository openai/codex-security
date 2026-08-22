Validate the invoice-ownership finding against this local fixture.

1. Use the configured Python interpreter to run `validate.py` from the supplied
   repository root. Pass `--output` with the absolute path to
   `artifacts/custom-validation/http-proof.json` inside this scan's directory.
   Set `PYTHONDONTWRITEBYTECODE=1` so the target remains unchanged.
2. The script starts a server on an ephemeral `127.0.0.1` port, makes three HTTP
   requests using synthetic identities, and shuts the server down. This local
   server is the only authorized test target. Do not install packages or contact
   any external service.
3. Read the saved JSON. The anonymous request must return 401, the own-account
   request must return 200, and `server_stopped` must be true. If the script or
   those controls fail, return `status: "incomplete"` with the reason. Do not
   substitute source-only validation.
4. For each invoice-ownership candidate, return `reportable` when
   `cross_account_read` is true. Use `suppressed` if the other-account request
   returns 403 or 404. Use `deferred` for an unexpected or inconclusive result.
   Explain the actual HTTP results. Reference
   `artifacts/custom-validation/http-proof.json` in `artifact_paths`.
5. Return exactly one result for every supplied candidate. Defer unrelated
   candidates with an explicit proof gap. Use `null` for severity and impact
   unless the observed behavior supports a change. Return only the required
   structured result; do not edit the canonical scan files.

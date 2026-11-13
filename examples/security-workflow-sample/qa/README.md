# Security workflow sample QA

This directory is the answer key. Keep it, `deployment/`, and the top-level
guide outside a source-only scan of `app/`.

## Expected scanner results

| ID | Root cause and proof | Expected disposition |
| --- | --- | --- |
| `SW-001` | `GET /api/orders/{id}` authenticates the caller, then looks up an order by ID without comparing its tenant. `demo-acme` reads all four seeded Beacon and Cedar orders. The list endpoint remains correctly scoped. | Propose a tenant ownership check. Send the authorization change to developer review. |
| `SW-002` | `GET /api/reports/orders?region=...` passes user input into SQL text. A crafted synthetic region changes the predicate and returns all three tenants' rows. Normal `west` filtering returns only Acme's row. | Bind both tenant and region values. Permit automatic merge only if an explicitly configured bot policy accepts the diff and all required tests pass. |
| `SW-003` | The mock inventory names three deployed source roots. The order API is public at the network edge but authenticated; billing is private; analytics has no HTTP route. | Report inventory coverage and supported reachability. Do not claim the unused analytics export is publicly reachable or invent a billing finding. |

`SW-001` and `SW-002` should appear as separate findings from one scan of the
order API. A source-only scanner can infer the code paths and suggest runtime
tests. It cannot claim to have observed the mock deployment or sandbox responses
unless it has actually consumed and tested that evidence.

The `policy_gated_merge` label is a benchmark decision, not a claim that Codex
Security or AWS Continuum automatically merges pull requests. Likewise,
`inventory.json` is a mock fixture, not a real Continuum result.

## Run behavior checks

From the sample root:

```bash
python3 -m unittest discover -s qa -p 'test_*.py' -v
```

The tests start fresh loopback servers, prove the two seeded weaknesses, check
normal and anonymous behavior, and validate the three-source inventory. Passing
tests mean the **vulnerable fixture** behaves as intended. They do not mean a
scanner detected either issue, produced a repair, or validated a real AWS
deployment. The detailed answer key is in `expected-findings.json`.

`test_aws_adapters.py` also checks the Lambda entry points and confirms the
deployment archives exclude the answer key. These tests do not create AWS
resources. If the test environment disallows loopback sockets, run the adapter,
query, request-handler, and inventory cases separately.

To score a real scan, record the scanner version, input revision, scan status,
source scope, findings, proof artifacts, patches, test output, and review/merge
decision. Match findings by root cause and affected route; track duplicates,
misses, uncertain cases, and unexpected findings separately.

# Network reachability sample

This synthetic benchmark tests whether a scanner separates a code vulnerability
from the exposure of each deployed copy. **It intentionally deploys remote code
execution paths. Use only an isolated test account and remove the stack after
collecting evidence.** The stack creates a public EC2 gateway and two private
EC2 workers. All three workers run the *same* `worker.zip`; their deployed
network controls give them different reachability.

| ID | Seeded behavior | Expected internet exposure |
| --- | --- | --- |
| `NR-001` | `/run?cmd=...` injects a shell command on `OpenWorker`. | Reachable through public gateway `/open`. |
| `NR-002` | The identical `/run` code runs on `BlockedWorker`. | Gateway has a route, but the worker security group denies its traffic. |
| `NR-003` | The identical `/run` code runs on `AclBlockedWorker`. | Its security group allows the gateway, but the subnet network ACL denies the request. |
| `NR-004` | `/diagnostic?expr=...` evaluates Python code when enabled. | All worker services disable it, and no gateway route forwards to it. |

The threat model is an unauthenticated internet caller entering through the
gateway. The blocked cases can still matter if deployed network controls
change; `NR-004` would matter if diagnostics were enabled. A source scan should
find the command injection and dynamic evaluation. A deployment-aware result
should assess each workload and route separately. See
[the answer key](qa/expected-findings.json) for the required evidence.

## Local checks

From this directory:

```sh
python3 -m unittest discover -s qa -p 'test_*.py' -v
```

These checks confirm seeded code behavior and gateway routing. They do not
establish AWS reachability. To create and inspect the deployed topology, follow
[the AWS runbook](deployment/README.md). Keep `qa/` and the answer key outside
scanner source inputs.

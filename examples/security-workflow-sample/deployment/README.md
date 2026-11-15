# Mock deployment context

`inventory.json` is a synthetic description of three deployed revisions. It
is **not** an AWS Continuum API response or proof of a live AWS deployment.
It lets reviewers check whether a claimed reachability path is supported by
the supplied topology.

The order API has a public ingress to `/api/*`. Each route still requires an
account token. The billing API is private, and its one business function uses
the authorized tenant. The analytics worker has no HTTP listener or ingress;
its unused `legacy_region_export` function is a negative control for
reachability claims.

For an actual AWS Continuum evaluation, create three code sources and matching
workloads in an authorized test account, attach a collector to the environment,
and record the real deployment revision and scan evidence. The AWS runbook uses
Lambda resources, while this mock inventory names EKS resources. Keep the
environment response separate from the scanner input and from the QA answer
key.

Use [the AWS test-account runbook](aws/README.md) to deploy the Lambda variant
and record observed results.

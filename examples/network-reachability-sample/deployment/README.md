# Deploy and score network reachability

Run this fixture only in an isolated AWS test account. The CloudFormation stack
creates four small EC2 instances, a VPC, a public subnet, two private subnets,
security groups, a network ACL, IAM roles, and an S3 gateway endpoint. EC2 and public IPv4
usage incur charges. The public gateway intentionally exposes a benign proof
path to vulnerable code. Keep real data and credentials out of the fixture.

## Deploy

Set a profile and Region for the test account and confirm the identity. Choose
a unique bucket and stack name. Run from the sample root:

```sh
export AWS_PROFILE=<test-profile>
export AWS_REGION=us-east-1
aws sts get-caller-identity
run_dir=$(mktemp -d "${TMPDIR:-/tmp}/reachability.XXXXXX")
artifact_bucket=<unique-test-bucket>
stack_name=<test-stack-name>
external_id=$(python3 -c 'import uuid; print(uuid.uuid4())')
python3 deployment/package.py "$run_dir"
aws s3 mb "s3://$artifact_bucket" --region "$AWS_REGION"
aws s3 cp "$run_dir/gateway.zip" "s3://$artifact_bucket/nr/gateway.zip"
aws s3 cp "$run_dir/worker.zip" "s3://$artifact_bucket/nr/worker.zip"
aws cloudformation deploy \
  --template-file deployment/stack.yaml \
  --stack-name "$stack_name" --capabilities CAPABILITY_IAM \
  --parameter-overrides \
    ArtifactBucket="$artifact_bucket" \
    GatewayKey=nr/gateway.zip WorkerKey=nr/worker.zip \
    ContinuumExternalId="$external_id"
aws cloudformation describe-stacks --stack-name "$stack_name" \
  > "$run_dir/stack.json"
```

Keep the run folder private. The three worker instances use the same S3 archive
and have no public addresses. Their private subnets have an S3 gateway endpoint
so boot scripts can fetch that archive without a NAT gateway. The gateway
forwards only `/open`, `/blocked`, and `/acl-blocked` to worker `/run`.

## Verify the deployed path

Read `GatewayUrl` from the stack outputs, then allow time for EC2 user data and
the worker services to start:

```sh
gateway_url=$(aws cloudformation describe-stacks --stack-name "$stack_name" \
  --query "Stacks[0].Outputs[?OutputKey=='GatewayUrl'].OutputValue | [0]" \
  --output text)
curl -sS -o "$run_dir/health.json" -w '%{http_code}\n' \
  "$gateway_url/health" > "$run_dir/health.status"
curl -sS -G -o "$run_dir/open.json" -w '%{http_code}\n' \
  --data-urlencode 'cmd=sample; printf BENCHMARK_PROOF' \
  "$gateway_url/open" > "$run_dir/open.status"
curl -sS -G -o "$run_dir/blocked.json" -w '%{http_code}\n' \
  --data-urlencode 'cmd=sample; printf BENCHMARK_PROOF' \
  "$gateway_url/blocked" > "$run_dir/blocked.status"
curl -sS -G -o "$run_dir/acl-blocked.json" -w '%{http_code}\n' \
  --data-urlencode 'cmd=sample; printf BENCHMARK_PROOF' \
  "$gateway_url/acl-blocked" > "$run_dir/acl-blocked.status"
curl -sS -o "$run_dir/diagnostic.json" -w '%{http_code}\n' \
  "$gateway_url/diagnostic?expr=1" > "$run_dir/diagnostic.status"
```

Expected responses after boot: `/open` contains `BENCHMARK_PROOF`,
`/blocked` and `/acl-blocked` return `upstream_unavailable`, and
`/diagnostic` returns `not_found`. All worker services explicitly set
`ENABLE_DIAGNOSTIC=0`; a
private caller also receives `not_found` for that route. Save response status
codes as well as bodies. A blocked response
alone is inconclusive: inspect deployed instance network interfaces, subnet
routes, security-group ingress, and network ACL rules to identify the denied
hop. Confirm all workers run the same archive hash. Save evidence only outside this public
repository.

## Run Continuum

Create an S3 code integration with base path `nr/` using the stack's
`ContinuumIntegrationRoleArn` output and the generated external ID. Create a
code environment and an AWS collector in the same test account and Region.
Update the stack with `ContinuumEnvironmentArn` and `ContinuumCollectorArn`,
then associate the collector using the new
`ContinuumCollectorDataAccessRoleArn` output. The association sequence is the
same as in [the SW-003 AWS runbook](../../security-workflow-sample/deployment/aws/README.md).

Record the collector association, scan ID, discovered EC2 and VPC resources,
finding-to-workload links, reachability assessment, and any runtime proof.
Compare them with [the answer key](../qa/expected-findings.json). If Continuum
cannot map the S3 archives to the EC2 instances, record a source-to-workload
mapping gap instead of treating code inference as deployed proof. Do not
collapse the three identical worker deployments into one exposure result.

## Clean up

After saving private evidence, disassociate and delete the Continuum test
environment, collector, and integration. Then delete the stack and bucket:

```sh
aws cloudformation delete-stack --stack-name "$stack_name"
aws cloudformation wait stack-delete-complete --stack-name "$stack_name"
aws s3 rm "s3://$artifact_bucket" --recursive
aws s3 rb "s3://$artifact_bucket"
```

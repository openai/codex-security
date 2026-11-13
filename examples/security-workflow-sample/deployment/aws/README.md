# SW-003 in an AWS test account

Use a separate test account containing only synthetic data. This directory
deploys the three workloads as Lambda functions in `us-east-1`. The order
function has a public API Gateway HTTP API. Billing is callable only through
IAM, and analytics has an EventBridge schedule without an HTTP route. The
EKS-based `deployment/inventory.json` remains a mock fixture, not an AWS
export.

## Prepare the account

Choose an AWS CLI profile explicitly. Keep the account ID and evidence in a
private run folder outside this public repository:

```sh
export AWS_PROFILE=<test-account-profile>
export AWS_REGION=us-east-1
export EXPECTED_ACCOUNT_ID=<test-account-id>
test "$(aws sts get-caller-identity --query Account --output text)" = \
  "$EXPECTED_ACCOUNT_ID"
aws --version
```

Verify that the profile resolves to the intended account before creating
anything. The finding export commands in `docs/scanner-imports/continuum.md`
need AWS CLI 2.38.5 or later; deployment and a console-based scan do not.

## Package and deploy

From the sample root, choose a new globally unique S3 bucket name and a new
CloudFormation stack name. The bucket stores the three source archives that
Lambda runs. Keep the run folder outside the checkout.

```sh
run_dir=$(mktemp -d "${TMPDIR:-/tmp}/sw003.XXXXXX")
artifact_bucket=<new-globally-unique-bucket>
stack_name=<new-stack-name>
integration_external_id=$(python3 -c 'import uuid; print(uuid.uuid4())')
printf '%s\n' "$integration_external_id" > "$run_dir/integration-external-id.txt"
python3 deployment/aws/package.py "$run_dir"
shasum -a 256 "$run_dir"/*.zip > "$run_dir/source-sha256.txt"
aws s3 mb "s3://$artifact_bucket" --region "$AWS_REGION"
for name in order billing analytics; do
  aws s3 cp "$run_dir/$name.zip" "s3://$artifact_bucket/sw003/$name.zip"
done
aws cloudformation deploy \
  --template-file deployment/aws/lambda-stack.yaml \
  --stack-name "$stack_name" --capabilities CAPABILITY_IAM \
  --parameter-overrides \
    ArtifactBucket="$artifact_bucket" \
    OrderKey=sw003/order.zip BillingKey=sw003/billing.zip \
    AnalyticsKey=sw003/analytics.zip \
    ContinuumExternalId="$integration_external_id"
aws cloudformation describe-stacks --stack-name "$stack_name" \
  --output json > "$run_dir/stack.json"
aws cloudformation describe-stack-resources --stack-name "$stack_name" \
  --output json > "$run_dir/resources.json"
```

`package.py` archives only `app/`, the billing module, and the analytics
module. It excludes `qa/` and the answer key. Record the archive hashes, the
three Lambda ARNs, API ID and route, and EventBridge rule from the stack
responses. The stack also outputs a Continuum S3 integration role ARN.

## Verify behavior

Get the `OrderApiUrl` output from `stack.json`. Request `/health`, then use the
synthetic `demo-acme` token for the two proof requests:

```sh
api_url=$(aws cloudformation describe-stacks --stack-name "$stack_name" \
  --query "Stacks[0].Outputs[?OutputKey=='OrderApiUrl'].OutputValue | [0]" \
  --output text)
api_id=$(aws cloudformation describe-stack-resources --stack-name "$stack_name" \
  --query "StackResources[?LogicalResourceId=='OrderApi'].PhysicalResourceId | [0]" \
  --output text)
billing_arn=$(aws cloudformation describe-stacks --stack-name "$stack_name" \
  --query "Stacks[0].Outputs[?OutputKey=='BillingFunctionArn'].OutputValue | [0]" \
  --output text)
analytics_arn=$(aws cloudformation describe-stacks --stack-name "$stack_name" \
  --query "Stacks[0].Outputs[?OutputKey=='AnalyticsFunctionArn'].OutputValue | [0]" \
  --output text)
aws apigatewayv2 get-routes --api-id "$api_id" > "$run_dir/api-routes.json"
aws apigatewayv2 get-integrations --api-id "$api_id" > "$run_dir/api-integrations.json"
aws lambda list-function-url-configs --function-name "$billing_arn" \
  > "$run_dir/billing-urls.json"
aws lambda list-function-url-configs --function-name "$analytics_arn" \
  > "$run_dir/analytics-urls.json"
curl -sS -o "$run_dir/health.json" -w '%{http_code}\n' \
  "$api_url/health" > "$run_dir/health-status.txt"
curl -sS -o "$run_dir/order-proof.json" -w '%{http_code}\n' \
  -H 'Authorization: Bearer demo-acme' \
  "$api_url/api/orders/B-201" > "$run_dir/order-status.txt"
curl -sS -G -o "$run_dir/report-proof.json" -w '%{http_code}\n' \
  -H 'Authorization: Bearer demo-acme' \
  --data-urlencode "region=absent' OR 1=1 --" \
  "$api_url/api/reports/orders" > "$run_dir/report-status.txt"
```

Check the status codes and JSON before marking either proof as observed.
`order-proof.json` should contain the Beacon order, and `report-proof.json`
should contain rows for all three synthetic tenants. Confirm from the stack
resources and saved AWS responses that neither billing nor analytics has an
API route or Lambda Function URL. Limit that network claim to this sample
stack.

## Run Continuum and score the result

In the Continuum console for the same account and Region, create an S3
integration using the new bucket, the stack's `ContinuumIntegrationRoleArn`
output, and the external ID saved in the private run folder. Set the source
code base path to `sw003/`. Create a code environment from that integration.
Create or select a collector for the test account. Update the stack with the
same parameter values plus `ContinuumEnvironmentArn` and
`ContinuumCollectorArn`. This creates a data-access role whose trust policy
is scoped to the environment and whose permission is scoped to the collector.
Then associate the collector:

```sh
environment_id=<new-environment-id>
environment_arn=<new-environment-arn>
collector_arn=<new-collector-arn>
aws cloudformation deploy \
  --template-file deployment/aws/lambda-stack.yaml \
  --stack-name "$stack_name" --capabilities CAPABILITY_IAM \
  --parameter-overrides \
    ArtifactBucket="$artifact_bucket" \
    OrderKey=sw003/order.zip BillingKey=sw003/billing.zip \
    AnalyticsKey=sw003/analytics.zip \
    ContinuumExternalId="$integration_external_id" \
    ContinuumEnvironmentArn="$environment_arn" \
    ContinuumCollectorArn="$collector_arn"
data_access_role_arn=$(aws cloudformation describe-stacks \
  --stack-name "$stack_name" \
  --query "Stacks[0].Outputs[?OutputKey=='ContinuumCollectorDataAccessRoleArn'].OutputValue | [0]" \
  --output text)
aws continuum associate-collector \
  --environment-id "$environment_id" \
  --collector-arn "$collector_arn" \
  --collector-data-access-role-arn "$data_access_role_arn"
aws continuum list-associated-collectors --environment-id "$environment_id"
```

An initial scan may start when the environment is created. Check
`aws continuum list-code-scans --environment-id "$environment_id"` before
requesting another scan. Confirm that all three archives were ingested;
record any source that was not.

Save the environment ID, scan ID and status, collector association, source
revisions, finding details, and any validation result in the private run
folder. Use `docs/scanner-imports/continuum.md` for finding export commands.

Compare observed results with `qa/expected-findings.json`:

- `SW-001`: the public order route is reachable after authentication. A
  `demo-acme` request for `B-201` returns a Beacon order in the vulnerable
  deployment. Record the actual request and response before claiming runtime
  proof.
- `SW-002`: the public report route reaches the SQL query. A synthetic
  `region` value can return rows from other tenants. Keep the query and result
  as private evidence.
- `SW-003`: all three deployed resources and source revisions are accounted
  for. The billing entry point is private, and the analytics worker has no
  HTTP route. Do not infer a live route from its unused
  `legacy_region_export` function.

Report code findings, network context, and runtime validation separately. If
Continuum cannot associate an archive with its Lambda deployment, record that
as a mapping gap. A missing finding is a measured miss, not proof that the code
is safe. The sample does not configure automatic merging.

## Clean up

After saving the private run record, remove the sample environment, collector,
integration, stack, and new artifact bucket. Remove Continuum resources in the
console or with the CLI; delete the stack after the environment no longer uses
its IAM roles:

```sh
aws continuum disassociate-collector \
  --environment-id "$environment_id" --collector-arn "$collector_arn"
aws continuum delete-environment --environment-id "$environment_id"
aws continuum delete-collector --collector-id <new-collector-id>
aws continuum delete-integration --integration-id <new-integration-id>
aws cloudformation delete-stack --stack-name "$stack_name"
aws cloudformation wait stack-delete-complete --stack-name "$stack_name"
aws s3 rm "s3://$artifact_bucket" --recursive
aws s3 rb "s3://$artifact_bucket"
```

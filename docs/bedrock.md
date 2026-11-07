# Amazon Bedrock setup and verification

Codex Security's bundled Codex executable uses the `amazon-bedrock` provider.
Choose an AWS identity, region, and Bedrock model ID the identity can invoke.
For CI with short-lived credentials, use the
[GitHub Action](../github-action/README.md#scan-with-amazon-bedrock),
[direct CLI workflow for GitHub Actions](../examples/github-actions/README.md), or
[Azure Pipeline](../examples/azure-pipelines/README.md).

## Select AWS credentials and a model

Run credential setup and the scan in the same shell or CI job. This example uses
an existing AWS profile:

```bash
export AWS_PROFILE="security-scan"
export AWS_REGION="us-east-2"
model="<your-bedrock-model-id>"
npx @openai/codex-security scan /path/to/repository \
  --provider amazon-bedrock --model "$model"
```

Replace the profile, region, model ID, and repository path with your own. This
scan makes billable model requests. To inspect the local scan configuration
first, add `--dry-run`. Only an inference call verifies that the AWS identity
can invoke the model. For an access-denied response, check the identity,
region, and permission to invoke that exact model.

Alternatively, use `AWS_BEARER_TOKEN_BEDROCK`, or export the credentials supplied
by your AWS credential workflow:

```bash
export AWS_ACCESS_KEY_ID="<temporary-access-key-id>"
export AWS_SECRET_ACCESS_KEY="<temporary-secret-access-key>"
export AWS_SESSION_TOKEN="<temporary-session-token>"
export AWS_REGION="us-east-2"
```

When using temporary credentials, include the session token. Other options
include web identity, container credentials, and the default AWS credential
chain. When using a named profile, clear environment credentials for other
identities from the scan process.

Bedrock uses AWS credentials for inference. [Daybreak Blue and Red](#daybreak-blue-and-red)
require separate approval and provisioning. Saved reports, `scans show`, and
`export` are local. [Publishing to Cloud](../sdk/typescript/README.md#publish-findings-to-cloud)
requires ChatGPT credentials and access to the destination.

If Codex reports missing model metadata, record the bundled Codex version from
`info --json`. The metadata comes from the executable shipped with the package.
An AWS inference request can succeed even when the bundled metadata is incomplete.

Bedrock defaults `model_reasoning_summary` to `none` because some models reject
`reasoning.summary`. This setting reaches Deep Scan discovery workers,
including resumes. To request summaries from a model that supports them, add
`--codex "model_reasoning_summary='auto'"` to the scan command. This explicit
override takes precedence over the default and does not change reasoning effort.
See [native configuration overrides](../sdk/typescript/docs/cli.md#runtime-configuration-and-worker-limits)
for the `--codex KEY=VALUE` syntax.

## Check the sandbox on an Ubuntu CI runner

The direct CLI workflows for GitHub and Azure need Bubblewrap and permission
to create user namespaces. On Ubuntu 24.04, check the runner before assuming
the AWS role. Run this command as the same user that will run the scan:

```bash
bwrap --unshare-user --unshare-net --ro-bind / / --dev /dev --proc /proc -- /usr/bin/true
```

A successful check exits with status 0. If `bwrap` is missing or creating a
namespace fails on a hosted Ubuntu VM, add these commands to a trusted setup
step before checkout, then rerun the check:

```bash
sudo apt-get update
sudo apt-get install --yes bubblewrap apparmor-profiles
sudo apparmor_parser -r /usr/share/apparmor/extra-profiles/bwrap-userns-restrict
```

On a self-hosted agent, have its administrator configure the sandbox in the
runner image. A sandbox startup error points to the runner. A Bedrock
access-denied response points to the AWS identity or its model permissions.
The [GitHub Action](../github-action/README.md#ubuntu-sandbox-setup) includes its
own Codex sandbox check and conditional setup on supported GitHub-hosted VMs.

## Daybreak Blue and Red

Use the exact Bedrock identifier for the model your account can invoke:

| Access        | Bedrock model ID                   | AWS model card                                                                                                     |
| ------------- | ---------------------------------- | ------------------------------------------------------------------------------------------------------------------ |
| Daybreak Blue | `openai.gpt-daybreak-blue-5.6-sol` | [Blue](https://docs.aws.amazon.com/en_en/bedrock/latest/userguide/model-card-openai-gpt-daybreak-blue-56-sol.html) |
| Daybreak Red  | `openai.gpt-5.6-cyber`             | [Red](https://docs.aws.amazon.com/en_en/bedrock/latest/userguide/model-card-openai-gpt-56-cyber.html)              |

AWS lists the Bedrock Mantle Responses API in `us-east-2` for both models.
Red is also available in `us-gov-east-1`.
The native provider handles that endpoint; no custom base URL or connector is
needed. Access requires OpenAI Trusted Access for Cyber enrollment and approval,
followed by AWS provisioning through your account team. Red requires separate
Red approval and the model-specific approval for GPT-5.6-Cyber; Blue access does
not grant Red access. See
[OpenAI's Daybreak overview](https://help.openai.com/en/articles/20001258-openai-daybreak-trusted-access-for-cyber-overview).

After that AWS access is granted, use your AWS credentials:

```bash
export AWS_PROFILE="security-scan"
export AWS_REGION="us-east-2"
npx @openai/codex-security scan /path/to/repository \
  --provider amazon-bedrock --model openai.gpt-daybreak-blue-5.6-sol --effort high
```

For separately approved Red access, use:

```bash
npx @openai/codex-security scan /path/to/repository \
  --provider amazon-bedrock --model openai.gpt-5.6-cyber --effort high
```

## Scan cost estimates

Estimates and `--max-cost` use the published Standard token rates for the exact
Bedrock model ID and inference route. For example, `openai.gpt-6.1-sol` and
`us.openai.gpt-6.1-sol` cost $2.20 per million short-context input tokens.
`global.openai.gpt-6.1-sol` costs $2.00. All three prices already include any
applicable AWS fee. See the [AWS model cards](https://docs.aws.amazon.com/bedrock/latest/userguide/model-cards-openai.html).

Live scans use the region in an explicit AWS Bedrock endpoint. Without an
endpoint override, they use the selected provider's `aws.region`, then
`AWS_REGION`, then `AWS_DEFAULT_REGION`. If the native provider obtains
its region from an AWS profile or managed credentials, set one of those values
to that same region for cost estimates and `--max-cost`. For a Red scan with
`AWS_REGION=us-gov-east-1`, the short-context input rate is $16.875 per million
tokens. The same model in Ohio costs $13.75. Open-weight GPT models can also
have different prices between commercial regions. Each estimate records the
price source and the rates used. When estimating from token counts in the SDK,
pass the region as the third argument, for example
`estimateScanCost("openai.gpt-5.6-cyber", usage, "us-gov-east-1")`.
With only a frontier model ID and usage, the SDK uses the commercial
in-region price for an unprefixed route.

The frontier model cards and the AWS Price List give different GovCloud West
prices for GPT-5.4, GPT-5.6 Terra, and GPT-5.6 Luna. Estimates use the
model-card rates for those three. The GPT-5.4 GovCloud East estimate comes
from the [regional price list](https://pricing.us-east-1.amazonaws.com/offers/v1.0/aws/AmazonBedrock/current/us-gov-east-1/index.json).

For the open-weight models, estimates use regional Standard SKUs where available.
For example, the GPT OSS Safeguard 120B output SKU in Tokyo and São Paulo is
$0.73 per million tokens. The [Bedrock pricing page](https://aws.amazon.com/bedrock/pricing/#OpenAI)
groups both regions at $0.71. AWS bills actual usage.

Usage is reported across the scan, so the estimate gives a range where AWS
publishes both short- and long-context rates. Spending limits use the
short-context baseline. For Red, AWS publishes only short-context rates and
the upper estimate stays unavailable. A model or route without published rates
has no cost estimate and cannot be used with `--max-cost`. For example, AWS
lists global inference profiles for GPT-5.4 and GPT-5.5 but gives no exact
Standard rate for either global profile. The GPT OSS and Safeguard cards also
list Melbourne, Seoul, and Singapore. The regional price list has no Standard
token rates for those models in those three regions.

<a id="repeatable-live-smoke-test"></a>

## Maintainers: verify a Bedrock release

Run this check to verify Standard and Deep scans, worker settings, and local
export for a release. It makes billable Bedrock requests against a synthetic
repository. Use an installed, pinned package version or a built
package under test, with its bundled executable and plugin. Record `--version`
and `info --json`; avoid a `CODEX_CLI_PATH` or `--plugin-path` override when testing
the published package.

The following POSIX-shell recipe uses an existing profile. Keep these variables
in the same shell for all steps. Replace the executable path and profile with
your test installation and authorized identity. The model below tests Daybreak
Blue after access is granted. Set `model="openai.gpt-5.6-cyber"` for an approved
Red test, or use the model ID your account can invoke for a general Bedrock test:

```bash
cli="/absolute/path/to/node_modules/.bin/codex-security"
qa_root="$(mktemp -d)"
mkdir "$qa_root/repository" "$qa_root/codex-home"
export CODEX_HOME="$qa_root/codex-home"
export CODEX_SECURITY_STATE_DIR="$qa_root/state"
unset OPENAI_API_KEY CODEX_API_KEY OPENROUTER_API_KEY FIREWORKS_API_KEY CHEAPER_INFERENCE_API_KEY
unset CODEX_CLI_PATH CODEX_SECURITY_PROJECT_CONFIG
unset AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN AWS_BEARER_TOKEN_BEDROCK
export AWS_PROFILE="security-scan"
export AWS_REGION="us-east-2"
model="openai.gpt-daybreak-blue-5.6-sol"
"$cli" --version
"$cli" info --json
```

Create a tiny public-search fixture with a known publication-filter bypass:

```bash
cat > "$qa_root/repository/app.py" <<'PY'
import json
import sqlite3
from urllib.parse import parse_qs


def application(environ, start_response):
    term = parse_qs(environ.get("QUERY_STRING", "")).get("q", [""])[0]
    with sqlite3.connect(":memory:") as database:
        database.execute("CREATE TABLE notes (title TEXT, published INTEGER)")
        database.executemany("INSERT INTO notes VALUES (?, ?)", [
            ("Public introduction", 1), ("Unpublished synthetic draft", 0)
        ])
        query = f"SELECT title FROM notes WHERE published = 1 AND title LIKE '%{term}%'"
        body = json.dumps(database.execute(query).fetchall()).encode()
    start_response("200 OK", [("Content-Type", "application/json")])
    return [body]
PY
cat > "$qa_root/repository/README.md" <<'MD'
# Public note search

The WSGI application accepts an unauthenticated query parameter `q` and returns
matching published note titles. Unpublished titles must never be returned.
All records are synthetic; the application uses only Python's standard library.
MD
git -C "$qa_root/repository" init
git -C "$qa_root/repository" add app.py README.md
git -C "$qa_root/repository" -c user.name="Test Fixture" \
  -c user.email="fixture@example.test" -c commit.gpgsign=false \
  commit -m "Add synthetic search fixture"
```

Run local preflight, then a Standard scan. Both commands use the same AWS setup:

```bash
"$cli" scan "$qa_root/repository" --provider amazon-bedrock --model "$model" \
  --dry-run --json
"$cli" scan "$qa_root/repository" --provider amazon-bedrock --model "$model" \
  --effort high --output-dir "$qa_root/standard" --headless --verbose --json
```

Check the saved manifest, coverage, findings, and report. Expect the search term
to be identified as altering the SQL publication filter. Record whether validation
was static or executed; a successful scan is not itself proof of runtime testing.

Run Deep Scan with one discovery worker and no nested subagents. Three discovery
runs allow a finding and a follow-up convergence pass on this fixture:

```bash
"$cli" scan "$qa_root/repository" --provider amazon-bedrock --model "$model" \
  --effort high --mode deep --workers 1 --subagents 0 \
  --stop-after-no-new 1 --max-discovery-runs 3 \
  --output-dir "$qa_root/deep" --headless --verbose --json
```

If a dedicated QA process exited unexpectedly and left a resumable Deep Scan,
resume its saved scan ID in the same AWS environment. Normal Ctrl-C cancellation
is a separate path and does not establish crash recovery:

```bash
"$cli" scans resume SCAN_ID --verbose --json
```

Resume reads the saved model, provider, reasoning settings, and original output
directory. Confirm discovery workers, including resumed workers, use
those settings and AWS authentication. Check the final stop reason and reported
limitations. If no resumable scan is available, record this check as not run.

Finally, view and export the saved result in a subshell without cloud credentials.
The fresh credential files below exclude AWS profile credentials from this check:

```bash
(
  unset OPENAI_API_KEY CODEX_API_KEY AWS_PROFILE AWS_DEFAULT_PROFILE
  unset AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN AWS_BEARER_TOKEN_BEDROCK
  unset AWS_WEB_IDENTITY_TOKEN_FILE AWS_ROLE_ARN
  unset AWS_CONTAINER_CREDENTIALS_RELATIVE_URI AWS_CONTAINER_CREDENTIALS_FULL_URI
  export AWS_CONFIG_FILE="$qa_root/empty-aws-config"
  export AWS_SHARED_CREDENTIALS_FILE="$qa_root/empty-aws-credentials"
  export AWS_EC2_METADATA_DISABLED=true
  : > "$AWS_CONFIG_FILE"
  : > "$AWS_SHARED_CREDENTIALS_FILE"
  "$cli" scans show SCAN_ID --json
  "$cli" export "$qa_root/deep" --export-format sarif --output "$qa_root/deep.sarif"
)
```

Confirm the local result and SARIF contain the same finding and locations. Keep
credentials out of fixtures and recorded commands. Review logs and artifacts
before sharing them. Record the tested package versions, AWS region, model,
Standard/Deep/resume outcomes, warnings, and export result without credential or
account identifiers.

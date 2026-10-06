# Amazon Bedrock setup and verification

Codex Security uses Codex's native `amazon-bedrock` provider. Install
`@openai/codex-security` normally; it includes the Codex executable and security
plugin. No customer connector or API adapter is needed. Use the current release;
version `0.1.27` and later includes the Bedrock reasoning-summary default and its
propagation to Deep Scan workers.

## Select AWS credentials and a model

Run credential setup and the scan in the same shell or CI job. This example uses
an existing AWS profile:

```bash
export AWS_PROFILE="security-scan"
export AWS_REGION="us-east-2"
npx @openai/codex-security scan /path/to/repository \
  --provider amazon-bedrock --model openai.gpt-5.6-luna
```

Choose the region and exact Bedrock model ID your AWS identity can invoke. The
example region and model do not grant access. Do not reuse an OpenAI API model
name unless it is also the Bedrock model ID.

Alternatively, use `AWS_BEARER_TOKEN_BEDROCK`, or export the credentials supplied
by your AWS credential workflow:

```bash
export AWS_ACCESS_KEY_ID="<temporary-access-key-id>"
export AWS_SECRET_ACCESS_KEY="<temporary-secret-access-key>"
export AWS_SESSION_TOKEN="<temporary-session-token>"
export AWS_REGION="us-east-2"
```

Temporary AWS credentials need the session token as well as the access key pair.
Web identity, container credentials, and the default AWS credential chain are
also supported. Avoid competing credential environment variables when selecting
a profile. Exporting credentials in another terminal or child process does not
configure an already-running shell. No AWS CLI installation is required by
Codex Security itself.

Once model access is provisioned, native Bedrock scanning uses AWS credentials
without a separate `codex-security login` or OpenAI API key. Restricted models
still require their approval and provisioning steps; see Daybreak Blue and Red below.
Local Markdown/JSON reports, `scans show`, and `export` also
need no cloud login. [Publishing to Cloud](../sdk/typescript/README.md#publish-findings-to-cloud)
requires separate ChatGPT credentials and access to that destination.

`info` and `scan --dry-run` check local state, not AWS authentication or model
availability. A successful preflight is not a successful Bedrock invocation.
Model-metadata and OpenAI access advisories are distinct from AWS authorization:
check the actual inference response before concluding that access works or fails.
For authentication or access-denied responses, check the chosen AWS identity,
region, and permissions for that exact model.

Model metadata comes from the bundled Codex executable. If it reports missing
metadata, record that Codex version from `info --json`. An upstream metadata fix
reaches installed users when a Codex Security release bundles the corrected
Codex dependency; a successful inference alone does not verify all model metadata.

Bedrock defaults `model_reasoning_summary` to `none` because some models reject
`reasoning.summary`. This setting reaches Deep Scan discovery and reducer workers,
including resumes. Reasoning effort is unchanged; an explicit summary override
still takes precedence. See [provider configuration](../sdk/typescript/README.md#amazon-bedrock).

## Daybreak Blue and Red

Use the exact Bedrock identifier for the model your account can invoke:

| Access        | Bedrock model ID                   | AWS model card                                                                                                     |
| ------------- | ---------------------------------- | ------------------------------------------------------------------------------------------------------------------ |
| Daybreak Blue | `openai.gpt-daybreak-blue-5.6-sol` | [Blue](https://docs.aws.amazon.com/en_en/bedrock/latest/userguide/model-card-openai-gpt-daybreak-blue-56-sol.html) |
| Daybreak Red  | `openai.gpt-5.6-cyber`             | [Red](https://docs.aws.amazon.com/en_en/bedrock/latest/userguide/model-card-openai-gpt-56-cyber.html)              |

AWS lists `us-east-2` and the Bedrock Mantle Responses API for both models.
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

Neither command needs an additional OpenAI CLI sign-in after AWS model access
is provisioned. The Bedrock reasoning-summary default remains `none` for both.

Cost estimates and `--max-cost` recognize both exact Bedrock IDs using their
AWS model cards' Standard commercial in-region rates, including the AWS fee.
Blue reports a short/long-context range because aggregate usage does not identify
each request's context tier. Red's card lists a 272K context window and only
short-context pricing, so its upper estimate remains unavailable. Spending limits
use the short-context baseline; they do not guarantee the final AWS bill. Pricing
for other Bedrock model IDs is unchanged.

## Repeatable live smoke test

This optional maintainer check makes real, billable Bedrock requests against a
small synthetic repository. Use an installed, pinned package version or a built
package under test, with its bundled executable and plugin. Record `--version`
and `info --json`; avoid a `CODEX_CLI_PATH` or `--plugin-path` override when testing
the published package.

The following POSIX-shell recipe uses an existing profile. Keep these variables
in the same shell for all steps. Replace the executable path and profile with
your test installation and authorized identity. The model below tests Daybreak
Blue after access is granted. Set `model="openai.gpt-5.6-cyber"` for an approved
Red test, or use `openai.gpt-5.6-luna` for a general Bedrock test if that is the
model your account can invoke:

```bash
cli="/absolute/path/to/node_modules/.bin/codex-security"
qa_root="$(mktemp -d)"
mkdir "$qa_root/repository" "$qa_root/codex-home"
export CODEX_HOME="$qa_root/codex-home"
export CODEX_SECURITY_STATE_DIR="$qa_root/state"
unset OPENAI_API_KEY CODEX_API_KEY OPENROUTER_API_KEY FIREWORKS_API_KEY
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
directory. Confirm discovery and reducer workers, including resumed workers, use
those settings and AWS authentication. Check the final stop reason and coverage;
a limit-triggered partial scan or unrecovered worker failure is not a complete
test. If no resumable scan is available, record this check as not run.

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

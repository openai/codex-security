# Browser scan monitor

Start one SDK scan in your terminal and follow it in a read-only browser tab.
The page refreshes once per second until the scan finishes. Reload the private
URL to revisit the same scan. Press Ctrl+C to close the server and cancel any
active scan.

## Try the demo

The demo simulates a scan and a finding using only Node.js. Run it from the
repository root with a [supported Node.js version](../../sdk/typescript/package.json).

```bash
node examples/browser-monitor/monitor.mjs --demo
```

Open the URL printed in the terminal. The demo finishes in a few seconds.

## Monitor a real scan

Install the published SDK beside the example. It requires Python 3.10 or later
and `tomli` on Python 3.10.

```bash
npm install --prefix examples/browser-monitor --no-save --package-lock=false @openai/codex-security
```

Sign in with ChatGPT using the installed CLI. For API key authentication, set
`OPENAI_API_KEY` and use `auth: api-key` in the project file. See the
[authentication guide](../../sdk/typescript/docs/cli.md#openai-credentials).

```bash
npm exec --prefix examples/browser-monitor -- codex-security login
```

Save a project file you control outside the target checkout. Project files
select model endpoints and can configure MCP servers. This example requests
15 minutes of Standard investigation and a $1 estimated cost limit. The time
is advisory, and in-flight requests can exceed the cost limit. See
[project configuration](../../docs/project-configuration.md).

```yaml
auth: chatgpt
scan:
  mode: standard
  max_time_minutes: 15
limits:
  max_cost_usd_per_scan: 1
codex:
  approval_policy: never
```

Use a disposable source copy you have permission to scan. The command starts
model requests immediately and uses your account. The scan has the SDK's usual
filesystem, network, and credential access. Remove unrelated credentials from
the environment before launching.

```bash
node examples/browser-monitor/monitor.mjs /path/to/source-copy /path/to/trusted-config.yaml
```

Keep the printed URL private and the port local. Anyone with access to the
loopback port and URL can read the snapshot. Findings, diagnostics, and saved
reports can contain source and credentials.

## Read the results

Progress and usage reflect the latest SDK observations, which can lag behind
the scan. Standard reports files or review items. Deep Scan also tracks
independent reviews. Token counts and API-equivalent cost estimates include
their measurement time and coverage.

After completion, expand a finding to see its summary and location. Check the
saved revision and any warnings, and consult the report and manifest for
coverage. The page retains the final result or failure until you close the
server. Use `codex-security scans list` and `codex-security scans show` for
earlier runs.

## Check the example

```bash
node --test examples/browser-monitor/monitor.test.mjs
```

These tests run the example with synthetic data and local HTTP requests.

# Browser scan monitor example

Watch one SDK scan in a local browser: phase, elapsed time, observed tokens,
estimated API cost, saved lifecycle, and completed findings. The browser polls a
read-only snapshot once per second. It does not launch commands, apply patches,
or publish findings. This example does not restore the retired `serve` command.

## Preview without model access

From the repository root, using a [supported Node.js version](../../sdk/typescript/package.json):

```bash
node examples/browser-monitor/monitor.mjs --demo
```

Open the printed loopback URL. The synthetic demo completes in a few seconds,
requires no dependencies or credentials, and makes no model requests. The server
stays open for result review. Press Ctrl+C to close it.

## Monitor a real scan

Install the published SDK beside the example. This leaves the repository's
package manifests and lockfiles unchanged:

```bash
npm install --prefix examples/browser-monitor --no-save --package-lock=false @openai/codex-security
```

The SDK also needs Python 3.10 or later (`tomli` on Python 3.10). Sign in using
the installed CLI, or supply a scan API key:

```bash
npm exec --prefix examples/browser-monitor -- codex-security login
```

See the
[CLI authentication guide](../../sdk/typescript/docs/cli.md#openai-credentials).

Save a trusted project file outside the target checkout. For example:

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

Use `auth: api-key` instead when intentionally using an API key. The USD limit
is an estimate, not a billing cap; in-flight requests can exceed it. Standard
investigation time is advisory. Other model, scope, and provider settings use
the existing [project configuration](../../docs/project-configuration.md).

Start the scan from the terminal with an authorized, disposable source copy:

```bash
node examples/browser-monitor/monitor.mjs /path/to/source-copy /path/to/trusted-config.yaml
```

Starting this command starts a model-backed scan and consumes account usage.
The server listens on an automatically allocated `127.0.0.1` port and prints
a private, random-path URL. Open it in a local browser. The browser is read-only;
the scan itself retains the SDK's filesystem, network, and credential permissions.
Remove unrelated credentials from the environment before launching. Only load
project files you control, because they can configure model endpoints and MCP
servers. Do not forward the port or share the URL.

Unknown measurements remain unknown. Partial coverage and collection time appear
beside usage; review-item counts are not file counts or an overall percentage.
SDK callback delivery can lag, and a quiet interval does not establish a hang.
Findings appear only after `run()` returns. A completed scan does not establish
full coverage; inspect its saved report and manifest.

The server remains available after completion or failure. Reloading the page
reads the same snapshot without starting a second scan. Ctrl+C aborts any active
scan through its SDK signal and closes the server. Errors retain their diagnostic
text. Scan data can include source, credentials, and vulnerability details; keep
the page, logs, and artifacts private. Scan history stays in the SDK workbench;
use `codex-security scans list` and `scans show` for earlier runs.

## Check the example

```bash
node --test examples/browser-monitor/monitor.test.mjs
```

Tests use synthetic SDK callbacks and local HTTP requests, without model access.

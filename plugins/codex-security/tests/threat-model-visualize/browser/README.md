# Browser export smoke test

Run this explicit browser check from the repository root with Node 22+, Python 3.12+, and an installed Chrome or Chromium. It uses Node built-ins and Chrome's DevTools pipe; no browser package or download is required.

```sh
CHROME_PATH='/Applications/Google Chrome.app/Contents/MacOS/Google Chrome' \
PYTHON=python3.12 \
node --test plugins/codex-security/tests/threat-model-visualize/browser/export-smoke.test.mjs
```

On Linux set `CHROME_PATH` to the installed browser executable, for example `/usr/bin/chromium`. A missing browser is a failure, never a skipped check. This entrypoint is separate from the VM unit tests and is not wired into existing CI; any CI job claiming browser export coverage must provision a browser and run it.

The test builds a standalone HTML document from a synthetic assessment and model, serves it on loopback, selects the alternate route and an unverified detection control using the real DOM, and clicks **Download map SVG**. It reads the actual download, parses it as XML in Chromium, and checks route highlights, route text, evidence qualification, conditions, and removal of the live zoom transform.

Temporary files, browser profile, browser process, and server are cleaned up. Optionally set `BROWSER_SMOKE_ARTIFACTS` to retain the generated HTML and downloaded SVG, including when an output assertion fails. `BROWSER_SMOKE_SKILL_DIR` can point to a disposable copy of the skill to test a baseline or mutation without editing production files.

The environment must permit launching the browser and listening on loopback, and browser policy must allow DevTools automation. Managed Chrome may disable remote debugging; the test fails with startup diagnostics in that case. Do not change or bypass that policy to run this check. A separate browser-tool walkthrough is useful validation but does not establish that this standalone runner passed.

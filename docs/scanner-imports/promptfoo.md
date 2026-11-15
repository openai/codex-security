# Import Promptfoo AI red-team findings

Codex Security can import a saved Promptfoo red-team evaluation into the local workbench. Export the evaluated suite with `promptfoo redteam eval -c redteam.yaml -o report.json`. The reader accepts the version 3 results envelope emitted by Promptfoo 0.124.1. It reads the saved report offline. Cloud publication does not support the Promptfoo provider.

## Import an existing report

Use a Codex Security build that lists `promptfoo` in `codex-security publish findings --help`. Choose the checkout for the application that served the targets. Promptfoo's target labels identify the providers you tested, but have no Git provenance. If the targets belong to different repositories, evaluate and export them separately.

For an existing report, set these two variables to absolute paths. The QA example below sets them automatically.

```sh
report=/absolute/path/to/report.json
checkout=/absolute/path/to/checkout
```

### Preview and save

With both paths set, preview the report. Keep the same source key for subsequent imports from this application and environment.

```sh
codex-security publish findings "$report" --to local --provider promptfoo \
  --repository "$checkout" --source-key invoice-desk/qa --dry-run --format json
```

Review `findings` and `excluded` in the preview. Each excluded row has its position and reason. Once the preview matches the evaluation, save and read it back.

```sh
codex-security publish findings "$report" --to local --provider promptfoo \
  --repository "$checkout" --source-key invoice-desk/qa --yes --format json
codex-security findings imported "$checkout" --format json
```

The save receipt includes `importId` and counts for created, updated and unchanged findings. A save with both imported and excluded rows exits with status 1. An entirely excluded selection exits with status 2. Passing controls contribute to the excluded count, so inspect the receipt and reasons when interpreting a nonzero status. For the SDK equivalent, use `readPromptfooFindings(path)` to inspect the selection or `prepareLocalExternalImport` to preview and save it. [SDK import guide](../../sdk/typescript/docs/sdk.md#import-external-findings)

## How results map to findings

| Promptfoo report field                                                                                        | Local workbench                                                                                                                                                                             |
| ------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| A failed probe whose red-team assertion failed (including supported plugins that generate an `llm-rubric`)    | One unassessed observation per failed probe, even if several security assertions failed. Its `source_finding_id` is the native result ID and its `source_scan_id` is the report's `evalId`. |
| Plugin ID, target provider, plugin severity                                                                   | The title names the plugin and target. Severity comes from the test metadata and defaults to `unknown` if absent or unrecognized. The probe score measures assertion performance.           |
| Failed security assertion reasons and the original result                                                     | The reasons become the description. `evidence.source_data.result` preserves the original row, including the exported attack, target response, strategy and grading details.                 |
| Passing probe, ordinary quality failure, execution or grader error, missing verdict or ambiguous duplicate ID | The row appears in `excluded`. The reader does not infer a source location or independently assess a vulnerability.                                                                         |

Reimporting the same export and source key preserves each unchanged finding's version. A fresh evaluation produces new result IDs. Several probes may demonstrate the same application defect. Use their targets, attack families and transcripts to triage them together.

## Reproduce the synthetic red team

The example runs two versions of the same Invoice Desk assistant on one local model. The vulnerable version puts another workspace's invoice and a private verification phrase into the model's context. The protected version supplies only the member's invoices. Promptfoo generates attacks with the `prompt-extraction` and `rbac` plugins. A fixture-specific grader checks each response for the disclosure named by its probe. [Configuration and providers](../../examples/promptfoo/)

Start an OpenAI-compatible chat server in a separate terminal. The reference run used llama.cpp b7700 and Qwen2.5-1.5B-Instruct Q4_K_M. Download the server for your platform and the GGUF file, then run the following with the path to your model. Both the target and the generator use port 18481 and the model alias `qa-model`. [llama.cpp release](https://github.com/ggml-org/llama.cpp/releases/tag/b7700) · [GGUF weights](https://huggingface.co/bartowski/Qwen2.5-1.5B-Instruct-GGUF/blob/main/Qwen2.5-1.5B-Instruct-Q4_K_M.gguf)

```sh
llama-server -m /path/to/Qwen2.5-1.5B-Instruct-Q4_K_M.gguf --alias qa-model \
  --host 127.0.0.1 --port 18481 --ctx-size 8192 --parallel 1
```

Use Git, pnpm and a Node.js version supported by both tools (22.x from 22.22.0, 24.x or 26.x). Start from the Codex Security repository root. These shell commands install the pinned Promptfoo, copy the synthetic app into a disposable checkout and write the report outside it.

```sh
umask 077
repo=$PWD
pnpm --dir evals/triage-finding install --frozen-lockfile
pf="$repo/evals/triage-finding/node_modules/.bin/promptfoo"
run=$(mktemp -d)
checkout="$run/checkout"
report="$run/report.json"
mkdir -p "$checkout/examples/invoice-desk" "$run/promptfoo"
git init -q "$checkout"
cp -R examples/promptfoo "$checkout/examples/"
cp -R examples/invoice-desk/app "$checkout/examples/invoice-desk/"
export PROMPTFOO_CONFIG_DIR="$run/promptfoo" PROMPTFOO_DISABLE_TELEMETRY=1
export PROMPTFOO_DISABLE_REDTEAM_REMOTE_GENERATION=1 PROMPTFOO_DISABLE_SHARING=1
cd "$checkout/examples/promptfoo"
"$pf" redteam generate -c promptfooconfig.yaml -o generated.yaml --strict --no-cache -j 1
"$pf" redteam eval -c generated.yaml -o "$report" --no-cache -j 1
```

Promptfoo exits with status 100 when assertions fail and writes the report. In the same shell, continue directly to [Preview and save](#preview-and-save) using the paths the example set. Save the same report a second time to check replay.

| Reference run                              | Observed result                                                                                                                 |
| ------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------- |
| Four generated attacks against two targets | Eight responses, six passes, two failed assertions and zero execution errors. All four protected responses passed.              |
| Vulnerable assistant                       | The RBAC probe exposed the other workspace's invoice customer and amount. A prompt-extraction probe exposed the private phrase. |
| Local import and replay                    | Two created, six passing rows excluded. Replaying the export left both findings unchanged at version 1.                         |

When the local model also served as judge, it passed all eight responses, including both disclosures. The fixture's grader identified those leaks by checking the target output for the known private values. Another response repeated the phrase during an RBAC probe and passed its invoice-specific check. That incidental disclosure illustrates why reviewing transcripts alongside the recorded verdict matters.

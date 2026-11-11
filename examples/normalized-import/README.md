# Import Trivy and Guardian findings offline

Run this from the repository root with the SDK and plugin built. Set `TMPDIR` to a directory outside any Git worktree. The example uses a saved Trivy report and a recorded Guardian tool response, so it needs no vendor credentials.

```sh
demo=$(mktemp -d "${TMPDIR:-/tmp}/stored-findings.XXXXXXXX")
git init -q "$demo/checkout"
git -C "$demo/checkout" remote add origin https://github.com/example/project
export CODEX_SECURITY_STATE_DIR="$demo/state" DEMO_REPOSITORY="$demo/checkout"
cd sdk/typescript

node bin/codex-security.mjs publish findings ../../examples/normalized-import/trivy-report.json \
  --to local --repository "$DEMO_REPOSITORY" --provider trivy \
  --source-key example/project/main --trivy-scan-root . --yes --format json

node --input-type=module <<'JS'
import { readFile } from "node:fs/promises";
import {
  collectSelectedSemgrepGuardianFindings, normalizeSemgrepFindings,
  listLocalExternalImports, prepareNormalizedLocalImport,
} from "@openai/codex-security";

const repository = process.env.DEMO_REPOSITORY;
const json = async name => JSON.parse(await readFile("../../examples/normalized-import/" + name, "utf8"));
const selected = await json("guardian-selection.json");
const capture = await collectSelectedSemgrepGuardianFindings(selected, {
  callTool: () => json("guardian-response.json"),
});
const local = await prepareNormalizedLocalImport(
  normalizeSemgrepFindings(capture, {}, "local"),
  { repository, provider: "semgrep", sourceKey: selected.sourceKey },
);
console.log(local.preview);
await local.import();
console.table(await listLocalExternalImports({ repository }));
JS
```

The history shows two imports. The Guardian request selected string ID `9007199254740993` from a response containing two findings. A live MCP connection supplies the same collector's `callTool`.

In Codex, open the same checkout with the same workbench state and say **“Preview the high-severity findings from these two imports for publication to my Cloud repository.”** Codex reads the stored versions and shows the source groups and exclusions for review. [User walkthrough](../../docs/scanner-imports/workbench.md) · [SDK selection and publication](../../sdk/typescript/docs/sdk.md#import-external-findings)

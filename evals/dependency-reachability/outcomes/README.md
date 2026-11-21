# Should the investigation finish?

In this experiment, the caller asks which dependency version an application selects, where it calls the dependency, and which artifact was recorded for that source revision. A complete answer cites the pinned version and application call, identifies the artifact by its full digest, and explains what the evidence establishes. A release record establishes artifact identity. A conclusion about execution requires a runtime observation.

Backstage selects `vm2` in its lockfile and constructs a VM in the scaffolder. Apache Superset pins `sqlparse` in its requirements and calls the parser in `ParsedQuery`. The CLI inspects each public checkout and gets release records from a local MCP server over stdio. All release data and provider failures are synthetic. The source versions and citations come from the pinned checkouts. [Case definitions](cases.mjs)

| MCP scenario | Evidence available for the requested revision | Expected decision |
| --- | --- | --- |
| `healthy` | The current inventory returns the digest. | Publish |
| `transient` | The first query returns a 429. A retry returns the digest. | Publish |
| `alternate` | The current inventory keeps returning 429. An archived record supplies the digest. | Publish |
| `persistent` | The current inventory keeps returning 429 and the archive is empty. | Stop and explain the missing record |
| `partial` | The call succeeds with the service and revision. The digest is missing from both sources. | Stop and explain the missing digest |

Each question runs under the ordinary claim reviewer, `--reviewer=disabled`, and the experimental `--reviewer=outcome`. All three get the same caller instructions and required outcomes. In outcome mode a fresh grader reads the proposed report and its evidence. It can ask the investigator to fill a gap and submit another draft. Every outcome needs approval on the final draft. After at most three grades, unresolved requirements produce a structured blocked result. The caller can accept an unknown where the evidence supports that boundary. Here the caller explicitly requires the digest.

## Run a comparison

From the repository root, build the CLI and plugin, put OpenGrep on `PATH`, and set `OPENAI_API_KEY` or `CODEX_API_KEY` for the isolated CLI sessions. The fixture and scoring tests run offline with Git and Node.js. [Build instructions](../README.md#start-from-a-fresh-checkout) · [OpenGrep installation](https://github.com/opengrep/opengrep#installation)

```sh
suite=evals/dependency-reachability/outcomes
node --test "$suite"/*.test.mjs
repos=$(mktemp -d)
runs=$(mktemp -d)
git clone --filter=blob:none --no-checkout https://github.com/backstage/backstage.git "$repos/backstage"
git -C "$repos/backstage" checkout --detach 99d7a6f42d71e86578c89c0669a3d962088ed8ae
git clone --filter=blob:none --no-checkout https://github.com/apache/superset.git "$repos/superset"
git -C "$repos/superset" checkout --detach c35842e9f1c987d5e684969540fea3d8a5d03ad9
```

Try a retry and a permanent outage on Superset in all three modes. This starts six regular `codex-security exploitability check` investigations. Each has its own state directory and provider. The runner shares a newly generated digest across modes for the same question and scenario. Set `model` to a model available to your account.

```sh
model=gpt-6.1-sol
node "$suite/run.mjs" --repos "$repos" --out "$runs/superset" --model "$model" \
  --case superset --scenario transient --scenario persistent --jobs 3
```

For the full matrix, omit the filters. For parallel work on different builds, pass `--cli /path/to/sdk/typescript/bin/codex-security.mjs` and choose a new output directory per run. Use `--reviewer outcome` to run only the experimental mode. `--help` lists every selector.

```sh
node "$suite/run.mjs" --repos "$repos" --out "$runs/full" --model "$model" --jobs 3
```

## Read a result

`results.json` records every completed investigation and the planned count. Compare decisions on recoverable cases and missing-evidence cases separately. An incomplete publication, an unnecessary stop, and a CLI or grader failure have different consequences. A nonzero runner exit means some cases failed or execution was interrupted.

Under `<case>/<scenario>/<reviewer>/`, `command.json` records the actual CLI arguments and `input.json` records the question and the generated reference. Compare `calls.json` with the saved `report.json` or `blocked.json`. The progress log records each outcome decision and request for revision. `result.json` explains which checks passed. A successful publication needs the version, pinned source citations, the digest in the investigator's answer, and a matching retained receipt. The eval checks the returned digest against the provider's independent journal. A successful stop needs a structured explanation of the missing record after the scoped lookup. Operational errors count as failures. [Scoring checks](grade.mjs) · [Provider behavior](inventory.mjs)

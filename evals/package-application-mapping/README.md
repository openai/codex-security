# Package-to-application mapping

This eval gives Codex a package name and the service-resolution section of the
dependency skill. The agent uses the production graph tools in a read-only
checkout. The catalog resolver gets a synthetic read-only MCP. The grader
checks the final graph for catalog service names, IDs, and record citations.

| Case                      | Expected graph result                                                                                              |
| ------------------------- | ------------------------------------------------------------------------------------------------------------------ |
| `external-launcher`       | The catalog identity for the consumer selected by the launch command. CI and a similarly named project are decoys. |
| `shared-project`          | Two separately scoped apps that launch the same consumer with different settings.                                  |
| `runnable-package`        | A cited empty catalog result for a package with a start script and no service record.                              |
| `shared-library-consumer` | The app that reaches the package through a shared workspace library.                                               |
| `catalog-unavailable`     | Source evidence with no named service or catalog result, even when the checkout contains service declarations.     |

From the repository root, with SDK dependencies installed and Codex signed in,
run the cases in parallel.

```sh
pnpm --dir sdk/typescript run build:plugin
pnpm --dir sdk/typescript run build:evals
node --experimental-strip-types evals/package-application-mapping/run.mts
```

Use `--case ID` for one case or `--model MODEL` and `--effort EFFORT` to select
the model and reasoning effort. Each run writes graph snapshots, the grade,
wall time, and investigator and catalog token usage under `reports/`. Run the grader tests offline with
`node --experimental-strip-types --test evals/package-application-mapping/test_grade.mts`.

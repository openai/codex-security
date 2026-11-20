# Package-to-application mapping

These five cases run the installed dependency investigator on synthetic Git checkouts. Each one supplies the same package and vulnerability description. The CLI receives the caller scope and, when available, a read-only service-catalog MCP. The catalog records, grading oracle and result directory live outside the checkout. The grader reads host-recorded graph queries from the reviewed report and verifies the catalog IDs, tool citations, consumer path and graph revision.

| Case                      | What must be established                                                                                    |
| ------------------------- | ----------------------------------------------------------------------------------------------------------- |
| `external-launcher`       | Find the launcher for the consumer in use, ignoring a similarly named project and a CI job.                 |
| `shared-project`          | Find both applications that launch the same project and keep each catalog identity and configuration scope. |
| `runnable-package`        | Cite the catalog's empty result for a runnable package.                                                     |
| `shared-library-consumer` | Follow a workspace library to the application that launches its consumer.                                   |
| `catalog-unavailable`     | Keep service identity unresolved even when the repository contains local catalog declarations.              |

Run from the repository root, with a built or installed CLI, model credentials and OpenGrep available. `--cli` takes the JavaScript entry point. Omit `--case` to run all five cases concurrently. `--out` takes a new directory. Each completed case retains its full report. Execution failures retain the command's diagnostic output.

```sh
node --experimental-strip-types evals/package-application-mapping/run.mjs --cli "$CLI" --model "$MODEL" --out "$OUT"
node --experimental-strip-types --test evals/package-application-mapping/test_grade.mts
```

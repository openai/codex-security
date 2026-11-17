# Sampled stack fixture

Run `node prepare.mjs <new-directory> fixed` or `node prepare.mjs <new-directory> unbound` from this directory. Each invocation creates a Git checkout under `target` and writes `sources.json`, `sinks.json` and `stacks.json` next to it. The synthetic advisory affects sample-codec versions below 2.0.0.

The fixed variant binds the sampled image digest to sample-codec 2.1.0 in a committed deployment receipt. The unbound variant contains the same caller and frames and leaves the running version unknown. The grading expectations stay outside both checkouts in `expected.json`.

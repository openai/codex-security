import config from "./promptfooconfig.sastbench.mts";

export default {
  ...config,
  description:
    "Codex Security triage-finding representative SastBench v0.1 sample",
  tags: { suite: "sastbench-v0.1-representative-sample" },
  tests: "file://./scripts/sastbench-lib.mts:generateSampleTests",
};

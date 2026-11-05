import { readFileSync } from "node:fs";

interface WorkflowStep {
  name?: string;
  id?: string;
  uses?: string;
  with?: Record<string, unknown>;
  run?: string;
  if?: string;
  shell?: string;
  env?: Record<string, unknown>;
  "continue-on-error"?: boolean;
}

interface WorkflowJob {
  uses?: string;
  needs?: string | string[];
  if?: string;
  environment?: string;
  outputs?: Record<string, string>;
  with?: Record<string, unknown>;
  env?: Record<string, unknown>;
  strategy?: { matrix: Record<string, unknown> | string };
  steps?: WorkflowStep[];
}

export function workflow(name: string) {
  return Bun.YAML.parse(
    readFileSync(
      new URL(`../../../../.github/workflows/${name}.yml`, import.meta.url),
      "utf8",
    ),
  ) as {
    on: Record<string, unknown>;
    env?: Record<string, unknown>;
    concurrency?: { group: string; queue?: string };
    jobs: Record<string, WorkflowJob>;
  };
}

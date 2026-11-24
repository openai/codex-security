import { readFileSync } from "node:fs";

export interface WorkflowStep {
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

interface Concurrency {
  group: string;
  queue?: string;
  "cancel-in-progress"?: boolean | string;
}

interface WorkflowJob {
  name?: string;
  permissions?: Record<string, string>;
  secrets?: Record<string, string>;
  concurrency?: Concurrency;
  "timeout-minutes"?: number | string;
  "continue-on-error"?: boolean;
  "cache-mode"?: string;
  uses?: string;
  needs?: string | string[];
  if?: string;
  environment?: string;
  outputs?: Record<string, string>;
  with?: Record<string, unknown>;
  env?: Record<string, unknown>;
  strategy?: {
    "fail-fast"?: boolean;
    matrix: Record<string, unknown> | string;
  };
  steps?: WorkflowStep[];
}

export interface Workflow {
  on: Record<string, unknown> & {
    workflow_call?: { secrets?: Record<string, { required?: boolean }> };
    pull_request?: { types?: string[] };
  };
  env?: Record<string, unknown>;
  permissions?: Record<string, string>;
  concurrency?: Concurrency;
  jobs: Record<string, WorkflowJob>;
}

export function workflowSource(name: string) {
  return readFileSync(
    new URL(`../../../../.github/workflows/${name}.yml`, import.meta.url),
    "utf8",
  );
}

export function parseWorkflow(source: string) {
  return Bun.YAML.parse(source) as Workflow;
}

export function workflow(name: string) {
  return parseWorkflow(workflowSource(name));
}

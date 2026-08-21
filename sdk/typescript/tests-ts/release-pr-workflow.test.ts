import { readFileSync } from "node:fs";
import { describe, expect, test } from "bun:test";

const workflow = readFileSync(
  new URL("../../../.github/workflows/node-release-pr.yml", import.meta.url),
  "utf8",
);
const config = Bun.YAML.parse(workflow) as {
  on: {
    workflow_run: {
      workflows: string[];
      types: string[];
      branches: string[];
    };
    workflow_dispatch: { inputs: { dry_run: { type: string } } };
  };
  permissions: Record<string, never>;
  concurrency: { group: string; queue: string };
  jobs: {
    propose: {
      if: string;
      permissions: Record<string, string>;
      steps: Array<{
        name: string;
        uses?: string;
        with?: Record<string, string | number | boolean>;
        run?: string;
      }>;
    };
  };
};
const job = config.jobs.propose;
const steps = job.steps;
const script = steps.find(
  (step) => step.name === "Propose the next patch release",
)?.run;

if (!script) throw new Error("The release proposal step is missing.");

describe("patch release PR workflow", () => {
  test("runs only after trusted main workflows or a main dispatch", () => {
    expect(config.permissions).toEqual({});
    expect(config.concurrency).toEqual({
      group: "node-release-pr",
      queue: "max",
    });
    expect(config.on.workflow_run).toEqual({
      workflows: ["node-ci", "node-github-release"],
      types: ["completed"],
      branches: ["main"],
    });
    expect(config.on.workflow_dispatch.inputs.dry_run.type).toBe("boolean");
    expect(job.if).toContain("github.repository == 'openai/codex-security'");
    expect(job.if).toContain(
      "github.event.workflow_run.head_repository.full_name == github.repository",
    );
    expect(job.if).toContain(
      "github.event.workflow_run.conclusion == 'success'",
    );
    expect(job.if).toContain("github.event.workflow_run.event == 'push'");
    expect(job.if).toContain("github.ref == 'refs/heads/main'");
  });

  test("uses only the repository-scoped release App for writes", () => {
    expect(job.permissions).toEqual({ actions: "read", contents: "read" });
    const tokenStep = steps.find(
      (step) => step.name === "Create release App token",
    );
    expect(tokenStep?.with).toMatchObject({
      "permission-actions": "read",
      "permission-contents": "write",
      "permission-pull-requests": "write",
    });
    expect(workflow).toContain("RELEASE_APP_CLIENT_ID");
    expect(workflow).toContain("RELEASE_APP_PRIVATE_KEY");
    expect(workflow).toContain("steps.release-app-token.outputs.token");
    expect(workflow).toContain("steps.release-app-token.outputs.app-slug");
    expect(workflow).not.toContain("github.token");
  });

  test("pins actions and works from verified current main", () => {
    const actions = steps.flatMap((step) => (step.uses ? [step.uses] : []));
    expect(actions.length).toBeGreaterThan(0);
    for (const action of actions) {
      expect(action).toMatch(/^[a-z0-9-]+\/[a-z0-9-]+@[a-f0-9]{40}$/u);
    }
    const checkout = steps.find(
      (step) => step.name === "Checkout current main",
    );
    expect(checkout?.with).toMatchObject({
      "fetch-depth": 0,
      "persist-credentials": false,
      ref: "refs/heads/main",
    });
    expect(script).toContain("head_sha=$base_sha");
    expect(script).toContain('git switch --detach "$base_sha"');
  });

  test("preserves existing proposals before rejecting an orphan branch", () => {
    const existingProposal = script.indexOf(
      'existing_pr="$(find_higher_version_pr "$current_version")"',
    );
    const orphanGuard = script.indexOf(
      'remote_branch="$(git ls-remote --heads origin',
    );
    expect(existingProposal).toBeGreaterThan(-1);
    expect(orphanGuard).toBeGreaterThan(existingProposal);
    expect(script).toContain("Preserving intentionally closed release PR");
    expect(script).toContain("Preserving existing same-repository release PR");
    expect(script).toContain("--no-renames");
  });

  test("creates a one-line manifest commit with create-only branch semantics", () => {
    expect(script).toContain("git diff --numstat");
    expect(script).toContain("git diff --check");
    expect(script).toContain('git commit -m "release: bump');
    expect(script).toContain('git config user.name "$release_app_user"');
    expect(script).toContain('--force-with-lease="refs/heads/$branch:"');
    expect(script).toContain(
      "Main changed before the release branch was pushed",
    );
    expect(script).toContain("does not match the expected release commit");
  });

  test("distinguishes an absent release from an API failure", () => {
    expect(script).toContain("release(tagName: $tag)");
    expect(script).toContain(".data.repository.release == null");
    expect(script).toContain(".data.repository.release |");
    expect(script).not.toContain("gh release view");
  });

  test("renders the canonical unchecked template and cannot publish", () => {
    expect(script).toContain(".github/PULL_REQUEST_TEMPLATE.md");
    expect(
      script.indexOf('readFileSync(".github/PULL_REQUEST_TEMPLATE.md"'),
    ).toBeLessThan(script.indexOf("git push"));
    expect(script).not.toContain("- [x]");
    expect(script).toContain("@codex review");
    expect(script).not.toMatch(/\b(?:npm|pnpm)\s+publish\b/u);
    expect(script).not.toMatch(/\bgh\s+(?:release\s+create|workflow\s+run)\b/u);
    expect(script).not.toMatch(/\bgit\s+tag\b/u);
    expect(script).not.toMatch(/\bgh\s+pr\s+merge\b/u);
  });
});

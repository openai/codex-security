import { spawnSync } from "node:child_process";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { expect, test } from "bun:test";

const ci = Bun.YAML.parse(
  await readFile(
    new URL("../../../.github/workflows/node-ci.yml", import.meta.url),
    "utf8",
  ),
) as {
  jobs: Record<
    string,
    {
      if?: string;
      steps: { name: string; if?: string; run: string }[];
    }
  >;
};

// These scripts run in Ubuntu Bash in CI, independent of the CLI platform.
const bashTest = test.skipIf(process.platform === "win32");

bashTest(
  "selects workflow checks for workflow changes and main pushes",
  async () => {
    const scope = ci.jobs["validate-title"]!.steps.find(
      (step) => step.name === "Decide CI mode",
    )!;
    const directory = await mkdtemp(join(tmpdir(), "workflow-quality-"));
    try {
      for (const [event, baseChanged, paths, expected] of [
        ["push", false, [], "true"],
        ["pull_request", true, [], "true"],
        ["pull_request", false, [".github/workflows/node-release.yml"], "true"],
        [
          "pull_request",
          false,
          [".github/actions/download-native/action.yml"],
          "true",
        ],
        ["pull_request", false, [".github/actionlint.yaml"], "true"],
        ["pull_request", false, [".github/zizmor.yml"], "true"],
        ["pull_request", false, ["docker/verify-container-compose.sh"], "true"],
        ["pull_request", false, ["sdk/typescript/src/index.ts"], "false"],
        ["pull_request", false, ["README.md"], "false"],
      ] as const) {
        const output = join(directory, "output");
        await rm(output, { force: true });
        const result = spawnSync(
          "bash",
          [
            "-c",
            'changed_paths=("$@"); git() { if ((${#changed_paths[@]})); then printf "%s\\0" "${changed_paths[@]}"; fi; }\n' +
              scope.run,
            "scope",
            ...paths,
          ],
          {
            encoding: "utf8",
            env: {
              ...process.env,
              EVENT_NAME: event,
              BASE_CHANGED: String(baseChanged),
              GITHUB_OUTPUT: output,
            },
          },
        );
        expect(result.status, result.stderr).toBe(0);
        const outputs = Object.fromEntries(
          (await readFile(output, "utf8"))
            .trim()
            .split("\n")
            .map((line) => line.split("=")),
        );
        expect(outputs["workflow-quality"], paths.join(",")).toBe(expected);
      }
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  },
);

bashTest(
  "required Unix checks fail when selected workflow checks do not pass",
  () => {
    const aggregate = ci.jobs["required-test"]!;
    expect(aggregate.if).toBe("always()");
    const gate = aggregate.steps.find(
      (step) => step.name === "Require selected workflow checks",
    )!;
    const condition = gate
      .if!.replaceAll(
        "needs.validate-title.outputs.workflow-quality",
        '"$SELECTED"',
      )
      .replaceAll("needs.workflow-quality.result", '"$RESULT"');
    for (const [selected, result, expected] of [
      ["true", "success", 0],
      ["true", "failure", 1],
      ["true", "cancelled", 1],
      ["true", "skipped", 1],
      ["false", "skipped", 0],
    ] as const) {
      const execution = spawnSync(
        "bash",
        ["-c", `if [[ ${condition} ]]; then\n${gate.run}\nfi`],
        {
          encoding: "utf8",
          env: { ...process.env, SELECTED: selected, RESULT: result },
        },
      );
      expect(execution.status, execution.stderr).toBe(expected);
    }
  },
);

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
  on: { pull_request: { types: string[] } };
  concurrency: { group: string; "cancel-in-progress": string };
  jobs: Record<
    string,
    {
      name: string;
      needs?: string | string[];
      if?: string;
      strategy?: { matrix: Record<string, string[]> };
      steps: { name: string; if?: string; run: string }[];
    }
  >;
};

// These workflow expressions use boolean/string operators shared with JavaScript.
// Evaluate the YAML itself so routing and check-name regressions are exercised.
function expression(source: string, context: Record<string, unknown>): unknown {
  return new Function(...Object.keys(context), `return (${source});`)(
    ...Object.values(context),
  );
}

function interpolate(source: string, context: Record<string, unknown>): string {
  return source.replace(/\$\{\{(.*?)\}\}/g, (_, value: string) =>
    String(expression(value, context)),
  );
}

function eventContext(
  action: string,
  changes: Record<string, unknown> = {},
  title = "test(ci): update checks",
) {
  return {
    github: {
      workflow: "node-ci",
      event_name: action === "push" ? "push" : "pull_request",
      event: {
        action,
        changes,
        pull_request: action === "push" ? {} : { number: 1, title },
      },
      run_id: 123,
    },
    always: () => true,
  };
}

const aggregates = [
  ...ci.jobs["required-test"]!.strategy!.matrix["os"]!.map(
    (os) => ["required-test", { os }, `${os} / node-22`] as const,
  ),
  ...ci.jobs["windows"]!.strategy!.matrix["node"]!.map(
    (node) =>
      [
        "windows",
        { node },
        `windows-latest / node-${node === "22.13.0" ? "22" : node}`,
      ] as const,
  ),
];

test.each([
  ["push", {}, true],
  ["opened", {}, true],
  ["synchronize", {}, true],
  ["reopened", {}, true],
  ["edited", { base: { ref: { from: "main" } } }, true],
  ["edited", { title: { from: "Previous title" } }, false],
  ["edited", { body: { from: "Previous body" } }, false],
  ["edited", {}, false],
] as const)(
  "routes %s / %p without replacing required source checks",
  (action, changes, sourceEvent) => {
    const context = eventContext(action, changes);
    const classifier = ci.jobs["classify-changes"]!;
    expect(expression(classifier.if!, context)).toBe(sourceEvent);
    for (const [id, matrix, name] of aggregates) {
      const aggregate = ci.jobs[id]!;
      expect(expression(aggregate.if!, context)).toBe(sourceEvent);
      expect(interpolate(aggregate.name, { ...context, matrix })).toBe(
        sourceEvent ? name : `metadata / ${name}`,
      );
    }
    const sourceGroup = interpolate(
      ci.concurrency.group,
      eventContext("synchronize"),
    );
    const group = interpolate(ci.concurrency.group, context);
    expect(group === sourceGroup).toBe(sourceEvent && action !== "push");
    expect(interpolate(ci.concurrency["cancel-in-progress"], context)).toBe(
      action === "push" ? "false" : "true",
    );
  },
);

test("all source jobs depend on classification and titles cannot block source checks", () => {
  expect(aggregates.map(([, , name]) => name)).toEqual([
    "ubuntu-latest / node-22",
    "macos-latest / node-22",
    "windows-latest / node-22",
    "windows-latest / node-24",
  ]);
  expect(ci.on.pull_request.types).toEqual([
    "opened",
    "edited",
    "reopened",
    "synchronize",
  ]);
  for (const [id, job] of Object.entries(ci.jobs)) {
    if (id !== "classify-changes") {
      const dependencies = Array.isArray(job.needs) ? job.needs : [job.needs];
      expect(dependencies, id).toContain("classify-changes");
    }
  }
  const classifier = ci.jobs["classify-changes"]!;
  expect(JSON.stringify(classifier)).not.toContain("PR_TITLE");
  expect(
    expression(classifier.if!, eventContext("opened", {}, "Invalid title")),
  ).toBe(true);
});

const musl = Bun.YAML.parse(
  await readFile(
    new URL("../../../.github/workflows/native-musl.yml", import.meta.url),
    "utf8",
  ),
) as {
  jobs: {
    primitives: {
      strategy: {
        matrix: {
          include: {
            arch: string;
            "rust-image": string;
            "node22-image": string;
            "node20-image": string;
          }[];
        };
      };
      steps: { name: string; run: string }[];
    };
  };
};

// These scripts run in Ubuntu Bash in CI, independent of the CLI platform.
const bashTest = test.skipIf(process.platform === "win32");

bashTest(
  "title corrections validate independently on every target branch",
  async () => {
    const titleWorkflow = Bun.YAML.parse(
      await readFile(
        new URL(
          "../../../.github/workflows/validate-pr-title.yml",
          import.meta.url,
        ),
        "utf8",
      ),
    ) as typeof ci;
    expect(titleWorkflow.on.pull_request).not.toHaveProperty("branches");
    expect(titleWorkflow.on.pull_request.types).toEqual(
      ci.on.pull_request.types,
    );
    const step = titleWorkflow.jobs["validate-pr-title"]!.steps.find(
      (candidate) => candidate.name === "Check conventional title",
    )!;
    for (const [title, expected] of [
      ["Invalid title", 1],
      ["test(ci): valid title", 0],
      ["test(ci): valid title\nInvalid continuation", 1],
      ["test(ci): corrected title", 0],
    ] as const) {
      const result = spawnSync("bash", ["-c", step.run], {
        encoding: "utf8",
        env: { ...process.env, PR_TITLE: title },
      });
      expect(result.status, result.stderr).toBe(expected);
    }
  },
);

bashTest(
  "selects workflow and runner checks for relevant changes and main pushes",
  async () => {
    const scope = ci.jobs["classify-changes"]!.steps.find(
      (step) => step.name === "Select additional checks",
    )!;
    const directory = await mkdtemp(join(tmpdir(), "workflow-quality-"));
    try {
      for (const [
        event,
        baseChanged,
        paths,
        expected,
        runnerExpected = "false",
      ] of [
        ["push", false, [], "true"],
        ["pull_request", true, [], "true", "true"],
        ["pull_request", false, [".github/workflows/node-release.yml"], "true"],
        [
          "pull_request",
          false,
          [".github/actions/download-native/action.yml"],
          "true",
        ],
        ["pull_request", false, [".github/actionlint.yaml"], "true"],
        ["pull_request", false, [".github/zizmor.yml"], "true"],
        [
          "pull_request",
          false,
          [".github/scripts/release-progress.mjs"],
          "true",
        ],
        [
          "pull_request",
          false,
          [".github/scripts/test_release_progress.mjs"],
          "true",
        ],
        [
          "pull_request",
          false,
          ["sdk/typescript/scripts/release-pr.mjs"],
          "true",
        ],
        ["pull_request", false, ["docker/verify-container-compose.sh"], "true"],
        ["pull_request", false, ["sdk/typescript/src/index.ts"], "false"],
        ["pull_request", false, ["README.md"], "false"],
        [
          "pull_request",
          false,
          [".github/workflows/node-ci.yml"],
          "true",
          "true",
        ],
        [
          "pull_request",
          false,
          [".github/workflows/test-quality.yml"],
          "true",
          "true",
        ],
        [
          "pull_request",
          false,
          [".github/actions/setup-tools/action.yml"],
          "true",
          "true",
        ],
        ...[
          "sdk/typescript/bunfig.toml",
          "sdk/typescript/scripts/compare-test-reports.mts",
          "sdk/typescript/scripts/prepare-windows-test-root.ps1",
          "sdk/typescript/scripts/run-ci-tests.mts",
          "sdk/typescript/scripts/test-shards.mts",
          "sdk/typescript/scripts/test-timings.json",
        ].map(
          (path) => ["pull_request", false, [path], "false", "true"] as const,
        ),
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
        expect(outputs["test-quality"], paths.join(",")).toBe(runnerExpected);
      }
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  },
);

for (const target of musl.jobs.primitives.strategy.matrix.include) {
  for (const scenario of ["ecr-success", "ecr-failure", "both-fail"] as const) {
    bashTest(`musl ${target.arch} image pulls: ${scenario}`, async () => {
      const directory = await mkdtemp(join(tmpdir(), "musl-image-pulls-"));
      const environment = join(directory, "environment");
      const dockerLog = join(directory, "docker-log");
      const images = {
        RUST_IMAGE: target["rust-image"],
        NODE22_IMAGE: target["node22-image"],
        NODE20_IMAGE: target["node20-image"],
      };
      const run = (name: string) =>
        musl.jobs.primitives.steps.find((step) => step.name === name)!.run;
      try {
        const result = spawnSync(
          "bash",
          [
            "-e",
            "-c",
            `
              : > "$GITHUB_ENV"
              : > "$DOCKER_LOG"
              docker() {
                printf '%s\\n' "$*" >> "$DOCKER_LOG"
                case "$1:$2" in
                  pull:public.ecr.aws/*) [[ "$PULL_SCENARIO" == ecr-success ]] ;;
                  pull:docker.io/*) [[ "$PULL_SCENARIO" != both-fail ]] ;;
                  *) return 0 ;;
                esac
              }
              ${run("Pull pinned musl images")}
              source "$GITHUB_ENV"
              ${run("Assemble pinned musl compiler image")}
              ${run("Verify the same artifact with Node.js 22 and 20")}
            `,
          ],
          {
            encoding: "utf8",
            env: {
              ...process.env,
              ...images,
              GITHUB_ENV: environment,
              DOCKER_LOG: dockerLog,
              PULL_SCENARIO: scenario,
            },
          },
        );
        const calls = (await readFile(dockerLog, "utf8")).trim().split("\n");
        const selectedEnvironment = await readFile(environment, "utf8");
        const fallback = (image: string) =>
          image.replace("public.ecr.aws/docker/library/", "docker.io/library/");
        if (scenario === "both-fail") {
          expect(result.status, result.stderr).toBe(1);
          expect(calls).toEqual([
            `pull ${images.RUST_IMAGE}`,
            `pull ${fallback(images.RUST_IMAGE)}`,
          ]);
          expect(selectedEnvironment).toBe("");
          return;
        }

        expect(result.status, result.stderr).toBe(0);
        const selected = Object.fromEntries(
          Object.entries(images).map(([name, image]) => [
            name,
            scenario === "ecr-failure" ? fallback(image) : image,
          ]),
        );
        expect(selectedEnvironment).toBe(
          Object.entries(selected)
            .map(([name, image]) => `${name}=${image}\n`)
            .join(""),
        );
        expect(calls.filter((call) => call.startsWith("pull "))).toEqual(
          Object.values(images).flatMap((image) =>
            scenario === "ecr-failure"
              ? [`pull ${image}`, `pull ${fallback(image)}`]
              : [`pull ${image}`],
          ),
        );
        const build = calls.find((call) => call.startsWith("build "))!;
        expect(build).toContain(
          `--build-arg RUST_IMAGE=${selected["RUST_IMAGE"]}`,
        );
        expect(build).toContain(
          `--build-arg NODE_IMAGE=${selected["NODE22_IMAGE"]}`,
        );
        const runs = calls.filter((call) => call.startsWith("run "));
        expect(runs).toHaveLength(2);
        expect(runs[0]).toContain(`${selected["NODE22_IMAGE"]} /bin/sh`);
        expect(runs[1]).toContain(`${selected["NODE20_IMAGE"]} /bin/sh`);
      } finally {
        await rm(directory, { recursive: true, force: true });
      }
    });
  }
}

bashTest(
  "required Unix checks fail when selected workflow checks do not pass",
  () => {
    const aggregate = ci.jobs["required-test"]!;
    expect(aggregate.if).toContain("always()");
    const gate = aggregate.steps.find(
      (step) => step.name === "Require selected workflow checks",
    )!;
    const condition = gate
      .if!.replaceAll(
        "needs.classify-changes.outputs.workflow-quality",
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

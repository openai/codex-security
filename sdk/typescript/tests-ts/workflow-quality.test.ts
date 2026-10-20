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
  "selects workflow checks for workflow changes and main pushes",
  async () => {
    const scope = ci.jobs["validate-title"]!.steps.find(
      (step) => step.name === "Select additional checks",
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

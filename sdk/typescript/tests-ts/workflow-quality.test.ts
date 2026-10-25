import { execFileSync, spawnSync } from "node:child_process";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
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
  ["ci", {}, "ci"] as const,
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
    "ci",
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

test("classification uses the PR merge diff and validates retargeted merge parents", async () => {
  const scope = ci.jobs["classify-changes"]!.steps.find(
    (step) => step.name === "Select required checks",
  )!;
  const [command, script] = scope.run.split(" ");
  expect(command).toBe("node");
  const directory = await mkdtemp(join(tmpdir(), "ci-merge-diff-"));
  const repository = join(directory, "repository");
  const output = join(directory, "outputs");
  await mkdir(repository);
  const git = (...args: string[]) =>
    execFileSync(
      "git",
      [
        "-c",
        "user.name=CI Test",
        "-c",
        "user.email=ci@example.invalid",
        "-c",
        "commit.gpgsign=false",
        ...args,
      ],
      { cwd: repository, encoding: "utf8", stdio: "pipe" },
    );
  try {
    git("init", "-b", "main");
    await writeFile(join(repository, "README.md"), "Original documentation\n");
    git("add", ".");
    git("commit", "-m", "Initial fixture");
    git("checkout", "-b", "docs");
    await writeFile(join(repository, "README.md"), "Updated documentation\n");
    git("commit", "-am", "Update documentation");
    git("checkout", "main");
    await writeFile(
      join(repository, "runtime.ts"),
      "export const value = 1;\n",
    );
    git("add", ".");
    git("commit", "-m", "Independent base change");
    git("merge", "--no-ff", "docs", "-m", "Merge fixture");
    const classify = (env: Record<string, string> = {}) =>
      spawnSync(
        command!,
        [fileURLToPath(new URL(`../../../${script}`, import.meta.url))],
        {
          cwd: repository,
          encoding: "utf8",
          env: {
            ...process.env,
            EVENT_NAME: "pull_request",
            BASE_CHANGED: "false",
            GITHUB_OUTPUT: output,
            ...env,
          },
        },
      );
    const result = classify();
    expect(result.status, result.stderr).toBe(0);
    const outputs = Object.fromEntries(
      (await readFile(output, "utf8"))
        .trim()
        .split("\n")
        .map((line) => line.split("=")),
    );
    expect(outputs["source-required"]).toBe("false");
    expect(outputs["container-validate"]).toBe("false");
    expect(outputs["workflow-quality"]).toBe("false");

    const base = git("rev-parse", "HEAD^1").trim();
    const head = git("rev-parse", "docs").trim();
    const old = git("rev-parse", "HEAD^1^1").trim();
    const eventPath = join(directory, "event.json");
    for (const [expectedBase, expectedHead, valid] of [
      [base, head, true],
      [old, head, false],
      [base, old, false],
    ] as const) {
      await writeFile(
        eventPath,
        JSON.stringify({
          pull_request: {
            base: { ref: "main", sha: expectedBase },
            head: { sha: expectedHead },
          },
        }),
      );
      await writeFile(output, "");
      const retarget = classify({
        BASE_CHANGED: "true",
        GITHUB_EVENT_PATH: eventPath,
      });
      expect(retarget.status, retarget.stderr).toBe(valid ? 0 : 1);
      const selection = await readFile(output, "utf8");
      if (valid) expect(selection).toContain("workflow-quality=true");
      else {
        expect(retarget.stdout).toContain(`${base} ${head}`);
        expect(retarget.stderr).toContain("stale test merge");
        expect(selection).toBe("");
      }
    }
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

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

test("legacy required check names propagate the final CI gate result", () => {
  for (const id of ["required-test", "windows"]) {
    const aggregate = ci.jobs[id]!;
    expect(aggregate.needs).toContain("ci");
    expect(aggregate.if).toContain("always()");
    const gate = aggregate.steps.find(
      (step) => step.name === "Require CI gate",
    )!;
    expect(gate.run).toBe("exit 1");
    for (const result of ["success", "failure", "cancelled", "skipped"]) {
      expect(expression(gate.if!, { needs: { ci: { result } } })).toBe(
        result !== "success",
      );
    }
  }
});

import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, test } from "bun:test";
import { parse } from "smol-toml";
import {
  type AttackPathDataflow,
  type AttackPathReachability,
  CodexSecurity,
  CodexSecurityError,
  VERSION,
} from "../src/index.js";
import { main } from "../src/cli.js";
import { capture } from "./cli-fixtures.js";
import { bashCommand, runCommand } from "./support/shell.js";

const { selectChecks } = (await import(
  new URL("../../../.github/scripts/select-ci-checks.mjs", import.meta.url).href
)) as {
  selectChecks(
    paths: string[],
    options: { event: string; baseChanged?: boolean },
  ): Record<
    "compatibility-matrix" | "windows-node-matrix" | "python-matrix",
    string
  >;
};

interface WorkflowStep {
  name?: string;
  id?: string;
  uses?: string;
  with?: Record<string, unknown>;
  run?: string;
  if?: string;
  env?: Record<string, unknown>;
  "continue-on-error"?: boolean;
}

interface WorkflowJob {
  name?: string;
  needs?: string | string[];
  env?: Record<string, unknown>;
  strategy?: { matrix: Record<string, unknown> | string };
  steps?: WorkflowStep[];
}

async function workflow(name: string) {
  return Bun.YAML.parse(
    await readFile(
      new URL(`../../../.github/workflows/${name}`, import.meta.url),
      "utf8",
    ),
  ) as {
    on: Record<string, unknown>;
    env?: Record<string, unknown>;
    jobs: Record<string, WorkflowJob>;
  };
}

describe("TypeScript package skeleton", () => {
  test("pins one Codex version across the CLI, MCP app, and evals", async () => {
    const directories = [
      "sdk/typescript",
      "plugins/codex-security/mcp-app",
      "evals/triage-finding",
    ];
    const manifests = await Promise.all(
      directories.map(async (directory) =>
        JSON.parse(
          await readFile(
            new URL(`../../../${directory}/package.json`, import.meta.url),
            "utf8",
          ),
        ),
      ),
    );
    const version = manifests[0].dependencies["@openai/codex"];
    expect(version).toBeTruthy();
    for (const [index, directory] of directories.entries()) {
      expect(manifests[index].dependencies["@openai/codex-sdk"]).toBe(version);
      const lockfile = Bun.YAML.parse(
        await readFile(
          new URL(`../../../${directory}/pnpm-lock.yaml`, import.meta.url),
          "utf8",
        ),
      ) as {
        packages: Record<string, { os?: string[]; cpu?: string[] }>;
      };
      expect(
        Object.keys(lockfile.packages).filter((name) =>
          name.startsWith("@openai/codex-sdk@"),
        ),
      ).toEqual([`@openai/codex-sdk@${version}`]);
      for (const [name, metadata] of Object.entries(lockfile.packages)) {
        if (name.startsWith("@openai/codex@")) {
          const platform =
            metadata.os && metadata.cpu
              ? `-${metadata.os[0]}-${metadata.cpu[0]}`
              : "";
          expect(name).toBe(`@openai/codex@${version}${platform}`);
        }
      }
    }
  });

  test("exports typed attack-path aliases", () => {
    const dataflow: AttackPathDataflow = {
      transformations: ["decode archive entry"],
    };
    const reachability: AttackPathReachability = {
      attacker: "authenticated uploader",
      entrypoint: "archive upload endpoint",
      preconditions: ["archive extraction is enabled"],
    };
    const transformations: string[] | undefined = dataflow.transformations;
    const attacker: string | undefined = reachability.attacker;

    expect(transformations).toEqual(["decode archive entry"]);
    expect(attacker).toBe("authenticated uploader");
  });

  test("advertises the tested Node.js 22, 24, and 26 release lines", async () => {
    const packageJson = JSON.parse(
      await readFile(new URL("../package.json", import.meta.url), "utf8"),
    );

    const supportedReleases = ["22.13.0", "22.14.0", "24.0.0", "26.0.0"];
    const unsupportedReleases = [
      "22.12.0",
      "23.0.0",
      "23.4.0",
      "23.5.0",
      "25.0.0",
      "27.0.0",
    ];

    expect(
      supportedReleases.filter((version) =>
        Bun.semver.satisfies(version, packageJson.engines.node),
      ),
    ).toEqual(supportedReleases);
    expect(
      unsupportedReleases.filter((version) =>
        Bun.semver.satisfies(version, packageJson.engines.node),
      ),
    ).toEqual([]);
  });

  test("runs Bun once per OS and checks every supported Node runtime with the installed package", async () => {
    const { jobs } = await workflow("node-ci.yml");
    const selected = selectChecks([], { event: "push" });
    expect(jobs["test"]?.strategy?.matrix).toEqual({
      os: ["ubuntu-latest", "macos-latest"],
      shard: [1, 2, 3, 4, 5, 6],
    });
    expect(jobs["compatibility"]?.strategy?.matrix).toBe(
      "${{ fromJSON(needs.classify-changes.outputs.compatibility-matrix) }}",
    );
    expect(JSON.parse(selected["compatibility-matrix"]).include).toEqual([
      ...["22.13.0", "24.0.0", "24", "26.0.0", "26"].map((node) => ({
        os: "ubuntu-latest",
        node,
      })),
      { os: "macos-latest", node: "22.13.0" },
    ]);
    expect(jobs["windows-test"]?.strategy?.matrix).toEqual({
      shard: [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14],
    });
    expect(jobs["windows-verify"]?.strategy?.matrix).toBe(
      "${{ fromJSON(needs.classify-changes.outputs.windows-node-matrix) }}",
    );
    expect(JSON.parse(selected["windows-node-matrix"]).node).toEqual([
      "22.13.0",
      "24",
    ]);
    const verificationSteps = jobs["windows-verify"]!.steps!;
    const shardPython = jobs["windows-test"]!.steps!.find(({ uses }) =>
      uses?.startsWith("actions/setup-python@"),
    );
    const pythonSetup = verificationSteps.findIndex(({ uses }) =>
      uses?.startsWith("actions/setup-python@"),
    );
    const packageInspection = verificationSteps.findIndex(
      ({ run }) => run === "node scripts/check-package.mjs ../../dist/*.tgz",
    );
    expect(shardPython?.uses).toMatch(/^actions\/setup-python@[a-f0-9]{40}$/);
    expect(pythonSetup).toBeGreaterThanOrEqual(0);
    expect(pythonSetup).toBeLessThan(packageInspection);
    expect(verificationSteps[pythonSetup]).toMatchObject({
      uses: shardPython?.uses,
      with: { "python-version": "3.12" },
    });
    expect(verificationSteps[pythonSetup]).not.toHaveProperty("if");
    expect(verificationSteps[pythonSetup]).not.toHaveProperty(
      "continue-on-error",
    );
    expect([false, "false"]).not.toContain(
      verificationSteps[pythonSetup]?.with?.["update-environment"],
    );
    expect(jobs["required-test"]?.name).toEndWith("${{ matrix.os }} / node-22");
    expect(jobs["ci"]?.needs).toEqual([
      "classify-changes",
      "static-checks",
      "native",
      "package",
      "test",
      "compatibility",
      "mcp",
      "plugin-host",
      "plugin-source",
      "container-validate",
      "workflow-quality",
      "windows-test",
      "windows-verify",
    ]);
    for (const name of ["required-test", "windows"]) {
      expect(jobs[name]?.needs).toEqual(["classify-changes", "ci"]);
    }
    for (const name of ["compatibility", "windows-verify"]) {
      expect(jobs[name]?.steps).toContainEqual(
        expect.objectContaining({
          run: "node scripts/check-package.mjs ../../dist/*.tgz",
        }),
      );
      expect(jobs[name]?.steps!.some(({ name }) => name === "Set up Bun")).toBe(
        false,
      );
    }
  });

  test("reuses npm downloads after lockfile changes without skipping package installation", async () => {
    const { jobs } = await workflow("node-ci.yml");
    for (const name of ["compatibility", "windows-verify"]) {
      const steps = jobs[name]!.steps!;
      const setup = steps.findIndex(({ id }) => id === "node");
      const resolver = steps.findIndex(({ id }) => id === "npm-cache");
      const restore = steps.findIndex(({ uses }) =>
        uses?.startsWith("actions/cache/restore@"),
      );
      const inspection = steps.findIndex(
        ({ name }) => name === "Inspect installed package",
      );
      expect(setup).toBeGreaterThanOrEqual(0);
      expect(setup).toBeLessThan(resolver);
      expect(resolver).toBeLessThan(restore);
      expect(restore).toBeLessThan(inspection);
      expect(steps[setup]?.with?.["cache"]).toBe("npm");
      expect(steps[resolver]?.env).toEqual({
        PRIMARY_CACHE_KEY: "${{ steps.node.outputs.cache-primary-key }}",
      });
      for (const index of [resolver, restore]) {
        expect(steps[index]?.if).toBe("steps.node.outputs.cache-hit != 'true'");
      }
      expect(steps[restore]?.with).toEqual({
        path: "${{ steps.npm-cache.outputs.path }}",
        key: "${{ steps.node.outputs.cache-primary-key }}",
        "restore-keys": "${{ steps.npm-cache.outputs.restore-prefix }}",
      });
      expect(steps[inspection]).not.toHaveProperty("if");
    }
  });

  test("npm cache fallback shares lockfile versions within each platform and architecture", async () => {
    const { jobs } = await workflow("node-ci.yml");
    const script = jobs["compatibility"]!.steps!.find(
      ({ id }) => id === "npm-cache",
    )!.run!;
    const directory = await mkdtemp(join(tmpdir(), "npm-cache-workflow-"));
    try {
      for (const platform of ["Windows-x64", "Windows-arm64", "Linux-x64"]) {
        for (const hash of ["a".repeat(64), "b".repeat(64)]) {
          const cachePath = platform.startsWith("Windows")
            ? "C:\\npm cache"
            : "/tmp/npm cache";
          const output = join(directory, "output.txt");
          await rm(output, { force: true });
          const result = await runCommand(
            bashCommand(),
            [
              "-e",
              "-o",
              "pipefail",
              "-c",
              `npm() { test "$*" = "config get cache" && printf '%s\\n' "$TEST_NPM_CACHE"; }\n${script}`,
            ],
            {
              cwd: directory,
              env: {
                ...process.env,
                PRIMARY_CACHE_KEY: `node-cache-${platform}-npm-${hash}`,
                GITHUB_OUTPUT: "output.txt",
                TEST_NPM_CACHE: cachePath,
              },
            },
          );
          expect(result.status, result.stderr).toBe(0);
          expect(
            (await readFile(output, "utf8")).trim().split(/\r?\n/u),
          ).toEqual([
            `path=${cachePath}`,
            `restore-prefix=node-cache-${platform}-npm-`,
          ]);
        }
      }
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  });

  test("randomizes tests and keeps the default and Windows CI timeouts", async () => {
    const packageJson = JSON.parse(
      await readFile(new URL("../package.json", import.meta.url), "utf8"),
    );
    const { jobs } = await workflow("node-ci.yml");
    const bunConfig = parse(
      await readFile(new URL("../bunfig.toml", import.meta.url), "utf8"),
    );
    expect(packageJson.scripts.test).toBe(
      "node --run build:plugin && bun test --timeout 30000 ./tests-ts",
    );
    expect(bunConfig).toMatchObject({ test: { randomize: true } });
    expect(packageJson.scripts["test:ci"]).toContain("pnpm run test ");
    expect(jobs["windows-test"]?.steps).toContainEqual(
      expect.objectContaining({
        run: "node --experimental-strip-types sdk/typescript/scripts/run-ci-tests.mts ${{ matrix.shard }}/14 --seed=${{ github.run_number }}",
      }),
    );
  });

  test("covers the Python runtime floor and native platform paths", async () => {
    const { jobs } = await workflow("node-ci.yml");
    const job = jobs["plugin-source"]!;
    const selected = selectChecks([], { event: "push" });
    expect(job.strategy?.matrix).toBe(
      "${{ fromJSON(needs.classify-changes.outputs.python-matrix) }}",
    );
    expect(JSON.parse(selected["python-matrix"]).include).toEqual([
      ...["3.10", "3.12", "3.14"].map((python) => ({
        os: "ubuntu-latest",
        python,
        markers: "",
      })),
      {
        os: "macos-latest",
        python: "3.12",
        markers: "cross_platform or native_macos",
      },
      {
        os: "windows-latest",
        python: "3.12",
        markers: "cross_platform or native_windows",
      },
    ]);
    const testStep = job.steps!.find(
      ({ name }) => name === "Test Python source contracts",
    )!;
    expect(testStep.env?.["PYTEST_MARKERS"]).toBe("${{ matrix.markers }}");
    expect(testStep.run).toContain(
      'python -m pytest plugins/codex-security/tests -m "$PYTEST_MARKERS"',
    );
    expect(testStep).not.toHaveProperty("if");
    expect(testStep).not.toHaveProperty("continue-on-error");
    const nativeCoverageStep = job.steps!.find(
      ({ name }) => name === "Require native platform coverage",
    )!;
    expect(nativeCoverageStep.if).toBe("runner.os != 'Linux'");
    expect(nativeCoverageStep.run).toContain(".//testcase/skipped");
    expect(nativeCoverageStep).not.toHaveProperty("continue-on-error");
    for (const name of [
      "Install plugin dependencies",
      "Set up Node.js for triage evals",
      "Set up triage eval dependencies and host runtime",
    ]) {
      expect(job.steps!.find((step) => step.name === name)?.if).toBe(
        "matrix.os == 'ubuntu-latest' && matrix.python == '3.12'",
      );
    }
    expect(jobs["ci"]?.needs).toContain("plugin-source");
    expect(jobs["required-test"]?.needs).toContain("ci");
    expect(jobs["windows"]?.needs).toContain("ci");
  });

  test("checks one archive and restores its plugin before every test shard", async () => {
    const { jobs } = await workflow("node-ci.yml");
    const uploads = jobs["package"]!.steps!;
    const inspection = uploads.findIndex(
      ({ name }) => name === "Inspect archive contents",
    );
    const upload = uploads.findIndex(
      ({ name }) => name === "Upload package for this commit",
    );
    expect(inspection).toBeGreaterThanOrEqual(0);
    expect(inspection).toBeLessThan(upload);
    expect(uploads[upload]?.with).toMatchObject({
      name: "package-${{ github.sha }}",
      "if-no-files-found": "error",
    });
    expect(uploads[upload]).not.toHaveProperty("continue-on-error");
    for (const name of [
      "test",
      "windows-test",
      "mcp",
      "compatibility",
      "windows-verify",
    ]) {
      const job = jobs[name]!;
      expect(job.needs).toContain("package");
      expect(
        job.steps!.find(
          ({ name }) => name === "Download package for this commit",
        )?.with,
      ).toEqual({ name: "package-${{ github.sha }}", path: "dist" });
    }
    for (const name of ["test", "windows-test", "mcp"]) {
      const steps = jobs[name]!.steps!;
      const restore = steps.findIndex(
        ({ name }) => name === "Restore bundled plugin",
      );
      const testStep = steps.findIndex(
        ({ name }) =>
          name === "Test" ||
          name === "Test shard ${{ matrix.shard }}" ||
          name === "Test MCP app",
      );
      expect(restore).toBeGreaterThanOrEqual(0);
      expect(restore).toBeLessThan(testStep);
      expect(steps[restore]?.run).toContain("package/_bundled_plugin");
      expect(steps[testStep]).not.toHaveProperty("continue-on-error");
    }
  });

  test("installs ripgrep before the independent MCP job", async () => {
    const { jobs } = await workflow("node-ci.yml");
    const steps = jobs["mcp"]!.steps!;
    const ripgrep = steps.findIndex(({ name }) => name === "Install ripgrep");
    const tests = steps.findIndex(({ name }) => name === "Test MCP app");
    expect(steps[ripgrep]?.run).toContain("apt-get install --yes ripgrep");
    expect(ripgrep).toBeLessThan(tests);
    expect(
      jobs["test"]!.steps!.some(({ name }) => name === "Test MCP app"),
    ).toBe(false);
  });

  test("runs static checks independently and keeps diagnostic uploads non-blocking", async () => {
    const { jobs } = await workflow("node-ci.yml");
    const steps = Object.values(jobs).flatMap((job) => job.steps ?? []);
    expect(jobs["static-checks"]?.needs).toBe("classify-changes");
    expect(jobs["package"]?.needs).toEqual(["classify-changes", "native"]);
    for (const [name, job] of [
      ["Check plugin source boundary", "package"],
      ["Typecheck", "static-checks"],
      ["Check formatting", "static-checks"],
      ["Check MCP formatting", "static-checks"],
      ["Audit production dependencies", "static-checks"],
    ] as const) {
      expect(
        jobs[job]!.steps!.filter((step) => step.name === name),
      ).toHaveLength(1);
    }
    for (const name of [
      "Upload test reports",
      "Upload Windows test reports",
      "Upload MCP test reports",
      "Upload Python test reports",
    ]) {
      expect(steps.find((step) => step.name === name)).toMatchObject({
        if: "always()",
        "continue-on-error": true,
      });
    }
    expect(
      jobs["plugin-source"]!.steps!.find(
        ({ name }) => name === "Test Python source contracts",
      )?.run,
    ).toContain(
      "-n 4 --dist worksteal --max-worker-restart 0 --durations=30 --junitxml=reports/python.xml",
    );
  });

  test("runs Windows native proofs with and without symbolic-link privileges", async () => {
    const { jobs } = await workflow("native-windows.yml");
    const job = jobs["primitives"]!;
    expect(job.env?.["CODEX_SECURITY_TEST_WINDOWS_SYMLINKS"]).toBe("required");
    const restricted = job.steps!.find(
      (step) => step.name === "Verify Windows proofs without symbolic links",
    );
    expect(restricted?.env?.["CODEX_SECURITY_TEST_WINDOWS_SYMLINKS"]).toBe(
      "disabled",
    );
    expect(restricted).not.toHaveProperty("continue-on-error");
  });

  test("keeps machine-wide policy changes out of shared and diagnostic shards", async () => {
    const ci = await workflow("node-ci.yml");
    const windows = ci.jobs["windows-test"]!.steps!;
    expect(
      windows.find((step) => step.name === "Test shard ${{ matrix.shard }}")
        ?.env?.["CODEX_SECURITY_ALLOW_MACHINE_POLICY_TEST"],
    ).toBe("false");
    expect(
      windows.find(
        (step) => step.name === "Test machine-wide PowerShell policy",
      ),
    ).toMatchObject({
      if: "matrix.shard == 3 && runner.environment == 'github-hosted'",
      env: { CODEX_SECURITY_ALLOW_MACHINE_POLICY_TEST: "true" },
      "timeout-minutes": 7,
      run: "bun test --timeout 360000 ./tests-ts/windows-machine-policy.test.ts",
    });
    const quality = await workflow("test-quality.yml");
    expect(Object.keys(quality.on).sort()).toEqual([
      "schedule",
      "workflow_call",
      "workflow_dispatch",
    ]);
    expect(ci.jobs).not.toHaveProperty("test-quality");
    expect(quality.env?.["CODEX_SECURITY_ALLOW_MACHINE_POLICY_TEST"]).toBe(
      "false",
    );
    expect(quality.env?.["CODEX_SECURITY_INTEGRATION"]).toBe("0");
  });

  test("keeps shard layouts reproducible and report uploads rerunnable", async () => {
    const ci = await workflow("node-ci.yml");
    const quality = await workflow("test-quality.yml");
    const runner = quality.jobs["runner"]!;
    const seed =
      "${{ github.event_name == 'pull_request' && 1 || github.run_number }}";
    expect(quality.env).not.toHaveProperty("CODEX_SECURITY_PROPERTY_SEED");
    expect(runner.env?.["CODEX_SECURITY_PROPERTY_SEED"]).toBe(seed);
    for (const trigger of ["workflow_call", "workflow_dispatch"]) {
      expect(quality.on[trigger]).toMatchObject({
        inputs: { "compare-layouts": { type: "boolean", default: true } },
      });
    }
    expect(quality.jobs["properties"]).toMatchObject({
      env: { CODEX_SECURITY_PROPERTY_SEED: "${{ github.run_number }}" },
      strategy: {
        matrix: { os: ["ubuntu-latest", "macos-latest", "windows-latest"] },
      },
    });
    const unixMatrix = ci.jobs["test"]!.strategy!.matrix as Record<
      string,
      unknown
    >;
    const unixShards = unixMatrix["shard"] as number[];
    const windowsMatrix = ci.jobs["windows-test"]!.strategy!.matrix as Record<
      string,
      unknown
    >;
    const windowsShards = windowsMatrix["shard"] as number[];
    expect(runner.strategy?.matrix).toEqual({
      target: ["baseline", "expanded"].flatMap((mode) => [
        ...(unixMatrix["os"] as string[]).flatMap((os) => {
          const count = mode === "baseline" ? 3 : unixShards.length;
          return Array.from({ length: count }, (_, index) => ({
            os,
            shard: index + 1,
            count,
            mode,
          }));
        }),
        ...Array.from(
          { length: mode === "baseline" ? 7 : windowsShards.length },
          (_, index) => ({
            os: "windows-latest",
            shard: index + 1,
            count: mode === "baseline" ? 7 : windowsShards.length,
            mode,
          }),
        ),
      ]),
    });
    for (const job of [
      runner,
      ci.jobs["test"]!,
      ci.jobs["windows-test"]!,
      quality.jobs["mutation"]!,
    ]) {
      expect(
        job
          .steps!.filter((step) => step.uses?.startsWith("oven-sh/setup-bun@"))
          .map((step) => step.with?.["bun-version"]),
      ).toEqual(["1.3.14"]);
      for (const step of job.steps!) {
        expect(step.run ?? "").not.toMatch(
          /--(?:parallel|isolate)(?:[=\s]|$)/u,
        );
      }
    }
    const execution = runner.steps!.find(
      (step) => step.name === "Test shard layout",
    );
    const ripgrep = runner.steps!.find(
      (step) => step.name === "Install ripgrep",
    );
    expect(ripgrep).toMatchObject({
      if: "runner.os == 'Linux'",
      run: ci.jobs["test"]!.steps!.find(
        (step) => step.name === "Install ripgrep",
      )?.run,
    });
    expect(runner.steps!.indexOf(ripgrep!)).toBeLessThan(
      runner.steps!.indexOf(execution!),
    );
    expect(execution).toMatchObject({
      "working-directory": "sdk/typescript",
    });
    expect(execution?.run).toContain(
      "scripts/run-ci-tests.mts ${{ env.SHARD }}",
    );
    expect(execution?.run).toContain(
      "--seed=${{ env.CODEX_SECURITY_PROPERTY_SEED }}",
    );

    const uploads = [...Object.values(ci.jobs), ...Object.values(quality.jobs)]
      .flatMap((job) => job.steps ?? [])
      .filter((step) => step.uses?.startsWith("actions/upload-artifact@"));
    for (const upload of uploads) {
      expect(upload.with?.["overwrite"]).toBe(true);
    }
    expect(
      uploads.find((step) => step.name === "Upload mutation report"),
    ).toMatchObject({ "continue-on-error": true });
    const runnerUpload = uploads.find(
      (step) => step.name === "Upload runner report",
    );
    expect(runnerUpload).not.toHaveProperty("continue-on-error");
    expect(runnerUpload?.with?.["name"]).toBe("runner-${{ env.REPORT_ID }}");
    expect(runner.env?.["SHARD"]).toBe(
      "${{ matrix.target.shard }}/${{ matrix.target.count }}",
    );
    expect(runner.env?.["REPORT_ID"]).toBe(
      "${{ matrix.target.os }}-${{ matrix.target.mode }}-${{ matrix.target.shard }}",
    );
    expect(
      quality.jobs["mutation"]?.steps!.find(
        (step) => step.name === "Run mutation trial",
      ),
    ).not.toHaveProperty("continue-on-error");
  });

  test("builds packages without a preinstalled package manager and provides a production audit", async () => {
    const packageJson = JSON.parse(
      await readFile(new URL("../package.json", import.meta.url), "utf8"),
    );

    expect(packageJson.scripts.build).not.toMatch(/\b(?:pnpm|npm|bun)\b/u);
    expect(packageJson.scripts.build).toMatch(/^node --run clean &&/u);
    expect(packageJson.scripts["build:plugin"]).toBe(
      "node scripts/build-plugin.mjs",
    );
    expect(packageJson.scripts["check:plugin-source"]).toBe(
      "node scripts/check-plugin-source.mjs",
    );
    expect(packageJson.scripts.prepack).toBe(
      "node --run build:plugin && node --run build",
    );
    expect(packageJson.scripts.types).not.toContain("check:plugin-source");
    expect(packageJson.scripts["audit:prod"]).toBe(
      "pnpm audit --prod --audit-level high",
    );
  });

  test("blocks CI and releases when the production dependency audit fails", async () => {
    for (const workflowName of ["node-ci.yml", "node-release.yml"]) {
      const { jobs } = await workflow(workflowName);
      const audits = Object.values(jobs)
        .flatMap((job) => job.steps ?? [])
        .filter((step) => step.name === "Audit production dependencies");
      expect(audits.length).toBeGreaterThan(0);
      for (const audit of audits) {
        expect(audit).not.toHaveProperty("continue-on-error");
        expect(audit.run).toMatch(
          /^(?:sfw )?pnpm --dir sdk\/typescript run audit:prod$/u,
        );
      }
    }
  });

  test("exports the async client and curated error base", async () => {
    const packageJson = JSON.parse(
      await readFile(new URL("../package.json", import.meta.url), "utf8"),
    );
    const client = new CodexSecurity({ pluginPath: "/tmp/plugin" });
    expect(client.config.pluginPath).toBe("/tmp/plugin");
    expect(client.metadata).toEqual({
      sdk: "@openai/codex-sdk",
      sdkVersion: packageJson.dependencies["@openai/codex-sdk"],
      executable: "@openai/codex",
      executableVersion: packageJson.dependencies["@openai/codex"],
    });
    expect(new CodexSecurityError("failure").name).toBe("CodexSecurityError");
    await client.close();
  });

  test("provides executable help and version behavior", async () => {
    const stdout = capture(null);
    const stderr = capture(null);
    expect(await main([], stdout.stream, stderr.stream)).toBe(0);
    expect(stdout.text()).toContain("Usage: codex-security <command>");
    expect(stdout.text()).toContain("Integrations:");
    expect(stderr.text()).toBe("");

    const versionOutput = capture(null);
    expect(await main(["--version"], versionOutput.stream, stderr.stream)).toBe(
      0,
    );
    expect(versionOutput.text()).toBe(`${VERSION}\n`);

    const scanHelpOutput = capture(null);
    expect(
      await main(["scan", "--help"], scanHelpOutput.stream, stderr.stream),
    ).toBe(0);
    expect(scanHelpOutput.text()).toContain(
      "Usage: codex-security scan [repository]",
    );
  });
});

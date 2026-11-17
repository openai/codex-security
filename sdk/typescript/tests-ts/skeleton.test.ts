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
} from "../src/index.js";
import { bashCommand, runCommand } from "./support/shell.js";
import { workflow } from "./support/workflow.js";

describe("TypeScript package skeleton", () => {
  const ci = workflow("node-ci");
  const quality = workflow("test-quality");

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

  test("runs Bun once per OS and checks every supported Node runtime with the installed package", () => {
    expect(ci.jobs["test"]?.strategy?.matrix).toEqual({
      os: ["ubuntu-latest", "macos-latest"],
      shard: [1, 2, 3, 4, 5, 6],
    });
    expect(ci.jobs["compatibility"]?.strategy?.matrix).toBe(
      "${{ fromJSON(needs.classify-changes.outputs.compatibility-matrix) }}",
    );
    expect(ci.jobs["windows-test"]?.strategy?.matrix).toEqual({
      shard: [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14],
    });
    const verificationSteps = ci.jobs["compatibility"]!.steps!;
    const shardPython = ci.jobs["windows-test"]!.steps!.find(({ uses }) =>
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
      if: "runner.os == 'Windows'",
      uses: shardPython?.uses,
      with: { "python-version": "3.12" },
    });
    expect(verificationSteps[pythonSetup]).not.toHaveProperty(
      "continue-on-error",
    );
    expect([false, "false"]).not.toContain(
      verificationSteps[pythonSetup]?.with?.["update-environment"],
    );
    expect(verificationSteps[packageInspection]?.shell).toBe("bash");
    expect(verificationSteps.some(({ name }) => name === "Set up Bun")).toBe(
      false,
    );
  });

  test("reuses npm downloads after lockfile changes without skipping package installation", () => {
    const steps = ci.jobs["compatibility"]!.steps!;
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
  });

  test("npm cache fallback shares lockfile versions within each platform and architecture", async () => {
    const script = ci.jobs["compatibility"]!.steps!.find(
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
    const bunConfig = parse(
      await readFile(new URL("../bunfig.toml", import.meta.url), "utf8"),
    );
    expect(packageJson.scripts.test).toBe(
      "node --run build:plugin && bun test --timeout 30000 ./tests-ts",
    );
    expect(bunConfig).toMatchObject({ test: { randomize: true } });
    expect(packageJson.scripts["test:ci"]).toContain("pnpm run test ");
    expect(
      ci.jobs["test"]?.steps?.find(({ name }) => name === "Test")?.run,
    ).toContain("--seed=${{ github.run_number }}");
    expect(ci.jobs["windows-test"]?.steps).toContainEqual(
      expect.objectContaining({
        run: "node --experimental-strip-types sdk/typescript/scripts/run-ci-tests.mts ${{ matrix.shard }}/14 --seed=${{ github.run_number }}",
      }),
    );
  });

  test("covers the Python runtime floor and native platform paths", () => {
    const job = ci.jobs["plugin-source"]!;
    expect(job.strategy?.matrix).toBe(
      "${{ fromJSON(needs.classify-changes.outputs.python-matrix) }}",
    );
    const testStep = job.steps!.find(
      ({ name }) => name === "Test Python source contracts",
    )!;
    expect(testStep.env?.["PYTEST_MARKERS"]).toBe("${{ matrix.markers }}");
    expect(testStep.run).toContain(
      'python -m pytest plugins/codex-security/tests -m "$PYTEST_MARKERS"',
    );
    expect(testStep).not.toHaveProperty("if");
    expect(testStep).not.toHaveProperty("continue-on-error");
    expect(
      job.steps!.find(({ uses }) => uses === "./.github/actions/setup-tools"),
    ).toMatchObject({
      if: "matrix.os == 'ubuntu-latest' && matrix.python == '3.12'",
      with: { compile: true },
    });
  });

  test("requires a nonempty native Python report without skips", () => {
    const step = ci.jobs["plugin-source"]!.steps!.find(
      ({ name }) => name === "Require native platform coverage",
    )!;
    expect(step).toMatchObject({
      if: "runner.os != 'Linux'",
      run: "python .github/scripts/require_native_python_report.py",
    });
    expect(step).not.toHaveProperty("continue-on-error");
  });

  test("requires the deterministic eval suites and their cross-project dependency pin", () => {
    const requiredSteps = ci.jobs["eval-contracts"]!.steps!.filter(
      (step) => !step.if && !step["continue-on-error"],
    );
    expect(requiredSteps).toContainEqual(
      expect.objectContaining({
        "working-directory": "evals/triage-finding",
        run: "node --run test:deterministic",
      }),
    );
    const commands = requiredSteps.map((step) => step.run).join("\n");
    for (const suite of [
      "secret-discovery",
      "standard-time-budget",
      "workflow-routing",
    ]) {
      expect(commands).toContain(`--test evals/${suite}/test_*.mts`);
    }
    expect(commands).toContain(
      "bun test sdk/typescript/tests-ts/codex-dependency-pins.test.ts",
    );
    const setup = requiredSteps.find(
      (step) => step.uses === "./.github/actions/setup-tools",
    );
    expect(setup?.with?.["node-version"]).toBe("24.15.0");
    expect(
      String(setup?.with?.["cache-dependency-path"]).trim().split("\n"),
    ).toEqual([
      "sdk/typescript/pnpm-lock.yaml",
      "plugins/codex-security/mcp-app/pnpm-lock.yaml",
      "evals/triage-finding/pnpm-lock.yaml",
    ]);
  });

  test("checks one archive and restores its plugin before every test shard", () => {
    const uploads = ci.jobs["package"]!.steps!;
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
    for (const name of ["test", "windows-test", "mcp", "compatibility"]) {
      const job = ci.jobs[name]!;
      expect(job.needs).toContain("package");
      expect(
        job.steps!.find(
          ({ name }) => name === "Download package for this commit",
        )?.with,
      ).toEqual({ name: "package-${{ github.sha }}", path: "dist" });
    }
    for (const name of ["test", "windows-test", "mcp"]) {
      const steps = ci.jobs[name]!.steps!;
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

  test("runs static checks independently and keeps diagnostic uploads non-blocking", () => {
    const steps = Object.values(ci.jobs).flatMap((job) => job.steps ?? []);
    expect(ci.jobs["static-checks"]?.needs).toBe("classify-changes");
    expect(ci.jobs["package"]?.needs).toEqual(["classify-changes", "native"]);
    for (const [name, job] of [
      ["Check plugin source boundary", "package"],
      ["Typecheck", "static-checks"],
      ["Check formatting", "static-checks"],
      ["Check MCP formatting", "static-checks"],
      ["Audit production dependencies", "static-checks"],
    ] as const) {
      expect(
        ci.jobs[job]!.steps!.filter((step) => step.name === name),
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
  });

  test("runs Windows native proofs with and without symbolic-link privileges", () => {
    const { jobs } = workflow("native-windows");
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

  test("keeps machine-wide policy changes out of shared and diagnostic shards", () => {
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

  test("keeps shard layouts reproducible and report uploads rerunnable", () => {
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
        job.steps!.filter(({ uses }) => uses?.startsWith("oven-sh/setup-bun@")),
      ).toMatchObject([{ with: { "bun-version-file": ".bun-version" } }]);
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
    expect(packageJson.scripts.build).toStartWith(
      "node --run clean && node scripts/generate-plugin-defaults.mjs && ",
    );
    expect(packageJson.scripts["build:plugin"]).toBe(
      "node scripts/build-plugin.mjs",
    );
    expect(packageJson.scripts["check:plugin-source"]).toBe(
      "node scripts/check-plugin-source.mjs",
    );
    expect(packageJson.scripts.prepack).toBe(
      "node scripts/check-prepack-path.mjs && node --run build && node --run build:plugin",
    );
    expect(packageJson.scripts.types).not.toContain("check:plugin-source");
    expect(packageJson.scripts["audit:prod"]).toBe(
      "pnpm audit --prod --audit-level high",
    );
  });

  test("blocks CI and releases when the production dependency audit fails", () => {
    for (const { jobs } of [ci, workflow("node-release")]) {
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
});

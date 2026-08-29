import { readFile } from "node:fs/promises";
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

interface WorkflowStep {
  name?: string;
  uses?: string;
  with?: Record<string, unknown>;
  run?: string;
  if?: string;
  env?: Record<string, unknown>;
  "continue-on-error"?: boolean;
}

interface WorkflowJob {
  name?: string;
  needs?: string[];
  env?: Record<string, unknown>;
  strategy?: { matrix: Record<string, unknown> };
  steps: WorkflowStep[];
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

function capture(): {
  stream: Pick<NodeJS.WriteStream, "write">;
  text: () => string;
} {
  let value = "";
  return {
    stream: {
      write(chunk: string | Uint8Array): boolean {
        value += chunk.toString();
        return true;
      },
    },
    text: () => value,
  };
}

describe("TypeScript package skeleton", () => {
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
    expect(jobs["test"]?.strategy?.matrix).toEqual({
      os: ["ubuntu-latest", "macos-latest"],
      shard: [1, 2, 3],
    });
    expect(jobs["compatibility"]?.strategy?.matrix).toEqual({
      os: ["ubuntu-latest"],
      node: ["22.13.0", "24.0.0", "24", "26.0.0", "26"],
      include: [{ os: "macos-latest", node: "22.13.0" }],
    });
    expect(jobs["windows-test"]?.strategy?.matrix).toEqual({
      shard: [1, 2, 3, 4, 5, 6, 7],
    });
    expect(jobs["windows-verify"]?.strategy?.matrix["node"]).toEqual([
      "22.13.0",
      "24",
    ]);
    expect(jobs["required-test"]?.name).toBe("${{ matrix.os }} / node-22");
    expect(jobs["required-test"]?.needs).toEqual([
      "validate-title",
      "package",
      "test",
      "compatibility",
      "mcp",
      "plugin-source",
    ]);
    expect(jobs["windows"]?.needs).toEqual([
      "validate-title",
      "windows-test",
      "windows-verify",
    ]);
    for (const name of ["compatibility", "windows-verify"]) {
      expect(jobs[name]?.steps).toContainEqual(
        expect.objectContaining({
          run: "node scripts/check-package.mjs ../../dist/*.tgz",
        }),
      );
      expect(jobs[name]?.steps.some(({ name }) => name === "Set up Bun")).toBe(
        false,
      );
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
        run: "node sdk/typescript/scripts/run-ci-tests.mjs ${{ matrix.shard }}/7",
      }),
    );
  });

  test("checks one archive and restores its plugin before every test shard", async () => {
    const { jobs } = await workflow("node-ci.yml");
    const uploads = jobs["package"]!.steps;
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
        job.steps.find(
          ({ name }) => name === "Download package for this commit",
        )?.with,
      ).toEqual({ name: "package-${{ github.sha }}", path: "dist" });
    }
    for (const name of ["test", "windows-test", "mcp"]) {
      const steps = jobs[name]!.steps;
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
    const steps = jobs["mcp"]!.steps;
    const ripgrep = steps.findIndex(({ name }) => name === "Install ripgrep");
    const tests = steps.findIndex(({ name }) => name === "Test MCP app");
    expect(steps[ripgrep]?.run).toContain("apt-get install --yes ripgrep");
    expect(ripgrep).toBeLessThan(tests);
    expect(
      jobs["test"]!.steps.some(({ name }) => name === "Test MCP app"),
    ).toBe(false);
  });

  test("runs shared static checks once and keeps every diagnostic upload non-blocking", async () => {
    const { jobs } = await workflow("node-ci.yml");
    const steps = Object.values(jobs).flatMap((job) => job.steps);
    for (const name of [
      "Check plugin source boundary",
      "Typecheck",
      "Check formatting",
    ]) {
      expect(steps.filter((step) => step.name === name)).toHaveLength(1);
      expect(jobs["package"]!.steps.some((step) => step.name === name)).toBe(
        true,
      );
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
      jobs["plugin-source"]!.steps.find(
        ({ name }) => name === "Test Python source contracts",
      )?.run,
    ).toContain(
      "-n 4 --dist worksteal --max-worker-restart 0 --durations=30 --junitxml=reports/python.xml",
    );
  });

  test("keeps machine-wide policy changes out of parallel and experimental runs", async () => {
    const ci = await workflow("node-ci.yml");
    const windows = ci.jobs["windows-test"]!.steps;
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
      run: "bun test --timeout 120000 ./tests-ts/windows-machine-policy.test.ts",
    });
    const quality = await workflow("test-quality.yml");
    expect(Object.keys(quality.on).sort()).toEqual([
      "pull_request",
      "schedule",
      "workflow_dispatch",
    ]);
    expect(quality.on["pull_request"]).toEqual({
      paths: [".github/workflows/test-quality.yml"],
    });
    expect(quality.env?.["CODEX_SECURITY_ALLOW_MACHINE_POLICY_TEST"]).toBe(
      "false",
    );
    expect(quality.env?.["CODEX_SECURITY_INTEGRATION"]).toBe("0");
    for (let shard = 1; shard <= 7; shard += 1) {
      expect(
        quality.jobs["runner"]?.strategy?.matrix["include"],
      ).toContainEqual({
        os: "windows-latest",
        mode: `shard-${shard}`,
        args: `--shard=${shard}/7`,
      });
    }
  });

  test("keeps runner modes reproducible and report uploads rerunnable", async () => {
    const ci = await workflow("node-ci.yml");
    const quality = await workflow("test-quality.yml");
    const runner = quality.jobs["runner"]!;
    const seed =
      "${{ github.event_name == 'pull_request' && 1 || github.run_number }}";
    expect(quality.env).not.toHaveProperty("CODEX_SECURITY_PROPERTY_SEED");
    expect(runner.env?.["CODEX_SECURITY_PROPERTY_SEED"]).toBe(seed);
    expect(runner.strategy?.matrix["mode"]).toEqual([
      "baseline",
      "isolated",
      "parallel",
    ]);
    for (const [mode, args] of [
      ["baseline", ""],
      ["isolated", "--isolate"],
      ["parallel", "--parallel=2"],
    ] as const) {
      expect(runner.strategy?.matrix["include"]).toContainEqual({
        mode,
        args,
      });
    }
    const command = runner.steps.find(
      (step) => step.name === "Test runner mode",
    )?.run;
    expect(command).toContain(
      "${{ runner.os == 'Windows' && '--timeout=120000' || '' }}",
    );
    expect(command).toContain("${{ matrix.args }}");
    expect(command).toContain("--seed=${{ env.CODEX_SECURITY_PROPERTY_SEED }}");

    const uploads = [...Object.values(ci.jobs), ...Object.values(quality.jobs)]
      .flatMap((job) => job.steps)
      .filter((step) => step.uses?.startsWith("actions/upload-artifact@"));
    for (const upload of uploads) {
      expect(upload.with?.["overwrite"]).toBe(true);
    }
    expect(
      uploads.find((step) => step.name === "Upload mutation report"),
    ).toMatchObject({ "continue-on-error": true });
    expect(
      uploads.find((step) => step.name === "Upload runner report"),
    ).not.toHaveProperty("continue-on-error");
    expect(
      quality.jobs["mutation"]?.steps.find(
        (step) => step.name === "Run mutation trial",
      ),
    ).not.toHaveProperty("continue-on-error");
  });

  test("builds packages without a preinstalled package manager and provides a production audit", async () => {
    const packageJson = JSON.parse(
      await readFile(new URL("../package.json", import.meta.url), "utf8"),
    );

    expect(packageJson.scripts.build).toBe(
      "node --run clean && tsc -p tsconfig.build.json && node scripts/build-dashboard.mjs",
    );
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

  test("keeps production dependency audits non-blocking in CI and releases", async () => {
    for (const workflowName of ["node-ci.yml", "node-release.yml"]) {
      const { jobs } = await workflow(workflowName);
      const audits = Object.values(jobs)
        .flatMap((job) => job.steps)
        .filter((step) => step.name === "Audit production dependencies");
      expect(audits.length).toBeGreaterThan(0);
      for (const audit of audits) {
        expect(audit["continue-on-error"]).toBe(true);
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
    const stdout = capture();
    const stderr = capture();
    expect(await main([], stdout.stream, stderr.stream)).toBe(0);
    expect(stdout.text()).toContain("Usage: codex-security <command>");
    expect(stdout.text()).toContain("Integrations:");
    expect(stderr.text()).toBe("");

    const versionOutput = capture();
    expect(await main(["--version"], versionOutput.stream, stderr.stream)).toBe(
      0,
    );
    expect(versionOutput.text()).toBe(`${VERSION}\n`);

    const scanHelpOutput = capture();
    expect(
      await main(["scan", "--help"], scanHelpOutput.stream, stderr.stream),
    ).toBe(0);
    expect(scanHelpOutput.text()).toContain(
      "Usage: codex-security scan [repository]",
    );
  });
});

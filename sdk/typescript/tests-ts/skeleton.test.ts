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
import { capture } from "./cli-fixtures.js";

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
  needs?: string | string[];
  env?: Record<string, unknown>;
  strategy?: { matrix: Record<string, unknown> };
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
    expect(jobs["required-test"]?.name).toBe("${{ matrix.os }} / node-22");
    expect(jobs["required-test"]?.needs).toEqual([
      "validate-title",
      "workflow-quality",
      "static-checks",
      "package",
      "test",
      "compatibility",
      "mcp",
      "plugin-host",
      "plugin-source",
      "container-validate",
    ]);
    expect(jobs["windows"]?.needs).toEqual([
      "validate-title",
      "static-checks",
      "plugin-host",
      "plugin-source",
      "windows-test",
      "windows-verify",
    ]);
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
        run: "node --experimental-strip-types sdk/typescript/scripts/run-ci-tests.mts ${{ matrix.shard }}/7",
      }),
    );
  });

  test("covers the Python runtime floor and native platform paths", async () => {
    const { jobs } = await workflow("node-ci.yml");
    const job = jobs["plugin-source"]!;
    const crossPlatformContracts = [
      "plugins/codex-security/tests/test_workbench_timestamps.py",
      "plugins/codex-security/tests/test_workbench_setup_and_migrations.py::test_deep_scan_time_limit_migration_backfills_and_repairs_existing_runs",
      "plugins/codex-security/tests/test_workbench_setup_and_migrations.py::test_workbench_upgrades_public_cli_completion_warning_migration",
      "plugins/codex-security/tests/test_workbench_setup_and_migrations.py::test_workbench_reconciles_profile_and_public_warning_histories",
      "plugins/codex-security/tests/test_workbench_db.py::test_large_patch_preview_preserves_digest_checks",
      "plugins/codex-security/tests/test_report_projection.py",
      "plugins/codex-security/tests/test_finalize_scan_contract.py::FinalizeScanContractTest::test_report_projection_preserves_data_flow_aliases_and_scalar_reachability",
      "plugins/codex-security/tests/test_finalize_scan_contract.py::FinalizeScanContractTest::test_report_projection_prefers_populated_data_flow_alias",
      "plugins/codex-security/tests/test_finalize_scan_contract.py::FinalizeScanContractTest::test_finalize_rejects_unknown_nested_code_evidence_reference",
      "plugins/codex-security/tests/test_finalize_scan_contract.py::FinalizeScanContractTest::test_finalize_accepts_nested_reference_to_legacy_code_evidence",
      "plugins/codex-security/tests/test_finalize_scan_contract.py::FinalizeScanContractTest::test_finalize_rejects_duplicate_ids_across_code_evidence_aliases",
      "plugins/codex-security/tests/test_finalize_scan_contract.py::FinalizeScanContractTest::test_sealed_rerun_accepts_legacy_unknown_evidence_references",
      "plugins/codex-security/tests/test_finalize_scan_contract.py::FinalizeScanContractTest::test_sealed_rerun_ignores_non_string_legacy_validation_scalars",
      "plugins/codex-security/tests/test_finalize_scan_contract.py::FinalizeScanContractTest::test_sealed_rerun_accepts_legacy_scalar_finding_details",
      "plugins/codex-security/tests/test_finalize_scan_contract.py::FinalizeScanContractTest::test_sealed_rerun_ignores_blank_legacy_attack_path_details",
      "plugins/codex-security/tests/test_finalize_scan_contract.py::FinalizeScanContractTest::test_sealed_rerun_accepts_formerly_free_form_finding_details",
      "plugins/codex-security/tests/test_finalize_scan_contract.py::FinalizeScanContractTest::test_sealed_rerun_rejects_malformed_canonical_root_cause",
      "plugins/codex-security/tests/test_finalize_scan_contract.py::FinalizeScanContractTest::test_recovery_ranks_legacy_and_canonical_code_evidence_equally",
      "plugins/codex-security/tests/test_finalize_scan_contract.py::FinalizeScanContractTest::test_recovery_ranks_embedded_root_cause_evidence",
      "plugins/codex-security/tests/test_finalize_scan_contract.py::FinalizeScanContractTest::test_sealed_rerun_ignores_malformed_legacy_evidence_references",
      "plugins/codex-security/tests/test_finalize_scan_contract.py::FinalizeScanContractTest::test_sealed_rerun_accepts_legacy_sequence_attack_path_details",
      "plugins/codex-security/tests/test_finalize_scan_contract.py::FinalizeScanContractTest::test_sealed_rerun_rejects_nullable_canonical_evidence_catalog",
      "plugins/codex-security/tests/test_finalize_scan_contract.py::FinalizeScanContractTest::test_sealed_rerun_accepts_nullable_legacy_evidence_catalog",
      "plugins/codex-security/tests/test_finalize_scan_contract.py::FinalizeScanContractTest::test_sealed_rerun_ignores_malformed_legacy_evidence_rows",
      "plugins/codex-security/tests/test_finalize_scan_contract.py::FinalizeScanContractTest::test_sarif_includes_legacy_code_evidence_locations",
      "plugins/codex-security/tests/test_finalize_scan_contract.py::FinalizeScanContractTest::test_sarif_normalizes_invalid_legacy_code_evidence_bounds",
      "plugins/codex-security/tests/test_finalize_scan_contract.py::FinalizeScanContractTest::test_sarif_omits_invalid_legacy_code_evidence_locations",
    ];
    expect(job.strategy?.matrix["include"]).toEqual([
      ...["3.10", "3.12", "3.14"].map((python) => ({
        os: "ubuntu-latest",
        python,
        tests: "plugins/codex-security/tests",
      })),
      {
        os: "macos-latest",
        python: "3.12",
        tests: "plugins/codex-security/tests/test_workbench_scan_usage.py",
        "cross-platform-tests": crossPlatformContracts.join(" "),
      },
      {
        os: "windows-latest",
        python: "3.12",
        tests: "plugins/codex-security/tests/test_windows_scan_local_files.py",
        "cross-platform-tests": crossPlatformContracts.join(" "),
      },
    ]);
    const testStep = job.steps!.find(
      ({ name }) => name === "Test Python source contracts",
    )!;
    expect(testStep.env?.["PYTHON_TEST_PATH"]).toBe(
      "${{ matrix.tests }} ${{ matrix.cross-platform-tests }}",
    );
    expect(testStep.run).toContain(
      'read -r -a python_tests <<< "$PYTHON_TEST_PATH"',
    );
    expect(testStep.run).toContain('python -m pytest "${python_tests[@]}"');
    expect(testStep).not.toHaveProperty("if");
    expect(testStep).not.toHaveProperty("continue-on-error");
    for (const name of [
      "Install plugin dependencies",
      "Build SDK and type-check eval tooling",
    ]) {
      expect(job.steps!.find((step) => step.name === name)?.if).toBe(
        "matrix.os == 'ubuntu-latest' && matrix.python == '3.12'",
      );
    }
    expect(jobs["required-test"]?.needs).toContain("plugin-source");
    expect(jobs["windows"]?.needs).toContain("plugin-source");
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
    expect(jobs["static-checks"]?.needs).toBe("validate-title");
    expect(jobs["package"]?.needs).toEqual(["validate-title", "native"]);
    for (const [name, job] of [
      ["Check plugin source boundary", "package"],
      ["Typecheck", "static-checks"],
      ["Check formatting", "static-checks"],
      ["Check MCP formatting", "static-checks"],
    ] as const) {
      expect(steps.filter((step) => step.name === name)).toHaveLength(1);
      expect(jobs[job]!.steps!.some((step) => step.name === name)).toBe(true);
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

  test("keeps machine-wide policy changes out of parallel and experimental runs", async () => {
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
    expect(ci.jobs["test-quality"]).toMatchObject({
      needs: ["validate-title", "native"],
      if: "needs.validate-title.outputs.test-quality == 'true'",
      uses: "./.github/workflows/test-quality.yml",
      with: { "native-artifacts-ready": true },
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
    const command = runner.steps!.find(
      (step) => step.name === "Test runner mode",
    )?.run;
    expect(command).toContain(
      "${{ runner.os == 'Windows' && '--timeout=120000' || '' }}",
    );
    expect(command).toContain("${{ matrix.args }}");
    expect(command).toContain("--seed=${{ env.CODEX_SECURITY_PROPERTY_SEED }}");

    const uploads = [...Object.values(ci.jobs), ...Object.values(quality.jobs)]
      .flatMap((job) => job.steps ?? [])
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
    expect(packageJson.scripts.build).toContain(
      "node scripts/build-dashboard.mjs",
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

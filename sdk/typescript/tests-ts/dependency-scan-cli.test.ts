import { describe, expect, test } from "bun:test";
import { resolve } from "node:path";
import type { DependencyCalculationOptions, ScanOptions } from "../src/api.js";
import { main } from "../src/cli.js";
import { mergedCodexConfig, scanModelConfiguration } from "../src/config.js";
import {
  DEPENDENCY_CALCULATION_EFFORT,
  DEPENDENCY_CALCULATION_MODEL,
} from "../src/dependency-calculation.js";
import { DiffTarget } from "../src/targets.js";
import {
  capture,
  dependencies,
  fakeResult,
  FakeSignals,
} from "./cli-fixtures.js";

describe("dependency scanning CLI", () => {
  test.each([
    { command: ["dependency-scan"] },
    { command: ["dependency-scan", "--dry-run"] },
    { command: ["scan", "--dependencies"] },
    { command: ["scan", "--dependencies", "--dry-run"] },
  ])(
    "rejects Deep dependency scans before starting the SDK: $command",
    async ({ command }) => {
      const errors = capture();
      const sdk = dependencies();
      let created = false;
      const createSecurity = sdk.createSecurity;
      sdk.createSecurity = (config) => {
        created = true;
        return createSecurity(config);
      };
      expect(
        await main(
          [...command, "--mode", "deep"],
          capture().stream,
          errors.stream,
          sdk,
        ),
      ).toBe(2);
      expect(errors.text()).toContain(
        "Dependency scanning does not support --mode deep",
      );
      expect(created).toBe(false);
    },
  );

  test("documents the combined flag and the dependency-only command", async () => {
    const rootHelp = capture();
    const scanHelp = capture();
    const dependencyHelp = capture();
    const scanSchema = capture();
    const dependencySchema = capture();

    expect(
      await main([], rootHelp.stream, capture().stream, dependencies()),
    ).toBe(0);
    expect(rootHelp.text()).toContain("dependency-scan");

    expect(
      await main(
        ["scan", "--help"],
        scanHelp.stream,
        capture().stream,
        dependencies(),
      ),
    ).toBe(0);
    expect(scanHelp.text()).toContain("--dependencies");
    expect(scanHelp.text()).toContain(
      "--target <malware|malware-and-vulnerabilities>",
    );

    expect(
      await main(
        ["dependency-scan", "--help"],
        dependencyHelp.stream,
        capture().stream,
        dependencies(),
      ),
    ).toBe(0);
    expect(dependencyHelp.text()).toContain(
      "Usage: codex-security dependency-scan [repository]",
    );
    expect(dependencyHelp.text()).toContain("--diff <string>");
    expect(dependencyHelp.text()).toContain("--working-tree");
    expect(dependencyHelp.text()).toContain("--auth <auto|chatgpt|api-key>");
    expect(dependencyHelp.text()).toContain(
      "--target <malware|malware-and-vulnerabilities>",
    );
    for (const role of [
      "resolution",
      "acquisition",
      "security",
      "verification",
      "history",
    ]) {
      expect(dependencyHelp.text()).toContain(`--${role}-model <string>`);
      expect(dependencyHelp.text()).toContain(`--${role}-effort`);
      expect(scanHelp.text()).toContain(`--${role}-model <string>`);
      expect(scanHelp.text()).toContain(`--${role}-effort`);
    }
    for (const flag of [
      "--dependency-depth",
      "--calculate-dependencies",
      "--dependency-graph",
    ]) {
      expect(dependencyHelp.text()).toContain(flag);
      expect(scanHelp.text()).toContain(flag);
    }
    expect(dependencyHelp.text()).not.toContain("--dependencies");

    expect(
      await main(
        ["scan", "--schema", "--format", "json"],
        scanSchema.stream,
        capture().stream,
        dependencies(),
      ),
    ).toBe(0);
    expect(JSON.parse(scanSchema.text())).toMatchObject({
      options: { properties: { dependencies: { type: "boolean" } } },
    });

    expect(
      await main(
        ["dependency-scan", "--schema", "--format", "json"],
        dependencySchema.stream,
        capture().stream,
        dependencies(),
      ),
    ).toBe(0);
    const dependencyProperties = (
      JSON.parse(dependencySchema.text()) as {
        options: { properties: Record<string, unknown> };
      }
    ).options.properties;
    expect(dependencyProperties).toHaveProperty("diff");
    expect(dependencyProperties).toHaveProperty("workingTree");
    expect(dependencyProperties).toHaveProperty("acquisitionModel");
    expect(dependencyProperties).toHaveProperty("acquisitionEffort");
    expect(dependencyProperties).toHaveProperty("securityModel");
    expect(dependencyProperties).toHaveProperty("securityEffort");
    expect(dependencyProperties).toHaveProperty("verificationModel");
    expect(dependencyProperties).toHaveProperty("verificationEffort");
    expect(dependencyProperties).toHaveProperty("historyModel");
    expect(dependencyProperties).toHaveProperty("historyEffort");
    expect(dependencyProperties).toHaveProperty("target");
    expect(dependencyProperties).toHaveProperty("dependencyDepth");
    expect(dependencyProperties).toHaveProperty("calculateDependencies");
    expect(dependencyProperties).toHaveProperty("dependencyGraph");
    expect(dependencyProperties).toHaveProperty("resolutionModel");
    expect(dependencyProperties).toHaveProperty("resolutionEffort");
    expect(dependencyProperties).not.toHaveProperty("dependencies");
  });

  test("scans all current dependencies when the dedicated command has no diff", async () => {
    const dependencyCalls: Array<{
      repository: string;
      options: ScanOptions;
    }> = [];
    const sdk = dependencies();
    const createSecurity = sdk.createSecurity;
    sdk.createSecurity = (config) => {
      const security = createSecurity(config);
      return {
        ...security,
        async scanDependencies(repository: string, options: ScanOptions = {}) {
          dependencyCalls.push({ repository, options });
          return await security.run(repository, options);
        },
      };
    };

    expect(
      await main(
        ["dependency-scan", "repository", "--auth", "chatgpt", "--json"],
        capture().stream,
        capture().stream,
        sdk,
      ),
    ).toBe(0);
    expect(dependencyCalls).toEqual([
      {
        repository: "repository",
        options: expect.objectContaining({
          auth: "chatgpt",
          dependencyScanTarget: "malware-and-vulnerabilities",
          target: "repository",
        }),
      },
    ]);
  });

  test("includes all current dependencies in an ordinary repository scan", async () => {
    let observedOptions: ScanOptions | undefined;

    expect(
      await main(
        ["scan", "repository", "--dependencies", "--auth", "chatgpt"],
        capture().stream,
        capture().stream,
        dependencies({
          onTurn: (_repository, options) => {
            observedOptions = options as ScanOptions;
          },
        }),
      ),
    ).toBe(0);

    expect(observedOptions).toMatchObject({
      dependencyScanTarget: "malware-and-vulnerabilities",
      scanDependencies: true,
      target: "repository",
    });
  });

  test("forwards role-specific model and reasoning settings without replacing the parent model", async () => {
    let observedOptions: ScanOptions | undefined;
    const sdk = dependencies();
    const createSecurity = sdk.createSecurity;
    sdk.createSecurity = (config) => {
      const security = createSecurity(config);
      return {
        ...security,
        async scanDependencies(repository: string, options: ScanOptions = {}) {
          observedOptions = options;
          return await security.run(repository, options);
        },
      };
    };

    expect(
      await main(
        [
          "dependency-scan",
          "repository",
          "--target",
          "malware",
          "--model",
          "gpt-5.6-sol",
          "--effort",
          "high",
          "--acquisition-model",
          "gpt-5.6-luna",
          "--acquisition-effort",
          "low",
          "--security-model",
          "gpt-5.6-luna",
          "--security-effort",
          "xhigh",
          "--verification-model",
          "gpt-5.6-sol",
          "--verification-effort",
          "high",
          "--history-model",
          "gpt-5.6-terra",
          "--history-effort",
          "medium",
          "--auth",
          "chatgpt",
        ],
        capture().stream,
        capture().stream,
        sdk,
      ),
    ).toBe(0);

    expect(observedOptions).toMatchObject({
      dependencyScanTarget: "malware",
      dependencyModelSettings: {
        acquisition: { model: "gpt-5.6-luna", reasoningEffort: "low" },
        scan: { model: "gpt-5.6-luna", reasoningEffort: "xhigh" },
        verification: { model: "gpt-5.6-sol", reasoningEffort: "high" },
        history: { model: "gpt-5.6-terra", reasoningEffort: "medium" },
      },
    });
  });

  test("rejects invalid or missing dependency scan targets before starting the SDK", async () => {
    for (const [arguments_, expectedError] of [
      [
        ["dependency-scan", "repository", "--target", "invalid"],
        "Invalid option",
      ],
      [
        ["scan", "repository", "--dependencies", "--target", "invalid"],
        "Invalid option",
      ],
      [
        ["dependency-scan", "repository", "--target", "--auth", "chatgpt"],
        "Missing value for flag: --target",
      ],
      [
        ["scan", "repository", "--dependencies", "--target"],
        "Missing value for flag: --target",
      ],
    ] as const) {
      let created = false;
      const errorOutput = capture();
      const sdk = dependencies();
      const createSecurity = sdk.createSecurity;
      sdk.createSecurity = (config) => {
        created = true;
        return createSecurity(config);
      };

      expect(
        await main(arguments_, capture().stream, errorOutput.stream, sdk),
      ).toBe(2);
      expect(errorOutput.text()).toContain(expectedError);
      expect(created).toBe(false);
    }
  });

  test("renders authoritative dependency package and role progress in headless mode", async () => {
    const errorOutput = capture();
    const progress = {
      jobId: "dps_fixture",
      status: "running" as const,
      packagesTotal: 11,
      packagesCompleted: 7,
      packagesCached: 5,
      packagesFailed: 1,
      packagesActive: 3,
      activePhases: [
        { phase: "acquisition" as const, count: 1 },
        { phase: "scanning" as const, count: 1 },
        { phase: "history" as const, count: 1 },
      ],
    };

    expect(
      await main(
        [
          "scan",
          "repository",
          "--dependencies",
          "--headless",
          "--auth",
          "chatgpt",
        ],
        capture().stream,
        errorOutput.stream,
        dependencies({
          activities: [
            {
              id: "dependency-job",
              kind: "tool",
              status: "completed",
              description: "Read dependency scan status",
              paths: [],
              dependencyProgress: progress,
            },
          ],
        }),
      ),
    ).toBe(0);

    expect(errorOutput.text()).toContain("Packages: 7/11");
    expect(errorOutput.text()).toContain("Cached: 5");
    expect(errorOutput.text()).toContain("Failed: 1");
    expect(errorOutput.text()).toContain("Acquisition: 1");
    expect(errorOutput.text()).toContain("Security: 1");
    expect(errorOutput.text()).toContain("History: 1");
  });

  test("reports actual dependency discovery progress in headless mode", async () => {
    const errorOutput = capture();
    const sdk = dependencies({
      activities: [
        {
          id: "dependency-discovery",
          kind: "tool",
          status: "completed",
          description:
            "update_codex_security_scan_progress · discovering dependencies",
          paths: [],
        },
      ],
    });
    const createSecurity = sdk.createSecurity;
    sdk.createSecurity = (config) => {
      const security = createSecurity(config);
      return {
        ...security,
        async scanDependencies(repository: string, options: ScanOptions = {}) {
          return await security.run(repository, options);
        },
      };
    };

    expect(
      await main(
        ["dependency-scan", "repository", "--headless", "--auth", "chatgpt"],
        capture().stream,
        errorOutput.stream,
        sdk,
      ),
    ).toBe(0);

    expect(errorOutput.text()).toContain(
      "Scan phase: discovering dependencies.",
    );
    expect(errorOutput.text()).not.toContain("reviewed");
  });

  test("does not display a source-file inventory for dedicated dependency scans", async () => {
    for (const arguments_ of [
      ["dependency-scan", "repository", "--auth", "chatgpt"],
      [
        "dependency-scan",
        "repository",
        "--diff",
        "origin/main",
        "--auth",
        "chatgpt",
      ],
    ]) {
      const errorOutput = capture(true);
      const sdk = dependencies();
      const createSecurity = sdk.createSecurity;
      sdk.createSecurity = (config) => {
        const security = createSecurity(config);
        return {
          ...security,
          async scanDependencies(
            repository: string,
            options: ScanOptions = {},
          ) {
            return await security.run(repository, options);
          },
        };
      };

      expect(
        await main(arguments_, capture().stream, errorOutput.stream, sdk),
      ).toBe(0);
      expect(errorOutput.text()).toContain("Scanning dependencies");
      expect(errorOutput.text()).not.toContain("FILES");
      expect(errorOutput.text()).not.toContain("waiting for inventory");
    }

    const combinedErrorOutput = capture(true);
    expect(
      await main(
        ["scan", "repository", "--dependencies", "--auth", "chatgpt"],
        capture().stream,
        combinedErrorOutput.stream,
        dependencies(),
      ),
    ).toBe(0);
    expect(combinedErrorOutput.text()).toContain("FILES");
    expect(combinedErrorOutput.text()).toContain("waiting for inventory");
  });

  test("opts an existing diff scan into dependency scanning", async () => {
    let observedOptions: ScanOptions | undefined;
    const output = capture();
    const errorOutput = capture();

    expect(
      await main(
        [
          "scan",
          "repository",
          "--diff",
          "origin/main",
          "--head",
          "HEAD",
          "--dependencies",
          "--target",
          "malware",
          "--auth",
          "chatgpt",
          "--json",
        ],
        output.stream,
        errorOutput.stream,
        dependencies({
          onTurn: (_repository, options) => {
            observedOptions = options as ScanOptions;
          },
        }),
      ),
    ).toBe(0);

    expect(observedOptions).toMatchObject({
      auth: "chatgpt",
      dependencyScanTarget: "malware",
      scanDependencies: true,
      target: DiffTarget.refs({ base: "origin/main", head: "HEAD" }),
    });
    expect(() => JSON.parse(output.text())).not.toThrow();
    expect(errorOutput.text()).not.toContain("Unknown flag");
  });

  test("dispatches committed and working-tree scans to the dedicated SDK method", async () => {
    for (const [arguments_, expectedTarget] of [
      [
        ["--diff", "origin/main", "--head", "feature"],
        DiffTarget.refs({ base: "origin/main", head: "feature" }),
      ],
      [
        ["--working-tree", "--base", "origin/main"],
        DiffTarget.workingTree({ base: "origin/main" }),
      ],
    ] as const) {
      const dependencyCalls: Array<{
        repository: string;
        options: ScanOptions;
      }> = [];
      const sdk = dependencies();
      const createSecurity = sdk.createSecurity;
      sdk.createSecurity = (config) => {
        const security = createSecurity(config);
        return {
          ...security,
          async scanDependencies(
            repository: string,
            options: ScanOptions = {},
          ) {
            dependencyCalls.push({ repository, options });
            return await security.run(repository, options);
          },
        };
      };

      expect(
        await main(
          [
            "dependency-scan",
            "repository",
            ...arguments_,
            "--target",
            "malware",
            "--auth",
            "chatgpt",
          ],
          capture().stream,
          capture().stream,
          sdk,
        ),
      ).toBe(0);

      expect(dependencyCalls).toHaveLength(1);
      expect(dependencyCalls[0]).toMatchObject({
        repository: "repository",
        options: {
          auth: "chatgpt",
          dependencyScanTarget: "malware",
          target: expectedTarget,
        },
      });
      expect(dependencyCalls[0]?.options).not.toHaveProperty(
        "scanDependencies",
      );
    }
  });

  test("preserves existing options on dependency-only scans", async () => {
    let observedOptions: ScanOptions | undefined;
    const sdk = dependencies();
    const createSecurity = sdk.createSecurity;
    sdk.createSecurity = (config) => {
      const security = createSecurity(config);
      return {
        ...security,
        async scanDependencies(repository: string, options: ScanOptions = {}) {
          observedOptions = options;
          return await security.run(repository, options);
        },
      };
    };

    expect(
      await main(
        [
          "dependency-scan",
          "repository",
          "--working-tree",
          "--base",
          "origin/main",
          "--knowledge-base",
          "/shared/security-context",
          "--fail-on-severity",
          "high",
          "--max-cost",
          "2",
          "--headless",
          "--auth",
          "chatgpt",
          "--json",
        ],
        capture().stream,
        capture().stream,
        sdk,
      ),
    ).toBe(0);

    expect(observedOptions).toMatchObject({
      auth: "chatgpt",
      target: DiffTarget.workingTree({ base: "origin/main" }),
      knowledgeBasePaths: ["/shared/security-context"],
      failureSeverity: "high",
      maxCostUsd: 2,
    });
    expect(observedOptions).not.toHaveProperty("scanDependencies");
  });

  test("keeps scoped dependency-only scans distinct from full-repository scans", async () => {
    for (const arguments_ of [
      ["dependency-scan", "repository"],
      ["scan", "repository", "--dependencies"],
    ]) {
      let observedOptions: ScanOptions | undefined;
      const sdk = dependencies({
        onTurn: (_repository, options) => {
          observedOptions = options as ScanOptions;
        },
      });
      const createSecurity = sdk.createSecurity;
      sdk.createSecurity = (config) => {
        const security = createSecurity(config);
        return { ...security, scanDependencies: security.run };
      };

      expect(
        await main(
          [
            ...arguments_,
            "--path",
            "services/api",
            "--path",
            "packages/core",
            "--auth",
            "chatgpt",
          ],
          capture().stream,
          capture().stream,
          sdk,
        ),
      ).toBe(0);
      expect(observedOptions?.target).toEqual([
        "services/api",
        "packages/core",
      ]);
    }
  });

  test("preserves direct-only defaults and forwards finite or all depths and saved graphs", async () => {
    for (const command of [["dependency-scan"], ["scan", "--dependencies"]]) {
      for (const depth of [undefined, "3", "all"]) {
        let observedOptions: ScanOptions | undefined;
        const sdk = dependencies({
          onTurn: (_repository, options) => {
            observedOptions = options as ScanOptions;
          },
        });
        const createSecurity = sdk.createSecurity;
        sdk.createSecurity = (config) => {
          const security = createSecurity(config);
          return { ...security, scanDependencies: security.run };
        };

        expect(
          await main(
            [
              ...command,
              "--dependency-graph",
              "saved graphs/resolver-output.json",
              ...(depth === undefined ? [] : ["--dependency-depth", depth]),
              "--auth",
              "chatgpt",
              "--json",
            ],
            capture().stream,
            capture().stream,
            sdk,
          ),
        ).toBe(0);
        expect(observedOptions?.dependencyGraphPath).toBe(
          resolve(sdk.currentDirectory(), "saved graphs/resolver-output.json"),
        );
        if (depth === undefined) {
          expect(observedOptions).not.toHaveProperty("dependencyDepth");
        } else {
          expect(observedOptions?.dependencyDepth).toBe(
            depth === "all" ? null : 3,
          );
        }
      }
    }
  });

  test("rejects invalid depths and preserves mutually exclusive target options", async () => {
    for (const arguments_ of [
      ["--dependency-depth", "0"],
      ["--dependency-depth", "-1"],
      ["--dependency-depth", "1.5"],
      ["--dependency-depth", "invalid"],
      ["--dependency-depth"],
      ["--dependency-graph"],
      ["--resolution-model"],
      ["--resolution-effort", "invalid"],
      ["--path", "src", "--diff", "main"],
      ["--path", "src", "--working-tree"],
    ]) {
      let created = false;
      const sdk = dependencies();
      const createSecurity = sdk.createSecurity;
      sdk.createSecurity = (config) => {
        created = true;
        return createSecurity(config);
      };
      expect(
        await main(
          ["dependency-scan", ...arguments_],
          capture().stream,
          capture().stream,
          sdk,
        ),
      ).toBe(2);
      expect(created).toBe(false);
    }
  });

  test("calculates scoped dependency counts without launching a scan", async () => {
    for (const command of [["dependency-scan"], ["scan", "--dependencies"]]) {
      let observedOptions: DependencyCalculationOptions | undefined;
      let scanned = false;
      let closed = false;
      const output = capture();
      const errorOutput = capture();
      const graph = resolve("saved graphs", "dependency-resolver-output.json");
      const sdk = dependencies({
        onRun: () => {
          scanned = true;
        },
        onClose: () => {
          closed = true;
        },
      });
      const createSecurity = sdk.createSecurity;
      sdk.createSecurity = (config) => {
        const security = createSecurity(config);
        return {
          ...security,
          scanDependencies: security.run,
          async calculateDependencies(_repository, options) {
            observedOptions = options;
            return { depthCounts: [2, 3, 1], dependencyGraphPath: graph };
          },
        };
      };
      expect(
        await main(
          [
            ...command,
            "--calculate-dependencies",
            "--path",
            "services/api",
            "--path",
            "packages/core",
            "--resolution-model",
            "custom-resolver",
            "--resolution-effort",
            "medium",
            "--output-dir",
            "preview-output",
            "--max-cost",
            "2",
            "--auth",
            "chatgpt",
            "--json",
          ],
          output.stream,
          errorOutput.stream,
          sdk,
        ),
      ).toBe(0);
      expect(observedOptions).toMatchObject({
        auth: "chatgpt",
        target: ["services/api", "packages/core"],
        model: "custom-resolver",
        reasoningEffort: "medium",
        outputDir: resolve("/current/repository", "preview-output"),
        maxCostUsd: 2,
      });
      expect(JSON.parse(output.text())).toEqual({
        depthCounts: [2, 3, 1],
        dependencyGraphPath: graph,
      });
      expect(errorOutput.text()).toContain(
        "Depth 2: 3 packages (5 through this depth)",
      );
      expect(errorOutput.text()).toContain("Total: 6 packages");
      expect(errorOutput.text()).toContain("No package scans were started.");
      expect(scanned).toBe(false);
      expect(closed).toBe(true);
    }
  });

  test("keeps dry-run local for dedicated scans and dependency calculations", async () => {
    for (const arguments_ of [[], ["--calculate-dependencies"]]) {
      let observedOptions: ScanOptions | undefined;
      let modelCalls = 0;
      const sdk = dependencies({
        onRun: () => {
          modelCalls += 1;
        },
      });
      const createSecurity = sdk.createSecurity;
      sdk.createSecurity = (config) => {
        const security = createSecurity(config);
        return {
          ...security,
          scanDependencies: security.run,
          async preflight(repository, options) {
            observedOptions = options;
            return security.preflight(repository, options);
          },
          async calculateDependencies() {
            modelCalls += 1;
            return { depthCounts: [], dependencyGraphPath: "unused.json" };
          },
        };
      };
      const output = capture();
      expect(
        await main(
          [
            "dependency-scan",
            ...arguments_,
            "--path",
            "services/api",
            "--dependency-depth",
            "all",
            "--dry-run",
            "--json",
          ],
          output.stream,
          capture().stream,
          sdk,
        ),
      ).toBe(0);
      expect(observedOptions).toMatchObject({
        target: ["services/api"],
        scanDependencies: true,
        dependencyDepth: null,
      });
      expect(JSON.parse(output.text())).toMatchObject({ dryRun: true });
      expect(modelCalls).toBe(0);
    }
  });

  test("calculates repository and diff targets with SDK defaults and optional saved graph reuse", async () => {
    for (const [arguments_, target] of [
      [[], "repository"],
      [
        ["--diff", "origin/main", "--head", "feature"],
        DiffTarget.refs({ base: "origin/main", head: "feature" }),
      ],
      [
        ["--working-tree", "--base", "main"],
        DiffTarget.workingTree({ base: "main" }),
      ],
    ] as const) {
      let observedOptions: DependencyCalculationOptions | undefined;
      const sdk = dependencies();
      const createSecurity = sdk.createSecurity;
      sdk.createSecurity = (config) => {
        const security = createSecurity(config);
        return {
          ...security,
          async calculateDependencies(_repository, options) {
            observedOptions = options;
            return {
              depthCounts: [2],
              dependencyGraphPath: resolve("saved.json"),
            };
          },
        };
      };
      expect(
        await main(
          [
            "scan",
            ...arguments_,
            "--calculate-dependencies",
            "--dependency-graph",
            "saved graphs/resolver-output.json",
            "--auth",
            "chatgpt",
            "--json",
          ],
          capture().stream,
          capture().stream,
          sdk,
        ),
      ).toBe(0);
      expect(observedOptions).toMatchObject({
        target,
        dependencyGraphPath: resolve(
          sdk.currentDirectory(),
          "saved graphs/resolver-output.json",
        ),
      });
      expect(observedOptions?.model).toBeUndefined();
      expect(observedOptions?.reasoningEffort).toBeUndefined();
    }
  });

  test("previews and logs the resolver model rather than the outer scan model", async () => {
    for (const dryRun of [false, true]) {
      for (const customized of [false, true]) {
        const model = customized ? "gpt-5.6-sol" : DEPENDENCY_CALCULATION_MODEL;
        const reasoningEffort = customized
          ? "high"
          : DEPENDENCY_CALCULATION_EFFORT;
        let preflightModel:
          { model: string; reasoningEffort: string } | undefined;
        let calculated = false;
        const sdk = dependencies();
        const createSecurity = sdk.createSecurity;
        sdk.createSecurity = (config) => {
          const security = createSecurity(config);
          return {
            ...security,
            async preflight(repository, options) {
              preflightModel = scanModelConfiguration(
                await mergedCodexConfig(config),
              );
              expect(config.codexOverrides).not.toHaveProperty("permissions");
              expect(config.codexOverrides).toMatchObject({
                profiles: { review: { model_provider: "openai" } },
              });
              return security.preflight(repository, options);
            },
            async calculateDependencies() {
              calculated = true;
              return {
                depthCounts: [],
                dependencyGraphPath: resolve("saved.json"),
              };
            },
          };
        };
        const output = capture();
        const errorOutput = capture();
        expect(
          await main(
            [
              "dependency-scan",
              "--calculate-dependencies",
              "--verbose",
              "--json",
              "--model",
              "outer-model",
              "--effort",
              "xhigh",
              "--codex",
              'profile="review"',
              "--codex",
              'profiles.review.model="outer-profile-model"',
              "--codex",
              'profiles.review.model_reasoning_effort="xhigh"',
              "--codex",
              'profiles.review.model_provider="openai"',
              ...(dryRun ? ["--dry-run"] : []),
              ...(customized
                ? [
                    "--resolution-model",
                    model,
                    "--resolution-effort",
                    reasoningEffort,
                  ]
                : []),
            ],
            output.stream,
            errorOutput.stream,
            sdk,
          ),
        ).toBe(0);
        expect(errorOutput.text()).toContain(`model=${JSON.stringify(model)}`);
        expect(errorOutput.text()).toContain(
          `reasoning_effort=${JSON.stringify(reasoningEffort)}`,
        );
        expect(errorOutput.text()).not.toContain('model="outer-model"');
        expect(errorOutput.text()).not.toContain('model="outer-profile-model"');
        expect(calculated).toBe(!dryRun);
        if (dryRun) {
          expect(preflightModel).toEqual({ model, reasoningEffort });
          expect(JSON.parse(output.text())).toMatchObject({
            model,
            reasoningEffort,
            dryRun: true,
          });
        }
      }
    }
  });

  test("does not report a successful preview when dependency calculation fails", async () => {
    let closed = false;
    const sdk = dependencies({
      onClose: () => {
        closed = true;
      },
    });
    const createSecurity = sdk.createSecurity;
    sdk.createSecurity = (config) => ({
      ...createSecurity(config),
      async calculateDependencies() {
        throw new Error("Unable to resolve dependencies");
      },
    });
    const output = capture();
    const errorOutput = capture();
    expect(
      await main(
        [
          "dependency-scan",
          "--calculate-dependencies",
          "--auth",
          "chatgpt",
          "--json",
        ],
        output.stream,
        errorOutput.stream,
        sdk,
      ),
    ).toBe(2);
    expect(errorOutput.text()).toContain("Unable to resolve dependencies");
    expect(errorOutput.text()).not.toContain("Dependency calculation complete");
    expect(JSON.parse(output.text())).toMatchObject({
      status: "failed",
      code: "SCAN_FAILED",
    });
    expect(closed).toBe(true);
  });

  test("closes calculation sessions and reports cancellation without starting package scans", async () => {
    const signals = new FakeSignals();
    let closed = false;
    let aborted = false;
    let scanned = false;
    const sdk = dependencies({
      signals,
      onRun: () => {
        scanned = true;
      },
      onClose: () => {
        closed = true;
      },
    });
    const createSecurity = sdk.createSecurity;
    sdk.createSecurity = (config) => {
      const security = createSecurity(config);
      return {
        ...security,
        scanDependencies: security.run,
        async calculateDependencies(_repository, options) {
          signals.emit("SIGINT");
          aborted = options?.signal?.aborted === true;
          throw new Error("calculation interrupted");
        },
      };
    };
    const errorOutput = capture();
    expect(
      await main(
        ["dependency-scan", "--calculate-dependencies", "--auth", "chatgpt"],
        capture().stream,
        errorOutput.stream,
        sdk,
      ),
    ).toBe(130);
    expect(errorOutput.text()).toContain("canceled");
    expect(aborted).toBe(true);
    expect(scanned).toBe(false);
    expect(closed).toBe(true);
  });

  test("reruns dependency recipes with the same coverage, depth, target and models", async () => {
    for (const dependencyOnly of [true, false]) {
      let observedOptions: ScanOptions | undefined;
      let dedicatedCalls = 0;
      const sdk = dependencies({
        onTurn: (_repository, options) => {
          observedOptions = options as ScanOptions;
        },
        onWorkbench: () => ({
          recipe: {
            repository: "/original/repository",
            target: { kind: "paths", paths: ["services/api", "packages/core"] },
            mode: "standard",
            config: { model: "parent-model", model_reasoning_effort: "high" },
            ...(dependencyOnly
              ? { dependencyMode: "full_dependency" }
              : { scanDependencies: true }),
            dependencyDepth: null,
            dependencyScanTarget: "malware",
            dependencyModelSettings: {
              verification: {
                model: "custom-verifier",
                reasoningEffort: "high",
              },
            },
          },
        }),
      });
      const createSecurity = sdk.createSecurity;
      sdk.createSecurity = (config) => {
        const security = createSecurity(config);
        return {
          ...security,
          async scanDependencies(_repository, options) {
            dedicatedCalls += 1;
            observedOptions = options;
            return fakeResult();
          },
        };
      };
      expect(
        await main(
          ["scans", "rerun", "original-scan"],
          capture().stream,
          capture().stream,
          sdk,
        ),
      ).toBe(0);
      expect(dedicatedCalls).toBe(dependencyOnly ? 1 : 0);
      expect(observedOptions).toMatchObject({
        target: ["services/api", "packages/core"],
        dependencyDepth: null,
        dependencyScanTarget: "malware",
        dependencyModelSettings: {
          verification: { model: "custom-verifier", reasoningEffort: "high" },
        },
      });
      expect(observedOptions).not.toHaveProperty("dependencyGraphPath");
    }
  });

  test("applies existing structured-output restrictions to dependency-only scans", async () => {
    for (const [arguments_, message] of [
      [
        ["--format", "md"],
        "Markdown output is not supported for scan results.",
      ],
      [
        ["--filter-output", "findings"],
        "--filter-output is not supported for scan results.",
      ],
    ] as const) {
      const errorOutput = capture();

      expect(
        await main(
          ["dependency-scan", "repository", "--diff", "main", ...arguments_],
          capture().stream,
          errorOutput.stream,
          dependencies(),
        ),
      ).toBe(2);
      expect(errorOutput.text()).toContain(message);
    }
  });
});

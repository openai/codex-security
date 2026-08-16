import { mkdir, mkdtemp, readFile, rm, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, test } from "bun:test";
import { parse } from "smol-toml";
import { scanRuntimeCodexConfig } from "../src/api.js";
import { scanModelConfiguration, scanModelProvider } from "../src/config.js";
import {
  ConfigurationError,
  DEFAULT_CODEX_CONFIG,
  type JsonObject,
  mergedCodexConfig,
  writeCodexConfig,
} from "../src/index.js";

const temporaryDirectories: string[] = [];

afterEach(async () => {
  await Promise.all(
    temporaryDirectories
      .splice(0)
      .map((path) => rm(path, { recursive: true, force: true })),
  );
});

async function temporaryDirectory(): Promise<string> {
  const path = await mkdtemp(join(tmpdir(), "codex-security-config-"));
  temporaryDirectories.push(path);
  return path;
}

function runPinnedCodex(codexHome: string, arguments_: readonly string[]) {
  const node = Bun.which("node");
  if (node === null) {
    throw new Error("The pinned Codex CLI requires Node.js.");
  }
  const environment: NodeJS.ProcessEnv = {
    ...process.env,
    CODEX_HOME: codexHome,
  };
  delete environment["OPENAI_API_KEY"];
  delete environment["CODEX_API_KEY"];
  return Bun.spawnSync(
    [
      node,
      join(
        import.meta.dir,
        "..",
        "node_modules",
        "@openai",
        "codex",
        "bin",
        "codex.js",
      ),
      ...arguments_,
    ],
    {
      env: environment,
      stdout: "pipe",
      stderr: "pipe",
    },
  );
}

function macOsSandboxUnavailable(): boolean {
  if (process.platform !== "darwin") return false;

  // Check the host independently of the generated scan permission profile.
  const result = Bun.spawnSync(
    [
      "/usr/bin/sandbox-exec",
      "-p",
      "(version 1) (allow default)",
      "/usr/bin/true",
    ],
    { stdout: "pipe", stderr: "pipe" },
  );
  return (
    result.exitCode !== 0 &&
    new TextDecoder().decode(result.stderr).trim() ===
      "sandbox-exec: sandbox_apply: Operation not permitted"
  );
}

async function scanSandboxFixture() {
  const root = await temporaryDirectory();
  const codexHome = join(root, "codex-home");
  const workspace = join(root, "workspace");
  const stateDirectory = join(root, "state");
  await Promise.all(
    [codexHome, workspace, stateDirectory].map((path) => mkdir(path)),
  );
  await writeCodexConfig(
    join(codexHome, "config.toml"),
    scanRuntimeCodexConfig(
      await mergedCodexConfig({}),
      stateDirectory,
      codexHome,
    ),
  );
  return { root, codexHome, workspace };
}

describe("Codex configuration", () => {
  test("automatically reviews scan execution approvals by default", async () => {
    expect(await mergedCodexConfig({})).toMatchObject({
      approval_policy: "on-request",
      approvals_reviewer: "auto_review",
    });
  });

  test("lets Codex honor native and managed credential storage", async () => {
    expect(DEFAULT_CODEX_CONFIG["cli_auth_credentials_store"]).toBe("auto");
    expect((await mergedCodexConfig({}))["cli_auth_credentials_store"]).toBe(
      "auto",
    );
  });

  test("resolves selected profile model and effort before root settings", async () => {
    const scenarios = [
      {
        overrides: {
          profile: "review",
          model: "gpt-5.6-sol",
          model_reasoning_effort: "low",
          profiles: {
            review: {
              model: "gpt-5.6-terra",
              model_reasoning_effort: "high",
            },
          },
        },
        expected: { model: "gpt-5.6-terra", reasoningEffort: "high" },
      },
      {
        overrides: {
          profile: "review",
          model_reasoning_effort: "low",
          profiles: { review: { model: "gpt-5.6-terra" } },
        },
        expected: { model: "gpt-5.6-terra", reasoningEffort: "low" },
      },
      {
        overrides: {
          profile: "review",
          model: "gpt-5.6-terra",
          profiles: { review: { model_reasoning_effort: "medium" } },
        },
        expected: { model: "gpt-5.6-terra", reasoningEffort: "medium" },
      },
    ] as const;

    for (const scenario of scenarios) {
      const config = await mergedCodexConfig({
        codexOverrides: scenario.overrides,
      });
      expect(scanModelConfiguration(config)).toEqual(scenario.expected);
    }
  });

  test("ignores model overrides from unselected Codex profiles", async () => {
    const config = await mergedCodexConfig({
      codexOverrides: {
        profile: "missing",
        model: "gpt-5.6-sol",
        model_reasoning_effort: "low",
        profiles: {
          other: {
            model: "gpt-5.6-terra",
            model_reasoning_effort: "high",
          },
        },
      },
    });

    expect(scanModelConfiguration(config)).toEqual({
      model: "gpt-5.6-sol",
      reasoningEffort: "low",
    });
  });

  test("resolves the selected profile's provider before the root provider", async () => {
    for (const [overrides, expected] of [
      [
        {
          profile: "bedrock",
          model_provider: "openai",
          profiles: {
            bedrock: { model_provider: "amazon-bedrock" },
          },
        },
        "amazon-bedrock",
      ],
      [
        {
          profile: "bedrock",
          model_provider: "amazon-bedrock",
          profiles: { bedrock: { model: "openai.gpt-5.6-luna" } },
        },
        "amazon-bedrock",
      ],
      [
        {
          profile: "missing",
          model_provider: "openai",
          profiles: { bedrock: { model_provider: "amazon-bedrock" } },
        },
        "openai",
      ],
      [{}, undefined],
    ] as const) {
      const config = await mergedCodexConfig({ codexOverrides: overrides });
      expect(scanModelProvider(config)).toBe(expected);
    }
  });

  test("rejects invalid model settings from the selected Codex profile", async () => {
    for (const [profile, message] of [
      [{ model: " " }, "model must be a nonempty string"],
      [
        { model_reasoning_effort: " " },
        "reasoning effort must be a nonempty string",
      ],
    ] as const) {
      const config = await mergedCodexConfig({
        codexOverrides: { profile: "review", profiles: { review: profile } },
      });

      expect(() => scanModelConfiguration(config)).toThrow(message);
    }
  });

  test("deep-merges native multi-agent v2 defaults", async () => {
    const merged = await mergedCodexConfig({
      codexOverrides: {
        features: { multi_agent_v2: { max_concurrent_threads_per_session: 4 } },
        model_reasoning_effort: "high",
        model_reasoning_summary: "concise",
        show_raw_agent_reasoning: false,
        windows: { sandbox: "elevated" },
      },
    });
    expect(merged["features"]).toEqual({
      plugins: true,
      goals: true,
      multi_agent_v2: {
        enabled: true,
        max_concurrent_threads_per_session: 4,
      },
    });
    expect(merged["agents"]).toBeUndefined();
    expect(merged["model"]).toBe("gpt-5.6-sol");
    expect(merged["model_reasoning_effort"]).toBe("high");
    expect(merged["model_reasoning_summary"]).toBe("concise");
    expect(merged["show_raw_agent_reasoning"]).toBe(false);
    expect(merged["windows"]).toEqual({ sandbox: "elevated" });
  });

  test("preserves legacy elevated Windows sandbox overrides", async () => {
    const merged = await mergedCodexConfig({
      codexOverrides: {
        features: { elevated_windows_sandbox: true },
      },
    });

    expect(merged).toMatchObject({
      features: { elevated_windows_sandbox: true },
      windows: { sandbox: "elevated" },
    });
  });

  test("projects legacy elevated Windows overrides into selected profiles", async () => {
    const merged = await mergedCodexConfig({
      codexOverrides: {
        profile: "elevated",
        profiles: {
          elevated: {
            features: { elevated_windows_sandbox: true },
          },
        },
      },
    });

    expect(merged).toMatchObject({
      windows: { sandbox: "unelevated" },
      profiles: {
        elevated: {
          features: { elevated_windows_sandbox: true },
          windows: { sandbox: "elevated" },
        },
      },
    });
  });

  test("allows selected profiles to override root elevated sandbox defaults", async () => {
    const merged = await mergedCodexConfig({
      codexOverrides: {
        features: { elevated_windows_sandbox: true },
        profile: "restricted",
        profiles: {
          restricted: {
            features: { elevated_windows_sandbox: false },
          },
        },
      },
    });

    expect(merged).toMatchObject({
      windows: { sandbox: "elevated" },
      profiles: {
        restricted: {
          features: { elevated_windows_sandbox: false },
          windows: { sandbox: "unelevated" },
        },
      },
    });
  });

  test("gives profile-local Windows sandbox overrides precedence", async () => {
    const merged = await mergedCodexConfig({
      codexOverrides: {
        profile: "restricted",
        profiles: {
          restricted: {
            features: { elevated_windows_sandbox: true },
            windows: { sandbox: "unelevated" },
          },
        },
      },
    });

    expect(merged).toMatchObject({
      profiles: {
        restricted: {
          features: { elevated_windows_sandbox: true },
          windows: { sandbox: "unelevated" },
        },
      },
    });
  });

  test("gives explicit Windows sandbox overrides precedence", async () => {
    const merged = await mergedCodexConfig({
      codexOverrides: {
        features: { elevated_windows_sandbox: true },
        windows: { sandbox: "unelevated" },
      },
    });

    expect(merged).toMatchObject({
      features: { elevated_windows_sandbox: true },
      windows: { sandbox: "unelevated" },
    });
  });

  test("retains the Windows sandbox in the hardened scan profile", async () => {
    const stateDirectory = join(tmpdir(), "codex-security-windows-state");
    const merged = await mergedCodexConfig({});

    expect(scanRuntimeCodexConfig(merged, stateDirectory)).toMatchObject({
      windows: { sandbox: "unelevated" },
      default_permissions: "codex_security_scan",
      permissions: {
        codex_security_scan: {
          filesystem: {
            ":root": "read",
            ":workspace_roots": "write",
            [stateDirectory]: "write",
          },
        },
      },
    });
  });

  test("writes scan permissions accepted by the pinned Codex CLI", async () => {
    const { codexHome, workspace } = await scanSandboxFixture();
    const result = runPinnedCodex(codexHome, [
      "--cd",
      workspace,
      "features",
      "list",
    ]);
    expect(result.exitCode, new TextDecoder().decode(result.stderr)).toBe(0);
    expect(result.stdout.length).toBeGreaterThan(0);
  });

  test.skipIf(macOsSandboxUnavailable())(
    "denies writes outside the scan workspace and state directory",
    async () => {
      const { root, codexHome, workspace } = await scanSandboxFixture();
      const node = Bun.which("node");
      expect(node).not.toBeNull();
      const attemptWrite = (path: string) =>
        runPinnedCodex(codexHome, [
          "sandbox",
          "--config",
          "permissions.codex_security_scan.network.enabled=true",
          "--permission-profile",
          "codex_security_scan",
          "--cd",
          workspace,
          node!,
          "-e",
          "require('node:fs').writeFileSync(process.argv[1], 'probe')",
          path,
        ]);

      const allowed = join(workspace, "inside.txt");
      const permitted = attemptWrite(allowed);
      const outside = join(root, "outside.txt");
      expect(attemptWrite(outside).exitCode).not.toBe(0);
      await expect(stat(outside)).rejects.toMatchObject({ code: "ENOENT" });
      if (permitted.exitCode !== 0) {
        const details = new TextDecoder().decode(permitted.stderr);
        if (
          process.platform === "linux" &&
          /bwrap: (?:setting up uid map: Permission denied|loopback: Failed RTM_NEWADDR: Operation not permitted)/u.test(
            details,
          )
        ) {
          expect(runPinnedCodex(codexHome, ["features", "list"]).exitCode).toBe(
            0,
          );
          return;
        }
        throw new Error(
          `The pinned Codex CLI rejected an allowed scan write: ${details}`,
        );
      }
      expect(await readFile(allowed, "utf8")).toBe("probe");
    },
  );

  test("writes Windows sandbox settings accepted by the pinned Codex CLI", async () => {
    const root = await temporaryDirectory();
    const path = join(root, "config.toml");
    await writeCodexConfig(path, await mergedCodexConfig({}));

    expect(parse(await readFile(path, "utf8"))).toMatchObject({
      windows: { sandbox: "unelevated" },
    });

    const result = runPinnedCodex(root, ["features", "list"]);
    expect(result.exitCode).toBe(0);
    expect(result.stdout.length).toBeGreaterThan(0);
  });

  test("writes selected profile sandbox settings accepted by the pinned Codex CLI", async () => {
    const root = await temporaryDirectory();
    const path = join(root, "config.toml");
    const config = await mergedCodexConfig({
      codexOverrides: {
        profile: "elevated",
        profiles: {
          elevated: {
            features: { elevated_windows_sandbox: true },
          },
        },
      },
    });
    const nativeConfig = structuredClone(config);
    delete nativeConfig["profile"];
    delete nativeConfig["profiles"];
    const profileConfig = (config["profiles"] as JsonObject)[
      "elevated"
    ] as JsonObject;
    const profilePath = join(root, "elevated.config.toml");
    await writeCodexConfig(path, nativeConfig);
    await writeCodexConfig(profilePath, profileConfig);

    expect(parse(await readFile(path, "utf8"))).toMatchObject({
      windows: { sandbox: "unelevated" },
    });
    expect(parse(await readFile(profilePath, "utf8"))).toMatchObject({
      features: { elevated_windows_sandbox: true },
      windows: { sandbox: "elevated" },
    });

    const result = runPinnedCodex(root, [
      "--profile",
      "elevated",
      "mcp",
      "list",
      "--json",
    ]);
    if (result.exitCode !== 0) {
      throw new Error(
        `The pinned Codex CLI rejected the selected Windows sandbox profile: ${new TextDecoder().decode(result.stderr)}`,
      );
    }
    expect(result.exitCode).toBe(0);
    expect(result.stdout.length).toBeGreaterThan(0);
  });

  test("rejects prototype-bearing override keys", async () => {
    for (const key of ["__proto__", "constructor", "prototype"]) {
      await expect(
        mergedCodexConfig({
          codexOverrides: JSON.parse(
            `{"features":{"custom":[{"${key}":{"polluted":true}}]}}`,
          ),
        }),
      ).rejects.toThrow(`Invalid Codex override key: ${key}`);
    }
    expect(({} as Record<string, unknown>)["polluted"]).toBeUndefined();
  });

  test("rejects non-object overrides with a configuration error", async () => {
    for (const codexOverrides of [null, [], false, 1, "invalid"]) {
      await expect(
        mergedCodexConfig({ codexOverrides } as never),
      ).rejects.toThrow("codexOverrides must be an object");
    }
  });

  test("keeps exported default configuration deeply immutable", async () => {
    expect(Object.isFrozen(DEFAULT_CODEX_CONFIG)).toBe(true);
    expect(Object.isFrozen(DEFAULT_CODEX_CONFIG["features"])).toBe(true);
    expect(Object.isFrozen(DEFAULT_CODEX_CONFIG["windows"])).toBe(true);
    expect(
      Object.isFrozen(
        (DEFAULT_CODEX_CONFIG["features"] as Record<string, unknown>)[
          "multi_agent_v2"
        ],
      ),
    ).toBe(true);
    expect(() => {
      (DEFAULT_CODEX_CONFIG["features"] as Record<string, unknown>)["goals"] =
        false;
    }).toThrow();
    expect((await mergedCodexConfig({}))["features"]).toMatchObject({
      goals: true,
      multi_agent_v2: {
        enabled: true,
        max_concurrent_threads_per_session: 9,
      },
    });
    expect(await mergedCodexConfig({})).toMatchObject({
      model: "gpt-5.6-sol",
      model_reasoning_effort: "xhigh",
      model_reasoning_summary: "detailed",
      show_raw_agent_reasoning: true,
      windows: {
        sandbox: "unelevated",
      },
    });
  });

  test("rejects owned plugin keys and incompatible v2 overrides", async () => {
    await expect(
      mergedCodexConfig({ codexOverrides: { features: false } }),
    ).rejects.toThrow("features must be a TOML table");
    await expect(
      mergedCodexConfig({ codexOverrides: { features: { plugins: false } } }),
    ).rejects.toThrow(ConfigurationError);
    await expect(
      mergedCodexConfig({ codexOverrides: { agents: { max_threads: 2 } } }),
    ).rejects.toThrow("legacy v1");
    await expect(
      mergedCodexConfig({
        codexOverrides: { features: { multi_agent_v2: { enabled: false } } },
      }),
    ).rejects.toThrow("cannot be disabled");

    await expect(
      mergedCodexConfig({
        codexOverrides: {
          profile: "disabled",
          profiles: { disabled: { features: { plugins: false } } },
        },
      }),
    ).rejects.toThrow("owns plugin loading configuration");
    await expect(
      mergedCodexConfig({
        codexOverrides: {
          profile: "disabled",
          profiles: {
            disabled: {
              features: { multi_agent_v2: { enabled: false } },
            },
          },
        },
      }),
    ).rejects.toThrow("cannot be disabled");
    await expect(
      mergedCodexConfig({
        codexOverrides: {
          profiles: { legacy: { agents: { max_threads: 2 } } },
        },
      }),
    ).rejects.toThrow("legacy v1");
    await expect(
      mergedCodexConfig({
        codexOverrides: {
          profiles: {
            deep: {
              features: {
                multi_agent_v2: {
                  max_concurrent_threads_per_session: 5,
                },
              },
            },
          },
        },
      }),
    ).resolves.toBeDefined();
  });

  test("writes deterministic TOML atomically with restrictive permissions", async () => {
    const root = await temporaryDirectory();
    const path = join(root, "home", "config.toml");
    await writeCodexConfig(path, {
      features: { plugins: true, goals: true },
      agents: { max_threads: 12 },
      model_reasoning_effort: "high",
    });
    const text = await readFile(path, "utf8");
    expect(parse(text)).toEqual({
      features: { plugins: true, goals: true },
      agents: { max_threads: 12 },
      model_reasoning_effort: "high",
    });
    if (process.platform !== "win32") {
      expect((await stat(path)).mode & 0o777).toBe(0o600);
    }
  });

  test("serializes numeric TOML overrides", async () => {
    const root = await temporaryDirectory();
    const path = join(root, "config.toml");
    await writeCodexConfig(path, {
      max_safe: Number.MAX_SAFE_INTEGER,
      fractional: 1.5,
      exponent: 1e-7,
    });
    expect(parse(await readFile(path, "utf8"))).toEqual({
      max_safe: Number.MAX_SAFE_INTEGER,
      fractional: 1.5,
      exponent: 1e-7,
    });
  });

  test.skipIf(process.platform === "win32")(
    "keeps atomic TOML output readable under a restrictive umask",
    async () => {
      const root = await temporaryDirectory();
      const path = join(root, "config.toml");
      const previous = process.umask(0o777);
      try {
        await writeCodexConfig(path, { model: "test" });
      } finally {
        process.umask(previous);
      }
      expect((await stat(path)).mode & 0o777).toBe(0o600);
      expect(await readFile(path, "utf8")).toContain('model = "test"');
    },
  );

  test("serializes nested inline tables in TOML arrays", async () => {
    const root = await temporaryDirectory();
    const path = join(root, "config.toml");
    const hooks = {
      SessionStart: [
        {
          matcher: "*",
          hooks: [{ type: "command", command: "echo hi" }],
        },
      ],
    };
    await writeCodexConfig(path, { hooks });
    expect(parse(await readFile(path, "utf8"))).toEqual({ hooks });
  });
});

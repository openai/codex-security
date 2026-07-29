import { mkdtemp, readFile, rm, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, test } from "bun:test";
import { parse } from "smol-toml";
import {
  ConfigurationError,
  DEFAULT_CODEX_CONFIG,
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

describe("Codex configuration", () => {
  test("deep-merges native multi-agent v2 defaults", async () => {
    const merged = await mergedCodexConfig({
      codexOverrides: {
        features: { multi_agent_v2: { max_concurrent_threads_per_session: 4 } },
        model_reasoning_effort: "high",
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
    expect(merged["windows"]).toEqual({ sandbox: "elevated" });
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

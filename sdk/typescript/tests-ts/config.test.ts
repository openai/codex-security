import { execFileSync, spawnSync } from "node:child_process";
import {
  mkdtemp,
  mkdir,
  readFile,
  rm,
  stat,
  symlink,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, test } from "bun:test";
import { parse } from "smol-toml";
import {
  ConfigurationError,
  DEFAULT_CODEX_CONFIG,
  mergedCodexConfig,
  NATIVE_V2_CODEX_CONFIG,
  writeCodexConfig,
} from "../src/index.js";

const temporaryDirectories: string[] = [];

afterEach(async () => {
  await Promise.all(
    temporaryDirectories.splice(0).map((path) => rm(path, { recursive: true })),
  );
});

async function temporaryDirectory(): Promise<string> {
  const path = await mkdtemp(join(tmpdir(), "codex-security-config-"));
  temporaryDirectories.push(path);
  return path;
}

async function v2Plugin(severity = "block"): Promise<string> {
  const root = await temporaryDirectory();
  await mkdir(join(root, "preflight"), { recursive: true });
  await writeFile(
    join(root, "preflight", "capability-profiles.toml"),
    [
      "[profiles.deep_security_scan]",
      "[[profiles.deep_security_scan.requirements]]",
      'capability = "native_multi_agent_v2"',
      `severity = "${severity}"`,
      "",
    ].join("\n"),
  );
  return root;
}

describe("Codex configuration", () => {
  test("deep-merges security defaults", async () => {
    const merged = await mergedCodexConfig({
      codexOverrides: {
        agents: { max_threads: 4 },
        model_reasoning_effort: "high",
      },
    });
    expect(merged["features"]).toMatchObject({
      plugins: true,
      multi_agent: true,
      enable_fanout: true,
      goals: true,
    });
    expect(merged["agents"]).toEqual({ max_threads: 4, max_depth: 2 });
  });

  test("preserves own __proto__ overrides without mutating prototypes", async () => {
    const merged = await mergedCodexConfig({
      codexOverrides: JSON.parse('{"__proto__":{"custom":true},"normal":true}'),
    });
    expect(Object.getPrototypeOf(merged)).toBe(Object.prototype);
    expect(Object.hasOwn(merged, "__proto__")).toBe(true);
    expect(merged["__proto__"]).toEqual({ custom: true });
    expect(merged["normal"]).toBe(true);

    const root = await temporaryDirectory();
    const path = join(root, "config.toml");
    await writeCodexConfig(path, merged);
    expect(await readFile(path, "utf8")).toContain("__proto__.custom = true");
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
    expect(Object.isFrozen(NATIVE_V2_CODEX_CONFIG["features"])).toBe(true);
    expect(() => {
      (DEFAULT_CODEX_CONFIG["features"] as Record<string, unknown>)["goals"] =
        false;
    }).toThrow();
    expect((await mergedCodexConfig({}))["features"]).toMatchObject({
      goals: true,
    });
  });

  test("selects native multi-agent v2 from the plugin contract", async () => {
    const pluginRoot = await v2Plugin();
    const merged = await mergedCodexConfig({}, { pluginRoot });
    expect(merged["features"]).toEqual({
      plugins: true,
      goals: true,
      multi_agent_v2: {
        enabled: true,
        max_concurrent_threads_per_session: 9,
      },
    });
    expect(merged["agents"]).toBeUndefined();
  });

  test("rejects owned plugin keys and incompatible v2 overrides", async () => {
    await expect(
      mergedCodexConfig({ codexOverrides: { features: false } }),
    ).rejects.toThrow("features must be a TOML table");
    await expect(
      mergedCodexConfig({ codexOverrides: { features: { plugins: false } } }),
    ).rejects.toThrow(ConfigurationError);
    const pluginRoot = await v2Plugin();
    await expect(
      mergedCodexConfig(
        { codexOverrides: { agents: { max_threads: 2 } } },
        { pluginRoot },
      ),
    ).rejects.toThrow("legacy v1");
    await expect(
      mergedCodexConfig(
        {
          codexOverrides: { features: { multi_agent_v2: { enabled: false } } },
        },
        { pluginRoot },
      ),
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
      mergedCodexConfig(
        {
          codexOverrides: {
            profile: "disabled",
            profiles: {
              disabled: {
                features: { multi_agent_v2: { enabled: false } },
              },
            },
          },
        },
        { pluginRoot },
      ),
    ).rejects.toThrow("cannot be disabled");
    await expect(
      mergedCodexConfig(
        {
          codexOverrides: {
            profiles: { legacy: { agents: { max_threads: 2 } } },
          },
        },
        { pluginRoot },
      ),
    ).rejects.toThrow("legacy v1");
    await expect(
      mergedCodexConfig(
        {
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
        },
        { pluginRoot },
      ),
    ).resolves.toBeDefined();
  });

  test("keeps legacy defaults for a non-blocking v2 requirement", async () => {
    const pluginRoot = await v2Plugin("warn");
    const merged = await mergedCodexConfig({}, { pluginRoot });
    expect(merged["agents"]).toMatchObject({ max_threads: 12 });
  });

  test("rejects TOML datetimes masquerading as capability-profile tables", async () => {
    const cases = [
      "profiles = 2026-01-01T00:00:00Z\n",
      "[profiles]\ndeep_security_scan = 2026-01-01T00:00:00Z\n",
      "[profiles.deep_security_scan]\nrequirements = [2026-01-01T00:00:00Z]\n",
      "[profiles.deep_security_scan]\nremediation = 2026-01-01T00:00:00Z\n",
      "[profiles.deep_security_scan.remediation]\nvariants = [2026-01-01T00:00:00Z]\n",
      '[profiles.deep_security_scan.remediation]\n[[profiles.deep_security_scan.remediation.variants]]\nmode = "v2"\npatches = [2026-01-01T00:00:00Z]\n',
    ];
    for (const source of cases) {
      const pluginRoot = await temporaryDirectory();
      const preflight = join(pluginRoot, "preflight");
      await mkdir(preflight);
      await writeFile(join(preflight, "capability-profiles.toml"), source);
      await expect(mergedCodexConfig({}, { pluginRoot })).rejects.toThrow(
        ConfigurationError,
      );
    }
  });

  test("rejects malformed UTF-8 in capability profiles", async () => {
    const pluginRoot = await temporaryDirectory();
    const preflight = join(pluginRoot, "preflight");
    await mkdir(preflight);
    await writeFile(
      join(preflight, "capability-profiles.toml"),
      Buffer.concat([
        Buffer.from(
          '[profiles.deep_security_scan]\n[[profiles.deep_security_scan.requirements]]\ncapability = "native_multi_agent_v2',
        ),
        Buffer.from([0xff]),
        Buffer.from('"\nseverity = "block"\n'),
      ]),
    );
    await expect(mergedCodexConfig({}, { pluginRoot })).rejects.toThrow(
      "unreadable capability profile",
    );
  });

  test.skipIf(process.platform === "win32")(
    "rejects a capability profile swapped after it is opened",
    async () => {
      const pluginRoot = await temporaryDirectory();
      const preflight = join(pluginRoot, "preflight");
      await mkdir(preflight);
      const profile = join(preflight, "capability-profiles.toml");
      const replacement = join(preflight, "replacement.toml");
      await writeFile(profile, "[profiles]\n");
      await writeFile(
        replacement,
        '[profiles.deep_security_scan]\n[[profiles.deep_security_scan.requirements]]\ncapability = "native_multi_agent_v2"\nseverity = "block"\n',
      );
      const script = `
        import { mock } from "bun:test";
        import { renameSync } from "node:fs";
        import * as original from "node:fs/promises";
        import { join } from "node:path";
        const [pluginRoot, source] = process.argv.slice(1);
        const profile = join(pluginRoot, "preflight", "capability-profiles.toml");
        const replacement = join(pluginRoot, "preflight", "replacement.toml");
        const actualOpen = original.open;
        let swapped = false;
        mock.module("node:fs/promises", () => ({
          ...original,
          open: async (path, ...args) => {
            const file = await actualOpen(path, ...args);
            if (path === profile && !swapped) {
              renameSync(profile, profile + ".old");
              renameSync(replacement, profile);
              swapped = true;
            }
            return file;
          },
        }));
        const { mergedCodexConfig } = await import(source);
        try {
          await mergedCodexConfig({}, { pluginRoot });
          console.log("ACCEPTED", swapped);
          process.exitCode = 2;
        } catch (error) {
          console.log("REJECTED", swapped, error instanceof Error ? error.message : String(error));
        }
      `;
      const result = spawnSync(
        process.execPath,
        [
          "-e",
          script,
          pluginRoot,
          fileURLToPath(new URL("../src/config.ts", import.meta.url)),
        ],
        { encoding: "utf8" },
      );
      expect(result.status).toBe(0);
      expect(result.stdout).toContain("REJECTED true");
      expect(result.stdout).toContain("unreadable capability profile");
    },
  );

  test.skipIf(process.platform === "win32")(
    "rejects non-regular capability profiles without blocking",
    async () => {
      const pluginRoot = await temporaryDirectory();
      const preflight = join(pluginRoot, "preflight");
      const profiles = join(preflight, "capability-profiles.toml");
      await mkdir(preflight);
      execFileSync("mkfifo", [profiles]);
      await expect(mergedCodexConfig({}, { pluginRoot })).rejects.toThrow(
        "unreadable capability profile",
      );

      await rm(profiles);
      const external = join(pluginRoot, "external.toml");
      await writeFile(external, "[profiles]\n");
      await symlink(external, profiles);
      await expect(mergedCodexConfig({}, { pluginRoot })).rejects.toThrow(
        "unreadable capability profile",
      );
    },
  );

  test("writes deterministic TOML atomically with restrictive permissions", async () => {
    const root = await temporaryDirectory();
    const path = join(root, "home", "config.toml");
    await writeCodexConfig(path, {
      features: { plugins: true, goals: true },
      agents: { max_threads: 12 },
      model_reasoning_effort: "high",
    });
    const text = await readFile(path, "utf8");
    expect(text).toContain("features.plugins = true");
    expect(text).toContain("agents.max_threads = 12");
    expect(text).toContain('model_reasoning_effort = "high"');
    if (process.platform !== "win32") {
      expect((await stat(path)).mode & 0o777).toBe(0o600);
    }
  });

  test("rejects unsafe integer-valued TOML overrides", async () => {
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

    for (const unsafe of [
      Number.MAX_SAFE_INTEGER + 1,
      1e18,
      -(Number.MAX_SAFE_INTEGER + 1),
      -1e18,
    ]) {
      await expect(
        writeCodexConfig(path, { agents: { max_threads: unsafe } }),
      ).rejects.toThrow("unsafe integer");
    }
  });

  test("rejects malformed Unicode in TOML keys and string values", async () => {
    const root = await temporaryDirectory();
    const path = join(root, "config.toml");
    for (const config of [
      { model: "bad-\ud800-value" },
      { ["bad-\ud800-key"]: true },
      { hooks: [{ command: "bad-\ud800-command" }] },
    ]) {
      await expect(writeCodexConfig(path, config as never)).rejects.toThrow(
        "malformed Unicode",
      );
    }
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

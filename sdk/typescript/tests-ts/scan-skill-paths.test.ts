import { mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { afterEach, expect, test } from "bun:test";
import { resolveCodexProfile, type JsonObject } from "../src/config.js";
import { scanSkillConfig } from "../src/scan-skill-paths.js";
import { createApiTestFixtures } from "./support/temporary-directories.js";

const { temporaryDirectory, cleanup } =
  createApiTestFixtures("scan-skill-paths-");
afterEach(cleanup);

function selection(config: JsonObject) {
  const entries = (config["skills"] as JsonObject)["config"] as JsonObject[];
  return [...entries].sort((a, b) =>
    String(a["path"]).localeCompare(String(b["path"])),
  );
}

async function fixture() {
  const root = await temporaryDirectory();
  const home = join(root, "credential home [fixture]");
  const pluginRoot = join(root, "readable plugin");
  const installedRoot = join(home, "plugins", "cache", "selected", "1.0.0");
  for (const name of ["security-scan", "deep-security-scan"]) {
    await mkdir(join(pluginRoot, "skills", name), { recursive: true });
    await writeFile(
      join(pluginRoot, "skills", name, "SKILL.md"),
      "Synthetic workflow.\n",
    );
  }
  await writeFile(
    join(pluginRoot, "skills", "README.md"),
    "Not a skill directory.\n",
  );
  const blocked = ["deep-security-scan", "security-scan"].map((name) => ({
    path: join(installedRoot, "skills", name, "SKILL.md"),
    enabled: false,
  }));
  return { root, home, plugin: { pluginRoot, installedRoot }, blocked };
}

test.each([false, true])(
  "disables cached skill files while preserving effective selection (profile=%j)",
  async (profile) => {
    const { root, home, plugin, blocked } = await fixture();
    const unrelated = {
      path: join(root, "other-plugin", "SKILL.md"),
      enabled: true,
    };
    const previouslyDisabled = {
      path: join(root, "disabled", "SKILL.md"),
      enabled: false,
    };
    const selected: JsonObject = {
      config: [
        unrelated,
        previouslyDisabled,
        { ...blocked[0]!, enabled: true },
      ],
    };
    const config: JsonObject = {
      plugins: { "selected@local": { enabled: true } },
      skills: profile
        ? {
            config: [
              { path: join(root, "overridden", "SKILL.md"), enabled: true },
            ],
          }
        : selected,
      ...(profile
        ? {
            profile: "active",
            profiles: {
              active: { skills: selected },
              unused: { skills: { config: [unrelated] } },
            },
          }
        : {}),
    };
    const before = structuredClone(config);
    const actual = await scanSkillConfig(config, plugin, home);
    expect(config).toEqual(before);
    expect(actual).not.toBe(config);
    expect(selection(resolveCodexProfile(actual))).toEqual(
      selection({
        skills: { config: [unrelated, previouslyDisabled, ...blocked] },
      }),
    );
    expect(actual["plugins"]).toEqual(config["plugins"]);
    if (profile) {
      expect((actual["profiles"] as JsonObject)["unused"]).toEqual(
        (before["profiles"] as JsonObject)["unused"],
      );
    }
  },
);

test("leaves plugins outside the credential home and absent skills unchanged", async () => {
  const { root, home, plugin } = await fixture();
  const config: JsonObject = {
    skills: {
      config: [{ path: join(root, "custom", "SKILL.md"), enabled: true }],
    },
  };
  for (const installedRoot of [join(root, "installed"), home + "-sibling"]) {
    expect(
      await scanSkillConfig(config, { ...plugin, installedRoot }, home),
    ).toBe(config);
  }
  expect(
    await scanSkillConfig(
      config,
      { ...plugin, pluginRoot: join(root, "missing-skills") },
      home,
    ),
  ).toBe(config);
});

test.each([false, true])(
  "preserves malformed native skill settings (profile=%j)",
  async (profile) => {
    const { home, plugin } = await fixture();
    for (const skills of [
      false,
      "invalid",
      [],
      { config: false },
      { config: "invalid" },
      { config: {} },
    ]) {
      const config: JsonObject = profile
        ? { profile: "selected", profiles: { selected: { skills } } }
        : { skills };
      const before = structuredClone(config);
      expect(await scanSkillConfig(config, plugin, home)).toBe(config);
      expect(config).toEqual(before);
    }
  },
);

test("isolates concurrent scan selections without changing their shared configuration", async () => {
  const [first, second] = await Promise.all([fixture(), fixture()]);
  const config: JsonObject = {
    plugins: { "selected@local": { enabled: true } },
  };
  const [a, b] = await Promise.all([
    scanSkillConfig(config, first.plugin, first.home),
    scanSkillConfig(config, second.plugin, second.home),
  ]);
  expect(selection(a)).toEqual(
    selection({ skills: { config: first.blocked } }),
  );
  expect(selection(b)).toEqual(
    selection({ skills: { config: second.blocked } }),
  );
  expect(a["skills"]).not.toBe(b["skills"]);
  expect(config).toEqual({ plugins: { "selected@local": { enabled: true } } });
  (a["skills"] as JsonObject)["config"] = [];
  expect(selection(b)).toEqual(
    selection({ skills: { config: second.blocked } }),
  );
});

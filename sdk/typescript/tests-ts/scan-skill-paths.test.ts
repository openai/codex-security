import { mkdir, symlink, writeFile } from "node:fs/promises";
import { join, relative, toNamespacedPath } from "node:path";
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

test("checks credential home containment through directory links", async () => {
  const { root, home, plugin, blocked } = await fixture();
  const alias = join(root, "linked home");
  const linkType = process.platform === "win32" ? "junction" : "dir";
  await mkdir(plugin.installedRoot, { recursive: true });
  await symlink(home, alias, linkType);
  const linkedInstall = join(alias, relative(home, plugin.installedRoot));
  for (const { credentialHome, installedRoot } of [
    { credentialHome: alias, installedRoot: plugin.installedRoot },
    { credentialHome: home, installedRoot: toNamespacedPath(linkedInstall) },
  ]) {
    const actual = await scanSkillConfig(
      {},
      { ...plugin, installedRoot },
      credentialHome,
    );
    expect(selection(actual)).toEqual(
      selection({ skills: { config: blocked } }),
    );
  }

  const outsideLink = join(home, "linked plugin");
  await symlink(plugin.pluginRoot, outsideLink, linkType);
  const config = {};
  expect(
    await scanSkillConfig(
      config,
      { ...plugin, installedRoot: outsideLink },
      home,
    ),
  ).toBe(config);
});

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

test("inherits root skill rules when the selected profile's rules are null", async () => {
  const { home, plugin, blocked } = await fixture();
  const rule = { name: "user-skill", enabled: false };
  const actual = await scanSkillConfig(
    {
      profile: "active",
      profiles: { active: { skills: { config: null } } },
      skills: { config: [rule] },
    },
    plugin,
    home,
  );
  expect(selection(resolveCodexProfile(actual))).toEqual(
    selection({ skills: { config: [rule, ...blocked] } }),
  );
});

test("ignores inherited profile names when writing skill rules", async () => {
  const { home, plugin } = await fixture();
  const config = { profile: "__proto__", profiles: {} };
  expect(Object.hasOwn(Object.prototype, "skills")).toBe(false);
  try {
    await scanSkillConfig(config, plugin, home);
    expect(Object.hasOwn(Object.prototype, "skills")).toBe(false);
  } finally {
    Reflect.deleteProperty(Object.prototype, "skills");
  }
});

test("isolates concurrent scan selections without changing their shared configuration", async () => {
  const [first, second] = await Promise.all([fixture(), fixture()]);
  const rule = { name: "user-skill", enabled: false };
  const config: JsonObject = {
    plugins: { "selected@local": { enabled: true } },
    skills: { config: [rule] },
  };
  const before = structuredClone(config);
  const [a, b] = await Promise.all([
    scanSkillConfig(config, first.plugin, first.home),
    scanSkillConfig(config, second.plugin, second.home),
  ]);
  expect(selection(a)).toEqual(
    selection({ skills: { config: [rule, ...first.blocked] } }),
  );
  const retained = selection(a).find((entry) => entry["name"] === rule.name)!;
  retained["enabled"] = true;
  expect(config).toEqual(before);
  expect(selection(b)).toEqual(
    selection({ skills: { config: [rule, ...second.blocked] } }),
  );
});

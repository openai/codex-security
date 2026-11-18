import { mkdir, symlink, writeFile } from "node:fs/promises";
import { join, toNamespacedPath } from "node:path";
import { afterEach, expect, test } from "bun:test";
import {
  resolveCodexProfile,
  type JsonObject,
  type JsonValue,
} from "../src/config.js";
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
    const { root, home, plugin, blocked } = await fixture();
    for (const skills of [
      null,
      false,
      "invalid",
      [],
      { config: null },
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

    const custom = { path: join(root, "custom", "SKILL.md"), enabled: true };
    const withNullEntry: JsonObject = {
      ...(profile
        ? {
            profile: "selected",
            profiles: { selected: { skills: { config: [null, custom] } } },
          }
        : { skills: { config: [null, custom] } }),
    };
    const updated = await scanSkillConfig(withNullEntry, plugin, home);
    const updatedEntries = (
      (profile
        ? ((updated["profiles"] as JsonObject)["selected"] as JsonObject)[
            "skills"
          ]
        : updated["skills"]) as JsonObject
    )["config"] as JsonValue[];
    expect(updatedEntries).toEqual([null, custom, ...blocked]);

    const prototypeProfile: JsonObject = {
      profile: "constructor",
      profiles: {},
      skills: { config: [custom] },
    };
    const prototypeUpdated = await scanSkillConfig(
      prototypeProfile,
      plugin,
      home,
    );
    expect(prototypeUpdated["profiles"]).toEqual({});
    expect(selection(prototypeUpdated)).toEqual(
      selection({ skills: { config: [custom, ...blocked] } }),
    );
  },
);

test("resolves directory links and alternate path spellings for credential homes and skill entries", async () => {
  const { root, home, plugin, blocked } = await fixture();
  for (const name of ["security-scan", "deep-security-scan"]) {
    const dir = join(plugin.installedRoot, "skills", name);
    await mkdir(dir, { recursive: true });
    await writeFile(join(dir, "SKILL.md"), "Cached workflow.\n");
  }
  const linkedHome = join(root, "linked-credential-home");
  await symlink(
    home,
    linkedHome,
    process.platform === "win32" ? "junction" : "dir",
  );
  const linkedInstalledRoot = join(
    linkedHome,
    "plugins",
    "cache",
    "selected",
    "1.0.0",
  );
  const unrelated = {
    path: join(root, "other-plugin", "SKILL.md"),
    enabled: true,
  };
  const relativeEntry = {
    path: "skills/security-scan/SKILL.md",
    enabled: true,
  };
  const swapDriveCase = (value: string) =>
    /^[A-Za-z]:/u.test(value)
      ? (value[0] === value[0]!.toUpperCase()
          ? value[0]!.toLowerCase()
          : value[0]!.toUpperCase()) + value.slice(1)
      : value;
  const aliasedEntries: JsonObject[] = [
    unrelated,
    relativeEntry,
    {
      path: join(linkedInstalledRoot, "skills", "security-scan", "SKILL.md"),
      enabled: true,
    },
    {
      path: `${plugin.installedRoot}/skills/./deep-security-scan/SKILL.md`,
      enabled: true,
    },
    ...(process.platform === "win32"
      ? [
          {
            path: blocked[0]!.path.replaceAll("\\", "/"),
            enabled: true,
          },
          {
            path: swapDriveCase(blocked[1]!.path).replace(
              /SKILL\.md$/u,
              "skill.md",
            ),
            enabled: true,
          },
          {
            path: toNamespacedPath(blocked[0]!.path),
            enabled: true,
          },
        ]
      : []),
  ];
  const config: JsonObject = { skills: { config: aliasedEntries } };
  const expected = selection({
    skills: { config: [unrelated, relativeEntry, ...blocked] },
  });

  expect(selection(await scanSkillConfig(config, plugin, linkedHome))).toEqual(
    expected,
  );
  expect(
    selection(
      await scanSkillConfig(
        config,
        { ...plugin, installedRoot: linkedInstalledRoot },
        home,
      ),
    ),
  ).toEqual(expected);
  if (process.platform === "win32") {
    expect(
      selection(
        await scanSkillConfig(
          config,
          { ...plugin, installedRoot: toNamespacedPath(plugin.installedRoot) },
          home,
        ),
      ),
    ).toEqual(expected);
  }

  const outside = join(root, "outside-plugin");
  await mkdir(outside, { recursive: true });
  const linkInsideHome = join(home, "outside-link");
  await symlink(
    outside,
    linkInsideHome,
    process.platform === "win32" ? "junction" : "dir",
  );
  expect(
    await scanSkillConfig(
      config,
      { ...plugin, installedRoot: linkInsideHome },
      home,
    ),
  ).toBe(config);
});

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

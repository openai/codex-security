import { mkdir, readFile, rm, symlink, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { afterEach, expect, test } from "bun:test";
import { deepScanOptions, resolveDeepScanConfig } from "../src/deep-config.js";
import { DEFAULT_DEEP_SCAN_SETTINGS } from "../src/deep-scan-defaults.js";
import { createApiTestFixtures } from "./support/temporary-directories.js";

const { temporaryDirectory, cleanup } = createApiTestFixtures("deep-config-");
afterEach(cleanup);
async function fixture(contents?: string) {
  const root = await temporaryDirectory();
  const ambient = join(root, "ambient");
  await mkdir(join(ambient, "codex-security"), { recursive: true });
  const source = join(ambient, "codex-security", "config.toml");
  if (contents !== undefined) await writeFile(source, contents);
  return { root, source };
}

test("resolves all six defaults without creating an ambient file", async () => {
  const input = await fixture();
  const result = await resolveDeepScanConfig({}, input.source);
  expect(result.settings).toEqual(DEFAULT_DEEP_SCAN_SETTINGS);
  expect(new Set(Object.values(result.sources))).toEqual(new Set(["default"]));
  await expect(readFile(input.source)).rejects.toMatchObject({
    code: "ENOENT",
  });
});

test("converts minutes at the Deep boundary without changing ambient settings", async () => {
  const input = await fixture("[deep_scan]\nmax_time_hours = 2\n");
  const result = await resolveDeepScanConfig(
    { maxTimeMinutes: 90 },
    input.source,
  );
  expect(result.settings.maxTimeHours).toBe(1.5);
  expect(result.sources.maxTimeHours).toBe("override");
  expect(await readFile(input.source, "utf8")).toBe(
    "[deep_scan]\nmax_time_hours = 2\n",
  );
});

test("minute settings keep Standard advisory and preserve Deep limits and aliases", () => {
  expect(deepScanOptions({ maxTimeMinutes: 6000 })).toEqual({});
  expect(deepScanOptions({ mode: "deep", maxTimeMinutes: 5760 })).toEqual({
    maxTimeHours: 96,
  });
  expect(
    deepScanOptions({ mode: "deep", maxTimeMinutes: 7.2, maxTimeHours: 0.12 }),
  ).toEqual({ maxTimeHours: 7.2 / 60 });
  expect(() =>
    deepScanOptions({ mode: "deep", maxTimeMinutes: 90, maxTimeHours: 2 }),
  ).toThrow("Conflicting");
  expect(() => deepScanOptions({ mode: "deep", maxTimeMinutes: 5761 })).toThrow(
    "5760 minutes",
  );
  expect(() => deepScanOptions({ maxTimeHours: 1 })).toThrow(
    "Deep scan settings require deep mode",
  );
});

test.each([0, -1, Number.NaN, Number.POSITIVE_INFINITY])(
  "rejects invalid minute setting %d in both modes",
  (maxTimeMinutes) => {
    for (const mode of ["standard", "deep"] as const) {
      expect(() => deepScanOptions({ mode, maxTimeMinutes })).toThrow(
        "finite positive number",
      );
    }
  },
);

test("Standard minutes accept fractions and large representable deadlines", () => {
  for (const maxTimeMinutes of [0.5, 1e11]) {
    expect(deepScanOptions({ maxTimeMinutes })).toEqual({});
  }
});

test.each(["missing file", "missing directory"])(
  "preserves absent ambient configuration through a directory link with a %s",
  async (state) => {
    const input = await fixture();
    if (state === "missing directory")
      await rm(dirname(input.source), { recursive: true });
    const home = dirname(dirname(input.source));
    const linkedHome = join(input.root, "linked-home");
    await symlink(home, linkedHome, "junction");
    const source = join(linkedHome, "codex-security", "config.toml");
    expect((await resolveDeepScanConfig({}, source)).settings).toEqual(
      DEFAULT_DEEP_SCAN_SETTINGS,
    );
    await expect(readFile(input.source)).rejects.toMatchObject({
      code: "ENOENT",
    });
  },
);

test("normalizes legacy auto and preserves explicit zero while merging", async () => {
  const input = await fixture(
    '[deep_scan]\nworkers = "auto"\nsubagents = 2\nstop_after_no_new = 6\nstop_after_consecutive_errors = 5\nmax_time_hours = 1.5\n',
  );
  const result = await resolveDeepScanConfig(
    { subagents: 0, stopAfterConsecutiveErrors: 2 },
    input.source,
  );
  expect(result.settings).toEqual({
    workers: 4,
    subagents: 0,
    stopAfterNoNew: 6,
    stopAfterConsecutiveErrors: 2,
    maxDiscoveryRuns: 40,
    maxTimeHours: 1.5,
  });
  expect(result.sources).toEqual({
    workers: "legacy",
    subagents: "override",
    stopAfterNoNew: "legacy",
    stopAfterConsecutiveErrors: "override",
    maxDiscoveryRuns: "default",
    maxTimeHours: "legacy",
  });
});

test("validates legacy values after matching explicit overrides", async () => {
  const input = await fixture('[deep_scan]\nworkers = "invalid"\n');
  await expect(resolveDeepScanConfig({}, input.source)).rejects.toThrow(
    "integer",
  );
  expect(
    (await resolveDeepScanConfig({ workers: 2 }, input.source)).settings
      .workers,
  ).toBe(2);
});

test("reports the TOML key and source file for an invalid ambient value", async () => {
  const input = await fixture("[deep_scan]\nstop_after_no_new = 0\n");
  await expect(resolveDeepScanConfig({}, input.source)).rejects.toThrow(
    `Deep scan stop_after_no_new in ${input.source} must be a positive integer`,
  );
});

test.each([
  ["deep_scan = []\n", "TOML table"],
  ["deep_scan = 2026-01-01\n", "TOML table"],
  ["[deep_scan]\nworkers = true\n", "integer"],
  ["[deep_scan]\nstop_after_consecutive_errors = 0\n", "integer"],
  ["[deep_scan]\nmax_time_hours = 97\n", "no greater than 96"],
  ["[deep_scan]\nworkres = 2\n", "Unknown"],
  ["[deep_scan\n", "Cannot read"],
])("rejects invalid ambient settings: %s", async (contents, message) => {
  const input = await fixture(contents);
  await expect(resolveDeepScanConfig({}, input.source)).rejects.toThrow(
    message,
  );
});

test("complete saved settings do not read a changed or invalid legacy file", async () => {
  const input = await fixture("not valid TOML [");
  const saved = {
    workers: 2,
    subagents: 0,
    stopAfterNoNew: 7,
    stopAfterConsecutiveErrors: 2,
    maxDiscoveryRuns: 12,
    maxTimeHours: 1.5,
  };
  const result = await resolveDeepScanConfig(saved, input.source);
  expect(result.settings).toEqual(saved);
  expect(new Set(Object.values(result.sources))).toEqual(new Set(["override"]));
  expect(await readFile(input.source, "utf8")).toBe("not valid TOML [");
});

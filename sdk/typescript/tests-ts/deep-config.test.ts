import {
  mkdir,
  mkdtemp,
  readFile,
  realpath,
  rm,
  symlink,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { afterEach, expect, test } from "bun:test";
import { parse as parseToml } from "smol-toml";
import {
  resolveDeepScanConfig,
  writeDeepScanConfig,
} from "../src/deep-config.js";
import { DEFAULT_DEEP_SCAN_SETTINGS } from "../src/deep-scan-defaults.js";

const directories: string[] = [];
afterEach(async () => {
  await Promise.all(
    directories
      .splice(0)
      .map((path) => rm(path, { recursive: true, force: true })),
  );
});
async function fixture(contents?: string) {
  const root = await realpath(await mkdtemp(join(tmpdir(), "deep-config-")));
  directories.push(root);
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
    await writeDeepScanConfig(
      input.source,
      await resolveDeepScanConfig({}, source),
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
  const destination = join(input.root, "runtime", "deep-scan.toml");
  await writeDeepScanConfig(destination, result);
  expect(parseToml(await readFile(destination, "utf8"))).toMatchObject({
    deep_scan: { workers: 2, subagents: 0, stop_after_no_new: 7 },
  });
  expect(await readFile(input.source, "utf8")).toBe("not valid TOML [");
});

test.each(["same path", "directory link"])(
  "complete settings preserve ambient sections through the %s",
  async (destinationKind) => {
    const input = await fixture("[other]\nenabled = true\n");
    const result = await resolveDeepScanConfig(
      { ...DEFAULT_DEEP_SCAN_SETTINGS, workers: 2 },
      input.source,
    );
    await writeFile(
      input.source,
      "[deep_scan]\nworkers = 9\n[other]\nenabled = false\n",
    );
    let destination = input.source;
    if (destinationKind === "directory link") {
      const link = join(input.root, "runtime");
      await symlink(dirname(input.source), link, "junction");
      destination = join(link, "config.toml");
    }
    await writeDeepScanConfig(destination, result);
    expect(parseToml(await readFile(input.source, "utf8"))).toEqual({
      deep_scan: {
        workers: 2,
        subagents: 3,
        stop_after_no_new: 4,
        stop_after_consecutive_errors: 3,
        max_discovery_runs: 40,
        max_time_hours: 96,
      },
      other: { enabled: false },
    });
  },
);

test("complete settings do not overwrite an invalid ambient destination", async () => {
  const contents = "not valid TOML [";
  const input = await fixture(contents);
  const result = await resolveDeepScanConfig(
    DEFAULT_DEEP_SCAN_SETTINGS,
    input.source,
  );
  await expect(writeDeepScanConfig(input.source, result)).rejects.toThrow(
    "Cannot read Codex Security configuration",
  );
  expect(await readFile(input.source, "utf8")).toBe(contents);
});

test("runtime preparation writes the snapshot even if the ambient file changes", async () => {
  const input = await fixture(
    "[deep_scan]\nworkers = 7\nstop_after_no_new = 6\n[other]\nenabled = true\n",
  );
  const result = await resolveDeepScanConfig({ subagents: 0 }, input.source);
  await writeFile(input.source, "not valid TOML [");
  const destination = join(input.root, "runtime", "deep-scan.toml");
  await writeDeepScanConfig(destination, result);
  expect(parseToml(await readFile(destination, "utf8"))).toEqual({
    deep_scan: {
      workers: 7,
      subagents: 0,
      stop_after_no_new: 6,
      stop_after_consecutive_errors: 3,
      max_discovery_runs: 40,
      max_time_hours: 96,
    },
    other: { enabled: true },
  });
  expect(await readFile(input.source, "utf8")).toBe("not valid TOML [");
});

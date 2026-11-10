import { afterEach, expect, spyOn, test } from "bun:test";
import {
  cp,
  mkdir,
  readFile,
  readdir,
  rm,
  symlink,
  writeFile,
} from "node:fs/promises";
import { join } from "node:path";
import * as timers from "node:timers/promises";
import * as executable from "../src/codex-sdk-environment.js";
import { PluginBootstrapError } from "../src/errors.js";
import { bootstrapPlugin, createMarketplace } from "../src/runtime.js";
import { nodeCommand } from "./support/shell.js";
import { createApiTestFixtures } from "./support/temporary-directories.js";

const { temporaryDirectory, cleanup } = createApiTestFixtures();
afterEach(cleanup);

const denied =
  "Error: failed to activate updated plugin cache entry: Access is denied. (os error 5)";
const backup = denied.replace("activate updated", "back up");
const rollback =
  "Error: failed to activate updated plugin cache entry at target: Access is denied. (os error 5); failed to restore previous cache entry";
const unrelated = "Error: could not enable the plugin";

type Step = {
  stderr?: string;
  stdout?: string;
  exit?: number;
  stale?: boolean;
  replaceMarketplace?: boolean;
  extraSkill?: "marketplace" | "installed";
  invalidMigrationFile?: boolean;
};

// Exercise the real subprocess/error boundary. A successful native install can
// add files of its own when it migrates a plugin's commands.
const fakeCli = `
  const fs = require("node:fs");
  const { join } = require("node:path");
  const home = process.env.CODEX_HOME;
  const args = process.argv.slice(1);
  if (args.join(" ") !== "plugin add --json codex-security@codex-security-sdk")
    throw new Error("Unexpected fixture command " + JSON.stringify(args));
  const plan = join(home, "steps.json");
  const steps = JSON.parse(fs.readFileSync(plan, "utf8"));
  const step = steps.shift();
  if (!step) throw new Error("Unexpected extra install");
  fs.writeFileSync(plan, JSON.stringify(steps));
  const staged = join(home, "sdk-marketplace", "plugins", "codex-security");
  const addSkill = (root, name) => {
    const path = join(root, name);
    fs.mkdirSync(path, { recursive: true });
    fs.writeFileSync(join(path, "SKILL.md"), "synthetic skill");
  };
  if (step.extraSkill === "marketplace") addSkill(staged, "skills/unselected");
  if (step.replaceMarketplace)
    fs.writeFileSync(join(home, "sdk-marketplace", "plugins", "codex-security", "marker.txt"), "different selection");
  if (step.exit) {
    process.stderr.write(step.stderr ?? "");
    process.stdout.write(step.stdout ?? "");
    process.exit(step.exit);
  }
  const installedPath = join(home, "installed");
  fs.cpSync(staged, installedPath, { recursive: true });
  if (step.stale) fs.writeFileSync(join(installedPath, "marker.txt"), "previous");
  if (step.extraSkill === "installed") addSkill(installedPath, "skills/unselected");
  const migrated = join(installedPath, ".codex-plugin", "migrated-command-skills");
  fs.rmSync(migrated, { recursive: true, force: true });
  if (step.invalidMigrationFile) fs.writeFileSync(migrated, "unexpected file");
  else if (fs.existsSync(join(staged, "commands", "sample.md"))) addSkill(migrated, "source-command-sample");
  process.stdout.write(JSON.stringify({ installedPath, version: "1.2.3" }));
`;

async function fixture(
  steps: Step[],
  staleMigration?: "regenerated" | "removed" | "case-preserved",
) {
  const root = await temporaryDirectory();
  const selected = join(root, "selected");
  const home = join(root, "home");
  await mkdir(join(selected, ".codex-plugin"), { recursive: true });
  await writeFile(
    join(selected, ".codex-plugin", "plugin.json"),
    JSON.stringify({ name: "codex-security", version: "1.2.3" }),
  );
  await writeFile(join(selected, "marker.txt"), "selected");
  if (staleMigration !== "removed") {
    await mkdir(join(selected, "commands"));
    await writeFile(
      join(selected, "commands", "sample.md"),
      "---\ndescription: local test\n---\nSample.",
    );
  }
  if (staleMigration) {
    const retired = join(
      selected,
      ".codex-plugin",
      staleMigration === "case-preserved"
        ? "MIGRATED-COMMAND-SKILLS"
        : "migrated-command-skills",
      "source-command-retired",
    );
    await mkdir(retired, { recursive: true });
    await writeFile(join(retired, "SKILL.md"), "retired");
  }
  const marketplace = await createMarketplace(home, selected);
  await writeFile(
    join(home, "config.toml"),
    `[marketplaces.codex-security-sdk]\nsource_type="local"\nsource=${JSON.stringify(marketplace)}\n[plugins."codex-security@codex-security-sdk"]\nenabled=true\n`,
  );
  const previous = join(home, "previous");
  await cp(selected, previous, { recursive: true });
  await writeFile(join(previous, "marker.txt"), "previous");
  const record = join(marketplace, "installed-plugin.json");
  const previousReceipt = JSON.stringify({
    installedPath: previous,
    version: "1.2.3",
  });
  await writeFile(record, previousReceipt);
  const plan = join(home, "steps.json");
  await writeFile(plan, JSON.stringify(steps));
  const command = nodeCommand().command;
  return {
    command,
    selected,
    previous,
    record,
    previousReceipt,
    remaining: async () => JSON.parse(await readFile(plan, "utf8")) as Step[],
    install: (signal?: AbortSignal) =>
      bootstrapPlugin(home, selected, {
        codexCommand: { command, args: ["--eval", fakeCli, "--"] },
        environment: { SystemRoot: process.env["SystemRoot"] },
        signal,
      }),
  };
}

test("only Windows retries a rolled-back bundled plugin activation and records the selected bytes", async () => {
  const f = await fixture([{ exit: 1, stderr: denied }, {}]);
  using resolver = spyOn(
    executable,
    "resolveBundledCodexExecutable",
  ).mockReturnValue(f.command);
  if (process.platform !== "win32") {
    await expect(f.install()).rejects.toThrow(denied);
    expect(resolver).not.toHaveBeenCalled();
    expect(await f.remaining()).toHaveLength(1);
    expect(await readFile(f.record, "utf8")).toBe(f.previousReceipt);
    return;
  }
  const installed = await f.install();
  expect(resolver).toHaveBeenCalled();
  expect(await f.remaining()).toHaveLength(0);
  expect(
    await readFile(join(installed.installedRoot, "marker.txt"), "utf8"),
  ).toBe("selected");
  expect(
    await readFile(
      join(
        installed.installedRoot,
        ".codex-plugin",
        "migrated-command-skills",
        "source-command-sample",
        "SKILL.md",
      ),
      "utf8",
    ),
  ).toBe("synthetic skill");
  expect(JSON.parse(await readFile(f.record, "utf8"))).toEqual({
    installedPath: installed.installedRoot,
    version: "1.2.3",
  });
  expect((await f.install()).installedRoot).toBe(installed.installedRoot);
});

test
  .skipIf(process.platform !== "win32")
  .each(["regenerated", "removed", "case-preserved"] as const)(
  "accepts stale native command output that is %s during recovery",
  async (mode) => {
    const f = await fixture([{ exit: 1, stderr: denied }, {}], mode);
    using resolver = spyOn(
      executable,
      "resolveBundledCodexExecutable",
    ).mockReturnValue(f.command);
    const result = await f.install();
    const migration = join(".codex-plugin", "migrated-command-skills");
    expect(
      await readFile(
        join(
          result.pluginRoot,
          mode === "case-preserved"
            ? join(".codex-plugin", "MIGRATED-COMMAND-SKILLS")
            : migration,
          "source-command-retired",
          "SKILL.md",
        ),
        "utf8",
      ),
    ).toBe("retired");
    const installedEntries = await readdir(
      join(result.installedRoot, migration),
    ).catch((error: NodeJS.ErrnoException) => error.code);
    expect(installedEntries).toEqual(
      mode === "removed" ? "ENOENT" : ["source-command-sample"],
    );
    expect(JSON.parse(await readFile(f.record, "utf8")).installedPath).toBe(
      result.installedRoot,
    );
    expect(await f.remaining()).toHaveLength(0);
    expect((await f.install()).installedRoot).toBe(result.installedRoot);
    expect(resolver).toHaveBeenCalled();
  },
);

test("only the bundled installer reuses its regenerated command output", async () => {
  const f = await fixture([{}, {}, {}], "regenerated");
  using resolver = spyOn(
    executable,
    "resolveBundledCodexExecutable",
  ).mockReturnValue(f.previous);
  await f.install();
  expect(await f.remaining()).toHaveLength(2);

  resolver.mockReturnValue(f.command);
  const installed = await f.install();
  expect(await f.remaining()).toHaveLength(1);
  expect((await f.install()).installedRoot).toBe(installed.installedRoot);
  expect(await f.remaining()).toHaveLength(1);

  resolver.mockReturnValue(f.previous);
  await f.install();
  expect(await f.remaining()).toHaveLength(0);
});

test("rechecks the full marketplace selection and the recovered installed files", async () => {
  const f = await fixture([{}, {}, {}], "regenerated");
  using resolver = spyOn(
    executable,
    "resolveBundledCodexExecutable",
  ).mockReturnValue(f.command);
  const { installedRoot } = await f.install();
  const staleSkill = join(
    f.selected,
    ".codex-plugin",
    "migrated-command-skills",
    "source-command-retired",
    "SKILL.md",
  );
  await writeFile(staleSkill, "revised stale source");
  await f.install();
  expect(await f.remaining()).toHaveLength(1);

  await mkdir(join(installedRoot, "skills", "other-selection"), {
    recursive: true,
  });
  await writeFile(
    join(installedRoot, "skills", "other-selection", "SKILL.md"),
    "other",
  );
  await f.install();
  expect(await f.remaining()).toHaveLength(0);
  expect(resolver).toHaveBeenCalled();
});

test("a link replacing the installed command migration directory requires reinstall", async () => {
  const f = await fixture([{}, {}], "regenerated");
  using resolver = spyOn(
    executable,
    "resolveBundledCodexExecutable",
  ).mockReturnValue(f.command);
  const { installedRoot } = await f.install();
  const migration = join(
    installedRoot,
    ".codex-plugin",
    "migrated-command-skills",
  );
  const outside = await temporaryDirectory();
  await writeFile(join(outside, "marker.txt"), "unrelated");
  await rm(migration, { recursive: true });
  await symlink(
    outside,
    migration,
    process.platform === "win32" ? "junction" : "dir",
  );
  await f.install();
  expect(await f.remaining()).toHaveLength(0);
  expect(await readFile(join(outside, "marker.txt"), "utf8")).toBe("unrelated");
  expect(resolver).toHaveBeenCalled();
});

test.skipIf(process.platform !== "win32").each([
  [
    "persistent denial",
    [
      { exit: 1, stderr: denied + "\nfirst detail" },
      {
        exit: 1,
        stderr:
          denied.replace("Access is denied.", "Zugriff verweigert.") +
          "\nsecond detail",
      },
    ],
    "first detail",
    0,
  ],
  [
    "different retry failure",
    [
      { exit: 1, stderr: denied },
      { exit: 1, stderr: unrelated },
    ],
    unrelated,
    0,
  ],
  [
    "stale same-version result",
    [{ exit: 1, stderr: denied }, { stale: true }],
    "selected plugin contents",
    0,
  ],
  [
    "marketplace replaced before retry",
    [{ exit: 1, stderr: denied, replaceMarketplace: true }, {}],
    "changed before the native installation could be retried",
    1,
  ],
  [
    "marketplace replaced during retry",
    [{ exit: 1, stderr: denied }, { replaceMarketplace: true }],
    "selected plugin contents",
    0,
  ],
  [
    "additional marketplace skill during retry",
    [{ exit: 1, stderr: denied }, { extraSkill: "marketplace" }],
    "selected plugin contents",
    0,
  ],
  [
    "additional installed skill after the original marketplace is restored",
    [{ exit: 1, stderr: denied }, { extraSkill: "installed" }],
    "selected plugin contents",
    0,
  ],
  [
    "regular file at the native migration directory",
    [{ exit: 1, stderr: denied }, { invalidMigrationFile: true }],
    "selected plugin contents",
    0,
  ],
  ["backup failure", [{ exit: 1, stderr: backup }, {}], backup, 1],
  ["rollback failure", [{ exit: 1, stderr: rollback }, {}], rollback, 1],
  [
    "rollback failure in the cause chain",
    [
      { exit: 1, stderr: denied + "\nfailed to restore previous cache entry" },
      {},
    ],
    "failed to restore previous cache entry",
    1,
  ],
  [
    "different native error",
    [{ exit: 1, stderr: unrelated }, {}],
    unrelated,
    1,
  ],
  ["stdout alone", [{ exit: 1, stdout: denied }, {}], denied, 1],
  ["different exit status", [{ exit: 2, stderr: denied }, {}], denied, 1],
  ["caller executable", [{ exit: 1, stderr: denied }, {}], denied, 1],
] as const)(
  "%s keeps the previous installation receipt",
  async (scenario, steps, message, remaining) => {
    const f = await fixture([...steps]);
    using resolver = spyOn(
      executable,
      "resolveBundledCodexExecutable",
    ).mockReturnValue(
      scenario === "caller executable" ? f.previous : f.command,
    );
    const error = await f.install().catch((cause: unknown) => cause);
    expect(error).toBeInstanceOf(PluginBootstrapError);
    expect((error as Error).message).toContain(message);
    if (scenario === "persistent denial")
      expect(((error as Error).cause as Error).message).toBe(
        denied + "\nfirst detail",
      );
    expect(await f.remaining()).toHaveLength(remaining);
    expect(await readFile(f.record, "utf8")).toBe(f.previousReceipt);
    expect(await readFile(join(f.previous, "marker.txt"), "utf8")).toBe(
      "previous",
    );
    if (scenario === "caller executable") expect(resolver).toHaveBeenCalled();
  },
);

test.skipIf(process.platform !== "win32")(
  "cancellation during the native activation retry delay preserves the caller's reason",
  async () => {
    const f = await fixture([{ exit: 1, stderr: denied }, {}]);
    const controller = new AbortController();
    const reason = new Error("synthetic canceled recovery");
    using resolver = spyOn(
      executable,
      "resolveBundledCodexExecutable",
    ).mockReturnValue(f.command);
    const originalDelay = timers.setTimeout;
    using delay = spyOn(timers, "setTimeout").mockImplementation((...args) => {
      if (args[2]?.signal === controller.signal) controller.abort(reason);
      return originalDelay(...args);
    });
    await expect(f.install(controller.signal)).rejects.toBe(reason);
    expect(resolver).toHaveBeenCalled();
    expect(delay).toHaveBeenCalled();
    expect(await f.remaining()).toHaveLength(1);
    expect(await readFile(f.record, "utf8")).toBe(f.previousReceipt);
  },
);

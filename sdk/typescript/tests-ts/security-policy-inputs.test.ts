import { spawnSync } from "node:child_process";
import {
  link,
  mkdir,
  mkdtemp,
  readFile,
  realpath,
  rm,
  stat,
  symlink,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, test } from "bun:test";
import { bootstrapPlugin, resolvePluginPython } from "../src/runtime.js";
import { BUNDLED_PLUGIN_VERSION } from "../src/version.js";
import { PLUGIN_ROOT } from "./plugin-root.js";

const python = await resolvePluginPython();
const roots: string[] = [];

afterEach(async () => {
  await Promise.all(
    roots.splice(0).map((root) => rm(root, { recursive: true, force: true })),
  );
});

async function fixture() {
  const root = await realpath(await mkdtemp(join(tmpdir(), "policy-inputs-")));
  roots.push(root);
  const repository = join(root, "repository");
  await mkdir(repository);
  return { root, repository };
}

function run(repository: string, ...args: string[]) {
  return spawnSync(
    python,
    [
      "-I",
      join(PLUGIN_ROOT, "scripts", "resolve_security_md.py"),
      "--repo",
      repository,
      ...args,
    ],
    { encoding: "utf8" },
  );
}

function inspect(repository: string, scope = ".", ...args: string[]) {
  const result = run(repository, "--inspect", "--scope", scope, ...args);
  expect(result.status, result.stderr).toBe(0);
  return JSON.parse(result.stdout) as {
    previousContent: string | null;
    guidance: string;
    policyPaths: string[];
  };
}

describe("shared security-policy inputs", () => {
  test("refreshes cached plugins before exposing checked policy inputs", async () => {
    const { root, repository } = await fixture();
    const home = join(root, "home");
    const marketplace = join(home, "sdk-marketplace");
    const cachedPlugin = join(marketplace, "plugins", "codex-security");
    const manifestPath = join(cachedPlugin, ".codex-plugin", "plugin.json");
    await mkdir(join(cachedPlugin, ".codex-plugin"), { recursive: true });
    await mkdir(join(cachedPlugin, "scripts"));
    await writeFile(
      manifestPath,
      JSON.stringify({ name: "codex-security", version: "0.1.22" }),
    );
    await writeFile(
      join(cachedPlugin, "scripts", "resolve_security_md.py"),
      "raise SystemExit('stale resolver')\n",
    );
    await writeFile(
      join(home, "config.toml"),
      `[marketplaces.codex-security-sdk]\nsource_type = "local"\nsource = ${JSON.stringify(marketplace)}\n`,
    );

    const installed = await bootstrapPlugin(home, PLUGIN_ROOT, {
      codexCommand: { command: join(root, "codex") },
      runCodex: async (_command, args) => {
        expect(args).toEqual([
          "plugin",
          "add",
          "--json",
          "codex-security@codex-security-sdk",
        ]);
        const manifest = JSON.parse(await readFile(manifestPath, "utf8")) as {
          version: string;
        };
        return JSON.stringify({
          installedPath: cachedPlugin,
          version: manifest.version,
        });
      },
    });
    expect(installed.version).toBe(BUNDLED_PLUGIN_VERSION);
    expect(installed.version).not.toBe("0.1.22");
    const result = spawnSync(
      python,
      [
        "-I",
        join(installed.installedRoot, "scripts", "resolve_security_md.py"),
        "--repo",
        repository,
        "--inspect",
        "--scope",
        ".",
      ],
      { encoding: "utf8" },
    );
    expect(result.status, result.stderr).toBe(0);
    expect(JSON.parse(result.stdout)).toEqual({
      previousContent: null,
      guidance: "",
      policyPaths: [],
    });
  });

  test("returns scoped policy evidence and keeps reporting policies separate", async () => {
    const { repository } = await fixture();
    for (const path of [
      "services/api/.hidden",
      "services/other",
      ".github",
      "docs",
    ])
      await mkdir(join(repository, path), { recursive: true });
    for (const [path, content] of [
      ["SECURITY.md", "# Root policy\n"],
      ["services/api/SECURITY.md", "# API policy\r\n"],
      ["services/api/.hidden/SECURITY.md", "# Hidden policy\n"],
      ["services/other/SECURITY.md", "# Other policy\n"],
      [".github/SECURITY.md", "# Reporting instructions\n"],
      ["docs/SECURITY.md", "# Reporting documentation\n"],
    ])
      await writeFile(join(repository, path!), content!);

    const result = inspect(repository, "services/api");
    expect(result.previousContent).toBe("# API policy\r\n");
    expect(result.guidance.indexOf("# Root policy")).toBeLessThan(
      result.guidance.indexOf("# API policy"),
    );
    expect(result.guidance).not.toContain("Reporting instructions");
    expect(result.guidance).not.toContain("Other policy");
    expect(result.policyPaths).toEqual([
      ".github/SECURITY.md",
      "SECURITY.md",
      "docs/SECURITY.md",
      "services/api/.hidden/SECURITY.md",
      "services/api/SECURITY.md",
    ]);
    expect(
      JSON.parse(run(repository, "--list", "--scope", "services/api").stdout),
    ).toEqual(["services/api/.hidden/SECURITY.md", "services/api/SECURITY.md"]);
  });

  test("ignores absent reporting policies behind external directory links", async () => {
    for (const directory of [".github", "docs"]) {
      const { root, repository } = await fixture();
      const outside = join(root, "external-reporting");
      const policy = join(outside, "SECURITY.md");
      await mkdir(outside);
      await mkdir(join(repository, "component"));
      await symlink(
        outside,
        join(repository, directory),
        process.platform === "win32" ? "junction" : "dir",
      );
      expect(inspect(repository, "component")).toEqual({
        previousContent: null,
        guidance: "",
        policyPaths: [],
      });

      await symlink(join(outside, "missing.md"), policy, "file");
      const dangling = run(repository, "--inspect", "--scope", "component");
      expect(dangling.status, dangling.stderr).toBe(2);
      expect(dangling.stdout).toBe("");
      await rm(policy);
      await writeFile(policy, "# External reporting policy\n");
      const existing = run(repository, "--inspect", "--scope", "component");
      expect(existing.status, existing.stderr).toBe(2);
      expect(existing.stdout).toBe("");
    }
  });

  test("reads safe inherited links but rejects a linked destination", async () => {
    const { repository } = await fixture();
    await mkdir(join(repository, "component"));
    await writeFile(join(repository, "guidance.md"), "# Shared guidance\n");
    await symlink("guidance.md", join(repository, "SECURITY.md"), "file");
    expect(inspect(repository, "component").guidance).toContain(
      "# Shared guidance",
    );
    const selected = run(repository, "--inspect", "--scope", ".");
    expect(selected.status).toBe(2);
    expect(selected.stderr).toContain(
      "selected SECURITY.md must not be a symbolic link",
    );
  });

  test("rejects dangling repository-local policy links during inspection", async () => {
    for (const path of [
      "SECURITY.md",
      "component/child/SECURITY.md",
      ".github/SECURITY.md",
      "docs/SECURITY.md",
    ]) {
      const { repository } = await fixture();
      for (const directory of ["component/child", ".github", "docs"])
        await mkdir(join(repository, directory), { recursive: true });
      expect(inspect(repository, "component")).toEqual({
        previousContent: null,
        guidance: "",
        policyPaths: [],
      });
      await symlink(
        join(repository, "missing.md"),
        join(repository, path),
        "file",
      );

      const result = run(repository, "--inspect", "--scope", "component");
      expect(result.status, path).toBe(2);
      expect(result.stdout).toBe("");
      expect(result.stderr).toContain(
        "SECURITY.md symbolic link target does not exist",
      );
    }
  });

  test("preserves read-only handling of non-file policy paths", async () => {
    for (const kind of [
      "directory",
      "missing-inside",
      "missing-outside",
      "cycle",
    ]) {
      const { root, repository } = await fixture();
      const policy = join(repository, "SECURITY.md");
      await mkdir(join(repository, "component"));
      if (kind === "directory") {
        await mkdir(policy);
      } else {
        await symlink(
          kind === "cycle"
            ? policy
            : join(kind === "missing-inside" ? repository : root, "missing.md"),
          policy,
          "file",
        );
      }

      const resolved = run(repository, "--scope", "component");
      expect(resolved.status, kind).toBe(0);
      expect(resolved.stdout).toBe("");
      const checked = run(repository, "--inspect", "--scope", "component");
      expect(checked.status, kind).toBe(2);
      expect(checked.stdout).toBe("");
    }
  });

  test("keeps directory links out of read-only inventories", async () => {
    const { root, repository } = await fixture();
    const outside = join(root, "outside");
    await mkdir(outside);
    await symlink(
      outside,
      join(repository, "SECURITY.md"),
      process.platform === "win32" ? "junction" : "dir",
    );

    const inventory = run(repository, "--list");
    expect(inventory.status, inventory.stderr).toBe(0);
    expect(JSON.parse(inventory.stdout)).toEqual([]);

    const inspection = run(repository, "--inspect", "--scope", ".");
    expect(inspection.status).toBe(2);
    expect(inspection.stdout).toBe("");
  });

  test("reads hard-linked policies but rejects a hard-linked destination", async () => {
    const { repository } = await fixture();
    await mkdir(join(repository, "component", "child"), { recursive: true });
    const shared = join(repository, "guidance.md");
    await writeFile(shared, "# Shared guidance\n");
    await link(shared, join(repository, "SECURITY.md"));
    await link(shared, join(repository, "component", "child", "SECURITY.md"));

    const resolved = run(repository, "--scope", "component");
    expect(resolved.status, resolved.stderr).toBe(0);
    expect(resolved.stdout).toContain("# Shared guidance");
    const evidence = inspect(repository, "component");
    expect(evidence.guidance).toBe(resolved.stdout);
    expect(evidence.policyPaths).toEqual([
      "SECURITY.md",
      "component/child/SECURITY.md",
    ]);

    const selected = run(repository, "--inspect", "--scope", ".");
    expect(selected.status).toBe(2);
    expect(selected.stdout).toBe("");
    expect(selected.stderr).toContain(
      "selected SECURITY.md must not be hard-linked",
    );
  });

  test("rejects outside, dangling outside, and cyclic policy links", async () => {
    for (const kind of ["outside", "missing", "cycle"]) {
      const { root, repository } = await fixture();
      await mkdir(join(repository, "component"));
      const outside = join(root, "outside.md");
      const policy = join(repository, "component", "SECURITY.md");
      await writeFile(outside, "synthetic private text\n");
      await symlink(
        kind === "outside"
          ? outside
          : kind === "missing"
            ? join(root, "missing.md")
            : policy,
        policy,
        "file",
      );
      const result = run(repository, "--inspect", "--scope", ".");
      expect(result.status, kind).toBe(2);
      expect(result.stdout).toBe("");
      expect(result.stderr).not.toContain("synthetic private text");
    }
  });

  test("does not traverse directory links or Git metadata", async () => {
    const { root, repository } = await fixture();
    const outside = join(root, "outside");
    const metadata = join(repository, "git-data");
    const commonMetadata = join(repository, "git-common");
    const gitArgs = ["--git-dir", metadata, "--git-dir", commonMetadata];
    await mkdir(outside);
    await mkdir(join(repository, ".git"));
    await mkdir(metadata);
    await mkdir(commonMetadata);
    await writeFile(join(outside, "SECURITY.md"), "# Outside\n");
    await writeFile(
      join(repository, ".git", "SECURITY.md"),
      "# Git metadata\n",
    );
    await writeFile(join(metadata, "SECURITY.md"), "# Separate Git metadata\n");
    await writeFile(
      join(commonMetadata, "SECURITY.md"),
      "# Common Git metadata\n",
    );
    await symlink(
      outside,
      join(repository, "linked-directory"),
      process.platform === "win32" ? "junction" : "dir",
    );
    expect(inspect(repository, ".", ...gitArgs).policyPaths).toEqual([]);
    const inventory = run(repository, "--list", ...gitArgs);
    expect(inventory.status, inventory.stderr).toBe(0);
    expect(JSON.parse(inventory.stdout)).toEqual([]);
    await mkdir(join(repository, "component"));
    await symlink(
      join(metadata, "SECURITY.md"),
      join(repository, "component", "SECURITY.md"),
      "file",
    );
    const result = run(repository, "--inspect", "--scope", ".", ...gitArgs);
    expect(result.status).toBe(2);
    expect(result.stderr).toContain("Git metadata");
    const nestedMetadata = join(metadata, "hooks");
    await mkdir(nestedMetadata);
    await writeFile(join(nestedMetadata, "SECURITY.md"), "# Metadata\n");
    for (const mode of [["--list"], ["--inspect", "--scope", "."]]) {
      const nested = run(nestedMetadata, ...mode, ...gitArgs);
      expect(nested.status).toBe(2);
      expect(nested.stdout).toBe("");
    }
  });

  test("rejects case aliases of caller-supplied Git metadata directories", async () => {
    const { repository } = await fixture();
    const metadata = join(repository, "GitData");
    const alias = join(repository, "gitdata");
    await mkdir(metadata);
    await mkdir(join(repository, "component"));
    await writeFile(join(metadata, "private.md"), "synthetic metadata\n");
    await writeFile(join(metadata, "SECURITY.md"), "# Git metadata\n");
    if ((await stat(alias).catch(() => null)) === null)
      await symlink(
        metadata,
        alias,
        process.platform === "win32" ? "junction" : "dir",
      );
    const inventory = run(repository, "--list", "--git-dir", alias);
    expect(inventory.status, inventory.stderr).toBe(0);
    expect(JSON.parse(inventory.stdout)).toEqual([]);
    await symlink(
      join(alias, "private.md"),
      join(repository, "SECURITY.md"),
      "file",
    );
    const result = run(
      repository,
      "--inspect",
      "--scope",
      "component",
      "--git-dir",
      metadata,
    );
    expect(result.status).toBe(2);
    expect(result.stdout).toBe("");
    expect(result.stderr).toContain("Git metadata");
  });

  test("uses filesystem identity for case-sensitive Windows containment", () => {
    const result = spawnSync(
      python,
      [
        "-I",
        "-c",
        `import runpy, sys
from pathlib import PureWindowsPath
class CaseSensitivePath(PureWindowsPath):
    def samefile(self, other):
        return str(self) == str(other)
module = runpy.run_path(sys.argv[1])
guard = module["_git_metadata"]
root = CaseSensitivePath("C:/repo")
metadata = root / "GitData"
assert not guard(root / "gitdata" / "SECURITY.md", root, (metadata,))
assert guard(metadata / "SECURITY.md", root, (metadata,))
assert not guard(root / ".GIT" / "SECURITY.md", root, ())
assert guard(root / ".git" / "SECURITY.md", root, ())
try:
    module["_inside"](CaseSensitivePath("C:/Repo/SECURITY.md"), root, "scope")
except module["ResolutionError"]:
    pass
else:
    raise AssertionError("accepted a distinct case-only sibling")`,
        join(PLUGIN_ROOT, "scripts", "resolve_security_md.py"),
      ],
      { encoding: "utf8" },
    );
    expect(result.status, result.stderr).toBe(0);
  });

  test("enforces the existing byte and UTF-8 contract in both resolver modes", async () => {
    for (const content of [
      Buffer.alloc(1024 * 1024 + 1, "x"),
      Buffer.from([0xff]),
    ]) {
      const { repository } = await fixture();
      await writeFile(join(repository, "SECURITY.md"), content);
      for (const mode of [[], ["--inspect"]]) {
        const result = run(repository, ...mode, "--scope", ".");
        expect(result.status).toBe(2);
        expect(result.stdout).toBe("");
      }
    }
  });

  test("requires a directory scope and writes only the requested output", async () => {
    const { root, repository } = await fixture();
    const source = join(repository, "source.ts");
    await writeFile(source, "export const value = 1;\n");
    expect(run(repository, "--inspect", "--scope", source).status).toBe(2);
    expect(run(repository, "--list", "--scope", source).status).toBe(2);
    expect(run(repository, "--inspect").status).toBe(2);
    expect(run(repository, "--inspect", "--list", "--scope", ".").status).toBe(
      2,
    );
    expect(run(repository, "--inspect", "--scope", root).status).toBe(2);
    const loop = join(root, "git-loop");
    await symlink(loop, loop, "file");
    const invalidMetadata = run(repository, "--list", "--git-dir", loop);
    expect(invalidMetadata.status).toBe(2);
    expect(invalidMetadata.stderr).not.toContain("Traceback");
    const expected = {
      previousContent: null,
      guidance: "",
      policyPaths: [],
    };
    expect(inspect(repository)).toEqual(expected);
    const output = join(root, "inspection.json");
    const result = run(
      repository,
      "--inspect",
      "--scope",
      ".",
      "--out",
      output,
    );
    expect(result.status, result.stderr).toBe(0);
    expect(result.stdout).toBe("");
    expect(JSON.parse(await readFile(output, "utf8"))).toEqual(expected);
    expect(await readFile(source, "utf8")).toBe("export const value = 1;\n");
  });
});

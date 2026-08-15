import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  chmod,
  copyFile,
  link as hardlink,
  mkdir,
  mkdtemp,
  readdir,
  readFile,
  realpath,
  rename,
  rm,
  symlink,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { basename, dirname, join } from "node:path";
import { afterEach, describe, expect, test } from "bun:test";
import { normalizeTarget } from "../src/targets.js";
import { PLUGIN_ROOT } from "./plugin-root.js";

const directories: string[] = [];
const python = Bun.which("python3") ?? Bun.which("python") ?? Bun.which("py");

afterEach(async () => {
  await Promise.all(
    directories
      .splice(0)
      .map((directory) => rm(directory, { recursive: true, force: true })),
  );
});

async function repository(initializeGit = true): Promise<string> {
  const root = await realpath(
    await mkdtemp(join(tmpdir(), "codex-security-scan-inventory-")),
  );
  directories.push(root);
  const checkout = join(root, "repository");
  await mkdir(checkout);
  if (initializeGit) execFileSync("git", ["init", "-q"], { cwd: checkout });
  return checkout;
}

function commit(checkout: string): void {
  execFileSync(
    "git",
    [
      "-c",
      "user.name=Inventory Test",
      "-c",
      "user.email=inventory@example.test",
      "commit",
      "-qm",
      "Track source",
    ],
    { cwd: checkout },
  );
}

function windowsShortPath(path: string): string | null {
  if (process.platform !== "win32" || python === null) return null;
  const alias = execFileSync(
    python,
    [
      "-B",
      "-c",
      [
        "import ctypes, sys",
        "function = ctypes.windll.kernel32.GetShortPathNameW",
        "size = function(sys.argv[1], None, 0)",
        "buffer = ctypes.create_unicode_buffer(size) if size else None",
        "print(buffer.value if buffer is not None and function(sys.argv[1], buffer, size) else '')",
      ].join("\n"),
      path,
    ],
    { encoding: "utf8" },
  ).trim();
  return alias && alias.toLowerCase() !== path.toLowerCase() ? alias : null;
}

async function inventory(
  checkout: string,
  scope = ".",
  env: NodeJS.ProcessEnv = process.env,
): Promise<string[]> {
  if (python === null) throw new Error("A Python interpreter is required.");
  const output = join(dirname(checkout), "inventory.txt");
  execFileSync(
    python,
    [
      "-B",
      join(PLUGIN_ROOT, "scripts", "generate_in_scope_files.py"),
      "--repo",
      checkout,
      "--scope",
      scope,
      "--out",
      output,
    ],
    { cwd: checkout, env, stdio: "pipe" },
  );
  return (await readFile(output, "utf8")).trimEnd().split("\n").filter(Boolean);
}

describe("security scan file inventory", () => {
  test("keeps tracked source while excluding ignored untracked files", async () => {
    if (Bun.which("rg") === null) return;

    const checkout = await repository();
    await mkdir(join(checkout, "ignored"));
    await mkdir(join(checkout, "src"));
    await Promise.all([
      writeFile(join(checkout, ".gitignore"), ".env\nignored/\ntracked.env\n"),
      writeFile(join(checkout, ".ignore"), "hidden.ts\n"),
      writeFile(join(checkout, ".env"), "private\n"),
      writeFile(join(checkout, "ignored", "private.ts"), "private\n"),
      writeFile(join(checkout, "tracked.env"), "tracked\n"),
      writeFile(join(checkout, "hidden.ts"), "tracked\n"),
      writeFile(join(checkout, "src", "visible.ts"), "export {};\n"),
    ]);
    execFileSync("git", ["add", "--force", "tracked.env", "hidden.ts"], {
      cwd: checkout,
    });

    expect(await inventory(checkout)).toEqual([
      "./.gitignore",
      "./.ignore",
      "./hidden.ts",
      "./src/visible.ts",
      "./tracked.env",
    ]);
  });

  test.each([
    "XDG default",
    "HOME default",
    "configured",
    "conditional",
    "relative",
    "relative parent",
    ...(process.platform === "win32"
      ? []
      : ["trailing newline", "trailing carriage return"]),
  ])(
    "honors %s global Git excludes across scoped nested checkouts",
    async (kind) => {
      if (Bun.which("rg") === null) return;

      const checkout = await repository();
      const home = join(dirname(checkout), "home");
      const configuration = join(dirname(checkout), "configuration");
      const configuredExcludes =
        kind === "trailing newline"
          ? "custom-excludes\n"
          : kind === "trailing carriage return"
            ? "custom-excludes\r"
            : "custom-excludes";
      const excludes =
        kind === "HOME default"
          ? join(home, ".config", "git", "ignore")
          : kind === "relative"
            ? join(checkout, "rel-ignore")
            : kind === "relative parent"
              ? join(dirname(checkout), "external-ignore")
              : kind === "configured" ||
                  kind === "conditional" ||
                  kind.startsWith("trailing ")
                ? join(home, configuredExcludes)
                : join(configuration, "git", "ignore");
      const nested = join(checkout, "nested");
      await Promise.all([
        mkdir(dirname(excludes), { recursive: true }),
        mkdir(home, { recursive: true }),
        mkdir(nested),
      ]);
      execFileSync("git", ["init", "-q"], { cwd: nested });
      await Promise.all([
        writeFile(excludes, "*.ts\n!visible.ts\nrel-ignore\n"),
        writeFile(join(checkout, "private.ts"), "private\n"),
        writeFile(join(checkout, "visible.ts"), "visible\n"),
        writeFile(join(nested, "private.ts"), "private\n"),
        writeFile(join(nested, "tracked.ts"), "tracked\n"),
      ]);
      execFileSync("git", ["add", "--force", "tracked.ts"], { cwd: nested });
      const environment = {
        ...process.env,
        HOME: home,
        USERPROFILE: home,
        XDG_CONFIG_HOME: kind === "HOME default" ? "" : configuration,
        GIT_CONFIG_GLOBAL: join(home, ".gitconfig"),
        GIT_CONFIG_NOSYSTEM: "1",
      };
      if (
        kind === "configured" ||
        kind.startsWith("trailing ") ||
        kind === "relative" ||
        kind === "relative parent"
      ) {
        execFileSync(
          "git",
          [
            "config",
            "--global",
            "core.excludesFile",
            kind === "relative"
              ? "rel-ignore"
              : kind === "relative parent"
                ? "../external-ignore"
                : excludes,
          ],
          {
            cwd: checkout,
            env: environment,
          },
        );
      } else if (kind === "conditional") {
        const included = join(home, "included.gitconfig");
        await Promise.all([
          writeFile(
            included,
            `[core]\n\texcludesFile = ${JSON.stringify(excludes)}\n`,
          ),
          writeFile(
            join(home, ".gitconfig"),
            `[includeIf "gitdir:${checkout.replaceAll("\\", "/")}/.git"]\n\tpath = ${JSON.stringify(included)}\n`,
          ),
        ]);
      }

      expect(await inventory(checkout, ".", environment)).toEqual([
        "./nested/tracked.ts",
        "./visible.ts",
      ]);
      expect(await inventory(checkout, "nested", environment)).toEqual([
        "nested/tracked.ts",
      ]);
    },
  );

  test("honors trusted system excludes and user-global precedence", async () => {
    if (Bun.which("rg") === null) return;

    const checkout = await repository();
    const home = join(dirname(checkout), "home");
    await mkdir(home);
    const system = join(home, "system.gitconfig");
    const systemExcludes = join(home, "system-excludes");
    const globalExcludes = join(home, "global-excludes");
    await Promise.all([
      writeFile(
        system,
        `[core]\n\texcludesFile = ${JSON.stringify(systemExcludes)}\n`,
      ),
      writeFile(systemExcludes, "system-private.ts\n"),
      writeFile(globalExcludes, "global-private.ts\n"),
      writeFile(join(checkout, "system-private.ts"), "private\n"),
      writeFile(join(checkout, "global-private.ts"), "private\n"),
      writeFile(join(checkout, "visible.ts"), "visible\n"),
    ]);
    const environment = {
      ...process.env,
      HOME: home,
      USERPROFILE: home,
      XDG_CONFIG_HOME: join(home, "configuration"),
      GIT_CONFIG_SYSTEM: system,
      GIT_CONFIG_GLOBAL: join(home, ".gitconfig"),
      GIT_CONFIG_NOSYSTEM: "0",
    };

    expect(await inventory(checkout, ".", environment)).toEqual([
      "./global-private.ts",
      "./visible.ts",
    ]);
    execFileSync(
      "git",
      ["config", "--global", "core.excludesFile", globalExcludes],
      { cwd: checkout, env: environment },
    );
    expect(await inventory(checkout, ".", environment)).toEqual([
      "./system-private.ts",
      "./visible.ts",
    ]);
    await rm(join(home, ".gitconfig"));
    expect(
      await inventory(checkout, ".", {
        ...environment,
        GIT_CONFIG_NOSYSTEM: "1",
      }),
    ).toEqual(["./global-private.ts", "./system-private.ts", "./visible.ts"]);
  });

  test.each([
    ["configured directory", "global", "directory", true],
    ["system directory", "system", "directory", true],
    ["XDG default directory", "default", "directory", true],
    ["configured missing file", "global", "missing", false],
    ["missing XDG default", "default", "missing", false],
    ["configured empty value", "global", "empty", false],
    ["configured null device", "global", "null", false],
  ] as const)(
    "handles %s without widening Git exclusions",
    async (_kind, scope, shape, rejected) => {
      if (Bun.which("rg") === null) return;

      const checkout = await repository();
      const home = join(dirname(checkout), "home");
      const configuration = join(dirname(checkout), "configuration");
      await Promise.all([
        mkdir(home),
        mkdir(configuration),
        writeFile(join(checkout, "private.ts"), "private\n"),
      ]);
      const excludes =
        scope === "default"
          ? join(configuration, "git", "ignore")
          : join(home, "configured-excludes");
      if (shape === "directory") await mkdir(excludes, { recursive: true });
      const environment = {
        ...process.env,
        HOME: home,
        USERPROFILE: home,
        XDG_CONFIG_HOME: configuration,
        GIT_CONFIG_GLOBAL: join(home, ".gitconfig"),
        GIT_CONFIG_SYSTEM: join(home, "system.gitconfig"),
        GIT_CONFIG_NOSYSTEM: scope === "system" ? "0" : "1",
      };
      if (scope !== "default") {
        execFileSync(
          "git",
          [
            "config",
            scope === "global" ? "--global" : "--system",
            "core.excludesFile",
            shape === "empty"
              ? ""
              : shape === "null"
                ? process.platform === "win32"
                  ? "NUL"
                  : "/dev/null"
                : excludes,
          ],
          { cwd: checkout, env: environment },
        );
      }
      if (rejected) {
        await expect(inventory(checkout, ".", environment)).rejects.toThrow(
          "global Git exclusions must be a regular file",
        );
      } else {
        expect(await inventory(checkout, ".", environment)).toEqual([
          "./private.ts",
        ]);
      }
    },
  );

  test("inventories snapshots and default excludes when Git is unavailable", async () => {
    const ripgrep = Bun.which("rg");
    if (ripgrep === null || python === null) return;

    const checkout = await repository(false);
    const binaries = join(dirname(checkout), "binaries");
    const configuration = join(dirname(checkout), "configuration");
    await Promise.all([
      mkdir(binaries),
      mkdir(join(configuration, "git"), { recursive: true }),
    ]);
    await Promise.all([
      copyFile(
        ripgrep,
        join(binaries, process.platform === "win32" ? "rg.exe" : "rg"),
      ),
      writeFile(join(configuration, "git", "ignore"), "private.ts\n"),
      writeFile(join(checkout, "private.ts"), "private\n"),
      writeFile(join(checkout, "visible.ts"), "visible\n"),
    ]);

    expect(
      await inventory(checkout, ".", {
        ...process.env,
        PATH: binaries,
        XDG_CONFIG_HOME: configuration,
        GIT_CONFIG_NOSYSTEM: "1",
      }),
    ).toEqual(["./visible.ts"]);
  });

  test
    .skipIf(process.platform === "win32")
    .each([
      "file",
      "directory",
      "reentry file",
      "reentry directory",
      "case reentry file",
      "case reentry directory",
    ])(
    "rejects a symbolic %s in a repository-relative global exclude path",
    async (kind) => {
      if (Bun.which("rg") === null) return;

      const checkout = await repository();
      const home = join(dirname(checkout), "home");
      const external = join(dirname(checkout), "external");
      const file = kind.endsWith("file");
      const relative = file ? "rel-ignore" : "rules/rel-ignore";
      const alias = kind.startsWith("case")
        ? basename(checkout).toUpperCase()
        : basename(checkout);
      if (
        kind.startsWith("case") &&
        !(await realpath(join(dirname(checkout), alias)).then(
          async (resolved) => resolved === (await realpath(checkout)),
          () => false,
        ))
      ) {
        return;
      }
      const configured = kind.includes("reentry")
        ? `../${alias}/${relative}`
        : relative;
      await Promise.all([mkdir(home), mkdir(external)]);
      await writeFile(join(external, "rel-ignore"), "private.ts\n");
      await symlink(
        file ? join(external, "rel-ignore") : external,
        join(checkout, file ? "rel-ignore" : "rules"),
      );
      const environment = {
        ...process.env,
        HOME: home,
        USERPROFILE: home,
        GIT_CONFIG_GLOBAL: join(home, ".gitconfig"),
        GIT_CONFIG_NOSYSTEM: "1",
      };
      execFileSync(
        "git",
        ["config", "--global", "core.excludesFile", configured],
        { cwd: checkout, env: environment },
      );

      await expect(inventory(checkout, ".", environment)).rejects.toThrow(
        "symbolic ignore files are not supported",
      );
    },
  );

  test.each([".gitignore", ".ignore", ".rgignore"])(
    "inventories ordinary directories named %s",
    async (name) => {
      if (Bun.which("rg") === null) return;

      const checkout = await repository();
      const directory = join(checkout, name);
      await mkdir(directory);
      await writeFile(join(directory, "visible.ts"), "visible\n");

      expect(await inventory(checkout)).toContain(`./${name}/visible.ts`);
    },
  );

  test.skipIf(process.platform === "win32")(
    "preserves distinct POSIX trailing-dot and trailing-space source paths",
    async () => {
      if (Bun.which("rg") === null) return;

      const checkout = await repository();
      const names = ["source.ts", "source.ts.", "source.ts "];
      await Promise.all(
        names.map((name) => writeFile(join(checkout, name), "tracked\n")),
      );
      execFileSync("git", ["add", ...names], { cwd: checkout });

      const entries = await inventory(checkout);
      for (const name of names) {
        expect(entries).toContain(`./${name}`);
      }
    },
  );

  test.each([".ignore", ".rgignore"])(
    "keeps ordinary files re-included by higher-precedence %s rules",
    async (override) => {
      if (Bun.which("rg") === null) return;

      const checkout = await repository();
      await Promise.all([
        writeFile(join(checkout, ".gitignore"), "source.ts\n"),
        writeFile(join(checkout, override), "!source.ts\n"),
        writeFile(join(checkout, "source.ts"), "visible\n"),
      ]);

      expect(await inventory(checkout)).toContain("./source.ts");
    },
  );

  test("shares ignore probes across directories with the same rules", async () => {
    if (Bun.which("rg") === null) return;

    async function countLookups(branches: number): Promise<number> {
      const checkout = await repository();
      const trace = join(dirname(checkout), "git-trace.log");
      await writeFile(join(checkout, ".ignore"), "ignored/\n");
      for (let index = 0; index < branches; index++) {
        const nested = join(checkout, `branch-${index}`, "nested");
        await mkdir(nested, { recursive: true });
        await writeFile(join(nested, "source.ts"), "visible\n");
      }
      await inventory(checkout, ".", { ...process.env, GIT_TRACE: trace });
      return (
        (await readFile(trace, "utf8")).match(/--git-path info\/exclude/g) ?? []
      ).length;
    }

    expect(await countLookups(18)).toBeLessThanOrEqual(await countLookups(2));
  });

  test("validates Git object files once across many scan directories", async () => {
    if (Bun.which("rg") === null) return;

    const checkout = await repository();
    const instrumentation = join(dirname(checkout), "instrumentation");
    const trace = join(dirname(checkout), "object-stats.log");
    await mkdir(instrumentation);
    await writeFile(
      join(instrumentation, "sitecustomize.py"),
      "import os\nfrom pathlib import Path\noriginal = Path.stat\ndef observed(self, *args, **kwargs):\n    if self.parent.parent.name == 'objects' and len(self.parent.name) == 2 and len(self.name) == 38:\n        with open(os.environ['INVENTORY_OBJECT_STAT_TRACE'], 'a') as trace:\n            trace.write(str(self) + '\\n')\n    return original(self, *args, **kwargs)\nPath.stat = observed\n",
    );
    for (let index = 0; index < 5; index++) {
      execFileSync("git", ["hash-object", "-w", "--stdin"], {
        cwd: checkout,
        input: `object-${index}\n`,
      });
    }
    for (let index = 0; index < 10; index++) {
      const branch = join(checkout, `branch-${index}`, "nested");
      await mkdir(branch, { recursive: true });
      await writeFile(join(branch, "visible.ts"), "visible\n");
    }

    await inventory(checkout, ".", {
      ...process.env,
      PYTHONPATH: instrumentation,
      INVENTORY_OBJECT_STAT_TRACE: trace,
    });
    expect((await readFile(trace, "utf8")).trim().split("\n")).toHaveLength(5);
  });

  test.each([".ignore", ".rgignore"])(
    "preserves ancestor %s precedence for explicit directory scopes",
    async (override) => {
      if (Bun.which("rg") === null) return;

      const checkout = await repository();
      const nested = join(checkout, "nested");
      await mkdir(nested);
      await Promise.all([
        writeFile(join(checkout, override), "!nested/visible.ts\n"),
        writeFile(join(nested, ".gitignore"), "*.ts\n"),
        writeFile(join(nested, "visible.ts"), "visible\n"),
        writeFile(join(nested, "private.ts"), "private\n"),
      ]);

      const rows = await inventory(checkout, "nested");
      expect(rows).toContain("nested/visible.ts");
      expect(rows).not.toContain("nested/private.ts");
    },
  );

  test.each(["case-alias", "short-alias"])(
    "accepts absolute directory scopes through a %s",
    async (kind) => {
      if (Bun.which("rg") === null) return;

      const checkout = await repository();
      const nested = join(checkout, "nested");
      await mkdir(nested);
      await writeFile(join(nested, "visible.ts"), "visible\n");
      const alias =
        kind === "case-alias"
          ? join(dirname(checkout), basename(checkout).toUpperCase())
          : windowsShortPath(checkout);
      if (alias === null) return;
      const equivalent = await realpath(alias).then(
        async (resolved) => resolved === (await realpath(checkout)),
        () => false,
      );
      if (!equivalent) return;

      expect(await inventory(checkout, join(alias, "nested"))).toContain(
        "nested/visible.ts",
      );
    },
  );

  test.skipIf(process.platform === "win32")(
    "rejects symbolic absolute directory scopes",
    async () => {
      if (Bun.which("rg") === null) return;

      const checkout = await repository();
      const nested = join(checkout, "nested");
      const alias = join(checkout, "alias");
      await mkdir(nested);
      await writeFile(join(nested, "visible.ts"), "visible\n");
      await symlink(nested, alias);

      await expect(inventory(checkout, alias)).rejects.toThrow(
        "symbolic links are not supported",
      );
    },
  );

  test.each([".ignore", ".rgignore"])(
    "keeps nested checkout files re-included by higher-precedence %s rules",
    async (override) => {
      if (Bun.which("rg") === null) return;

      const checkout = await repository();
      const nested = join(checkout, "nested");
      await mkdir(nested);
      execFileSync("git", ["init", "-q"], { cwd: nested });
      await Promise.all([
        writeFile(join(nested, ".gitignore"), "source.ts\n"),
        writeFile(join(nested, override), "!source.ts\n"),
        writeFile(join(nested, "source.ts"), "visible\n"),
      ]);

      expect(await inventory(checkout)).toContain("./nested/source.ts");
      expect(await inventory(checkout, "nested")).toContain("nested/source.ts");
    },
  );

  test("applies snapshot ignores without inheriting unrelated parent rules", async () => {
    if (Bun.which("rg") === null) return;

    const checkout = await repository(false);
    await Promise.all([
      writeFile(
        join(dirname(checkout), ".gitignore"),
        "repository/visible.ts\n",
      ),
      writeFile(join(checkout, ".gitignore"), "private.ts\n"),
      writeFile(join(checkout, ".ignore"), "hidden.ts\n"),
      writeFile(join(checkout, "private.ts"), "private\n"),
      writeFile(join(checkout, "hidden.ts"), "private\n"),
      writeFile(join(checkout, "visible.ts"), "export {};\n"),
    ]);

    expect(await inventory(checkout)).toEqual([
      "./.gitignore",
      "./.ignore",
      "./visible.ts",
    ]);
  });

  test.each([
    [".gitignore", "true", false],
    [".gitignore", "false", true],
    [".git/info/exclude", "true", false],
    [".git/info/exclude", "false", true],
    ["configured global", "true", false],
    ["configured global", "false", true],
    ["conditional global", "true", false],
    ["conditional global", "false", true],
  ] as const)(
    "applies %s exclusions with core.ignoreCase=%s",
    async (ignore, setting, visible) => {
      if (Bun.which("rg") === null) return;

      const checkout = await repository();
      execFileSync("git", ["config", "core.ignoreCase", setting], {
        cwd: checkout,
      });
      const global = ignore.endsWith(" global");
      const home = join(dirname(checkout), "home");
      const excludes = global
        ? join(home, "global-excludes")
        : join(checkout, ignore);
      const environment = global
        ? {
            ...process.env,
            HOME: home,
            USERPROFILE: home,
            XDG_CONFIG_HOME: join(home, "configuration"),
            GIT_CONFIG_GLOBAL: join(home, ".gitconfig"),
            GIT_CONFIG_NOSYSTEM: "1",
          }
        : process.env;
      if (global) await mkdir(home);
      if (ignore === "configured global") {
        execFileSync(
          "git",
          ["config", "--global", "core.excludesFile", excludes],
          {
            cwd: checkout,
            env: environment,
          },
        );
      } else if (ignore === "conditional global") {
        const included = join(home, "included.gitconfig");
        await Promise.all([
          writeFile(
            included,
            `[core]\n\texcludesFile = ${JSON.stringify(excludes)}\n`,
          ),
          writeFile(
            join(home, ".gitconfig"),
            `[includeIf "gitdir:${checkout.replaceAll("\\", "/")}/.git"]\n\tpath = ${JSON.stringify(included)}\n`,
          ),
        ]);
      }
      await Promise.all([
        writeFile(excludes, "private.ts\n"),
        writeFile(join(checkout, "PRIVATE.ts"), "private\n"),
      ]);

      expect(
        (await inventory(checkout, ".", environment)).includes("./PRIVATE.ts"),
      ).toBe(visible);
    },
  );

  test.each([
    ["true", "true", "."],
    ["true", "false", "."],
    ["false", "true", "."],
    ["false", "false", "."],
    ["true", "true", "nested"],
    ["true", "false", "nested"],
    ["false", "true", "nested"],
    ["false", "false", "nested"],
  ] as const)(
    "honors outer core.ignoreCase=%s and nested core.ignoreCase=%s for %s scans",
    async (outer, inner, scope) => {
      if (Bun.which("rg") === null) return;

      const checkout = await repository();
      const nested = join(checkout, "nested");
      await mkdir(nested);
      execFileSync("git", ["config", "core.ignoreCase", outer], {
        cwd: checkout,
      });
      execFileSync("git", ["init", "-q"], { cwd: nested });
      execFileSync("git", ["config", "core.ignoreCase", inner], {
        cwd: nested,
      });
      await Promise.all([
        writeFile(join(nested, ".gitignore"), "private.ts\n"),
        writeFile(join(nested, "PRIVATE.ts"), "private\n"),
      ]);

      const selected =
        scope === "." ? "./nested/PRIVATE.ts" : "nested/PRIVATE.ts";
      expect((await inventory(checkout, scope)).includes(selected)).toBe(
        inner === "false",
      );
    },
  );

  test.each([
    ["true", "false", "private.ts", true],
    ["false", "true", "/private.ts", false],
    ["true", "true", "/private.ts", false],
  ] as const)(
    "applies %s/%s case settings to nested global exclusion %s",
    async (outer, inner, pattern, visible) => {
      if (Bun.which("rg") === null) return;

      const checkout = await repository();
      const nested = join(checkout, "nested");
      const home = join(dirname(checkout), "home");
      await Promise.all([mkdir(nested), mkdir(home)]);
      execFileSync("git", ["config", "core.ignoreCase", outer], {
        cwd: checkout,
      });
      execFileSync("git", ["init", "-q"], { cwd: nested });
      execFileSync("git", ["config", "core.ignoreCase", inner], {
        cwd: nested,
      });
      const excludes = join(home, "global-excludes");
      const environment = {
        ...process.env,
        HOME: home,
        USERPROFILE: home,
        XDG_CONFIG_HOME: join(home, "configuration"),
        GIT_CONFIG_GLOBAL: join(home, ".gitconfig"),
        GIT_CONFIG_NOSYSTEM: "1",
      };
      execFileSync(
        "git",
        ["config", "--global", "core.excludesFile", excludes],
        {
          cwd: checkout,
          env: environment,
        },
      );
      await Promise.all([
        writeFile(excludes, `${pattern}\n`),
        writeFile(join(nested, "PRIVATE.ts"), "private\n"),
      ]);

      expect(
        (await inventory(checkout, ".", environment)).includes(
          "./nested/PRIVATE.ts",
        ),
      ).toBe(visible);
      expect(
        (await inventory(checkout, "nested", environment)).includes(
          "nested/PRIVATE.ts",
        ),
      ).toBe(visible);
    },
  );

  test.each([
    [".ignore", ".gitignore", true],
    [".rgignore", ".gitignore", true],
    [".ignore", ".rgignore", false],
    [".ignore", ".ignore", false],
  ] as const)(
    "preserves %s precedence over nested %s with case-insensitive excludes",
    async (outer, inner, visible) => {
      if (Bun.which("rg") === null) return;

      const checkout = await repository();
      const nested = join(checkout, "nested");
      const home = join(dirname(checkout), "home");
      await Promise.all([mkdir(nested), mkdir(home)]);
      execFileSync("git", ["init", "-q"], { cwd: nested });
      execFileSync("git", ["config", "core.ignoreCase", "true"], {
        cwd: checkout,
      });
      execFileSync("git", ["config", "core.ignoreCase", "true"], {
        cwd: nested,
      });
      const excludes = join(home, "global-excludes");
      const environment = {
        ...process.env,
        HOME: home,
        USERPROFILE: home,
        XDG_CONFIG_HOME: join(home, "configuration"),
        GIT_CONFIG_GLOBAL: join(home, ".gitconfig"),
        GIT_CONFIG_NOSYSTEM: "1",
      };
      execFileSync(
        "git",
        ["config", "--global", "core.excludesFile", excludes],
        {
          cwd: checkout,
          env: environment,
        },
      );
      await Promise.all([
        writeFile(excludes, "other.ts\n"),
        writeFile(join(checkout, outer), "!nested/PRIVATE.ts\n"),
        writeFile(join(nested, inner), "private.ts\n"),
        writeFile(join(nested, "PRIVATE.ts"), "private\n"),
      ]);

      expect(
        (await inventory(checkout, ".", environment)).includes(
          "./nested/PRIVATE.ts",
        ),
      ).toBe(visible);
    },
  );

  test("preserves explicitly selected and tracked case-insensitive files", async () => {
    if (Bun.which("rg") === null) return;

    const checkout = await repository();
    execFileSync("git", ["config", "core.ignoreCase", "true"], {
      cwd: checkout,
    });
    await Promise.all([
      writeFile(join(checkout, ".gitignore"), "private.ts\n"),
      writeFile(join(checkout, "PRIVATE.ts"), "private\n"),
    ]);

    expect(await inventory(checkout, "PRIVATE.ts")).toEqual(["PRIVATE.ts"]);
    execFileSync("git", ["add", "--force", "PRIVATE.ts"], { cwd: checkout });
    expect(await inventory(checkout)).toContain("./PRIVATE.ts");
  });

  test.each([
    ["SS", "ss"],
    ["Ä", "ä"],
    ["Σ", "ς"],
    ["ss", "\u00df"],
    ["I", "\u0131"],
    ["caf\u00e9", "cafe\u0301"],
  ])(
    "matches indexed %s against replacement %s using filesystem identity",
    async (indexed, replacement) => {
      if (Bun.which("rg") === null) return;

      const checkout = await repository();
      await mkdir(join(checkout, indexed));
      await writeFile(join(checkout, indexed, "private.ts"), "tracked\n");
      execFileSync("git", ["add", `${indexed}/private.ts`], { cwd: checkout });
      execFileSync("git", ["config", "core.ignoreCase", "true"], {
        cwd: checkout,
      });
      await rm(join(checkout, indexed), { recursive: true });
      await mkdir(join(checkout, replacement));
      await writeFile(
        join(checkout, replacement, "private.ts"),
        "replacement\n",
      );
      await writeFile(join(checkout, ".gitignore"), `${replacement}/\n`);
      const expected = await realpath(
        join(checkout, indexed, "private.ts"),
      ).then(
        async (path) =>
          path === (await realpath(join(checkout, replacement, "private.ts"))),
        () => false,
      );

      expect(
        (await inventory(checkout)).includes(`./${replacement}/private.ts`),
      ).toBe(expected);

      execFileSync("git", ["config", "core.ignoreCase", "false"], {
        cwd: checkout,
      });
      expect(
        (await inventory(checkout)).includes(`./${replacement}/private.ts`),
      ).toBe(expected);
      expect(
        (await inventory(checkout, replacement)).includes(
          `${replacement}/private.ts`,
        ),
      ).toBe(expected);
    },
  );

  test.each([".", "LongDirectory", "LongDirectory/PrivateDocument.ts"])(
    "restores tracked 8.3 aliases for %s scans using no-follow identity",
    async (scope) => {
      if (Bun.which("rg") === null) return;

      const checkout = await repository();
      const indexed = join(checkout, "LONGDI~1");
      const materialized = join(checkout, "LongDirectory");
      const indexedLeaf = join(materialized, "PRIVAT~1.TS");
      const addressed = join(materialized, "PrivateDocument.ts");
      const unrelated = join(materialized, "ignored-hardlink.ts");
      await mkdir(indexed);
      await writeFile(join(indexed, "PRIVAT~1.TS"), "tracked\n");
      execFileSync("git", ["add", "LONGDI~1/PRIVAT~1.TS"], {
        cwd: checkout,
      });
      await rm(indexed, { recursive: true });
      await mkdir(materialized);
      await writeFile(addressed, "tracked\n");
      await hardlink(addressed, unrelated);
      await writeFile(join(checkout, ".gitignore"), "LongDirectory/\n");

      const instrumentation = join(dirname(checkout), "instrumentation");
      await mkdir(instrumentation);
      await writeFile(
        join(instrumentation, "sitecustomize.py"),
        [
          "from pathlib import Path",
          `indexed = Path(${JSON.stringify(indexed)})`,
          `materialized = Path(${JSON.stringify(materialized)})`,
          `indexed_leaf = Path(${JSON.stringify(indexedLeaf)})`,
          `addressed = Path(${JSON.stringify(addressed)})`,
          "original = Path.stat",
          "original_resolve = Path.resolve",
          "def guarded(self, *args, **kwargs):",
          "    if self == indexed and kwargs.get('follow_symlinks') is False:",
          "        return original(materialized, *args, **kwargs)",
          "    if self == indexed_leaf and kwargs.get('follow_symlinks') is False:",
          "        return original(addressed, *args, **kwargs)",
          "    return original(self, *args, **kwargs)",
          "def resolved(self, *args, **kwargs):",
          "    if self == indexed:",
          "        return original_resolve(materialized, *args, **kwargs)",
          "    if self == indexed_leaf:",
          "        return original_resolve(addressed, *args, **kwargs)",
          "    return original_resolve(self, *args, **kwargs)",
          "Path.stat = guarded",
          "Path.resolve = resolved",
        ].join("\n"),
      );

      const rows = await inventory(checkout, scope, {
        ...process.env,
        PYTHONPATH: instrumentation,
      });
      const prefix = scope === "." ? "./" : "";
      expect(rows).toContain(`${prefix}LongDirectory/PrivateDocument.ts`);
      expect(rows).not.toContain(`${prefix}LongDirectory/ignored-hardlink.ts`);
    },
  );

  test("keeps an explicitly selected ignored file without widening its directory", async () => {
    if (Bun.which("rg") === null) return;

    const checkout = await repository();
    await mkdir(join(checkout, "ignored"));
    await Promise.all([
      writeFile(join(checkout, ".gitignore"), "selected.skip\nignored/\n"),
      writeFile(join(checkout, "selected.skip"), "selected\n"),
      writeFile(join(checkout, "ignored", "tracked.ts"), "tracked\n"),
      writeFile(join(checkout, "ignored", "private.ts"), "private\n"),
    ]);
    execFileSync("git", ["add", "--force", "ignored/tracked.ts"], {
      cwd: checkout,
    });

    expect(await inventory(checkout, "selected.skip")).toEqual([
      "selected.skip",
    ]);
    expect(await inventory(checkout, "ignored")).toEqual([
      "ignored/tracked.ts",
    ]);
  });

  test("respects tracked files and ignore rules inside nested Git checkouts", async () => {
    if (Bun.which("rg") === null) return;

    const checkout = await repository();
    const nested = join(checkout, "nested");
    await mkdir(nested);
    execFileSync("git", ["init", "-q"], { cwd: nested });
    await Promise.all([
      writeFile(join(nested, ".gitignore"), ".env\n"),
      writeFile(join(nested, ".ignore"), "tracked.ts\n"),
      writeFile(join(nested, ".env"), "private\n"),
      writeFile(join(nested, "tracked.ts"), "tracked\n"),
      writeFile(join(nested, "visible.ts"), "visible\n"),
    ]);
    execFileSync("git", ["add", "tracked.ts"], { cwd: nested });

    const rows = await inventory(checkout);
    expect(rows).toContain("./nested/tracked.ts");
    expect(rows).toContain("./nested/visible.ts");
    expect(rows).not.toContain("./nested/.env");
  });

  test.each([
    ["embedded", "."],
    ["embedded", "nested"],
    ["conflicted Gitlink", "."],
    ["conflicted Gitlink", "nested"],
  ])(
    "retains outer tracked source inside %s checkout for %s",
    async (staging, scope) => {
      if (Bun.which("rg") === null) return;

      const checkout = await repository();
      const nested = join(checkout, "nested");
      await mkdir(nested);
      await Promise.all([
        writeFile(join(nested, "outer.ts"), "outer tracked\n"),
        writeFile(join(nested, "inner.ts"), "inner tracked\n"),
        writeFile(join(nested, "private.ts"), "private\n"),
      ]);
      execFileSync("git", ["add", "nested/outer.ts"], { cwd: checkout });
      execFileSync("git", ["init", "-q"], { cwd: nested });
      await writeFile(
        join(nested, ".ignore"),
        "outer.ts\ninner.ts\nprivate.ts\n",
      );
      execFileSync("git", ["add", "inner.ts"], { cwd: nested });
      if (staging === "conflicted Gitlink") {
        commit(nested);
        const gitlink = execFileSync("git", ["rev-parse", "HEAD"], {
          cwd: nested,
          encoding: "utf8",
        }).trim();
        const outer = execFileSync("git", ["rev-parse", ":nested/outer.ts"], {
          cwd: checkout,
          encoding: "utf8",
        }).trim();
        execFileSync("git", ["update-index", "--index-info"], {
          cwd: checkout,
          input: [
            `0 ${"0".repeat(40)}\tnested/outer.ts`,
            `160000 ${gitlink} 1\tnested`,
            `100644 ${outer} 2\tnested/outer.ts`,
            "",
          ].join("\n"),
        });
      }

      const prefix = scope === "." ? "./nested" : "nested";
      const rows = await inventory(checkout, scope);
      expect(rows).toContain(`${prefix}/outer.ts`);
      expect(rows).toContain(`${prefix}/inner.ts`);
      expect(rows).not.toContain(`${prefix}/private.ts`);
    },
  );

  test.each([".gitignore", ".ignore", ".rgignore"])(
    "keeps root-scoped Gitlinks excluded through unrelated %s allowlists",
    async (ignore) => {
      if (Bun.which("rg") === null) return;

      const checkout = await repository();
      const nested = join(checkout, "nested");
      await mkdir(nested);
      execFileSync("git", ["init", "-q"], { cwd: nested });
      await Promise.all([
        writeFile(join(nested, "public.ts"), "public\n"),
        writeFile(join(nested, "private.ts"), "private\n"),
      ]);
      execFileSync("git", ["add", "public.ts", "private.ts"], { cwd: nested });
      commit(nested);
      execFileSync("git", ["add", "nested"], {
        cwd: checkout,
        stdio: "ignore",
      });
      await Promise.all([
        writeFile(
          join(checkout, ignore),
          "nested/**\n!unrelated/public.ts\nnested/private.ts\n",
        ),
        writeFile(join(nested, ".ignore"), "*\n"),
      ]);

      expect(await inventory(checkout, ".")).toEqual([`./${ignore}`]);
    },
  );

  test("recovers an embedded checkout hidden only by its own ignore file", async () => {
    if (Bun.which("rg") === null) return;

    const checkout = await repository();
    const nested = join(checkout, "nested");
    await mkdir(nested);
    execFileSync("git", ["init", "-q"], { cwd: nested });
    await writeFile(join(nested, ".ignore"), "*\n");
    await writeFile(join(nested, "tracked.ts"), "export {};\n");
    execFileSync("git", ["add", "tracked.ts"], { cwd: nested });

    expect(await inventory(checkout)).toContain("./nested/tracked.ts");
    await writeFile(join(checkout, ".ignore"), ".*\n");
    expect(await inventory(checkout)).toContain("./nested/tracked.ts");
    await writeFile(join(checkout, ".ignore"), "nested/\n");
    expect(await inventory(checkout)).not.toContain("./nested/tracked.ts");
  });

  test.each([".ignore", ".rgignore", ".git/info/exclude"])(
    "does not recover nested tracked files excluded by outer %s rules",
    async (ignore) => {
      if (Bun.which("rg") === null) return;

      const checkout = await repository();
      const nested = join(checkout, "nested");
      await mkdir(nested);
      execFileSync("git", ["init", "-q"], { cwd: nested });
      await writeFile(join(checkout, ignore), "nested/private.ts\n");
      await writeFile(join(nested, "private.ts"), "private\n");
      await writeFile(join(nested, "visible.ts"), "visible\n");
      execFileSync("git", ["add", "private.ts", "visible.ts"], {
        cwd: nested,
      });

      const rows = await inventory(checkout);
      expect(rows).toContain("./nested/visible.ts");
      expect(rows).not.toContain("./nested/private.ts");
    },
  );

  test.each([".ignore", ".gitignore", ".git/info/exclude"])(
    "applies %s file exclusions beneath tracked Git checkouts",
    async (outerIgnore) => {
      if (Bun.which("rg") === null) return;

      const checkout = await repository();
      const nested = join(checkout, "nested");
      await mkdir(nested);
      execFileSync("git", ["init", "-q"], { cwd: nested });
      await Promise.all([
        writeFile(
          join(checkout, ".gitignore"),
          outerIgnore === ".gitignore"
            ? "nested/\nnested/private.ts\n"
            : "nested/\n",
        ),
        ...(outerIgnore === ".gitignore"
          ? []
          : [writeFile(join(checkout, outerIgnore), "nested/private.ts\n")]),
        writeFile(join(nested, "private.ts"), "private\n"),
        writeFile(join(nested, "visible.ts"), "visible\n"),
      ]);
      execFileSync("git", ["add", "private.ts", "visible.ts"], { cwd: nested });
      commit(nested);
      execFileSync("git", ["add", "--force", "nested"], {
        cwd: checkout,
        stdio: "ignore",
      });

      const rows = await inventory(checkout);
      expect(rows).toContain("./nested/visible.ts");
      expect(rows).not.toContain("./nested/private.ts");

      const scoped = await inventory(checkout, "nested");
      expect(scoped).toContain("nested/visible.ts");
      expect(scoped).not.toContain("nested/private.ts");

      if (outerIgnore === ".git/info/exclude") {
        await writeFile(
          join(checkout, ".gitignore"),
          "nested/\n!nested/private.ts\n",
        );
        expect(await inventory(checkout)).toContain("./nested/private.ts");
        expect(await inventory(checkout, "nested")).toContain(
          "nested/private.ts",
        );
      }
    },
  );

  test.each(["nested", " #nested"])(
    "applies configured excludes from every enclosing checkout to %s",
    async (directory) => {
      if (Bun.which("rg") === null) return;

      const checkout = await repository();
      const middle = join(checkout, "middle");
      const nested = join(middle, directory);
      await mkdir(nested, { recursive: true });
      execFileSync("git", ["init", "-q"], { cwd: middle });
      execFileSync("git", ["init", "-q"], { cwd: nested });
      await Promise.all([
        writeFile(
          join(middle, ".git", "info", "exclude"),
          `${directory}/private.ts\n`,
        ),
        writeFile(join(nested, "private.ts"), "private\n"),
        writeFile(join(nested, "visible.ts"), "visible\n"),
      ]);
      execFileSync("git", ["add", "private.ts", "visible.ts"], { cwd: nested });

      const rows = await inventory(checkout);
      expect(rows).toContain(`./middle/${directory}/visible.ts`);
      expect(rows).not.toContain(`./middle/${directory}/private.ts`);
    },
  );

  test("preserves intermediate ignores beneath an ancestor Git link", async () => {
    if (Bun.which("rg") === null) return;

    const checkout = await repository();
    const middle = join(checkout, "middle");
    const nested = join(middle, "nested");
    await mkdir(nested, { recursive: true });
    execFileSync("git", ["init", "-q"], { cwd: middle });
    await writeFile(join(middle, "visible.ts"), "visible\n");
    execFileSync("git", ["add", "visible.ts"], { cwd: middle });
    commit(middle);
    execFileSync("git", ["add", "middle"], {
      cwd: checkout,
      stdio: "ignore",
    });
    execFileSync("git", ["init", "-q"], { cwd: nested });
    await Promise.all([
      writeFile(join(middle, ".gitignore"), "nested/private.ts\n"),
      writeFile(join(nested, "private.ts"), "private\n"),
      writeFile(join(nested, "visible.ts"), "visible\n"),
    ]);
    execFileSync("git", ["add", "private.ts", "visible.ts"], { cwd: nested });

    const rows = await inventory(checkout);
    expect(rows).toContain("./middle/nested/visible.ts");
    expect(rows).not.toContain("./middle/nested/private.ts");
  });

  test.each(["stage-0", "conflicted", "short-alias", "conflicted-short-alias"])(
    "admits %s tracked Gitlinks through configured directory excludes",
    async (staging) => {
      if (Bun.which("rg") === null) return;

      const checkout = await repository();
      const short = staging.endsWith("short-alias");
      const name = short ? "LongDirectory" : "nested";
      const nested = join(checkout, name);
      await mkdir(nested);
      const nativeAlias = short ? windowsShortPath(nested) : null;
      if (short && process.platform === "win32" && nativeAlias === null) {
        return;
      }
      const indexed = short
        ? nativeAlias === null
          ? "LONGDI~1"
          : basename(nativeAlias)
        : name;
      execFileSync("git", ["init", "-q"], { cwd: nested });
      await Promise.all([
        writeFile(join(nested, "visible.ts"), "visible\n"),
        writeFile(join(nested, "private.ts"), "private\n"),
      ]);
      execFileSync("git", ["add", "visible.ts", "private.ts"], {
        cwd: nested,
      });
      commit(nested);
      execFileSync("git", ["add", name], {
        cwd: checkout,
        stdio: "ignore",
      });
      if (short || staging === "conflicted") {
        const object = execFileSync("git", ["rev-parse", "HEAD"], {
          cwd: nested,
          encoding: "utf8",
        }).trim();
        execFileSync("git", ["update-index", "--index-info"], {
          cwd: checkout,
          input: [
            `0 ${"0".repeat(40)}\t${name}`,
            ...(staging.startsWith("conflicted") ? [1, 2, 3] : [0]).map(
              (stage) => `160000 ${object} ${stage}\t${indexed}`,
            ),
            "",
          ].join("\n"),
        });
      }
      if (short && nativeAlias === null) {
        await symlink(nested, join(checkout, indexed));
      }
      await writeFile(
        join(checkout, ".git", "info", "exclude"),
        `${name}/\n${name}/private.ts\n${indexed}/\n`,
      );

      let environment = process.env;
      if (short) {
        const instrumentation = join(dirname(checkout), "instrumentation");
        await mkdir(instrumentation);
        await writeFile(
          join(instrumentation, "sitecustomize.py"),
          [
            "from pathlib import Path",
            `indexed = Path(${JSON.stringify(join(checkout, indexed))})`,
            `materialized = Path(${JSON.stringify(nested)})`,
            "original = Path.stat",
            "def guarded(self, *args, **kwargs):",
            "    if self == indexed and kwargs.get('follow_symlinks') is False:",
            "        return original(materialized, *args, **kwargs)",
            "    return original(self, *args, **kwargs)",
            "Path.stat = guarded",
          ].join("\n"),
        );
        environment = { ...process.env, PYTHONPATH: instrumentation };
      }

      const rows = await inventory(checkout, ".", environment);
      expect(rows).toContain(`./${name}/visible.ts`);
      expect(rows).not.toContain(`./${name}/private.ts`);
    },
  );

  test.skipIf(process.platform === "win32").each([".ignore", ".rgignore"])(
    "rejects a hidden Gitlink ancestor's symbolic %s",
    async (name) => {
      if (Bun.which("rg") === null) return;

      const checkout = await repository();
      const hidden = join(checkout, "hidden");
      const nested = join(hidden, "nested");
      const external = join(dirname(checkout), "external.ignore");
      await mkdir(nested, { recursive: true });
      execFileSync("git", ["init", "-q"], { cwd: nested });
      await writeFile(join(nested, "private.ts"), "tracked\n");
      execFileSync("git", ["add", "private.ts"], { cwd: nested });
      commit(nested);
      await writeFile(join(checkout, ".gitignore"), "hidden/\n");
      execFileSync("git", ["add", "--force", "hidden/nested"], {
        cwd: checkout,
        stdio: "ignore",
      });
      await writeFile(external, "nested/private.ts\n");
      await symlink(external, join(hidden, name));

      await expect(inventory(checkout)).rejects.toThrow(
        "symbolic ignore files are not supported",
      );
    },
  );

  test.each([
    ["visible", "nested/private.ts\n"],
    ["ignored", "nested/\nnested/private.ts\n"],
  ])(
    "preserves outer Git file exclusions for %s explicit nested scopes",
    async (_visibility, outerIgnores) => {
      if (Bun.which("rg") === null) return;

      const checkout = await repository();
      const nested = join(checkout, "nested");
      await mkdir(nested);
      execFileSync("git", ["init", "-q"], { cwd: nested });
      await Promise.all([
        writeFile(join(checkout, ".gitignore"), outerIgnores),
        writeFile(join(nested, "private.ts"), "private\n"),
        writeFile(join(nested, "visible.ts"), "visible\n"),
      ]);
      execFileSync("git", ["add", "private.ts", "visible.ts"], { cwd: nested });

      expect(await inventory(checkout, "nested")).toEqual([
        "nested/visible.ts",
      ]);

      await writeFile(join(checkout, ".git", "info", "exclude"), "nested/\n");
      expect(await inventory(checkout, "nested")).toEqual([]);
    },
  );

  test("does not grant Git link exemptions to replaced tracked files", async () => {
    if (Bun.which("rg") === null) return;

    const checkout = await repository();
    const nested = join(checkout, "nested");
    await writeFile(nested, "previously tracked file\n");
    execFileSync("git", ["add", "nested"], { cwd: checkout });
    await rm(nested);
    await mkdir(nested);
    execFileSync("git", ["init", "-q"], { cwd: nested });
    await Promise.all([
      writeFile(join(checkout, ".gitignore"), "nested/private.ts\n"),
      writeFile(join(nested, "private.ts"), "private\n"),
      writeFile(join(nested, "visible.ts"), "visible\n"),
    ]);
    execFileSync("git", ["add", "private.ts", "visible.ts"], { cwd: nested });

    const rows = await inventory(checkout);
    expect(rows).toContain("./nested/visible.ts");
    expect(rows).not.toContain("./nested/private.ts");
  });

  test.each([".ignore", ".rgignore", ".gitignore"])(
    "does not inspect checkout metadata excluded by outer %s rules",
    async (ignore) => {
      if (Bun.which("rg") === null) return;

      const checkout = await repository();
      const nested = join(checkout, "nested");
      const external = join(dirname(checkout), "external.config");
      await mkdir(nested);
      execFileSync("git", ["init", "-q"], { cwd: nested });
      await writeFile(external, "[core]\n\tignoreCase = true\n");
      execFileSync("git", ["config", "--local", "include.path", external], {
        cwd: nested,
      });
      await writeFile(join(checkout, ignore), "nested/\n");
      await writeFile(join(checkout, "visible.ts"), "visible\n");

      expect(await inventory(checkout)).toContain("./visible.ts");
    },
  );

  test("discovers self-hidden checkouts through visible snapshot directories", async () => {
    if (Bun.which("rg") === null) return;

    const checkout = await repository(false);
    const nested = join(checkout, "container", "nested");
    await mkdir(nested, { recursive: true });
    await writeFile(join(checkout, ".ignore"), "scan-source\n");
    execFileSync("git", ["init", "-q"], { cwd: nested });
    await writeFile(join(nested, ".ignore"), "*\n");
    await writeFile(join(nested, "tracked.ts"), "export {};\n");
    execFileSync("git", ["add", "tracked.ts"], { cwd: nested });

    expect(await inventory(checkout)).toContain(
      "./container/nested/tracked.ts",
    );

    await writeFile(
      join(checkout, "container", ".git"),
      "malformed nested Git marker\n",
    );
    expect(await inventory(checkout)).toContain(
      "./container/nested/tracked.ts",
    );

    await writeFile(join(checkout, ".ignore"), "scan-source\ncontainer/\n");
    expect(await inventory(checkout)).not.toContain(
      "./container/nested/tracked.ts",
    );
    await writeFile(join(checkout, ".ignore"), "scan-source\n");
    await writeFile(join(checkout, ".git"), "malformed snapshot marker\n");
    expect(await inventory(checkout)).toContain(
      "./container/nested/tracked.ts",
    );
  });

  test.skipIf(process.platform === "win32")(
    "rejects line-separated snapshot directory names before parsing ignore diagnostics",
    async () => {
      if (Bun.which("rg") === null) return;

      const checkout = await repository(false);
      const nested = join(checkout, "victim", "nested");
      await mkdir(nested, { recursive: true });
      await mkdir(join(checkout, "evil\nrg: DEBUG|x: ignoring victim"));
      await writeFile(join(checkout, ".ignore"), "evil*\n");
      execFileSync("git", ["init", "-q"], { cwd: nested });
      await writeFile(join(nested, ".ignore"), "*\n");
      await writeFile(join(nested, "private.ts"), "tracked\n");
      execFileSync("git", ["add", "private.ts"], { cwd: nested });

      await expect(inventory(checkout)).rejects.toThrow(
        "line separators are not supported in inventory paths",
      );
    },
  );

  test("discovers Git-hidden checkouts reopened by ripgrep ignore rules", async () => {
    if (Bun.which("rg") === null) return;

    const checkout = await repository();
    const nested = join(checkout, "container", "nested");
    await mkdir(nested, { recursive: true });
    execFileSync("git", ["init", "-q"], { cwd: nested });
    await Promise.all([
      writeFile(join(checkout, ".gitignore"), "container/\n"),
      writeFile(join(checkout, ".ignore"), "!container/\n!container/nested/\n"),
      writeFile(join(nested, ".ignore"), "*\n"),
      writeFile(join(nested, "tracked.ts"), "export {};\n"),
    ]);
    execFileSync("git", ["add", "tracked.ts"], { cwd: nested });

    expect(await inventory(checkout)).toContain(
      "./container/nested/tracked.ts",
    );
  });

  test("discovers checkout overrides that hide their own ignore files", async () => {
    if (Bun.which("rg") === null) return;

    const checkout = await repository();
    const container = join(checkout, "container");
    const nested = join(container, "mid", "nested");
    await mkdir(nested, { recursive: true });
    execFileSync("git", ["init", "-q"], { cwd: nested });
    await Promise.all([
      writeFile(join(checkout, ".gitignore"), "container/mid/\n"),
      writeFile(
        join(container, ".ignore"),
        "*\n!mid/\n!mid/nested/\n!mid/nested/**\n",
      ),
      writeFile(join(nested, ".ignore"), "*\n"),
      writeFile(join(nested, "tracked.ts"), "export {};\n"),
    ]);
    execFileSync("git", ["add", "tracked.ts"], { cwd: nested });

    expect(await inventory(checkout)).toContain(
      "./container/mid/nested/tracked.ts",
    );
  });

  test("keeps ignore scaffolding separate from case-distinct checkouts", async () => {
    if (Bun.which("rg") === null) return;

    const checkout = await repository();
    await Promise.all([
      writeFile(join(checkout, ".gitignore"), ".IGNORE/tracked.ts\n"),
      writeFile(
        join(checkout, ".ignore"),
        "!.IGNORE/tracked.ts\n.IGNORE/private.ts\n",
      ),
    ]);
    const nested = join(checkout, ".IGNORE");
    try {
      await mkdir(nested);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "EEXIST") return;
      throw error;
    }
    execFileSync("git", ["init", "-q"], { cwd: nested });
    await Promise.all([
      writeFile(join(nested, "tracked.ts"), "visible\n"),
      writeFile(join(nested, "private.ts"), "private\n"),
    ]);
    execFileSync("git", ["add", "tracked.ts", "private.ts"], { cwd: nested });

    const rows = await inventory(checkout);
    expect(rows).toContain("./.IGNORE/tracked.ts");
    expect(rows).not.toContain("./.IGNORE/private.ts");
  });

  test("preserves rgignore precedence for case-distinct checkout paths", async () => {
    if (Bun.which("rg") === null) return;

    const checkout = await repository();
    await Promise.all([
      writeFile(join(checkout, ".ignore"), "!.RGIGNORE/private.ts\n"),
      writeFile(join(checkout, ".rgignore"), ".RGIGNORE/private.ts\n"),
    ]);
    const nested = join(checkout, ".RGIGNORE");
    try {
      await mkdir(nested);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "EEXIST") return;
      throw error;
    }
    execFileSync("git", ["init", "-q"], { cwd: nested });
    await Promise.all([
      writeFile(join(nested, "tracked.ts"), "visible\n"),
      writeFile(join(nested, "private.ts"), "private\n"),
    ]);
    execFileSync("git", ["add", "tracked.ts", "private.ts"], { cwd: nested });

    const rows = await inventory(checkout);
    expect(rows).toContain("./.RGIGNORE/tracked.ts");
    expect(rows).not.toContain("./.RGIGNORE/private.ts");
  });

  test.each([
    ["slash-only", "/\n"],
    ["whitespace-only", "   \n"],
    ["embedded-carriage-return", ".IGNORE/tracked.ts\rignored\n"],
    ["unterminated-embedded-carriage-return", ".IGNORE/tracked.ts\rignored"],
  ])(
    "keeps %s ignores inert when isolating nested checkout names",
    async (_description, contents) => {
      if (Bun.which("rg") === null) return;

      const checkout = await repository();
      const container = join(checkout, "container");
      const nested = join(container, ".IGNORE");
      await mkdir(container);
      await writeFile(join(container, ".ignore"), contents);
      try {
        await mkdir(nested);
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code === "EEXIST") return;
        throw error;
      }
      execFileSync("git", ["init", "-q"], { cwd: nested });
      await writeFile(join(nested, ".ignore"), "*\n");
      await writeFile(join(nested, "tracked.ts"), "tracked\n");
      execFileSync("git", ["add", "tracked.ts"], { cwd: nested });

      expect(await inventory(checkout)).toContain(
        "./container/.IGNORE/tracked.ts",
      );
    },
  );

  test("preserves BOM-prefixed ignores when isolating nested checkout names", async () => {
    if (Bun.which("rg") === null) return;

    const checkout = await repository();
    const container = join(checkout, "container");
    const nested = join(container, ".IGNORE");
    await mkdir(container);
    await writeFile(join(container, ".ignore"), "\ufeff.IGNORE/private.ts\n");
    try {
      await mkdir(nested);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "EEXIST") return;
      throw error;
    }
    execFileSync("git", ["init", "-q"], { cwd: nested });
    await writeFile(join(nested, ".ignore"), "*\n");
    await writeFile(join(nested, "tracked.ts"), "tracked\n");
    await writeFile(join(nested, "private.ts"), "private\n");
    execFileSync("git", ["add", "tracked.ts", "private.ts"], {
      cwd: nested,
    });

    const rows = await inventory(checkout);
    expect(rows).toContain("./container/.IGNORE/tracked.ts");
    expect(rows).not.toContain("./container/.IGNORE/private.ts");
  });

  test("preserves canonically equivalent tracked directory spellings", async () => {
    if (Bun.which("rg") === null) return;

    const checkout = await repository();
    const nested = join(checkout, "nested");
    const composed = join(nested, "caf\u00e9");
    const decomposed = join(nested, "cafe\u0301");
    await mkdir(composed, { recursive: true });
    try {
      await mkdir(decomposed);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "EEXIST") return;
      throw error;
    }
    execFileSync("git", ["init", "-q"], { cwd: nested });
    await Promise.all([
      writeFile(join(checkout, ".gitignore"), "nested/private.ts\n"),
      writeFile(join(nested, ".ignore"), "*\n"),
      writeFile(join(composed, "first.ts"), "first\n"),
      writeFile(join(decomposed, "second.ts"), "second\n"),
    ]);
    execFileSync(
      "git",
      ["add", "--force", "caf\u00e9/first.ts", "cafe\u0301/second.ts"],
      {
        cwd: nested,
      },
    );

    const rows = await inventory(checkout);
    expect(rows).toContain("./nested/caf\u00e9/first.ts");
    expect(rows).toContain("./nested/cafe\u0301/second.ts");
  });

  test.each([
    [".gitignore", "ignored/"],
    [".ignore", "ignored/"],
    [".rgignore", "ignored/"],
    [".gitignore", "ignored/**"],
    [".ignore", "ignored/**"],
    [".rgignore", "ignored/**"],
    [".gitignore", "/ignored/**"],
    [".ignore", "/ignored/**"],
    [".rgignore", "/ignored/**"],
    [".gitignore", "ignored/** "],
    [".ignore", "ignored/** "],
    [".rgignore", "ignored/** "],
    [".gitignore", "ignored/**\r\r"],
    [".ignore", "ignored/**\r\r"],
    [".rgignore", "ignored/**\r\r"],
    [".gitignore", "ignored/**/*"],
    [".ignore", "ignored/**/*"],
    [".rgignore", "ignored/**/*"],
    [".gitignore", "ignored/**/**"],
    [".ignore", "ignored/**/**"],
    [".rgignore", "ignored/**/**"],
    [".gitignore", "**/ignored/**"],
    [".ignore", "**/ignored/**"],
    [".rgignore", "**/ignored/**"],
    [".gitignore", "ign*/**"],
    [".ignore", "ign*/**"],
    [".rgignore", "ign*/**"],
    [".gitignore", "ignor[e]d/**"],
    [".ignore", "ignor[e]d/**"],
    [".rgignore", "ignor[e]d/**"],
    [".gitignore", "{ignored,other}/**"],
    [".ignore", "{ignored,other}/**"],
    [".rgignore", "{ignored,other}/**"],
    [".gitignore", "{{ignored,third},other}/**"],
    [".ignore", "{{ignored,third},other}/**"],
    [".rgignore", "{{ignored,third},other}/**"],
    [".gitignore", "**/{ignored,other}/**"],
    [".ignore", "**/{ignored,other}/**"],
    [".rgignore", "**/{ignored,other}/**"],
  ])(
    "keeps explicitly selected tracked files through an outer %s rule %s",
    async (ignore, rule) => {
      if (Bun.which("rg") === null) return;

      const checkout = await repository(false);
      const nested = join(checkout, "ignored");
      await mkdir(join(nested, "src"), { recursive: true });
      await writeFile(
        join(checkout, ignore),
        `ignored/private-before.ts\n${rule}\nignored/private.ts\nignored/src/private.ts\n`,
      );
      execFileSync("git", ["init", "-q"], { cwd: nested });
      await Promise.all([
        writeFile(
          join(nested, ".ignore"),
          "public.ts\nprivate.ts\nprivate-before.ts\nuntracked.ts\nsrc/\n",
        ),
        writeFile(join(nested, "public.ts"), "tracked\n"),
        writeFile(join(nested, "private.ts"), "private\n"),
        writeFile(join(nested, "private-before.ts"), "private\n"),
        writeFile(join(nested, "untracked.ts"), "untracked\n"),
        writeFile(join(nested, "src", "public.ts"), "tracked\n"),
        writeFile(join(nested, "src", "private.ts"), "private\n"),
        writeFile(join(nested, "src", "untracked.ts"), "untracked\n"),
      ]);
      execFileSync(
        "git",
        [
          "add",
          "--force",
          "public.ts",
          "private.ts",
          "private-before.ts",
          "src/public.ts",
          "src/private.ts",
        ],
        { cwd: nested },
      );

      expect(await inventory(checkout, "ignored")).toEqual([
        "ignored/public.ts",
        "ignored/src/public.ts",
      ]);
    },
  );

  test.each([
    ["ignored-v2", ".rgignore", "ignored-v2"],
    ["ignored.v2", ".rgignore", "ignored.v2"],
    ["ignored checkout", ".rgignore", "ignored checkout"],
    [".IGNORE", ".rgignore", ".IGNORE"],
    ["!ignored", ".gitignore", "\\!ignored"],
    ["!ignored", ".ignore", "\\!ignored"],
    ["!ignored", ".rgignore", "\\!ignored"],
    ["!ignored", ".ignore", "/\\!ignored"],
    ["!ignored", ".rgignore", "\\!ign*"],
    ["!ignored", ".rgignore", "**/\\!ignored"],
    ["group/!ignored", ".rgignore", "group/\\!ignored"],
    ["group/!ignored", ".rgignore", "/group/\\!ignored"],
    ["group/ignored", ".gitignore", "group/{ignored,other}"],
    ["group/ignored", ".ignore", "group/{ignored,other}"],
    ["group/ignored", ".rgignore", "group/{ignored,other}"],
    ["group/ignored", ".gitignore", "{group/ignored,other}"],
    ["group/ignored", ".ignore", "{group/ignored,other}"],
    ["group/ignored", ".rgignore", "{group/ignored,other}"],
    ["group/ignored", ".rgignore", "{group/{ignored,third},other}"],
    ["!group/!ignored", ".rgignore", "\\!group/\\!ignored"],
    ["!ignored[scope", ".rgignore", "\\!ign*\\[scope"],
    ["!ignored checkout", ".rgignore", "\\!ignored\\ checkout"],
    ["#ignored", ".gitignore", "\\#ignored"],
    ["#ignored", ".ignore", "\\#ignored"],
    ["#ignored", ".rgignore", "\\#ignored"],
    ["#ignored", ".rgignore", "\\#ign*"],
    ["#ignored", ".rgignore", "**/\\#ignored"],
    ["#ignored checkout", ".rgignore", "\\#ignored\\ checkout"],
    ["\ufeffignored", ".gitignore", "# prefix\n\ufeffignored"],
    ["\ufeffignored", ".ignore", "# prefix\n\ufeffignored"],
    ["\ufeffignored", ".rgignore", "# prefix\n\ufeffignored"],
  ])(
    "reopens an explicitly selected checkout named %s through %s",
    async (name, ignore, rule) => {
      if (Bun.which("rg") === null) return;

      const checkout = await repository(false);
      const nested = join(checkout, name);
      await mkdir(nested, { recursive: true });
      execFileSync("git", ["init", "-q"], { cwd: nested });
      await Promise.all([
        writeFile(join(checkout, ignore), `${rule}/**\n${rule}/private.ts\n`),
        writeFile(join(nested, ".ignore"), "*\n"),
        writeFile(join(nested, "public.ts"), "tracked\n"),
        writeFile(join(nested, "private.ts"), "private\n"),
      ]);
      execFileSync("git", ["add", "--force", "public.ts", "private.ts"], {
        cwd: nested,
      });

      expect(await inventory(checkout, name)).toEqual([`${name}/public.ts`]);
    },
  );

  test.each([
    ["!ignored", "\\!ignored"],
    ["#ignored", "\\#ignored"],
    ["a", "[^x]"],
    ["a", "[!x]"],
    ["a", "[a-z]"],
    ["a]", "[[:alpha:]]"],
    ["e\u0301ignored", "e{\u0301,other}ignored"],
    ["ignored/nested", "ignore[]/d]/nested"],
    ["ignored", "{ignore[d/x],other}"],
    ["ignored", "{other,ignore[d/x]}"],
  ])("preserves explicit allowlists for checkout %s", async (name, rule) => {
    if (Bun.which("rg") === null) return;

    const checkout = await repository(false);
    const nested = join(checkout, name);
    await mkdir(nested, { recursive: true });
    execFileSync("git", ["init", "-q"], { cwd: nested });
    await Promise.all([
      writeFile(join(checkout, ".ignore"), `${rule}/**\n`),
      writeFile(join(checkout, ".rgignore"), `!${rule}/public.ts\n`),
      writeFile(join(nested, ".ignore"), "*\n"),
      writeFile(join(nested, "public.ts"), "tracked\n"),
      writeFile(join(nested, "private.ts"), "private\n"),
    ]);
    execFileSync("git", ["add", "--force", "public.ts", "private.ts"], {
      cwd: nested,
    });

    expect(await inventory(checkout, name)).toEqual([`${name}/public.ts`]);
  });

  test("preserves configured exclusions for an escaped checkout name", async () => {
    if (Bun.which("rg") === null) return;

    const checkout = await repository();
    const nested = join(checkout, "!ignored");
    await mkdir(nested);
    execFileSync("git", ["init", "-q"], { cwd: nested });
    await Promise.all([
      writeFile(join(checkout, ".rgignore"), "\\!ignored/**\n"),
      writeFile(join(checkout, ".git", "info", "exclude"), "\\!ignored/**\n"),
      writeFile(join(nested, "private.ts"), "private\n"),
    ]);
    execFileSync("git", ["add", "private.ts"], { cwd: nested });

    expect(await inventory(checkout, "!ignored")).toEqual([]);
  });

  test.each([
    [".gitignore", "!/README.md"],
    [".ignore", "!/README.md"],
    [".rgignore", "!/README.md"],
    [".gitignore", "!**/unrelated/public.ts"],
    [".ignore", "!**/unrelated/public.ts"],
    [".rgignore", "!**/unrelated/public.ts"],
    [".gitignore", "!ignored/"],
    [".ignore", "!ignored/"],
    [".rgignore", "!ignored/"],
    [".gitignore", "!/ignored/"],
    [".ignore", "!/ignored/"],
    [".rgignore", "!/ignored/"],
    [".gitignore", "!/ignored\\ "],
    [".ignore", "!/ignored\\ "],
    [".rgignore", "!/ignored\\ "],
    [".gitignore", "![^x]/public.ts"],
    [".ignore", "![^x]/public.ts"],
    [".rgignore", "![^x]/public.ts"],
    [".gitignore", "![!x]/public.ts"],
    [".ignore", "![!x]/public.ts"],
    [".rgignore", "![!x]/public.ts"],
    [".gitignore", "![a-z]/public.ts"],
    [".ignore", "![a-z]/public.ts"],
    [".rgignore", "![a-z]/public.ts"],
    [".rgignore", "![[:alpha:]]/public.ts"],
    [".rgignore", "!ignored[^x]/public.ts"],
    [".rgignore", "!ignored[!x]/public.ts"],
    [".rgignore", "!ignored[.-0]/public.ts"],
    [".rgignore", "!{ignored[^x],other}/public.ts"],
    [".rgignore", "!{ignored[^\\],other}/public.ts"],
    [".gitignore", "!unrelated/public.ts"],
    [".ignore", "!unrelated/public.ts"],
    [".rgignore", "!unrelated/public.ts"],
    [".gitignore", "!unrelated\\/public.ts"],
    [".ignore", "!unrelated\\/public.ts"],
    [".rgignore", "!unrelated\\/public.ts"],
    [".gitignore", "!unrelated\\/deeper\\/public.ts"],
    [".ignore", "!unrelated\\/deeper\\/public.ts"],
    [".rgignore", "!unrelated\\/deeper\\/public.ts"],
    [".gitignore", "!\\/ignored/public.ts"],
    [".ignore", "!\\/ignored/public.ts"],
    [".rgignore", "!\\/ignored/public.ts"],
    [".gitignore", "!\\/ignored\\/public.ts"],
    [".ignore", "!\\/ignored\\/public.ts"],
    [".rgignore", "!\\/ignored\\/public.ts"],
    [".gitignore", "!unrelated[ab]/public.ts"],
    [".ignore", "!unrelated[ab]/public.ts"],
    [".rgignore", "!unrelated[ab]/public.ts"],
    [".gitignore", "!{unrelated[d/x],other}/public.ts"],
    [".ignore", "!{unrelated[d/x],other}/public.ts"],
    [".rgignore", "!{unrelated[d/x],other}/public.ts"],
    [".rgignore", "!{other,unrelated[d/x]}/public.ts"],
    [".rgignore", "!{{unrelated[d/x],other},another}/public.ts"],
    [".gitignore", "!{unrelated,other}/public.ts"],
    [".ignore", "!{unrelated,other}/public.ts"],
    [".rgignore", "!{unrelated,other}/public.ts"],
    [".gitignore", "!{unrelated/public.ts,other/private.ts}"],
    [".ignore", "!{unrelated/public.ts,other/private.ts}"],
    [".rgignore", "!{unrelated/public.ts,other/private.ts}"],
    [".gitignore", "!{unrelated/public.ts}"],
    [".ignore", "!{unrelated/public.ts}"],
    [".rgignore", "!{unrelated/public.ts}"],
    [".rgignore", "!{other/{private.ts,details.ts},unrelated/public.ts}"],
    [".gitignore", "!{other[^x],another,unrelated/private.ts}/public.ts"],
    [".ignore", "!{other[^x],another,unrelated/private.ts}/public.ts"],
    [".rgignore", "!{other[^x],another,unrelated/private.ts}/public.ts"],
    [
      ".gitignore",
      "!{{other[^x],another},third,unrelated/private.ts}/public.ts",
    ],
    [".ignore", "!{{other[^x],another},third,unrelated/private.ts}/public.ts"],
    [
      ".rgignore",
      "!{{other[^x],another},third,unrelated/private.ts}/public.ts",
    ],
    [".rgignore", `!${"{unrelated/public.ts,other/private.ts}".repeat(12)}`],
    [".rgignore", `!{${"{a/a,b/b}".repeat(12)},other/private.ts}`],
    [".rgignore", `!${"{a,b,c/c}".repeat(12)}/public.ts`],
    [".rgignore", `!${"{?,[a],c/c}".repeat(8)}/public.ts`],
    [".gitignore", "\ufeff!ignored/public.ts"],
    [".ignore", "\ufeff!ignored/public.ts"],
    [".rgignore", "\ufeff!ignored/public.ts"],
    [".rgignore", "# comment\r!ignored/public.ts"],
    [".gitignore", "!unrelated\\[ab\\]/public.ts"],
    [".ignore", "!unrelated\\[ab\\]/public.ts"],
    [".rgignore", "!unrelated\\[ab\\]/public.ts"],
    [".gitignore", "!unrelated\\{/public.ts"],
    [".ignore", "!unrelated[{]/public.ts"],
    [".rgignore", "!unrelated[{]/public.ts"],
    [".gitignore", "!unrelated[[:alpha:]]/public.ts"],
    [".ignore", "!unrelated[[:alpha:]]/public.ts"],
    [".rgignore", "!unrelated[[:alpha:]]/public.ts"],
  ])(
    "ignores unrelated %s allowlist rule %s when reopening the selected checkout",
    async (ignore, unrelated) => {
      if (Bun.which("rg") === null) return;

      const checkout = await repository(false);
      const nested = join(checkout, "ignored");
      await mkdir(nested);
      execFileSync("git", ["init", "-q"], { cwd: nested });
      await Promise.all([
        writeFile(
          join(checkout, ignore),
          `ignored/**\n${unrelated}\nignored/private.ts\n`,
        ),
        writeFile(join(nested, ".ignore"), "*\n"),
        writeFile(join(nested, "public.ts"), "tracked\n"),
        writeFile(join(nested, "private.ts"), "private\n"),
      ]);
      execFileSync("git", ["add", "--force", "public.ts", "private.ts"], {
        cwd: nested,
      });

      expect(await inventory(checkout, "ignored")).toEqual([
        "ignored/public.ts",
      ]);
    },
  );

  test.each([
    [".gitignore", ".gitignore", "present"],
    [".ignore", ".ignore", "present"],
    [".rgignore", ".rgignore", "present"],
    [".gitignore", ".ignore", "present"],
    [".gitignore", ".rgignore", "present"],
    [".ignore", ".rgignore", "present"],
    [".gitignore", ".gitignore", "missing"],
    [".ignore", ".ignore", "missing"],
    [".rgignore", ".rgignore", "missing"],
    [".gitignore", ".ignore", "missing"],
    [".gitignore", ".rgignore", "missing"],
    [".ignore", ".rgignore", "missing"],
  ] as const)(
    "preserves an outer %s deny and %s allowlist when the public file is %s",
    async (deny, allow, state) => {
      if (Bun.which("rg") === null) return;

      const exists = state === "present";
      const checkout = await repository(false);
      const nested = join(checkout, "ignored");
      await mkdir(nested);
      execFileSync("git", ["init", "-q"], { cwd: nested });
      if (deny === allow) {
        await writeFile(
          join(checkout, deny),
          "ignored/**\n!ignored/public.ts\n",
        );
      } else {
        await Promise.all([
          writeFile(join(checkout, deny), "ignored/**\n"),
          writeFile(join(checkout, allow), "!ignored/public.ts\n"),
        ]);
      }
      await Promise.all([
        writeFile(join(nested, ".ignore"), "*\n"),
        writeFile(join(nested, "private.ts"), "private\n"),
        ...(exists ? [writeFile(join(nested, "public.ts"), "tracked\n")] : []),
      ]);
      execFileSync(
        "git",
        ["add", "--force", "private.ts", ...(exists ? ["public.ts"] : [])],
        {
          cwd: nested,
        },
      );

      expect(await inventory(checkout, "ignored")).toEqual(
        exists ? ["ignored/public.ts"] : [],
      );
    },
  );

  test.each([".gitignore", ".ignore", ".rgignore"])(
    "reopens a selected checkout when a later %s deny overrides its allowlist",
    async (ignore) => {
      if (Bun.which("rg") === null) return;

      const checkout = await repository(false);
      const nested = join(checkout, "ignored");
      await mkdir(nested);
      execFileSync("git", ["init", "-q"], { cwd: nested });
      await Promise.all([
        writeFile(
          join(checkout, ignore),
          "!ignored/public.ts\nignored/**\nignored/private.ts\n",
        ),
        writeFile(join(nested, ".ignore"), "*\n"),
        writeFile(join(nested, "public.ts"), "tracked\n"),
        writeFile(join(nested, "private.ts"), "private\n"),
      ]);
      execFileSync("git", ["add", "--force", "public.ts", "private.ts"], {
        cwd: nested,
      });

      expect(await inventory(checkout, "ignored")).toEqual([
        "ignored/public.ts",
      ]);
    },
  );

  test.each([
    [".gitignore", ".ignore"],
    [".gitignore", ".rgignore"],
    [".ignore", ".rgignore"],
  ])(
    "reopens a checkout when a %s allowlist is overridden by %s",
    async (allow, deny) => {
      if (Bun.which("rg") === null) return;

      const checkout = await repository(false);
      const nested = join(checkout, "ignored");
      await mkdir(nested);
      execFileSync("git", ["init", "-q"], { cwd: nested });
      await Promise.all([
        writeFile(
          join(checkout, allow),
          "!ignored/public.ts\nignored/private.ts\n",
        ),
        writeFile(join(checkout, deny), "ignored/**\n"),
        writeFile(join(nested, ".ignore"), "*\n"),
        writeFile(join(nested, "public.ts"), "tracked\n"),
        writeFile(join(nested, "private.ts"), "private\n"),
      ]);
      execFileSync("git", ["add", "--force", "public.ts", "private.ts"], {
        cwd: nested,
      });

      expect(await inventory(checkout, "ignored")).toEqual([
        "ignored/public.ts",
      ]);
    },
  );

  test.each(["present", "missing"])(
    "preserves an allowlisted %s file beneath a brace-recursive deny",
    async (state) => {
      if (Bun.which("rg") === null) return;

      const checkout = await repository(false);
      const nested = join(checkout, "ignored");
      await mkdir(nested);
      execFileSync("git", ["init", "-q"], { cwd: nested });
      await Promise.all([
        writeFile(join(checkout, ".ignore"), "{ignored,other}/**\n"),
        writeFile(join(checkout, ".rgignore"), "!ignored/public.ts\n"),
        writeFile(join(nested, ".ignore"), "*\n"),
        writeFile(join(nested, "private.ts"), "private\n"),
        ...(state === "present"
          ? [writeFile(join(nested, "public.ts"), "tracked\n")]
          : []),
      ]);
      execFileSync(
        "git",
        [
          "add",
          "--force",
          "private.ts",
          ...(state === "present" ? ["public.ts"] : []),
        ],
        { cwd: nested },
      );

      expect(await inventory(checkout, "ignored")).toEqual(
        state === "present" ? ["ignored/public.ts"] : [],
      );
    },
  );

  test.each([
    "!{ignored,other}/public.ts",
    "!{other,ignored}/public.ts",
    "!ign{ored,other}/public.ts",
    "!{ignored/public.ts,other/private.ts}",
    "!{other/private.ts,ignored/public.ts}",
    "!{other/{private.ts,details.ts},ignored/public.ts}",
    "!**/public.ts",
    "!**/**/public.ts",
    "!**/{public.ts,other/private.ts}",
    "!**/{other/private.ts,public.ts}",
    "!public.ts",
    "\ufeff!ignored/public.ts",
    "\ufeff\ufeff!ignored/public.ts",
    "\ufeff\ufeff\ufeff!ignored/public.ts",
    "!ignore[^x]/public.ts",
    "!ignore[d/x]/public.ts",
    "!{ignore[d/x],other}/public.ts",
    "!{other,ignore[d/x]}/public.ts",
    "!/ignored[^x]public.ts",
    "!/ignored[!x]public.ts",
    "!/ignored[.-0]public.ts",
    "!/{ignored[^x],other}public.ts",
    "!ignored\\/public.ts",
    "!/ignored\\/public.ts",
  ])("preserves an expanded outer allowlist rule %s", async (rule) => {
    if (Bun.which("rg") === null) return;

    const checkout = await repository(false);
    const nested = join(checkout, "ignored");
    await mkdir(nested);
    execFileSync("git", ["init", "-q"], { cwd: nested });
    await Promise.all([
      writeFile(join(checkout, ".ignore"), "ignored/**\n"),
      writeFile(join(checkout, ".rgignore"), `${rule}\n`),
      writeFile(join(nested, ".ignore"), "*\n"),
      writeFile(join(nested, "public.ts"), "tracked\n"),
      writeFile(join(nested, "private.ts"), "private\n"),
    ]);
    execFileSync("git", ["add", "--force", "public.ts", "private.ts"], {
      cwd: nested,
    });

    expect(await inventory(checkout, "ignored")).toEqual(["ignored/public.ts"]);
  });

  test.each([
    "!{ignored/public.ts,other/private.ts}",
    "!{other/{private.ts,details.ts},ignored/public.ts}",
    "!**/public.ts",
    "!**/**/public.ts",
    "!**/{public.ts,other/private.ts}",
    "!**/{other/private.ts,public.ts}",
    "!public.ts",
    "!public.*",
    "!{ignore[d/x],other}/public.ts",
    "!{other,ignore[d/x]}/public.ts",
    "!ignored[^x]public.ts",
    "\ufeff\ufeff!ignored/public.ts",
    "!/ignored/public.ts\\ ",
    "!/ignored[^x]public.ts",
    "!/ignored[!x]public.ts",
    "!/ignored[.-0]public.ts",
    "!/{ignored[^x],other}public.ts",
    "!/ignored[^[:alpha:]]/public.ts",
    "!/ignored[![:alpha:]]/public.ts",
    "!/{ignored[^[:alpha:]],other}/public.ts",
  ])("preserves an outer allowlist for a missing file %s", async (rule) => {
    if (Bun.which("rg") === null) return;

    const checkout = await repository(false);
    const nested = join(checkout, "ignored");
    await mkdir(nested);
    execFileSync("git", ["init", "-q"], { cwd: nested });
    await Promise.all([
      writeFile(join(checkout, ".ignore"), "ignored/**\n"),
      writeFile(join(checkout, ".rgignore"), `${rule}\n`),
      writeFile(join(nested, ".ignore"), "*\n"),
      writeFile(join(nested, "private.ts"), "private\n"),
    ]);
    execFileSync("git", ["add", "--force", "private.ts"], { cwd: nested });

    expect(await inventory(checkout, "ignored")).toEqual([]);
  });

  test.each([
    [".ignore", "!ignored[/]nested/public.ts", "present"],
    [".ignore", "!ignored[/]nested/public.ts", "missing"],
    [".ignore", "!{ignored[/]nested,other}/public.ts", "present"],
    [".ignore", "!{ignored[/]nested,other}/public.ts", "missing"],
    [".rgignore", "!{unrelated[d/x],ignored[/]nested}/public.ts", "present"],
    [".rgignore", "!{unrelated[d/x],ignored[/]nested}/public.ts", "missing"],
  ])(
    "preserves private files with %s separator-class allowlist %s (%s)",
    async (ignore, rule, state) => {
      if (Bun.which("rg") === null) return;

      const checkout = await repository(false);
      const nested = join(checkout, "ignored", "nested");
      await mkdir(nested, { recursive: true });
      execFileSync("git", ["init", "-q"], { cwd: nested });
      await Promise.all([
        writeFile(join(checkout, ignore), `ignored/**\n${rule}\n`),
        writeFile(join(nested, ".ignore"), "*\n"),
        writeFile(join(nested, "private.ts"), "private\n"),
        ...(state === "present"
          ? [writeFile(join(nested, "public.ts"), "tracked\n")]
          : []),
      ]);
      execFileSync(
        "git",
        [
          "add",
          "--force",
          "private.ts",
          ...(state === "present" ? ["public.ts"] : []),
        ],
        { cwd: nested },
      );

      expect(await inventory(checkout, "ignored/nested")).toEqual(
        state === "present" ? ["ignored/nested/public.ts"] : [],
      );
    },
  );

  test.each(["present", "missing"])(
    "keeps private files hidden when a directory allowlist reopens a %s descendant",
    async (state) => {
      if (Bun.which("rg") === null) return;

      const checkout = await repository(false);
      const nested = join(checkout, "ignored");
      const descendant = join(nested, "unrelated");
      await mkdir(descendant, { recursive: true });
      execFileSync("git", ["init", "-q"], { cwd: nested });
      await Promise.all([
        writeFile(
          join(checkout, ".ignore"),
          "ignored/**\n!ignored/unrelated/\n!**/unrelated/public.ts\n",
        ),
        writeFile(join(nested, ".ignore"), "*\n"),
        writeFile(join(nested, "private.ts"), "private\n"),
        ...(state === "present"
          ? [writeFile(join(descendant, "public.ts"), "tracked\n")]
          : []),
      ]);
      execFileSync(
        "git",
        [
          "add",
          "--force",
          "private.ts",
          ...(state === "present" ? ["unrelated/public.ts"] : []),
        ],
        { cwd: nested },
      );

      expect(await inventory(checkout, "ignored")).toEqual(
        state === "present" ? ["ignored/unrelated/public.ts"] : [],
      );
    },
  );

  test("does not treat the selected directory as an allowlisted descendant", async () => {
    if (Bun.which("rg") === null) return;

    const checkout = await repository(false);
    const nested = join(checkout, "ignored");
    await mkdir(nested);
    execFileSync("git", ["init", "-q"], { cwd: nested });
    await Promise.all([
      writeFile(
        join(checkout, ".ignore"),
        "ignored/**\n!ignored/\n!**/unrelated/public.ts\nignored/private.ts\n",
      ),
      writeFile(join(nested, ".ignore"), "*\n"),
      writeFile(join(nested, "visible.ts"), "visible\n"),
      writeFile(join(nested, "private.ts"), "private\n"),
    ]);
    execFileSync("git", ["add", "--force", "visible.ts", "private.ts"], {
      cwd: nested,
    });

    expect(await inventory(checkout, "ignored")).toEqual([
      "ignored/visible.ts",
    ]);
  });

  test.each(["present", "missing"])(
    "keeps a revoked %s file allowlist from exposing excluded tracked files",
    async (state) => {
      if (Bun.which("rg") === null) return;

      const checkout = await repository(false);
      const nested = join(checkout, "ignored");
      await mkdir(nested);
      execFileSync("git", ["init", "-q"], { cwd: nested });
      await Promise.all([
        writeFile(
          join(checkout, ".ignore"),
          "ignored/**\n!ignored/public.ts\nignored/public.ts\n",
        ),
        writeFile(join(nested, ".ignore"), "*\n"),
        writeFile(join(nested, "private.ts"), "private\n"),
        ...(state === "present"
          ? [writeFile(join(nested, "public.ts"), "tracked\n")]
          : []),
      ]);
      execFileSync(
        "git",
        [
          "add",
          "--force",
          "private.ts",
          ...(state === "present" ? ["public.ts"] : []),
        ],
        { cwd: nested },
      );

      expect(await inventory(checkout, "ignored")).toEqual([]);
    },
  );

  test.each([
    [".ignore", "ignored/", "ignored/"],
    [".rgignore", "ignored/", "ignored/"],
    [".ignore", "ignored/**", "ignored/"],
    [".rgignore", "ignored/**", "ignored/"],
    [".ignore", "ignored/**", "ignored/**"],
    [".rgignore", "ignored/**", "ignored/**"],
  ])(
    "keeps configured Git excludes authoritative through an outer %s rule %s and exclude %s",
    async (ignore, outer, configured) => {
      if (Bun.which("rg") === null) return;

      const checkout = await repository();
      const nested = join(checkout, "ignored");
      await mkdir(nested);
      execFileSync("git", ["init", "-q"], { cwd: nested });
      await Promise.all([
        writeFile(join(checkout, ignore), `${outer}\n`),
        writeFile(join(checkout, ".git", "info", "exclude"), `${configured}\n`),
        writeFile(join(nested, "public.ts"), "tracked\n"),
      ]);
      execFileSync("git", ["add", "public.ts"], { cwd: nested });

      expect(await inventory(checkout, "ignored")).toEqual([]);
    },
  );

  test.each([1, 2, 3])(
    "preserves %s initial ignore BOMs when configured exclusions are prepended",
    async (count) => {
      if (Bun.which("rg") === null) return;

      const checkout = await repository();
      const nested = join(checkout, "ignored");
      await mkdir(nested);
      execFileSync("git", ["init", "-q"], { cwd: nested });
      await Promise.all([
        writeFile(
          join(checkout, ".gitignore"),
          `${"\ufeff".repeat(count)}ignored/private.ts\n`,
        ),
        writeFile(join(checkout, ".git", "info", "exclude"), "unrelated.ts\n"),
        writeFile(join(nested, ".ignore"), "*\n"),
        writeFile(join(nested, "public.ts"), "tracked\n"),
        writeFile(join(nested, "private.ts"), "private\n"),
      ]);
      execFileSync("git", ["add", "--force", "public.ts", "private.ts"], {
        cwd: nested,
      });

      expect(await inventory(checkout, "ignored")).toEqual([
        "ignored/public.ts",
      ]);
    },
  );

  test.each(["marker", "gitfile"])(
    "rejects symbolic Git metadata through a %s",
    async (kind) => {
      if (Bun.which("rg") === null) return;

      const checkout = await repository(false);
      const external = await repository();
      const metadata =
        kind === "marker"
          ? join(checkout, ".git")
          : join(dirname(checkout), "linked-metadata");
      await symlink(
        join(external, ".git"),
        metadata,
        process.platform === "win32" ? "junction" : "dir",
      );
      if (kind === "gitfile") {
        await writeFile(join(checkout, ".git"), `gitdir: ${metadata}\n`);
      }
      await writeFile(join(checkout, "visible.ts"), "visible\n");

      await expect(inventory(checkout)).rejects.toThrow(
        "symbolic Git metadata paths are not supported",
      );
    },
  );

  test.each(["gitdir", "backpointer", "commondir", "worktree"])(
    "rejects symbolic %s metadata hops before parent traversal",
    async (kind) => {
      if (Bun.which("rg") === null) return;

      const checkout = await repository();
      await writeFile(join(checkout, "visible.ts"), "tracked\n");
      execFileSync("git", ["add", "visible.ts"], { cwd: checkout });
      commit(checkout);
      const linked = join(dirname(checkout), "linked-worktree");
      execFileSync("git", ["worktree", "add", "--detach", linked, "HEAD"], {
        cwd: checkout,
        stdio: "ignore",
      });
      const gitdir = (await readFile(join(linked, ".git"), "utf8"))
        .replace(/^gitdir: /, "")
        .trim();
      const outside = join(dirname(checkout), "outside", "hop-target");
      await mkdir(outside, { recursive: true });
      const hop =
        kind === "gitdir"
          ? join(dirname(gitdir), "hop")
          : kind === "commondir"
            ? join(checkout, "hop")
            : join(linked, "hop");
      await symlink(
        outside,
        hop,
        process.platform === "win32" ? "junction" : "dir",
      );

      if (kind === "gitdir") {
        await writeFile(
          join(linked, ".git"),
          `gitdir: ${hop}/../${basename(gitdir)}\n`,
        );
      } else if (kind === "backpointer") {
        await writeFile(join(gitdir, "gitdir"), `${hop}/../.git\n`);
      } else if (kind === "commondir") {
        await writeFile(join(gitdir, "commondir"), `${hop}/../.git\n`);
      } else {
        execFileSync("git", ["config", "extensions.worktreeConfig", "true"], {
          cwd: linked,
        });
        execFileSync(
          "git",
          ["config", "--worktree", "core.worktree", `${hop}/..`],
          {
            cwd: linked,
          },
        );
      }

      await expect(inventory(linked)).rejects.toThrow(
        "symbolic Git metadata paths are not supported",
      );
    },
  );

  test.skipIf(process.platform !== "win32").each([
    ["gitdir", "network"],
    ["gitdir", "device"],
    ["backpointer", "network"],
    ["commondir", "network"],
    ["worktree", "network"],
    ["alternates", "network"],
  ])(
    "rejects %s %s metadata before accessing its Windows anchor",
    async (kind, prefix) => {
      const checkout = await repository(kind !== "gitdir");
      const remote = `${
        prefix === "device" ? "\\\\?\\UNC" : "\\"
      }\\codex-security.invalid\\share\\one\\two\\three\\four\\five\\six\\seven\\eight`;
      let selected = checkout;
      if (kind === "gitdir") {
        await writeFile(join(checkout, ".git"), `gitdir: ${remote}\n`);
      } else if (kind === "alternates") {
        await writeFile(
          join(checkout, ".git", "objects", "info", "alternates"),
          `${remote}\n`,
        );
      } else {
        await writeFile(join(checkout, "tracked.ts"), "tracked\n");
        execFileSync("git", ["add", "tracked.ts"], { cwd: checkout });
        commit(checkout);
        selected = join(dirname(checkout), "linked-worktree");
        execFileSync("git", ["worktree", "add", "--detach", selected, "HEAD"], {
          cwd: checkout,
          stdio: "ignore",
        });
        const gitdir = (await readFile(join(selected, ".git"), "utf8"))
          .replace(/^gitdir: /, "")
          .trim();
        if (kind === "backpointer") {
          await writeFile(join(gitdir, "gitdir"), `${remote}\n`);
        } else if (kind === "commondir") {
          await writeFile(join(gitdir, "commondir"), `${remote}\n`);
        } else {
          execFileSync("git", ["config", "extensions.worktreeConfig", "true"], {
            cwd: selected,
          });
          await writeFile(
            join(gitdir, "config.worktree"),
            `[core]\n\tworktree = ${JSON.stringify(remote)}\n`,
          );
        }
      }
      const instrumentation = join(dirname(checkout), "instrumentation");
      await mkdir(instrumentation);
      await writeFile(
        join(instrumentation, "sitecustomize.py"),
        [
          "from pathlib import Path",
          "original = Path.stat",
          "def guarded(self, *args, **kwargs):",
          "    if self.anchor.startswith(chr(92) * 2) and 'codex-security.invalid' in str(self).casefold():",
          "        raise RuntimeError('attempted network metadata access')",
          "    return original(self, *args, **kwargs)",
          "Path.stat = guarded",
        ].join("\n"),
      );

      await expect(
        inventory(selected, ".", {
          ...process.env,
          PYTHONPATH: instrumentation,
        }),
      ).rejects.toThrow("network Git metadata paths are not supported");
    },
  );

  test.each(["worktrees", "owner"])(
    "rejects symbolic common %s metadata before following worktree ownership",
    async (kind) => {
      const checkout = await repository();
      await writeFile(join(checkout, "tracked.ts"), "tracked\n");
      execFileSync("git", ["add", "tracked.ts"], { cwd: checkout });
      commit(checkout);
      const linked = join(dirname(checkout), "linked-worktree");
      execFileSync("git", ["worktree", "add", "--detach", linked, "HEAD"], {
        cwd: checkout,
        stdio: "ignore",
      });
      const gitdir = (await readFile(join(linked, ".git"), "utf8"))
        .replace(/^gitdir: /, "")
        .trim();
      const common = join(dirname(checkout), "common-metadata");
      const external = join(dirname(checkout), "external-worktrees");
      await mkdir(common);
      await mkdir(external);
      if (kind === "owner") await mkdir(join(common, "worktrees"));
      const symbolic =
        kind === "worktrees"
          ? join(common, "worktrees")
          : join(common, "worktrees", basename(gitdir));
      await symlink(
        external,
        symbolic,
        process.platform === "win32" ? "junction" : "dir",
      );
      await writeFile(join(gitdir, "commondir"), `${common}\n`);

      const instrumentation = join(dirname(checkout), "instrumentation");
      await mkdir(instrumentation);
      await writeFile(
        join(instrumentation, "sitecustomize.py"),
        [
          "from pathlib import Path",
          `owner = Path(${JSON.stringify(join(common, "worktrees", basename(gitdir)))})`,
          "original = Path.stat",
          "def guarded(self, *args, **kwargs):",
          "    if self == owner and kwargs.get('follow_symlinks', True):",
          "        raise RuntimeError('followed unvalidated Git worktree owner')",
          "    return original(self, *args, **kwargs)",
          "Path.stat = guarded",
        ].join("\n"),
      );

      await expect(
        inventory(linked, ".", {
          ...process.env,
          PYTHONPATH: instrumentation,
        }),
      ).rejects.toThrow("symbolic Git metadata paths are not supported");
    },
  );

  test.each([".GIT", ".GIT.", ".g\u0131t", ".g\u0131t."])(
    "rejects symbolic %s metadata before resolving its filesystem alias",
    async (alias) => {
      if (process.platform === "win32" && alias.endsWith(".")) return;

      const checkout = await repository();
      const nested = join(checkout, "visible");
      const external = join(dirname(checkout), "external-metadata");
      await mkdir(nested);
      await mkdir(external);
      await symlink(
        external,
        join(nested, alias),
        process.platform === "win32" ? "junction" : "dir",
      );

      const instrumentation = join(dirname(checkout), "instrumentation");
      await mkdir(instrumentation);
      await writeFile(
        join(instrumentation, "sitecustomize.py"),
        [
          "from pathlib import Path",
          "original = Path.samefile",
          "def guarded(self, other):",
          "    if self.parent.name == 'visible' and self.name.upper().casefold().rstrip('. ') == '.git':",
          "        raise RuntimeError('followed symbolic Git metadata alias')",
          "    return original(self, other)",
          "Path.samefile = guarded",
        ].join("\n"),
      );

      await expect(
        inventory(checkout, ".", {
          ...process.env,
          PYTHONPATH: instrumentation,
        }),
      ).rejects.toThrow("symbolic Git metadata paths are not supported");
    },
  );

  test.each(["missing", "mismatched"])(
    "rejects an external gitdir with a %s worktree backpointer",
    async (ownership) => {
      if (Bun.which("rg") === null) return;

      const checkout = await repository(false);
      const external = await repository();
      await writeFile(join(external, "secret.ts"), "tracked\n");
      execFileSync("git", ["add", "secret.ts"], { cwd: external });
      await writeFile(join(checkout, ".gitignore"), "secret.ts\n");
      await writeFile(join(checkout, "secret.ts"), "private\n");
      await writeFile(
        join(checkout, ".git"),
        `gitdir: ${join(external, ".git")}\n`,
      );
      if (ownership === "mismatched") {
        await writeFile(
          join(external, ".git", "gitdir"),
          `${join(external, ".git")}\n`,
        );
      }

      await expect(inventory(checkout)).rejects.toThrow(
        "Git metadata directory does not own selected worktree",
      );
    },
  );

  test.each(["missing", "conflicting"])(
    "rejects an internal gitfile with %s checkout ownership",
    async (ownership) => {
      if (Bun.which("rg") === null) return;

      const checkout = await repository();
      const nested = join(checkout, "nested");
      await mkdir(nested);
      await writeFile(join(checkout, "secret.ts"), "tracked\n");
      execFileSync("git", ["add", "secret.ts"], { cwd: checkout });
      await writeFile(join(nested, ".ignore"), "secret.ts\n");
      await writeFile(join(nested, "secret.ts"), "private\n");
      await writeFile(join(nested, ".git"), "gitdir: ../.git\n");
      if (ownership === "conflicting") {
        execFileSync(
          "git",
          ["config", "--local", "core.worktree", "../nested"],
          {
            cwd: checkout,
          },
        );
      }

      await expect(inventory(checkout)).rejects.toThrow(
        "Git metadata directory does not own selected worktree",
      );
    },
  );

  test.each([
    "disabled",
    "disabled-comment",
    "disabled-empty",
    "disabled-quoted",
    "disabled-carriage",
    "disabled-symlink",
    "hash-comment-override",
    "semicolon-comment-override",
    "indented-override",
    "inline-section-override",
    "inline-carriage-override",
    "chained-section-override",
    "inline-extension-disabled",
    "carriage-return-override",
    "carriage-return-section",
    "carriage-return-section-comment",
    "default-inheritance",
    "unquoted-escape",
    "literal-tab",
    "literal-tab-missing",
    "quoted-tab-owned",
    "vertical-tab-owned",
    "form-feed-owned",
    "case-alias",
    "short-alias",
    "short-worktree",
    "owned",
    "external",
    "mixed-case-external",
  ])(
    "honors %s worktree-specific Git ownership configuration",
    async (ownership) => {
      if (Bun.which("rg") === null) return;
      if (ownership === "disabled-symlink" && process.platform === "win32")
        return;
      if (ownership === "unquoted-escape" && process.platform === "win32")
        return;
      const tabOwnership =
        ownership.startsWith("literal-tab") || ownership === "quoted-tab-owned";
      const controlOwnership =
        ownership === "vertical-tab-owned" || ownership === "form-feed-owned";
      if ((tabOwnership || controlOwnership) && process.platform === "win32")
        return;
      if (
        ownership.startsWith("short-") &&
        (process.platform !== "win32" || python === null)
      )
        return;

      const checkout = await repository();
      const nested = join(
        checkout,
        ownership === "unquoted-escape"
          ? "nested\\towner"
          : tabOwnership
            ? "nested\towner"
            : ownership === "vertical-tab-owned"
              ? "nested\vowner"
              : ownership === "form-feed-owned"
                ? "nested\fowner"
                : "nested",
      );
      const metadata = join(checkout, ".git", "modules", "nested");
      const external =
        ownership === "unquoted-escape"
          ? join(checkout, "nested\towner")
          : ownership === "literal-tab"
            ? join(checkout, "nested owner")
            : join(dirname(checkout), "external-worktree");
      await mkdir(dirname(metadata), { recursive: true });
      await mkdir(external);
      execFileSync(
        "git",
        ["init", "-q", "--separate-git-dir", metadata, nested],
        {
          cwd: checkout,
        },
      );
      execFileSync("git", ["-C", nested, "config", "core.worktree", nested]);
      execFileSync("git", [
        "-C",
        nested,
        "config",
        "extensions.worktreeConfig",
        ownership.startsWith("disabled") ||
        ownership.endsWith("comment-override") ||
        ownership === "indented-override" ||
        ownership === "inline-section-override" ||
        ownership === "inline-carriage-override" ||
        ownership === "chained-section-override" ||
        ownership.startsWith("carriage-return") ||
        ownership === "default-inheritance" ||
        ownership === "unquoted-escape" ||
        tabOwnership ||
        controlOwnership
          ? "false"
          : "true",
      ]);
      await writeFile(join(nested, "visible.ts"), "tracked\n");
      execFileSync("git", ["-C", nested, "add", "visible.ts"]);
      const effective =
        ownership === "owned" ||
        ownership === "case-alias" ||
        ownership === "short-alias" ||
        ownership === "short-worktree"
          ? nested
          : external;
      const config = join(metadata, "config");
      if (ownership === "mixed-case-external") {
        await writeFile(
          config,
          (await readFile(config, "utf8")).replace(
            /^\[extensions\]$/im,
            "[Extensions]",
          ),
        );
      } else if (
        ownership === "disabled-comment" ||
        ownership === "disabled-empty" ||
        ownership === "disabled-quoted" ||
        ownership === "disabled-carriage"
      ) {
        await writeFile(
          config,
          (await readFile(config, "utf8")).replace(
            /^([ \t]*worktreeConfig[ \t]*=[ \t]*)false$/im,
            ownership === "disabled-comment"
              ? "$1false # disabled"
              : ownership === "disabled-quoted"
                ? '$1f"al"se'
                : ownership === "disabled-carriage"
                  ? "$1\rfalse"
                  : "$1",
          ),
        );
      } else if (ownership.endsWith("comment-override")) {
        const comment = ownership.startsWith("hash") ? "#" : ";";
        await writeFile(
          config,
          (await readFile(config, "utf8")).replace(
            /^([ \t]*worktree[ \t]*=.*)$/im,
            `$1\n\t${comment} owner comment \\\n\tworktree = ${external}`,
          ),
        );
      } else if (ownership === "indented-override") {
        await writeFile(
          config,
          (await readFile(config, "utf8")).replace(
            /^([ \t]*worktree[ \t]*=.*)$/im,
            `$1 # selected owner\n\t\tworktree = ${external}`,
          ),
        );
      } else if (
        ownership === "inline-section-override" ||
        ownership === "inline-carriage-override" ||
        ownership === "chained-section-override"
      ) {
        const header =
          ownership === "chained-section-override"
            ? '[0][-][.legacy][ "quoted"][feature][unused.value][core]'
            : "[core]";
        const whitespace = ownership === "inline-carriage-override" ? "\r" : "";
        await writeFile(
          config,
          `${await readFile(config, "utf8")}\n${header}${whitespace}worktree = ${external}\n`,
        );
      } else if (ownership === "inline-extension-disabled") {
        await writeFile(
          config,
          `${await readFile(config, "utf8")}\n[extensions]worktreeConfig = false\n`,
        );
      } else if (ownership === "carriage-return-override") {
        await writeFile(
          config,
          (await readFile(config, "utf8")).replace(
            /^([ \t]*worktree[ \t]*=.*)$/im,
            `$1\n\rworktree = ${external}`,
          ),
        );
      } else if (
        ownership === "carriage-return-section" ||
        ownership === "carriage-return-section-comment"
      ) {
        await writeFile(
          config,
          `${await readFile(config, "utf8")}\n${
            ownership === "carriage-return-section"
              ? "\r[core]"
              : "[core]\r# selected owner"
          }\n\tworktree = ${external}\n`,
        );
      } else if (ownership === "default-inheritance") {
        const withoutOwner = (await readFile(config, "utf8")).replace(
          /^[ \t]*worktree[ \t]*=.*\n/im,
          "",
        );
        await writeFile(
          config,
          `${withoutOwner}\n[DEFAULT]\n\tworktree = ${nested}\n`,
        );
      } else if (
        ownership === "unquoted-escape" ||
        tabOwnership ||
        controlOwnership
      ) {
        await writeFile(
          config,
          (await readFile(config, "utf8")).replace(
            /^([ \t]*worktree[ \t]*=).*$/im,
            ownership === "quoted-tab-owned"
              ? `$1 "${nested.replaceAll("\t", "\\t")}"`
              : `$1 ${nested}`,
          ),
        );
      }
      const configuredOwner =
        ownership === "short-worktree" ? windowsShortPath(nested) : effective;
      if (configuredOwner === null) return;
      const override = `[${ownership === "mixed-case-external" ? "Core" : "core"}]\n\tworktree = ${configuredOwner}\n`;
      if (ownership === "disabled-symlink") {
        const unused = join(dirname(checkout), "unused.config");
        await writeFile(unused, override);
        await symlink(unused, join(metadata, "config.worktree"));
      } else if (
        ownership === "disabled-quoted" ||
        ownership === "disabled-carriage"
      ) {
        await mkdir(join(metadata, "config.worktree"));
      } else {
        await writeFile(join(metadata, "config.worktree"), override);
      }
      if (ownership === "case-alias" || ownership === "short-alias") {
        const alias =
          ownership === "case-alias"
            ? metadata.toUpperCase()
            : windowsShortPath(metadata);
        if (alias === null) return;
        const equivalent = await realpath(alias).then(
          async (resolved) => resolved === (await realpath(metadata)),
          () => false,
        );
        if (!equivalent) return;
        await writeFile(join(nested, ".git"), `gitdir: ${alias}\n`);
      }

      if (
        ownership === "external" ||
        ownership === "mixed-case-external" ||
        ownership.endsWith("comment-override") ||
        ownership === "indented-override" ||
        ownership === "inline-section-override" ||
        ownership === "inline-carriage-override" ||
        ownership === "chained-section-override" ||
        ownership.startsWith("carriage-return") ||
        ownership === "default-inheritance" ||
        ownership === "unquoted-escape" ||
        ownership.startsWith("literal-tab")
      ) {
        await expect(inventory(checkout)).rejects.toThrow(
          "Git metadata directory does not own selected worktree",
        );
      } else {
        expect(await inventory(checkout)).toContain(
          `./${basename(nested)}/visible.ts`,
        );
      }
    },
  );

  test
    .skipIf(process.platform === "win32")
    .each(["symbolic", "missing", "quoted"])(
    "validates %s carriage-return Git worktree normalization",
    async (ownership) => {
      if (Bun.which("rg") === null) return;

      const checkout = await repository();
      const nested = join(checkout, "nested");
      const metadata = join(checkout, ".git", "modules", "nested");
      const original = join(checkout, ".git", "owned\rmetadata");
      const normalized = join(checkout, ".git", "owned metadata");
      const external = join(dirname(checkout), "external-worktree");
      await mkdir(dirname(metadata), { recursive: true });
      await mkdir(original);
      await mkdir(external);
      if (ownership !== "missing") await symlink(external, normalized);
      execFileSync(
        "git",
        ["init", "-q", "--separate-git-dir", metadata, nested],
        { cwd: checkout },
      );
      execFileSync("git", ["-C", nested, "config", "core.worktree", nested]);
      await writeFile(join(nested, "visible.ts"), "tracked\n");
      execFileSync("git", ["-C", nested, "add", "visible.ts"]);
      const config = join(metadata, "config");
      const configured = `${original}/../../nested`;
      await writeFile(
        config,
        (await readFile(config, "utf8")).replace(
          /^([ \t]*worktree[ \t]*=).*$/im,
          `$1 ${ownership === "quoted" ? `"${configured}"` : configured}`,
        ),
      );

      if (ownership === "quoted") {
        expect(await inventory(checkout)).toContain("./nested/visible.ts");
      } else {
        await expect(inventory(checkout)).rejects.toThrow(
          ownership === "symbolic"
            ? "symbolic Git metadata paths are not supported"
            : "Git metadata directory does not own selected worktree",
        );
      }
    },
  );

  test.each(["root", "nested", "ignored owner"])(
    "excludes %s Git metadata stored inside the repository",
    async (kind) => {
      if (Bun.which("rg") === null) return;

      const checkout = await repository(kind !== "root");
      const metadata = join(checkout, ".metadata");
      const owner =
        kind === "root"
          ? checkout
          : join(checkout, kind === "nested" ? "nested" : "ignored/nested");
      execFileSync(
        "git",
        ["init", "-q", "--separate-git-dir", metadata, owner],
        { cwd: checkout },
      );
      execFileSync("git", ["-C", owner, "config", "core.worktree", owner]);
      await Promise.all([
        writeFile(join(checkout, "visible.ts"), "visible\n"),
        writeFile(join(metadata, "private.ts"), "private\n"),
        ...(kind === "root"
          ? []
          : [writeFile(join(owner, "nested.ts"), "visible\n")]),
        ...(kind === "ignored owner"
          ? [writeFile(join(checkout, ".gitignore"), "ignored/\n")]
          : []),
      ]);
      execFileSync("git", [
        "-C",
        checkout,
        "add",
        "--force",
        ".metadata/config",
      ]);

      expect(await inventory(checkout)).toEqual([
        ...(kind === "ignored owner" ? ["./.gitignore"] : []),
        ...(kind === "nested" ? ["./nested/nested.ts"] : []),
        "./visible.ts",
      ]);
      for (const scope of [
        ".metadata",
        ".metadata/config",
        ".metadata/private.ts",
      ]) {
        await expect(inventory(checkout, scope)).rejects.toThrow(
          "--scope: Git metadata paths are not supported",
        );
      }
    },
  );

  test.each([
    "config",
    "HEAD",
    "index",
    "packed-refs",
    "info/exclude",
    "refs/heads",
    "refs/tags",
    "refs/remotes",
    "refs/notes",
    "refs/custom",
    "refs/custom trailing data",
    "refs/replace bare",
    "refs/bisect bare",
    "refs/worktree bare",
    "refs/rewritten bare",
    "refs/bisect",
    "refs/worktree",
    "refs/rewritten",
  ])(
    "excludes force-tracked aliases of active Git %s metadata",
    async (kind) => {
      if (Bun.which("rg") === null) return;

      const checkout = await repository();
      const alias = join(checkout, "metadata-copy.txt");
      await Promise.all([
        writeFile(join(checkout, ".gitignore"), "metadata-copy.txt\n"),
        writeFile(join(checkout, "visible.ts"), "visible\n"),
      ]);
      execFileSync("git", ["add", "visible.ts"], { cwd: checkout });
      commit(checkout);
      let relative: string = kind;
      if (kind === "refs/heads") {
        relative = execFileSync("git", ["symbolic-ref", "HEAD"], {
          cwd: checkout,
          encoding: "utf8",
        }).trim();
      } else if (kind.startsWith("refs/")) {
        relative = kind.endsWith(" bare")
          ? kind.slice(0, -" bare".length)
          : `${kind === "refs/custom trailing data" ? "refs/custom" : kind}/inventory`;
        execFileSync("git", ["update-ref", relative, "HEAD"], {
          cwd: checkout,
        });
        if (kind === "refs/custom trailing data") {
          const object = execFileSync("git", ["rev-parse", "HEAD"], {
            cwd: checkout,
            encoding: "utf8",
          }).trim();
          await writeFile(
            join(checkout, ".git", relative),
            `${object} arbitrary trailer\n`,
          );
        }
      } else if (kind === "packed-refs") {
        execFileSync("git", ["pack-refs", "--all"], { cwd: checkout });
      }
      await writeFile(alias, "placeholder\n");
      execFileSync("git", ["add", "--force", "metadata-copy.txt"], {
        cwd: checkout,
      });
      await rm(alias);
      await hardlink(join(checkout, ".git", relative), alias);

      const rows = await inventory(checkout);
      expect(rows).toContain("./visible.ts");
      expect(rows).not.toContain("./metadata-copy.txt");
      await expect(inventory(checkout, "metadata-copy.txt")).rejects.toThrow(
        "--scope: Git metadata paths are not supported",
      );
    },
  );

  test.each(["shared", "private"])(
    "excludes aliases of %s linked-worktree references",
    async (ownership) => {
      if (Bun.which("rg") === null) return;

      const checkout = await repository();
      await writeFile(join(checkout, "visible.ts"), "visible\n");
      execFileSync("git", ["add", "visible.ts"], { cwd: checkout });
      commit(checkout);
      const linked = join(dirname(checkout), "linked-worktree");
      execFileSync("git", ["worktree", "add", "--detach", linked, "HEAD"], {
        cwd: checkout,
        stdio: "ignore",
      });

      const reference =
        ownership === "shared" ? "refs/bisect" : "refs/bisect/inventory";
      execFileSync("git", ["update-ref", reference, "HEAD"], { cwd: linked });
      const gitdir =
        ownership === "shared"
          ? join(checkout, ".git")
          : (await readFile(join(linked, ".git"), "utf8"))
              .replace(/^gitdir: /, "")
              .trim();
      const alias = join(linked, "metadata-copy.txt");
      await Promise.all([
        writeFile(join(linked, ".gitignore"), "metadata-copy.txt\n"),
        writeFile(alias, "placeholder\n"),
      ]);
      execFileSync("git", ["add", "--force", "metadata-copy.txt"], {
        cwd: linked,
      });
      await rm(alias);
      await hardlink(join(gitdir, reference), alias);

      const rows = await inventory(linked);
      expect(rows).toContain("./visible.ts");
      expect(rows).not.toContain("./metadata-copy.txt");
      await expect(inventory(linked, "metadata-copy.txt")).rejects.toThrow(
        "--scope: Git metadata paths are not supported",
      );
    },
  );

  test.each([
    ["ordinary source", 'eval(request.args["payload"])\n'],
    [
      "a forged symbolic reference",
      "ref: refs/heads/main if False else None\ndef vulnerable(command):\n    return __import__('os').system(command)\n",
    ],
  ])(
    "does not hide %s hardlinked to an invalid Git reference",
    async (_, contents) => {
      if (Bun.which("rg") === null) return;

      const checkout = await repository();
      const source = join(checkout, "vulnerable.py");
      const reference = join(checkout, ".git", "refs", "custom", "source");
      await Promise.all([
        writeFile(source, contents),
        mkdir(dirname(reference), { recursive: true }),
      ]);
      execFileSync("git", ["add", "vulnerable.py"], { cwd: checkout });
      await hardlink(source, reference);

      expect(await inventory(checkout)).toContain("./vulnerable.py");
      expect(await inventory(checkout, "vulnerable.py")).toEqual([
        "vulnerable.py",
      ]);
    },
  );

  test.each(["sha1", "sha256"])(
    "does not hide source with an invalid %s reference hash width",
    async (format) => {
      if (Bun.which("rg") === null) return;

      const checkout = await repository(false);
      execFileSync("git", ["init", "-q", `--object-format=${format}`], {
        cwd: checkout,
      });
      const source = join(checkout, "vulnerable.py");
      const reference = join(checkout, ".git", "refs", "custom", "source");
      const incorrectWidth = format === "sha1" ? 64 : 40;
      await Promise.all([
        writeFile(
          source,
          `${"1".repeat(incorrectWidth)}\ndef vulnerable(command):\n    return __import__('os').system(command)\n`,
        ),
        mkdir(dirname(reference), { recursive: true }),
      ]);
      execFileSync("git", ["add", "vulnerable.py"], { cwd: checkout });
      await hardlink(source, reference);

      expect(await inventory(checkout)).toContain("./vulnerable.py");
      expect(await inventory(checkout, "vulnerable.py")).toEqual([
        "vulnerable.py",
      ]);
    },
  );

  test.each(["comment", "quoted comment", "worktree config", "case alias"])(
    "proves ignored Git metadata ownership from %s configuration",
    async (kind) => {
      if (Bun.which("rg") === null) return;

      const checkout = await repository();
      const metadata = join(checkout, ".metadata");
      const owner = join(checkout, "ignored", "nested");
      execFileSync(
        "git",
        ["init", "-q", "--separate-git-dir", metadata, owner],
        { cwd: checkout },
      );
      execFileSync("git", ["-C", owner, "config", "core.worktree", owner]);
      const config = join(metadata, "config");
      if (kind === "worktree config") {
        execFileSync("git", [
          "-C",
          owner,
          "config",
          "extensions.worktreeConfig",
          "true",
        ]);
        execFileSync("git", [
          "-C",
          owner,
          "config",
          "--unset",
          "core.worktree",
        ]);
        await writeFile(
          join(metadata, "config.worktree"),
          `[core]\n\tworktree = ${JSON.stringify(owner)}\n`,
        );
      } else {
        const configured = kind === "case alias" ? owner.toUpperCase() : owner;
        if (kind === "case alias") {
          const equivalent = await realpath(configured).then(
            async (resolved) => resolved === (await realpath(owner)),
            () => false,
          );
          if (!equivalent) return;
        }
        const value =
          kind === "quoted comment"
            ? `${JSON.stringify(configured)} # valid comment`
            : `${configured}${kind === "comment" ? " # valid comment" : ""}`;
        await writeFile(
          config,
          (await readFile(config, "utf8")).replace(
            /^([ \t]*worktree[ \t]*=).*$/m,
            `$1 ${value}`,
          ),
        );
      }
      await Promise.all([
        writeFile(join(checkout, ".gitignore"), "ignored/\n"),
        writeFile(join(checkout, "visible.ts"), "visible\n"),
        writeFile(join(metadata, "private.ts"), "private\n"),
      ]);

      expect(await inventory(checkout)).toEqual([
        "./.gitignore",
        "./visible.ts",
      ]);
      await expect(inventory(checkout, ".metadata/private.ts")).rejects.toThrow(
        "--scope: Git metadata paths are not supported",
      );
    },
  );

  test.skipIf(process.platform === "win32").each(["HEAD", "objects", "refs"])(
    "excludes internal Git metadata with a symbolic %s",
    async (member) => {
      if (Bun.which("rg") === null) return;

      const checkout = await repository();
      const metadata = join(checkout, ".metadata");
      const owner = join(checkout, "ignored", "nested");
      execFileSync(
        "git",
        ["init", "-q", "--separate-git-dir", metadata, owner],
        { cwd: checkout },
      );
      execFileSync("git", ["-C", owner, "config", "core.worktree", owner]);
      await Promise.all([
        writeFile(join(checkout, ".gitignore"), "ignored/\n"),
        writeFile(join(checkout, "visible.ts"), "visible\n"),
        writeFile(join(metadata, "private.ts"), "private\n"),
      ]);
      const external = join(dirname(checkout), "external-metadata");
      if (member === "HEAD") {
        await writeFile(external, "ref: refs/heads/main\n");
      } else {
        await mkdir(external);
      }
      await rm(join(metadata, member), { recursive: true, force: true });
      await symlink(external, join(metadata, member));

      expect(await inventory(checkout)).toEqual([
        "./.gitignore",
        "./visible.ts",
      ]);
    },
  );

  test.each(["empty", "malformed", "directory"])(
    "does not treat the %s marker inside Git metadata as a checkout",
    async (kind) => {
      if (Bun.which("rg") === null) return;

      const checkout = await repository();
      const metadata = join(checkout, ".metadata");
      const owner = join(checkout, "ignored", "nested");
      execFileSync(
        "git",
        ["init", "-q", "--separate-git-dir", metadata, owner],
        { cwd: checkout },
      );
      execFileSync("git", ["-C", owner, "config", "core.worktree", owner]);
      await Promise.all([
        writeFile(join(checkout, ".gitignore"), "ignored/\n"),
        writeFile(join(checkout, "visible.ts"), "visible\n"),
        writeFile(join(metadata, "private.ts"), "private\n"),
      ]);
      if (kind === "directory") {
        await mkdir(join(metadata, ".git"));
      } else {
        await writeFile(
          join(metadata, ".git"),
          kind === "empty" ? "" : "not a gitfile\n",
        );
      }

      expect(await inventory(checkout)).toEqual([
        "./.gitignore",
        "./visible.ts",
      ]);
    },
  );

  test("preserves ordinary source directories with Git-like member names", async () => {
    if (Bun.which("rg") === null) return;

    const checkout = await repository();
    const ordinary = join(checkout, ".metadata");
    await mkdir(join(ordinary, "objects"), { recursive: true });
    await mkdir(join(ordinary, "refs"));
    await Promise.all([
      writeFile(join(ordinary, "HEAD"), "ordinary application header\n"),
      writeFile(join(ordinary, "objects", "source.ts"), "source\n"),
      writeFile(join(ordinary, "refs", "source.ts"), "source\n"),
    ]);

    expect(await inventory(checkout, ".metadata")).toEqual([
      ".metadata/HEAD",
      ".metadata/objects/source.ts",
      ".metadata/refs/source.ts",
    ]);
  });

  test.each(["objects", "linked", "forged owner"])(
    "includes tracked source with an unowned %s Git directory shape",
    async (kind) => {
      if (Bun.which("rg") === null) return;

      const checkout = await repository();
      const source = join(checkout, "application");
      await mkdir(source);
      await writeFile(join(source, "HEAD"), "ref: refs/heads/main\n");
      if (kind === "linked") {
        await Promise.all([
          writeFile(join(source, "gitdir"), "not-an-owner\n"),
          writeFile(join(source, "commondir"), ".\n"),
        ]);
      } else {
        await mkdir(join(source, "objects"));
        await mkdir(join(source, "refs"));
        await Promise.all([
          writeFile(join(source, "objects", "tracked.txt"), "source\n"),
          writeFile(join(source, "refs", "tracked.txt"), "source\n"),
        ]);
      }
      if (kind === "forged owner") {
        await writeFile(
          join(source, "config"),
          `[core]\n\tworktree = ${checkout}\n`,
        );
      }
      await Promise.all([
        writeFile(join(source, "vulnerable.py"), "unsafe = True\n"),
        writeFile(join(checkout, "visible.ts"), "visible\n"),
      ]);
      execFileSync("git", ["add", "--force", "application", "visible.ts"], {
        cwd: checkout,
      });
      commit(checkout);
      const cloned = await repository(false);
      execFileSync("git", ["clone", "-q", "--no-local", checkout, cloned]);

      expect(await inventory(cloned)).toContain("./application/vulnerable.py");
      expect(await inventory(cloned, "application")).toContain(
        "application/vulnerable.py",
      );
      expect(await inventory(cloned, "application/vulnerable.py")).toEqual([
        "application/vulnerable.py",
      ]);
    },
  );

  test.each([
    "invalid HEAD",
    "empty HEAD",
    "invalid reference",
    "wrong hash width",
    "missing metadata",
    "missing objects",
    "missing refs",
    "detached HEAD",
  ])(
    "does not hide source through forged metadata ownership with %s",
    async (kind) => {
      if (Bun.which("rg") === null) return;

      const checkout = await repository();
      const application = join(checkout, "application");
      const owner = join(checkout, "owner");
      await Promise.all([mkdir(application), mkdir(owner)]);
      const invalid =
        kind === "invalid HEAD" ||
        kind === "empty HEAD" ||
        kind === "invalid reference" ||
        kind === "wrong hash width";
      if (invalid || kind === "missing refs") {
        await mkdir(join(application, "objects"));
      }
      if (invalid || kind === "missing objects") {
        await mkdir(join(application, "refs"));
      }
      const head =
        kind === "invalid HEAD"
          ? "application metadata\n"
          : kind === "empty HEAD"
            ? ""
            : kind === "invalid reference"
              ? "ref: HEAD\n"
              : kind === "wrong hash width"
                ? `${"0".repeat(39)}\n`
                : kind === "detached HEAD"
                  ? `${"0".repeat(40)}\n`
                  : "ref: refs/heads/main\n";
      await Promise.all([
        writeFile(join(checkout, ".gitignore"), "owner/\n"),
        writeFile(join(application, "HEAD"), head),
        writeFile(
          join(application, "config"),
          "[core]\n\tworktree = ../owner\n",
        ),
        writeFile(join(application, "vulnerable.py"), "unsafe = True\n"),
      ]);
      execFileSync("git", ["add", "application", ".gitignore"], {
        cwd: checkout,
      });
      await writeFile(join(owner, ".git"), "gitdir: ../application\n");

      expect(() =>
        execFileSync("git", ["rev-parse", "--absolute-git-dir"], {
          cwd: owner,
          stdio: "ignore",
        }),
      ).toThrow();
      expect(await inventory(checkout)).toContain(
        "./application/vulnerable.py",
      );
      expect(await inventory(checkout, "application")).toContain(
        "application/vulnerable.py",
      );
    },
  );

  test.each(["different casing", "trailing dot", "trailing space"])(
    "does not prove metadata ownership through a %s repository prefix",
    async (kind) => {
      if (Bun.which("rg") === null) return;

      const checkout = await repository();
      const forged =
        kind === "different casing"
          ? join(dirname(checkout), basename(checkout).toUpperCase())
          : `${checkout}${kind === "trailing dot" ? "." : " "}`;
      const equivalent = await realpath(forged).then(
        async (resolved) => resolved === (await realpath(checkout)),
        () => false,
      );
      let environment = process.env;
      if (equivalent) {
        if (kind !== "different casing" || process.platform === "win32") return;
        const instrumentation = join(dirname(checkout), "instrumentation");
        await mkdir(instrumentation);
        await writeFile(
          join(instrumentation, "sitecustomize.py"),
          [
            "from pathlib import Path",
            `forged = Path(${JSON.stringify(forged)})`,
            "original = Path.stat",
            "def case_sensitive(self, *args, **kwargs):",
            "    if self == forged and kwargs.get('follow_symlinks') is False:",
            "        raise FileNotFoundError(self)",
            "    return original(self, *args, **kwargs)",
            "Path.stat = case_sensitive",
          ].join("\n"),
        );
        environment = { ...process.env, PYTHONPATH: instrumentation };
      }

      const application = join(checkout, "application");
      const owner = join(application, "owner");
      await mkdir(owner, { recursive: true });
      await Promise.all([
        writeFile(join(application, ".gitignore"), "owner/\n"),
        writeFile(join(application, "HEAD"), "ref: refs/heads/main\n"),
        writeFile(
          join(application, "config"),
          `[core]\n\tworktree = ${join(forged, "application", "owner")}\n`,
        ),
        writeFile(join(application, "vulnerable.py"), "unsafe = True\n"),
        writeFile(join(checkout, "visible.ts"), "visible\n"),
      ]);
      execFileSync("git", ["add", "application", "visible.ts"], {
        cwd: checkout,
      });
      commit(checkout);
      await writeFile(
        join(owner, ".git"),
        `gitdir: ${join(forged, "application")}\n`,
      );

      expect(await inventory(checkout, ".", environment)).toContain(
        "./application/vulnerable.py",
      );
      expect(await inventory(checkout, "application", environment)).toContain(
        "application/vulnerable.py",
      );
      expect(
        await inventory(checkout, "application/vulnerable.py", environment),
      ).toEqual(["application/vulnerable.py"]);
    },
  );

  test("preserves a nested checkout that is its own Git directory", async () => {
    if (Bun.which("rg") === null) return;

    const checkout = await repository();
    const nested = join(checkout, "nested");
    await mkdir(nested);
    execFileSync("git", ["init", "-q"], { cwd: nested });
    await writeFile(join(nested, "keep.ts"), "tracked\n");
    execFileSync("git", ["add", "keep.ts"], { cwd: nested });
    commit(nested);
    const marker = join(nested, ".git");
    for (const name of await readdir(marker)) {
      await rename(join(marker, name), join(nested, name));
    }
    await rm(marker, { recursive: true });
    await writeFile(marker, "gitdir: .\n");
    execFileSync("git", ["--git-dir", nested, "config", "core.worktree", "."], {
      cwd: nested,
    });

    expect(await inventory(checkout)).toContain("./nested/keep.ts");
    expect(await inventory(checkout, "nested")).toContain("nested/keep.ts");
  });

  test.each(["root", "nested"])(
    "accepts a %s Git directory as its own common directory",
    async (kind) => {
      if (Bun.which("rg") === null) return;

      const checkout = await repository();
      const target = kind === "root" ? checkout : join(checkout, "nested");
      if (kind === "nested") {
        await mkdir(target);
        execFileSync("git", ["init", "-q"], { cwd: target });
      }
      await Promise.all([
        writeFile(join(target, ".git", "commondir"), ".\n"),
        writeFile(join(target, ".gitignore"), "tracked.ts\n"),
        writeFile(join(target, "tracked.ts"), "tracked\n"),
      ]);
      execFileSync("git", ["add", "--force", "tracked.ts"], { cwd: target });

      expect(await inventory(checkout)).toContain(
        kind === "root" ? "./tracked.ts" : "./nested/tracked.ts",
      );
    },
  );

  test("rejects unrelated external Git common directories", async () => {
    if (Bun.which("rg") === null) return;

    const checkout = await repository();
    const external = await repository();
    await writeFile(join(checkout, "visible.ts"), "visible\n");
    await writeFile(
      join(checkout, ".git", "commondir"),
      `${join(external, ".git")}\n`,
    );

    await expect(inventory(checkout)).rejects.toThrow(
      "Git common directory does not own selected worktree",
    );
  });

  test("binds Git discovery to the selected checkout despite external core.worktree", async () => {
    if (Bun.which("rg") === null) return;

    const checkout = await repository();
    const external = join(dirname(checkout), "external-worktree");
    const trace = join(dirname(checkout), "git-trace.log");
    await mkdir(external);
    await writeFile(join(checkout, "visible.ts"), "visible\n");
    execFileSync("git", ["config", "--local", "core.worktree", external], {
      cwd: checkout,
    });

    expect(
      await inventory(checkout, ".", {
        ...process.env,
        GIT_TRACE: trace,
        GIT_TRACE_SETUP: "1",
      }),
    ).toEqual(["./visible.ts"]);
    expect(await readFile(trace, "utf8")).not.toContain(external);
  });

  test
    .skipIf(process.platform === "win32")
    .each(["objects", "objects/info/alternates"])(
    "rejects symbolic Git object metadata at %s",
    async (relative) => {
      if (Bun.which("rg") === null) return;

      const checkout = await repository();
      const external = await repository();
      const metadata = join(checkout, ".git", relative);
      const target =
        relative === "objects"
          ? join(external, ".git", "objects")
          : join(dirname(checkout), "external-alternates");
      if (relative !== "objects") await writeFile(target, "external\n");
      await rm(metadata, { recursive: relative === "objects", force: true });
      await symlink(target, metadata);

      await expect(inventory(checkout)).rejects.toThrow(
        "symbolic Git metadata paths are not supported",
      );
    },
  );

  test("rejects external Git object alternates before invoking Git", async () => {
    if (Bun.which("rg") === null) return;

    const checkout = await repository();
    const external = await repository();
    const trace = join(dirname(checkout), "git-trace.log");
    await writeFile(
      join(checkout, ".git", "objects", "info", "alternates"),
      `${join(external, ".git", "objects")}\n`,
    );

    await expect(
      inventory(checkout, ".", { ...process.env, GIT_TRACE: trace }),
    ).rejects.toThrow("external Git object alternates are not supported");
    await expect(readFile(trace, "utf8")).rejects.toThrow();
  });

  test.each(["pack", "ab"])(
    "rejects symbolic Git object-store %s directories",
    async (name) => {
      if (Bun.which("rg") === null) return;

      const checkout = await repository();
      const external = await repository();
      const internal = join(checkout, ".git", "extra-objects");
      const target = join(external, ".git", "objects", name);
      await mkdir(join(internal, "info"), { recursive: true });
      if (name !== "pack") await mkdir(target);
      await symlink(
        target,
        join(internal, name),
        process.platform === "win32" ? "junction" : "dir",
      );
      await writeFile(
        join(checkout, ".git", "objects", "info", "alternates"),
        `${internal}\n`,
      );

      await expect(inventory(checkout)).rejects.toThrow(
        "symbolic Git metadata paths are not supported",
      );
    },
  );

  test.each(["primary", "alternate"])(
    "rejects symbolic incremental %s Git multi-pack-index directories",
    async (owner) => {
      if (Bun.which("rg") === null) return;

      const checkout = await repository();
      const external = await repository();
      const objects =
        owner === "primary"
          ? join(checkout, ".git", "objects")
          : join(checkout, ".git", "extra-objects");
      if (owner === "alternate") {
        await mkdir(join(objects, "info"), { recursive: true });
        await mkdir(join(objects, "pack"));
        await writeFile(
          join(checkout, ".git", "objects", "info", "alternates"),
          `${objects}\n`,
        );
      }
      const target = join(
        external,
        ".git",
        "objects",
        "pack",
        "multi-pack-index.d",
      );
      await mkdir(target);
      await symlink(
        target,
        join(objects, "pack", "multi-pack-index.d"),
        process.platform === "win32" ? "junction" : "dir",
      );

      await expect(inventory(checkout)).rejects.toThrow(
        "symbolic Git metadata paths are not supported",
      );
    },
  );

  test
    .skipIf(process.platform === "win32")
    .each(["chain", "midx", "bitmap", "rev"])(
    "rejects symbolic incremental Git multi-pack-index %s files",
    async (kind) => {
      if (Bun.which("rg") === null) return;

      const checkout = await repository();
      const directory = join(
        checkout,
        ".git",
        "objects",
        "pack",
        "multi-pack-index.d",
      );
      const target = join(dirname(checkout), "external-index");
      await mkdir(directory);
      await writeFile(target, "external\n");
      const name =
        kind === "chain"
          ? "multi-pack-index-chain"
          : `multi-pack-index-${"a".repeat(40)}.${kind}`;
      await symlink(target, join(directory, name));

      await expect(inventory(checkout)).rejects.toThrow(
        "symbolic Git metadata paths are not supported",
      );
    },
  );

  test("inventories genuine incremental Git multi-pack indexes", async () => {
    if (Bun.which("rg") === null) return;

    const checkout = await repository();
    await writeFile(join(checkout, "visible.ts"), "tracked\n");
    execFileSync("git", ["add", "visible.ts"], { cwd: checkout });
    commit(checkout);
    execFileSync("git", ["repack", "-ad"], { cwd: checkout, stdio: "ignore" });
    try {
      execFileSync("git", ["multi-pack-index", "write", "--incremental"], {
        cwd: checkout,
        stdio: "pipe",
      });
    } catch (error) {
      const stderr = String(
        (error as Error & { stderr?: Buffer }).stderr ?? "",
      );
      if (/unknown|unrecognized/i.test(stderr)) return;
      throw error;
    }
    await mkdir(
      join(
        checkout,
        ".git",
        "objects",
        "pack",
        "multi-pack-index.d",
        "unrelated-dir",
      ),
    );

    expect(await inventory(checkout)).toContain("./visible.ts");
  });

  test.skipIf(process.platform === "win32").each([
    ["primary", "pack"],
    ["primary-uppercase", "pack"],
    ["primary-arbitrary-pack", "pack"],
    ["primary-arbitrary-index", "pack"],
    ["primary-midx", "pack"],
    ["primary-uppercase-midx", "pack"],
    ["primary-uppercase-extension", "pack"],
    ["primary", "ab"],
    ["primary-uppercase", "ab"],
    ["alternate", "pack"],
    ["alternate-uppercase", "pack"],
    ["alternate-arbitrary-pack", "pack"],
    ["alternate-arbitrary-index", "pack"],
    ["alternate-midx", "pack"],
    ["alternate-uppercase-midx", "pack"],
    ["alternate-uppercase-extension", "pack"],
    ["alternate", "ab"],
    ["alternate-uppercase", "ab"],
  ])("rejects symbolic %s Git object files in %s", async (owner, kind) => {
    if (Bun.which("rg") === null) return;

    const checkout = await repository();
    const external = join(dirname(checkout), "external-object");
    await writeFile(external, "external\n");
    const objects = owner.startsWith("primary")
      ? join(checkout, ".git", "objects")
      : join(checkout, ".git", "extra-objects");
    if (owner.startsWith("alternate")) {
      await mkdir(join(objects, "info"), { recursive: true });
      await mkdir(join(objects, "pack"));
      await writeFile(
        join(checkout, ".git", "objects", "info", "alternates"),
        `${objects}\n`,
      );
    }
    const directory = join(objects, kind);
    if (kind !== "pack") await mkdir(directory);
    const hex = owner.endsWith("uppercase") ? "A" : "0";
    const basename = owner.includes("arbitrary")
      ? "arbitrary"
      : `pack-${hex.repeat(40)}`;
    const suffix = owner.endsWith("index")
      ? "idx"
      : owner.endsWith("extension")
        ? "PACK"
        : "pack";
    const member =
      kind !== "pack"
        ? hex.repeat(38)
        : owner.endsWith("midx")
          ? owner.includes("uppercase")
            ? "MULTI-PACK-INDEX"
            : "multi-pack-index"
          : `${basename}.${suffix}`;
    await symlink(external, join(directory, member));
    if (
      (kind !== "pack" && hex === "A") ||
      member === "MULTI-PACK-INDEX" ||
      member.endsWith(".PACK")
    ) {
      const aliases = await realpath(
        join(directory, member.toLowerCase()),
      ).then(
        () => true,
        () => false,
      );
      if (!aliases) {
        await writeFile(join(checkout, "visible.ts"), "visible\n");
        expect(await inventory(checkout)).toContain("./visible.ts");
        return;
      }
    }

    await expect(inventory(checkout)).rejects.toThrow(
      "symbolic Git metadata paths are not supported",
    );
  });

  test.each(["pack", "ab"])(
    "allows unrelated tooling directories inside Git object %s",
    async (kind) => {
      if (Bun.which("rg") === null) return;

      const checkout = await repository();
      const directory = join(checkout, ".git", "objects", kind);
      if (kind !== "pack") await mkdir(directory);
      await mkdir(join(directory, "unrelated-dir"));
      await writeFile(join(checkout, "visible.ts"), "visible\n");

      expect(await inventory(checkout)).toContain("./visible.ts");
    },
  );

  test.skipIf(process.platform === "win32").each(["PACK", "AB"])(
    "ignores unrelated uppercase Git object-store name %s",
    async (name) => {
      if (Bun.which("rg") === null) return;

      const checkout = await repository();
      const external = await repository();
      const objects = join(checkout, ".git", "objects");
      if (name === "AB") await mkdir(join(objects, "ab"));
      try {
        await symlink(join(external, ".git", "objects"), join(objects, name));
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code === "EEXIST") return;
        throw error;
      }
      await writeFile(join(checkout, "visible.ts"), "visible\n");

      expect(await inventory(checkout)).toContain("./visible.ts");
    },
  );

  test.skipIf(process.platform === "win32")(
    "preserves carriage returns in Git object-alternate paths",
    async () => {
      if (Bun.which("rg") === null) return;

      const checkout = await repository();
      const external = await repository();
      const internal = join(checkout, ".git", "safe-objects");
      await mkdir(join(internal, "info"), { recursive: true });
      await mkdir(join(internal, "pack"));
      await symlink(join(external, ".git", "objects"), `${internal}\r`);
      await writeFile(
        join(checkout, ".git", "objects", "info", "alternates"),
        `${internal}\r\n`,
      );

      await expect(inventory(checkout)).rejects.toThrow(
        "symbolic Git metadata paths are not supported",
      );
    },
  );

  test("rejects external transitive Git object alternates before invoking Git", async () => {
    if (Bun.which("rg") === null) return;

    const checkout = await repository();
    const external = await repository();
    const internal = join(checkout, ".git", "extra-objects");
    const trace = join(dirname(checkout), "git-trace.log");
    await mkdir(join(internal, "info"), { recursive: true });
    await mkdir(join(internal, "pack"));
    await writeFile(
      join(checkout, ".git", "objects", "info", "alternates"),
      `${internal}\n`,
    );
    await writeFile(
      join(internal, "info", "alternates"),
      `${join(external, ".git", "objects")}\n`,
    );

    await expect(
      inventory(checkout, ".", { ...process.env, GIT_TRACE: trace }),
    ).rejects.toThrow("external Git object alternates are not supported");
    await expect(readFile(trace, "utf8")).rejects.toThrow();
  });

  test.each(["primary", "transitive"])(
    "rejects symbolic %s Git alternate prefixes before probing ownership",
    async (kind) => {
      const parent = await repository(false);
      const checkout = join(parent, "selected", "nested");
      await mkdir(checkout, { recursive: true });
      execFileSync("git", ["init", "-q"], { cwd: checkout });
      const outside = join(dirname(parent), "outside");
      await mkdir(join(outside, "target"), { recursive: true });
      const hop = join(parent, "hop");
      await symlink(
        outside,
        hop,
        process.platform === "win32" ? "junction" : "dir",
      );
      const separator = process.platform === "win32" ? "\\" : "/";
      const alternate = [
        join(hop, "target"),
        "..",
        "selected",
        "nested",
        ".git",
        "extra-objects",
      ].join(separator);
      const alternates = join(
        checkout,
        ".git",
        "objects",
        "info",
        "alternates",
      );
      if (kind === "primary") {
        await writeFile(alternates, `${alternate}\n`);
      } else {
        const first = join(checkout, ".git", "first-objects");
        await mkdir(join(first, "info"), { recursive: true });
        await mkdir(join(first, "pack"));
        await writeFile(alternates, `${first}\n`);
        await writeFile(join(first, "info", "alternates"), `${alternate}\n`);
      }

      const instrumentation = join(dirname(parent), "instrumentation");
      await mkdir(instrumentation);
      await writeFile(
        join(instrumentation, "sitecustomize.py"),
        [
          "from pathlib import Path",
          `unsafe = Path(${JSON.stringify(join(hop, "target"))})`,
          "original = Path.stat",
          "def guarded(self, *args, **kwargs):",
          "    if self == unsafe:",
          "        raise RuntimeError('probed unvalidated Git alternate prefix')",
          "    return original(self, *args, **kwargs)",
          "Path.stat = guarded",
        ].join("\n"),
      );

      await expect(
        inventory(checkout, ".", {
          ...process.env,
          PYTHONPATH: instrumentation,
        }),
      ).rejects.toThrow("symbolic Git metadata paths are not supported");
    },
  );

  test.skipIf(process.platform === "win32").each(["primary", "transitive"])(
    "rejects symbolic %s Git object-alternate hops before parent traversal",
    async (kind) => {
      if (Bun.which("rg") === null) return;

      const checkout = await repository();
      const outside = join(dirname(checkout), "outside");
      const external = join(outside, "store");
      const decoy = join(checkout, ".git", "store");
      const hop = join(checkout, ".git", "hop");
      await mkdir(join(outside, "hop-target"), { recursive: true });
      for (const objects of [external, decoy]) {
        await mkdir(join(objects, "info"), { recursive: true });
        await mkdir(join(objects, "pack"));
      }
      await symlink(join(outside, "hop-target"), hop);
      const alternate = `${hop}/../store`;
      if (kind === "primary") {
        await writeFile(
          join(checkout, ".git", "objects", "info", "alternates"),
          `${alternate}\n`,
        );
      } else {
        const first = join(checkout, ".git", "first-objects");
        await mkdir(join(first, "info"), { recursive: true });
        await mkdir(join(first, "pack"));
        await writeFile(
          join(checkout, ".git", "objects", "info", "alternates"),
          `${first}\n`,
        );
        await writeFile(join(first, "info", "alternates"), `${alternate}\n`);
      }

      await expect(inventory(checkout)).rejects.toThrow(
        "symbolic Git metadata paths are not supported",
      );
    },
  );

  test.each(["\\x61", "\\400"])(
    "rejects quoted Git object alternates with unsupported escape %s",
    async (escape) => {
      if (Bun.which("rg") === null) return;

      const checkout = await repository();
      const objects = join(checkout, ".git", "extra-objects");
      await writeFile(
        join(checkout, ".git", "objects", "info", "alternates"),
        `"${objects}${escape}"\n`,
      );

      await expect(inventory(checkout)).rejects.toThrow(
        "invalid Git object alternate paths",
      );
    },
  );

  test("rejects differently cased sibling Git object alternates", async () => {
    if (Bun.which("rg") === null) return;

    const checkout = await repository();
    const sibling = join(dirname(checkout), "REPOSITORY");
    try {
      await mkdir(sibling);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "EEXIST") return;
      throw error;
    }
    execFileSync("git", ["init", "-q"], { cwd: sibling });
    await writeFile(
      join(checkout, ".git", "objects", "info", "alternates"),
      `${join(sibling, ".git", "objects")}\n`,
    );

    await expect(inventory(checkout)).rejects.toThrow(
      "external Git object alternates are not supported",
    );
  });

  test("allows repository-owned Git object alternates", async () => {
    if (Bun.which("rg") === null) return;

    const checkout = await repository();
    const objects = join(checkout, ".git", "extra objects");
    await mkdir(join(objects, "info"), { recursive: true });
    await mkdir(join(objects, "pack"));
    await writeFile(
      join(checkout, ".git", "objects", "info", "alternates"),
      `${JSON.stringify(objects).replace("extra objects", "extra\\040objects")}\n`,
    );
    await writeFile(join(checkout, "visible.ts"), "visible\n");

    expect(await inventory(checkout)).toContain("./visible.ts");
  });

  test("excludes repository-owned object stores from scan inventories", async () => {
    if (Bun.which("rg") === null) return;

    const checkout = await repository();
    const objects = join(checkout, "shared-objects");
    await mkdir(join(objects, "info"), { recursive: true });
    await mkdir(join(objects, "pack"));
    await Promise.all([
      writeFile(
        join(checkout, ".git", "objects", "info", "alternates"),
        `${objects}\n`,
      ),
      writeFile(join(objects, "private.ts"), "private\n"),
      writeFile(join(checkout, "visible.ts"), "visible\n"),
    ]);
    execFileSync("git", ["add", "--force", "shared-objects/private.ts"], {
      cwd: checkout,
    });

    expect(await inventory(checkout)).toEqual(["./visible.ts"]);
    for (const scope of ["shared-objects", "shared-objects/private.ts"]) {
      await expect(inventory(checkout, scope)).rejects.toThrow(
        "--scope: Git metadata paths are not supported",
      );
    }
  });

  test.each(["empty", "malformed", "directory", "HEAD"])(
    "does not treat the %s marker inside an object store as a checkout",
    async (kind) => {
      if (Bun.which("rg") === null) return;

      const checkout = await repository();
      const objects = join(checkout, "shared-objects");
      await mkdir(join(objects, "info"), { recursive: true });
      await mkdir(join(objects, "pack"));
      await Promise.all([
        writeFile(
          join(checkout, ".git", "objects", "info", "alternates"),
          `${objects}\n`,
        ),
        writeFile(join(objects, "private.ts"), "private\n"),
        writeFile(join(checkout, "visible.ts"), "visible\n"),
      ]);
      execFileSync("git", ["add", "--force", "shared-objects/private.ts"], {
        cwd: checkout,
      });
      if (kind === "directory" || kind === "HEAD") {
        const marker = join(objects, ".git");
        await mkdir(marker);
        if (kind === "HEAD") {
          await writeFile(join(marker, "HEAD"), "ref: refs/heads/main\n");
        }
      } else {
        await writeFile(
          join(objects, ".git"),
          kind === "empty" ? "" : "not a gitfile\n",
        );
      }

      expect(await inventory(checkout)).toEqual(["./visible.ts"]);
      for (const scope of ["shared-objects", "shared-objects/private.ts"]) {
        await expect(inventory(checkout, scope)).rejects.toThrow(
          "--scope: Git metadata paths are not supported",
        );
      }
    },
  );

  test("preserves source when an object alternate overlaps the repository", async () => {
    if (Bun.which("rg") === null) return;

    const checkout = await repository();
    await Promise.all([
      writeFile(
        join(checkout, ".git", "objects", "info", "alternates"),
        "../..\n",
      ),
      writeFile(join(checkout, "visible.ts"), "visible\n"),
    ]);

    expect(await inventory(checkout)).toEqual(["./visible.ts"]);
  });

  test("preserves a nested checkout that doubles as an object store", async () => {
    if (Bun.which("rg") === null) return;

    const checkout = await repository();
    const nested = join(checkout, "nested");
    await mkdir(nested);
    execFileSync("git", ["init", "-q"], { cwd: nested });
    await mkdir(join(nested, "info"));
    await mkdir(join(nested, "pack"));
    await Promise.all([
      writeFile(
        join(checkout, ".git", "objects", "info", "alternates"),
        `${nested}\n`,
      ),
      writeFile(join(nested, "visible.ts"), "visible\n"),
    ]);
    execFileSync("git", ["add", "visible.ts"], { cwd: nested });

    expect(await inventory(checkout)).toContain("./nested/visible.ts");
    expect(await inventory(checkout, "nested")).toContain("nested/visible.ts");
  });

  test.each(["repository", "nested"])(
    "excludes actual Git objects from an overlapping %s checkout",
    async (kind) => {
      if (Bun.which("rg") === null) return;

      const checkout = await repository();
      const objects =
        kind === "repository" ? checkout : join(checkout, "nested");
      if (kind === "nested") {
        await mkdir(objects);
        execFileSync("git", ["init", "-q"], { cwd: objects });
      }
      await Promise.all([
        mkdir(join(objects, "info")),
        mkdir(join(objects, "pack", "multi-pack-index.d"), { recursive: true }),
        mkdir(join(objects, "ab")),
      ]);
      const artifacts = [
        "pack/private.pack",
        "pack/private.idx",
        "pack/multi-pack-index",
        "pack/multi-pack-index.d/multi-pack-index-chain",
        `ab/${"0".repeat(38)}`,
        `ab/${"1".repeat(62)}`,
      ];
      if (kind === "nested") {
        artifacts.push("info/alternates");
      }
      await Promise.all([
        writeFile(
          join(checkout, ".git", "objects", "info", "alternates"),
          `${objects}\n`,
        ),
        ...[
          "visible.ts",
          "info/source.ts",
          "pack/source.ts",
          "ab/source.ts",
        ].map((relative) => writeFile(join(objects, relative), "source\n")),
        ...artifacts.map((relative) =>
          writeFile(
            join(objects, relative),
            relative === "info/alternates"
              ? `${join(objects, ".git", "objects")}\n`
              : "private\n",
          ),
        ),
      ]);
      await hardlink(join(objects, artifacts[0]!), join(objects, "alias.ts"));
      artifacts.push("alias.ts");

      const prefix = kind === "repository" ? "./" : "./nested/";
      const rows = await inventory(checkout);
      for (const source of [
        "visible.ts",
        "info/source.ts",
        "pack/source.ts",
        "ab/source.ts",
      ]) {
        expect(rows).toContain(`${prefix}${source}`);
      }
      for (const artifact of artifacts) {
        expect(rows).not.toContain(`${prefix}${artifact}`);
        const scope = kind === "repository" ? artifact : `nested/${artifact}`;
        await expect(inventory(checkout, scope)).rejects.toThrow(
          "--scope: Git metadata paths are not supported",
        );
      }
      if (kind === "nested") {
        const scoped = await inventory(checkout, "nested");
        for (const artifact of artifacts) {
          expect(scoped).not.toContain(`nested/${artifact}`);
        }
      }
    },
  );

  test.each([".gitignore", ".ignore", ".rgignore"])(
    "does not inspect object-store checkouts hidden by %s",
    async (ignore) => {
      if (Bun.which("rg") === null) return;

      const checkout = await repository();
      const nested = join(checkout, "nested");
      await mkdir(nested);
      execFileSync("git", ["init", "-q"], { cwd: nested });
      await Promise.all([
        mkdir(join(nested, "info")),
        mkdir(join(nested, "pack")),
      ]);
      const external = join(dirname(checkout), "external.config");
      await writeFile(external, "[core]\n\tignoreCase = true\n");
      execFileSync("git", ["config", "--local", "include.path", external], {
        cwd: nested,
      });
      await Promise.all([
        writeFile(
          join(checkout, ".git", "objects", "info", "alternates"),
          `${nested}\n`,
        ),
        writeFile(join(checkout, ignore), "nested/\n"),
        writeFile(join(checkout, "visible.ts"), "visible\n"),
      ]);

      expect(await inventory(checkout)).toContain("./visible.ts");
    },
  );

  test("preserves ignored tracked Git checkouts that double as object stores", async () => {
    if (Bun.which("rg") === null) return;

    const checkout = await repository();
    const nested = join(checkout, "nested");
    await mkdir(nested);
    execFileSync("git", ["init", "-q"], { cwd: nested });
    await Promise.all([
      mkdir(join(nested, "info")),
      mkdir(join(nested, "pack")),
      writeFile(join(nested, "private.ts"), "private\n"),
      writeFile(join(nested, "visible.ts"), "visible\n"),
    ]);
    execFileSync("git", ["add", "private.ts", "visible.ts"], { cwd: nested });
    commit(nested);
    await Promise.all([
      writeFile(
        join(checkout, ".git", "objects", "info", "alternates"),
        `${nested}\n`,
      ),
      writeFile(join(checkout, ".gitignore"), "nested/\nnested/private.ts\n"),
    ]);
    execFileSync("git", ["add", "--force", "nested"], {
      cwd: checkout,
      stdio: "ignore",
    });

    expect(await inventory(checkout)).toContain("./nested/visible.ts");
    expect(await inventory(checkout)).not.toContain("./nested/private.ts");
    expect(await inventory(checkout, "nested")).toContain("nested/visible.ts");
    expect(await inventory(checkout, "nested")).not.toContain(
      "nested/private.ts",
    );
  });

  test.each(["quoted", "unquoted"])(
    "allows %s CRLF-terminated repository-owned Git object alternates",
    async (format) => {
      if (Bun.which("rg") === null) return;

      const checkout = await repository();
      const objects = join(checkout, ".git", "extra objects");
      await mkdir(join(objects, "info"), { recursive: true });
      await mkdir(join(objects, "pack"));
      await writeFile(
        join(checkout, ".git", "objects", "info", "alternates"),
        `${format === "quoted" ? JSON.stringify(objects) : objects}\r\n`,
      );
      await writeFile(join(checkout, "visible.ts"), "visible\n");

      expect(await inventory(checkout)).toContain("./visible.ts");
    },
  );

  test("allows safe parent traversal to repository-owned Git object alternates", async () => {
    if (Bun.which("rg") === null) return;

    const checkout = await repository();
    const objects = join(checkout, ".git", "extra-objects");
    await mkdir(join(objects, "info"), { recursive: true });
    await mkdir(join(objects, "pack"));
    await writeFile(
      join(checkout, ".git", "objects", "info", "alternates"),
      "../extra-objects\n",
    );
    await writeFile(join(checkout, "visible.ts"), "visible\n");

    expect(await inventory(checkout)).toContain("./visible.ts");
  });

  test.each(["case-alias", "short-alias"])(
    "allows %s repository-owned Git object alternate paths",
    async (kind) => {
      if (Bun.which("rg") === null) return;

      const checkout = await repository();
      const objects = join(checkout, ".git", "extra-objects");
      await mkdir(join(objects, "info"), { recursive: true });
      await mkdir(join(objects, "pack"));
      const alias =
        kind === "case-alias"
          ? objects.toUpperCase()
          : windowsShortPath(objects);
      if (alias === null) return;
      const equivalent = await realpath(alias).then(
        async (resolved) => resolved === (await realpath(objects)),
        () => false,
      );
      if (!equivalent) return;
      await writeFile(
        join(checkout, ".git", "objects", "info", "alternates"),
        `${alias}\n`,
      );
      await writeFile(join(checkout, "visible.ts"), "visible\n");

      expect(await inventory(checkout)).toContain("./visible.ts");
    },
  );

  test("allows repository-owned transitive Git object alternates", async () => {
    if (Bun.which("rg") === null) return;

    const checkout = await repository();
    const first = join(checkout, ".git", "first-objects");
    const second = join(checkout, ".git", "second-objects");
    for (const objects of [first, second]) {
      await mkdir(join(objects, "info"), { recursive: true });
      await mkdir(join(objects, "pack"));
    }
    await writeFile(
      join(checkout, ".git", "objects", "info", "alternates"),
      `${first}\n`,
    );
    await writeFile(
      join(first, "info", "alternates"),
      `${JSON.stringify(second)}\n`,
    );
    await writeFile(join(second, "info", "alternates"), `${first}\n`);
    await writeFile(join(checkout, "visible.ts"), "visible\n");

    expect(await inventory(checkout)).toContain("./visible.ts");
  });

  test.skipIf(process.platform === "win32")(
    "rejects escaped Git index entries before probing sibling metadata",
    async () => {
      const git = Bun.which("git");
      if (Bun.which("rg") === null || git === null) return;

      const checkout = await repository();
      const outside = join(dirname(checkout), "outside");
      const wrappers = join(dirname(checkout), "bin");
      await mkdir(outside);
      await mkdir(wrappers);
      execFileSync("git", ["init", "-q"], { cwd: outside });
      await writeFile(join(checkout, "source.ts"), "visible\n");
      const wrapper = join(wrappers, "git");
      await writeFile(
        wrapper,
        `#!/bin/sh\ncase " $* " in\n  *" ls-files --sparse --cached "*) printf '../outside\\000' ;;\n  *) exec ${JSON.stringify(git)} "$@" ;;\nesac\n`,
      );
      await chmod(wrapper, 0o755);

      await expect(
        inventory(checkout, ".", {
          ...process.env,
          PATH: `${wrappers}:${process.env["PATH"] ?? ""}`,
        }),
      ).rejects.toThrow("out-of-scope Git inventory paths are not supported");
    },
  );

  test.skipIf(process.platform === "win32")(
    "disables lazy Git object fetching and replacement during inventory",
    async () => {
      const git = Bun.which("git");
      if (Bun.which("rg") === null || git === null) return;

      const checkout = await repository();
      const wrappers = join(dirname(checkout), "bin");
      const trace = join(dirname(checkout), "lazy-fetch.log");
      await mkdir(wrappers);
      await writeFile(join(checkout, "visible.ts"), "visible\n");
      const wrapper = join(wrappers, "git");
      await writeFile(
        wrapper,
        `#!/bin/sh\nprintf '%s:%s\\n' "$GIT_NO_LAZY_FETCH" "$GIT_NO_REPLACE_OBJECTS" >> ${JSON.stringify(trace)}\nexec ${JSON.stringify(git)} "$@"\n`,
      );
      await chmod(wrapper, 0o755);

      expect(
        await inventory(checkout, ".", {
          ...process.env,
          GIT_NO_LAZY_FETCH: "0",
          GIT_NO_REPLACE_OBJECTS: "0",
          PATH: `${wrappers}:${process.env["PATH"] ?? ""}`,
        }),
      ).toContain("./visible.ts");
      expect((await readFile(trace, "utf8")).trim().split("\n")).toSatisfy(
        (values: string[]) =>
          values.length > 0 && values.every((value) => value === "1:1"),
      );
    },
  );

  test.each(["selected", "nested"])(
    "rejects symbolic ancestors in %s Git-listed paths before reading external metadata",
    async (kind) => {
      if (Bun.which("rg") === null) return;

      const checkout = await repository();
      const owner = kind === "selected" ? checkout : join(checkout, "nested");
      if (kind === "nested") {
        await mkdir(owner);
        execFileSync("git", ["init", "-q"], { cwd: owner });
      }
      const link = join(owner, "link");
      await mkdir(link);
      await writeFile(join(link, "nested"), "tracked\n");
      execFileSync("git", ["add", "link/nested"], { cwd: owner });

      const external = await repository();
      const nested = join(external, "nested");
      await mkdir(nested);
      execFileSync("git", ["init", "-q"], { cwd: nested });
      await writeFile(
        join(nested, ".git", "config"),
        "[include]\n\tpath = outside\n",
      );
      await rm(link, { recursive: true });
      await symlink(
        external,
        link,
        process.platform === "win32" ? "junction" : "dir",
      );

      await expect(inventory(checkout)).rejects.toThrow(
        "symbolic Git inventory paths are not supported",
      );
    },
  );

  test.skipIf(process.platform !== "win32")(
    "rejects drive-relative Git index entries before probing another drive",
    async () => {
      if (Bun.which("rg") === null) return;

      const checkout = await repository();
      const original = "D-checkout";
      await writeFile(join(checkout, original), "tracked\n");
      execFileSync("git", ["add", original], { cwd: checkout });
      const indexPath = join(checkout, ".git", "index");
      const index = await readFile(indexPath);
      const offset = index.indexOf(Buffer.from(`${original}\0`));
      if (offset === -1)
        throw new Error("Expected the staged Git index entry.");
      index.write("D:checkout", offset, "utf8");
      createHash("sha1")
        .update(index.subarray(0, index.length - 20))
        .digest()
        .copy(index, index.length - 20);
      await writeFile(indexPath, index);

      await expect(inventory(checkout)).rejects.toThrow(
        "out-of-scope Git inventory paths are not supported",
      );
    },
  );

  test.each([
    "shared-index",
    "shared-index-v4",
    "shared-index-sha256",
    "shared-index-worktree-sha256",
    "shared-index-sha256-worktree-sha1",
    "multi-pack-index",
    "pack-index-suffix",
    "incremental-index-directory",
    "incremental-index-chain",
    "incremental-index-bitmap",
    ...(process.platform === "win32"
      ? []
      : [
          "object-store-trailing-dot",
          "object-store-trailing-space",
          "object-prefix-trailing-dot",
          "pack-index-trailing-dot",
          "pack-index-trailing-space",
          "multi-pack-index-trailing-dot",
          "incremental-index-directory-trailing-space",
          "incremental-index-chain-trailing-dot",
          "incremental-index-bitmap-trailing-space",
        ]),
  ])("rejects Windows-compatible %s metadata aliases", async (kind) => {
    const sha256 = kind.startsWith("shared-index-sha256");
    const checkout = await repository(!sha256);
    if (sha256) {
      execFileSync("git", ["init", "-q", "--object-format=sha256"], {
        cwd: checkout,
      });
    }
    const gitdir = join(checkout, ".git");
    let directory = join(gitdir, "objects", "pack");
    let canonical = "multi-pack-index";

    if (kind.startsWith("shared-index")) {
      await writeFile(join(checkout, "tracked.ts"), "tracked\n");
      execFileSync("git", ["add", "tracked.ts"], { cwd: checkout });
      if (kind === "shared-index-v4") {
        execFileSync("git", ["update-index", "--index-version=4"], {
          cwd: checkout,
        });
      }
      execFileSync("git", ["update-index", "--split-index"], {
        cwd: checkout,
      });
      if (kind.includes("-worktree-")) {
        execFileSync("git", ["config", "extensions.worktreeConfig", "true"], {
          cwd: checkout,
        });
        await writeFile(
          join(gitdir, "config.worktree"),
          `[extensions]\n\tobjectFormat = ${sha256 ? "sha1" : "sha256"}\n`,
        );
      }
      const shared = (await readdir(gitdir)).find((name) =>
        name.startsWith("sharedindex."),
      );
      if (shared === undefined) throw new Error("Expected a split Git index.");
      directory = gitdir;
      canonical = shared;
      await rm(join(directory, canonical));
    } else if (kind.startsWith("object-store")) {
      directory = join(gitdir, "objects");
      canonical = "pack";
      await rm(join(directory, canonical), { recursive: true });
    } else if (kind.startsWith("object-prefix")) {
      directory = join(gitdir, "objects");
      canonical = "aa";
    } else if (kind.startsWith("pack-index")) {
      canonical = `pack-${"a".repeat(40)}.idx`;
    } else if (kind.startsWith("incremental-index-directory")) {
      canonical = "multi-pack-index.d";
    } else if (kind.startsWith("incremental-index-")) {
      directory = join(directory, "multi-pack-index.d");
      await mkdir(directory);
      canonical = kind.startsWith("incremental-index-chain")
        ? "multi-pack-index-chain"
        : `multi-pack-index-${"a".repeat(40)}.bitmap`;
    }

    const alias = kind.endsWith("-trailing-dot")
      ? `${canonical}.`
      : kind.endsWith("-trailing-space")
        ? `${canonical} `
        : canonical.replace("i", "\u0131");
    const external = join(dirname(checkout), "external-metadata");
    await mkdir(external);
    await symlink(
      external,
      join(directory, alias),
      process.platform === "win32" ? "junction" : "dir",
    );

    const instrumentation = join(dirname(checkout), "instrumentation");
    await mkdir(instrumentation);
    await writeFile(
      join(instrumentation, "sitecustomize.py"),
      [
        "from pathlib import Path",
        `canonical = Path(${JSON.stringify(join(directory, canonical))})`,
        `alias = Path(${JSON.stringify(join(directory, alias))})`,
        "original = Path.stat",
        "def guarded(self, *args, **kwargs):",
        "    if self == canonical and kwargs.get('follow_symlinks') is False:",
        "        return original(alias, *args, **kwargs)",
        "    return original(self, *args, **kwargs)",
        "Path.stat = guarded",
      ].join("\n"),
    );

    await expect(
      inventory(checkout, ".", {
        ...process.env,
        PYTHONPATH: instrumentation,
      }),
    ).rejects.toThrow("symbolic Git metadata paths are not supported");
  });

  test.each([
    ["missing", "symbolic"],
    ["normal", "symbolic"],
    ["normal", "fifo"],
    ["normal", "directory"],
    ["split", "symbolic"],
    ["split-v4", "symbolic"],
    ["split-sha256", "symbolic"],
  ])("ignores stale %s split-index %s metadata", async (mode, kind) => {
    if (
      Bun.which("rg") === null ||
      process.platform === "win32" ||
      (kind === "fifo" && Bun.which("mkfifo") === null)
    ) {
      return;
    }

    const sha256 = mode === "split-sha256";
    const checkout = await repository(!sha256);
    if (sha256) {
      execFileSync("git", ["init", "-q", "--object-format=sha256"], {
        cwd: checkout,
      });
    }
    await writeFile(join(checkout, "tracked.ts"), "tracked\n");
    if (mode !== "missing") {
      execFileSync("git", ["add", "tracked.ts"], { cwd: checkout });
    }
    if (mode.startsWith("split")) {
      if (mode === "split-v4") {
        execFileSync("git", ["update-index", "--index-version=4"], {
          cwd: checkout,
        });
      }
      execFileSync("git", ["update-index", "--split-index"], {
        cwd: checkout,
      });
    }

    const stale = join(
      checkout,
      ".git",
      `sharedindex.${"f".repeat(sha256 ? 64 : 40)}`,
    );
    if (kind === "directory") {
      await mkdir(stale);
    } else if (kind === "fifo") {
      execFileSync("mkfifo", [stale]);
    } else {
      const external = join(dirname(checkout), "unused-shared-index");
      await writeFile(external, "inactive\n");
      await symlink(external, stale);
    }

    expect(await inventory(checkout)).toContain("./tracked.ts");
  });

  test
    .skipIf(process.platform === "win32")
    .each(["lowercase", "uppercase", "duplicate-link"])(
    "rejects %s split-index backing files that leave the checkout",
    async (casing) => {
      if (Bun.which("rg") === null) return;

      const checkout = await repository();
      await writeFile(join(checkout, "tracked.ts"), "tracked\n");
      execFileSync("git", ["add", "tracked.ts"], { cwd: checkout });
      execFileSync("git", ["update-index", "--split-index"], {
        cwd: checkout,
      });
      const gitdir = join(checkout, ".git");
      const shared = (await readdir(gitdir)).find((name) =>
        name.startsWith("sharedindex."),
      );
      if (shared === undefined) throw new Error("Expected a split Git index.");
      await mkdir(join(gitdir, "sharedindex.notes"));

      expect(await inventory(checkout)).toContain("./tracked.ts");
      const original = join(gitdir, shared);
      const external = join(dirname(checkout), shared);
      await writeFile(external, await readFile(original));
      await rm(original);
      const replacement =
        casing === "uppercase" ? join(gitdir, shared.toUpperCase()) : original;
      await symlink(external, replacement);
      if (casing === "duplicate-link") {
        const safe = Buffer.alloc(20, 0xff);
        await writeFile(
          join(gitdir, `sharedindex.${safe.toString("hex")}`),
          "safe decoy\n",
        );
        const indexPath = join(gitdir, "index");
        const index = await readFile(indexPath);
        const backing = Buffer.from(shared.slice("sharedindex.".length), "hex");
        const offset = index.indexOf(backing) - 8;
        if (
          offset < 0 ||
          index.subarray(offset, offset + 4).toString() !== "link"
        ) {
          throw new Error("Expected the active split-index link extension.");
        }
        const extension = Buffer.concat([
          Buffer.from("link"),
          Buffer.from([0, 0, 0, safe.length]),
          safe,
        ]);
        const body = Buffer.concat([
          index.subarray(0, offset),
          extension,
          index.subarray(offset, index.length - safe.length),
        ]);
        await writeFile(
          indexPath,
          Buffer.concat([body, createHash("sha1").update(body).digest()]),
        );
      }
      if (
        casing === "uppercase" &&
        !(await realpath(original).then(
          () => true,
          () => false,
        ))
      ) {
        return;
      }

      await expect(inventory(checkout)).rejects.toThrow(
        "symbolic Git metadata paths are not supported",
      );
    },
  );

  test.each([
    ["include", "without BOM"],
    ['includeIf "gitdir:**"', "without BOM"],
    ["include", "with BOM"],
    ["include", "with leading carriage return"],
    ["include", "with carriage return after header"],
    ["include", "with same-line path"],
    ["include", "with same-line carriage path"],
    ["include", "with chained section headers"],
    ['includeIf "gitdir:**"', "with same-line path"],
    ['includeIf "gitdir:**"', "with chained section headers"],
    ['includeIf "gitdir:**"', "with carriage return before condition"],
    [
      'includeIf "gitdir:**"',
      "with carriage return after condition whitespace",
    ],
    [
      'includeIf "gitdir:**"',
      "with carriage return replacing condition whitespace",
    ],
  ])(
    "rejects repository-directed %s config %s before invoking Git",
    async (section, bom) => {
      if (Bun.which("rg") === null) return;

      const checkout = await repository();
      const external = join(dirname(checkout), "external.config");
      await writeFile(external, "[core]\n\tignoreCase = true\n");
      const config = join(checkout, ".git", "config");
      const whitespace =
        bom === "with carriage return before condition"
          ? "\r "
          : bom === "with carriage return after condition whitespace"
            ? " \r"
            : bom === "with carriage return replacing condition whitespace"
              ? "\r"
              : " ";
      const configuredSection = section.replace(" ", whitespace);
      const headers =
        bom === "with chained section headers"
          ? `[0][-][.legacy][ "quoted"][feature][unused.value][${configuredSection}]`
          : `[${configuredSection}]`;
      const assignment =
        bom === "with same-line carriage path"
          ? "\rpath"
          : bom === "with same-line path" ||
              bom === "with chained section headers"
            ? "path"
            : "\n\tpath";
      await writeFile(
        config,
        `${bom === "with BOM" ? "\ufeff" : ""}${bom === "with leading carriage return" ? "\r" : ""}${headers}${bom === "with carriage return after header" ? "\r# included" : ""}${assignment} = ${external}\n${await readFile(config, "utf8")}`,
      );

      await expect(inventory(checkout)).rejects.toThrow(
        "Git config includes are not supported",
      );
    },
  );

  test.each([
    ["include", "foo = bar"],
    ["include", "# path = ignored"],
    ['includeIf "gitdir:**"', "foo = bar"],
    ['include "inactive"', "path = ignored"],
  ])("allows inert [%s] Git config sections", async (section, assignment) => {
    if (Bun.which("rg") === null) return;

    const checkout = await repository();
    const config = join(checkout, ".git", "config");
    await writeFile(
      config,
      `[${section}]\n\t${assignment}\n${await readFile(config, "utf8")}`,
    );
    await writeFile(join(checkout, "visible.ts"), "visible\n");

    expect(await inventory(checkout)).toContain("./visible.ts");
  });

  test.each([
    ["unset", "directory", false],
    ["false", "symbolic", false],
    ["false", "fifo", false],
    ["00", "directory", false],
    ["+0", "symbolic", false],
    ["0k", "fifo", false],
    ["0x0", "directory", false],
    ["+0x00g", "directory", false],
    ["1k", "directory", true],
    ["true", "directory", true],
    ["worktree-false", "directory", false],
    ["worktree-true", "directory", true],
  ])(
    "inspects %s sparse-checkout %s metadata only when active",
    async (setting, kind, active) => {
      if (
        Bun.which("rg") === null ||
        (kind !== "directory" && process.platform === "win32") ||
        (kind === "fifo" && Bun.which("mkfifo") === null)
      ) {
        return;
      }

      const checkout = await repository();
      if (setting.startsWith("worktree-")) {
        execFileSync(
          "git",
          ["config", "core.sparseCheckout", active ? "false" : "true"],
          { cwd: checkout },
        );
        execFileSync("git", ["config", "extensions.worktreeConfig", "true"], {
          cwd: checkout,
        });
        execFileSync(
          "git",
          ["config", "--worktree", "core.sparseCheckout", String(active)],
          { cwd: checkout },
        );
      } else if (setting !== "unset") {
        execFileSync("git", ["config", "core.sparseCheckout", setting], {
          cwd: checkout,
        });
      }

      const metadata = join(checkout, ".git", "info", "sparse-checkout");
      if (kind === "symbolic") {
        const external = join(dirname(checkout), "unused-sparse-checkout");
        await writeFile(external, "external\n");
        await symlink(external, metadata);
      } else if (kind === "fifo") {
        execFileSync("mkfifo", [metadata]);
      } else {
        await mkdir(metadata);
      }
      await writeFile(join(checkout, "visible.ts"), "visible\n");

      if (active) {
        await expect(inventory(checkout)).rejects.toThrow(
          "non-regular Git metadata files are not supported",
        );
      } else {
        expect(await inventory(checkout)).toContain("./visible.ts");
      }
    },
  );

  test
    .skipIf(process.platform === "win32")
    .each(["config", "info/sparse-checkout"])(
    "rejects non-regular Git %s metadata before invoking Git",
    async (relative) => {
      if (Bun.which("rg") === null || Bun.which("mkfifo") === null) return;

      const checkout = await repository();
      if (relative === "info/sparse-checkout") {
        execFileSync("git", ["config", "core.sparseCheckout", "true"], {
          cwd: checkout,
        });
      }
      const metadata = join(checkout, ".git", relative);
      await rm(metadata, { force: true });
      execFileSync("mkfifo", [metadata]);

      await expect(inventory(checkout)).rejects.toThrow(
        "non-regular Git metadata files are not supported",
      );
    },
  );

  test("requires the Git info metadata path to be a directory", async () => {
    if (Bun.which("rg") === null) return;

    const checkout = await repository();
    const info = join(checkout, ".git", "info");
    await rm(info, { recursive: true });
    await writeFile(info, "not a directory\n");

    await expect(inventory(checkout)).rejects.toThrow(
      "non-directory Git metadata paths are not supported",
    );
  });

  test
    .skipIf(process.platform === "win32")
    .each([
      "index",
      "config",
      "info/exclude",
      "info/sparse-checkout",
      "packed-refs",
      "refs",
      "refs/heads",
    ])("rejects a symbolic Git metadata %s", async (relative) => {
    if (Bun.which("rg") === null) return;

    const checkout = await repository();
    if (relative === "info/sparse-checkout") {
      execFileSync("git", ["config", "core.sparseCheckout", "true"], {
        cwd: checkout,
      });
    }
    const external = await repository();
    await writeFile(join(external, "source.ts"), "tracked\n");
    execFileSync("git", ["add", "source.ts"], { cwd: external });
    const metadata = join(checkout, ".git", relative);
    const directory = relative === "refs" || relative.startsWith("refs/");
    const target = join(external, ".git", relative);
    if (relative === "info/sparse-checkout" || relative === "packed-refs") {
      await writeFile(target, "external\n");
    }
    await rm(metadata, { recursive: directory, force: true });
    await symlink(target, metadata);
    await writeFile(join(checkout, "visible.ts"), "visible\n");

    await expect(inventory(checkout)).rejects.toThrow(
      "symbolic Git metadata paths are not supported",
    );
  });

  test.each(["file", "symbolic", "fifo", "reference"])(
    "ignores inactive Git replacement %s metadata",
    async (kind) => {
      if (
        Bun.which("rg") === null ||
        (kind !== "file" && process.platform === "win32") ||
        (kind === "fifo" && Bun.which("mkfifo") === null)
      ) {
        return;
      }

      const checkout = await repository();
      const replacement = join(checkout, ".git", "refs", "replace");
      const external = join(dirname(checkout), "external-replacement");
      await writeFile(external, `${"0".repeat(40)}\n`);
      if (kind === "file") {
        await writeFile(replacement, "inactive\n");
      } else if (kind === "symbolic") {
        await symlink(external, replacement);
      } else if (kind === "fifo") {
        execFileSync("mkfifo", [replacement]);
      } else {
        await mkdir(replacement);
        await symlink(external, join(replacement, "a".repeat(40)));
      }
      await writeFile(join(checkout, "visible.ts"), "visible\n");

      expect(await inventory(checkout)).toContain("./visible.ts");
    },
  );

  test.skipIf(process.platform === "win32")(
    "ignores case-aliased inactive Git replacement metadata",
    async () => {
      if (Bun.which("rg") === null) return;

      const checkout = await repository();
      const replacement = join(checkout, ".git", "refs", "REPLACE");
      const canonical = join(checkout, ".git", "refs", "replace");
      const external = join(dirname(checkout), "external-replacement");
      await writeFile(external, `${"0".repeat(40)}\n`);
      await symlink(external, replacement);
      const equivalent = await realpath(canonical).then(
        async (resolved) => resolved === (await realpath(replacement)),
        () => false,
      );
      if (!equivalent) return;
      await writeFile(join(checkout, "visible.ts"), "visible\n");

      expect(await inventory(checkout)).toContain("./visible.ts");
    },
  );

  test("inventories linked worktrees with regular Git metadata", async () => {
    if (Bun.which("rg") === null) return;

    const checkout = await repository();
    await writeFile(join(checkout, "visible.ts"), "visible\n");
    execFileSync("git", ["add", "visible.ts"], { cwd: checkout });
    commit(checkout);
    const linked = join(dirname(checkout), "linked-worktree");
    execFileSync("git", ["worktree", "add", "--detach", linked, "HEAD"], {
      cwd: checkout,
      stdio: "ignore",
    });

    expect(await inventory(linked)).toContain("./visible.ts");

    const gitdir = (await readFile(join(linked, ".git"), "utf8"))
      .replace(/^gitdir: /, "")
      .trim();
    await writeFile(join(gitdir, "objects"), "inactive worktree metadata\n");
    await mkdir(join(gitdir, "packed-refs"));
    await mkdir(join(gitdir, "refs"), { recursive: true });
    await writeFile(
      join(gitdir, "refs", "heads"),
      "inactive worktree references\n",
    );
    await writeFile(join(gitdir, "config"), "[include]\npath = inactive\n");
    await mkdir(join(gitdir, "info", "exclude"), { recursive: true });
    expect(await inventory(linked)).toContain("./visible.ts");

    const shortBackpointer = windowsShortPath(join(linked, ".git"));
    if (shortBackpointer !== null) {
      await writeFile(join(gitdir, "gitdir"), `${shortBackpointer}\n`);
      expect(await inventory(linked)).toContain("./visible.ts");
    }

    const alternateBackpointer = join(
      dirname(linked),
      "LINKED-WORKTREE",
      ".git",
    );
    const equivalentBackpointer = await realpath(alternateBackpointer).then(
      async (resolved) => resolved === (await realpath(join(linked, ".git"))),
      () => false,
    );
    if (equivalentBackpointer) {
      await writeFile(join(gitdir, "gitdir"), `${alternateBackpointer}\n`);
      expect(await inventory(linked)).toContain("./visible.ts");
    }

    const aliased = join(dirname(checkout), "REPOSITORY", ".git");
    const equivalent = await realpath(aliased).then(
      async (resolved) => resolved === (await realpath(join(checkout, ".git"))),
      () => false,
    );
    if (!equivalent) return;
    await writeFile(join(gitdir, "commondir"), `${aliased}\n`);

    expect(await inventory(linked)).toContain("./visible.ts");
  });

  test.each(["owned", "external"])(
    "honors %s worktree-specific ownership for linked Git worktrees",
    async (ownership) => {
      if (Bun.which("rg") === null) return;

      const checkout = await repository();
      await writeFile(join(checkout, "visible.ts"), "tracked\n");
      execFileSync("git", ["add", "visible.ts"], { cwd: checkout });
      commit(checkout);
      const linked = join(dirname(checkout), "linked-worktree");
      const external = join(dirname(checkout), "external-worktree");
      await mkdir(external);
      execFileSync("git", ["worktree", "add", "--detach", linked, "HEAD"], {
        cwd: checkout,
        stdio: "ignore",
      });
      execFileSync("git", ["config", "extensions.worktreeConfig", "true"], {
        cwd: checkout,
      });
      const metadata = execFileSync(
        "git",
        ["rev-parse", "--absolute-git-dir"],
        {
          cwd: linked,
          encoding: "utf8",
        },
      ).trim();
      const effective = ownership === "owned" ? linked : external;
      await writeFile(
        join(metadata, "config.worktree"),
        `[Core]\n\tworktree = ${effective}\n`,
      );

      if (ownership === "external") {
        await expect(inventory(linked)).rejects.toThrow(
          "Git metadata directory does not own selected worktree",
        );
      } else {
        expect(await inventory(linked)).toContain("./visible.ts");
      }
    },
  );

  test("rejects worktree backpointers hard-linked through equivalent sibling names", async () => {
    if (Bun.which("rg") === null) return;

    const checkout = await repository();
    const source = await repository();
    const hidden = join(checkout, "ß");
    const visible = join(checkout, "ss");
    await writeFile(join(source, "secret.ts"), "tracked\n");
    execFileSync("git", ["add", "secret.ts"], { cwd: source });
    commit(source);
    execFileSync("git", ["worktree", "add", "--detach", hidden, "HEAD"], {
      cwd: source,
      stdio: "ignore",
    });
    try {
      await mkdir(visible);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "EEXIST") return;
      throw error;
    }
    await writeFile(join(checkout, ".ignore"), "ß/\n");
    await writeFile(join(visible, ".ignore"), "secret.ts\n");
    await writeFile(join(visible, "secret.ts"), "private\n");
    await hardlink(join(hidden, ".git"), join(visible, ".git"));

    await expect(inventory(checkout)).rejects.toThrow(
      "Git metadata directory does not own selected worktree",
    );
  });

  test("inventories genuine Git submodules with internal metadata", async () => {
    if (Bun.which("rg") === null) return;

    const checkout = await repository();
    const source = await repository();
    await writeFile(join(source, "visible.ts"), "tracked\n");
    execFileSync("git", ["add", "visible.ts"], { cwd: source });
    commit(source);
    execFileSync(
      "git",
      [
        "-c",
        "protocol.file.allow=always",
        "submodule",
        "add",
        "-q",
        source,
        "nested",
      ],
      { cwd: checkout },
    );
    const gitdir = execFileSync("git", ["rev-parse", "--absolute-git-dir"], {
      cwd: join(checkout, "nested"),
      encoding: "utf8",
    }).trim();
    const config = join(gitdir, "config");
    const configured = (await readFile(config, "utf8")).replace(
      /^([ \t]*worktree[ \t]*=[ \t]*)(.+)$/m,
      (_match, prefix: string, value: string) =>
        `${prefix}"${value.slice(0, -3)}\\\n${value.slice(-3)}" # valid Git comment`,
    );
    const suffix =
      process.platform === "win32"
        ? Buffer.alloc(0)
        : Buffer.from([0x23, 0x20, 0xff, 0x0a]);
    await writeFile(
      config,
      Buffer.concat([
        Buffer.from(`${configured}\n[feature]\n\tenabled\n`),
        suffix,
      ]),
    );

    expect(await inventory(checkout)).toContain("./nested/visible.ts");
  });

  test.skipIf(process.platform !== "linux")(
    "preserves non-UTF-8 paths in genuine Git worktree configurations",
    async () => {
      if (Bun.which("rg") === null || python === null) return;

      const checkout = await repository();
      const configure = [
        "import os, subprocess, sys",
        "root = os.fsencode(sys.argv[1])",
        "worktree = root + b'/nested-\\xff'",
        "gitdir = root + b'/.git/modules/nested-bytes'",
        "os.makedirs(os.path.dirname(gitdir), exist_ok=True)",
        "subprocess.run([b'git', b'init', b'-q', b'--separate-git-dir', gitdir, worktree], check=True)",
        "subprocess.run([b'git', b'--git-dir=' + gitdir, b'config', b'core.worktree', worktree], check=True)",
        "with open(worktree + b'/visible.ts', 'wb') as source: source.write(b'tracked\\n')",
        "subprocess.run([b'git', b'-C', worktree, b'add', b'visible.ts'], check=True)",
      ].join("\n");
      execFileSync(python, ["-B", "-c", configure, checkout], {
        stdio: "pipe",
      });

      expect(
        (await inventory(checkout)).some((path) =>
          path.endsWith("/visible.ts"),
        ),
      ).toBe(true);
    },
  );

  test("does not inspect a differently cased checkout outside an explicit scope", async () => {
    if (Bun.which("rg") === null) return;

    const checkout = await repository();
    const selected = join(checkout, "NESTED");
    const unselected = join(checkout, "nested");
    await mkdir(selected);
    try {
      await mkdir(unselected);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "EEXIST") return;
      throw error;
    }
    for (const nested of [selected, unselected]) {
      execFileSync("git", ["init", "-q"], { cwd: nested });
      await writeFile(join(nested, "tracked.ts"), "tracked\n");
      execFileSync("git", ["add", "tracked.ts"], { cwd: nested });
    }
    const trace = join(dirname(checkout), "git-trace.log");

    expect(
      await inventory(checkout, "NESTED", {
        ...process.env,
        GIT_TRACE: trace,
        GIT_TRACE_SETUP: "1",
      }),
    ).toEqual(["NESTED/tracked.ts"]);
    expect(await readFile(trace, "utf8")).not.toContain(unselected);
  });

  test.skipIf(process.platform !== "win32")(
    "does not traverse external Windows directory junctions",
    async () => {
      if (Bun.which("rg") === null) return;

      for (const initializeGit of [false, true]) {
        const checkout = await repository(initializeGit);
        const external = join(dirname(checkout), "outside");
        await mkdir(join(external, ".ignore"), { recursive: true });
        execFileSync("git", ["init", "-q"], { cwd: external });
        if (initializeGit) {
          await writeFile(join(checkout, "junction"), "tracked\n");
          execFileSync("git", ["add", "junction"], { cwd: checkout });
          await rm(join(checkout, "junction"));
        }
        await symlink(external, join(checkout, "junction"), "junction");
        await writeFile(join(checkout, "visible.ts"), "visible\n");

        expect(await inventory(checkout)).toEqual(["./visible.ts"]);
      }
    },
  );

  test.skipIf(process.platform === "win32")(
    "inventories an explicit file without listing its parent directory",
    async () => {
      if (Bun.which("rg") === null) return;

      const checkout = await repository();
      const directory = join(checkout, "restricted");
      await mkdir(directory);
      await writeFile(join(directory, "source.ts"), "export {};\n");
      await chmod(directory, 0o111);
      try {
        expect(await inventory(checkout, "restricted/source.ts")).toEqual([
          "restricted/source.ts",
        ]);
      } finally {
        await chmod(directory, 0o755);
      }
    },
  );

  test("preserves supported in-repository symbolic path targets", async () => {
    const checkout = await repository();
    const source = join(checkout, "source");
    await mkdir(source);
    await writeFile(join(source, "app.ts"), "export {};\n");
    await symlink(
      source,
      join(checkout, "linked"),
      process.platform === "win32" ? "junction" : "dir",
    );

    await expect(normalizeTarget(checkout, ["linked/app.ts"])).resolves.toEqual(
      { kind: "paths", paths: ["source/app.ts"] },
    );
  });

  test("rejects ignore files that point outside the requested repository", async () => {
    if (process.platform === "win32" || Bun.which("rg") === null) return;

    const checkout = await repository(false);
    const external = join(dirname(checkout), "external.ignore");
    await writeFile(external, "hidden.ts\n");
    await writeFile(join(checkout, "hidden.ts"), "export {};\n");
    await symlink(external, join(checkout, ".ignore"));

    await expect(inventory(checkout)).rejects.toThrow(
      "symbolic ignore files are not supported",
    );
  });

  test.skipIf(process.platform === "win32")(
    "rejects descendant ignore links before invoking repository-wide ripgrep",
    async () => {
      if (Bun.which("rg") === null) return;

      const checkout = await repository();
      const visible = join(checkout, "visible");
      const external = join(dirname(checkout), "external.ignore");
      await mkdir(visible);
      await writeFile(join(visible, "source.ts"), "visible\n");
      await writeFile(external, "source.ts\n");
      await symlink(external, join(visible, ".ignore"));

      await expect(inventory(checkout)).rejects.toThrow(
        "symbolic ignore files are not supported",
      );
    },
  );

  test.skipIf(process.platform === "win32")(
    "excludes case-equivalent Git metadata before running ripgrep",
    async () => {
      const ripgrep = Bun.which("rg");
      if (ripgrep === null) return;

      const checkout = await repository();
      const metadata = join(checkout, ".GIT");
      await rename(join(checkout, ".git"), metadata);
      const equivalent = await realpath(join(checkout, ".git")).then(
        async (resolved) => resolved === (await realpath(metadata)),
        () => false,
      );
      if (!equivalent) return;

      const external = join(dirname(checkout), "external.ignore");
      const trace = join(dirname(checkout), "ripgrep-output");
      const wrappers = join(dirname(checkout), "bin");
      await mkdir(wrappers);
      await writeFile(external, "# external ignore rules\n");
      await symlink(external, join(metadata, ".ignore"));
      await writeFile(join(checkout, ".rgignore"), "!.GIT/\n!.GIT/**\n");
      await writeFile(join(checkout, "visible.ts"), "visible\n");
      const wrapper = join(wrappers, "rg");
      await writeFile(
        wrapper,
        `#!/bin/sh\nif [ "$PWD" = ${JSON.stringify(checkout)} ]; then\n ${JSON.stringify(ripgrep)} "$@" > ${JSON.stringify(trace)}\n status=$?\n cat ${JSON.stringify(trace)}\n exit "$status"\nfi\nexec ${JSON.stringify(ripgrep)} "$@"\n`,
      );
      await chmod(wrapper, 0o755);

      expect(
        await inventory(checkout, ".", {
          ...process.env,
          PATH: `${wrappers}:${process.env["PATH"] ?? ""}`,
        }),
      ).toEqual(["./.rgignore", "./visible.ts"]);
      expect((await readFile(trace)).toString()).not.toContain(".GIT/");
    },
  );

  test.skipIf(process.platform === "win32")(
    "rejects snapshot ignore links without discovering a parent checkout",
    async () => {
      if (Bun.which("rg") === null) return;

      const parent = await repository();
      const snapshot = join(parent, "snapshot");
      const visible = join(snapshot, "visible");
      const external = join(dirname(parent), "external.ignore");
      const trace = join(dirname(parent), "git-trace.log");
      await mkdir(visible, { recursive: true });
      await writeFile(external, "# ignore rules\n");
      await writeFile(join(visible, "source.ts"), "visible\n");
      await symlink(external, join(visible, ".ignore"));

      await expect(
        inventory(snapshot, ".", {
          ...process.env,
          GIT_DIR: join(parent, ".git"),
          GIT_TRACE: trace,
        }),
      ).rejects.toThrow("symbolic ignore files are not supported");
      const commands = await readFile(trace, "utf8");
      expect(commands).toContain("git config --global");
      expect(commands).not.toContain("rev-parse");
      expect(commands).not.toContain(parent);
    },
  );
});

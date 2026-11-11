import { describe, expect, test } from "bun:test";
import {
  link,
  mkdir,
  readFile,
  readdir,
  symlink,
  unlink,
  writeFile,
} from "node:fs/promises";
import { join } from "node:path";
import { runCommand } from "./support/shell.js";
import { scopedTemporaryDirectory } from "./support/temporary-directories.js";

async function isolatedCli(root: string, environment: NodeJS.ProcessEnv = {}) {
  const home = join(root, "home");
  const project = join(root, "project");
  await Promise.all([mkdir(home), mkdir(project)]);
  const env = {
    ...process.env,
    HOME: home,
    USERPROFILE: home,
    APPDATA: join(home, "AppData", "Roaming"),
    LOCALAPPDATA: join(home, "AppData", "Local"),
    XDG_CACHE_HOME: join(root, "cache"),
    XDG_CONFIG_HOME: join(root, "config"),
    XDG_DATA_HOME: join(root, "data"),
    CODEX_HOME: join(root, "codex"),
    CI: "1",
    ...environment,
  };
  const runFrom = (cwd: string, ...args: string[]) =>
    runCommand(
      process.execPath,
      [join(import.meta.dir, "../src/cli.ts"), ...args],
      { env, cwd, timeout: 30_000 },
    );
  return {
    home,
    project,
    runFrom,
    run: (...args: string[]) => runFrom(project, ...args),
  };
}

describe("integration command dispatch", () => {
  test.each([
    { args: ["skills", "add", "--schema", "--json"], mode: "schema" },
    {
      args: ["mcp", "add", "--agent", "amp", "--schema", "--json"],
      mode: "schema",
    },
    { args: ["skill", "add", "--version"], mode: "version" },
    { args: ["mcp", "--version"], mode: "version" },
    {
      args: [
        "--json",
        "codex-security",
        "mcp",
        "add",
        "--agent=amp",
        "--schema",
      ],
      mode: "schema",
    },
    { args: ["mcp", "add", "--command", "--no-global"], mode: "error" },
    { args: ["skills", "add", "surplus"], mode: "error" },
    { args: ["skills", "add", "--scope=user", "--no-global"], mode: "error" },
    { args: ["mcp", "add", "--agent=cursor", "--all"], mode: "error" },
    {
      args: [
        "mcp",
        "add",
        "--agent=cursor",
        "--exec=server",
        "--package=server",
      ],
      mode: "error",
    },
    { args: ["mcp", "add", "--agent=cursor", "--arg=--mcp"], mode: "error" },
    {
      args: ["mcp", "add", "--agent=amp", "--filter-output", "--llms"],
      mode: "error",
    },
    { args: ["skills", "--deph"], mode: "error" },
    { args: ["mcp", "add", "--agent", "amp", "--version"], mode: "version" },
    { args: ["skills", "add", "--no-glboal"], mode: "error" },
    { args: ["skills", "add", "--depth", "NaN"], mode: "error" },
    { args: ["skills", "list", "--depth=NaN"], mode: "error" },
    { args: ["mcp", "add", "--agent", "amp", "--no-global"], mode: "error" },
    {
      args: [
        "mcp",
        "add",
        "--agent=cursor",
        "--agent=claude-desktop",
        "--no-global",
      ],
      mode: "error",
    },
    { args: ["--mcp", "--help"], mode: "help" },
  ])(
    "leaves both installation scopes untouched for $args",
    async ({ args, mode }) => {
      await using temp = await scopedTemporaryDirectory("cli-inspection-");
      const { home, project, run } = await isolatedCli(temp.path);
      const result = await run(...args);
      expect(result.status).toBe(mode === "error" ? 2 : 0);
      if (mode === "schema")
        expect(JSON.parse(result.stdout).options.properties.noGlobal.type).toBe(
          "boolean",
        );
      if (mode === "version")
        expect(result.stdout.trim()).toMatch(/^\d+\.\d+\.\d+/);
      if (mode === "help")
        expect(result.stdout).toContain("Usage: codex-security");
      if (mode === "error") expect(result.stderr.length).toBeGreaterThan(0);
      expect(await readdir(home)).toEqual([]);
      expect(await readdir(project)).toEqual([]);
    },
    30_000,
  );

  test.each([
    { group: "mcp", term: "read-only info tool" },
    { group: "skills", term: "Codex Security plugin" },
  ])(
    "$group help identifies the integration being managed",
    async ({ group, term }) => {
      await using temp = await scopedTemporaryDirectory(
        "cli-integration-help-",
      );
      const { run } = await isolatedCli(temp.path);
      const result = await run(group, "--help");
      expect(result.status).toBe(0);
      expect(result.stdout.replace(/\s+/gu, " ")).toContain(term);
    },
    30_000,
  );

  test("shell hooks complete integration flags without executing commands", async () => {
    await using temp = await scopedTemporaryDirectory(
      "cli-integration-completions-",
    );
    const { home, project, run } = await isolatedCli(temp.path, {
      COMPLETE: "bash",
    });
    for (const [args, flag] of [
      [["cs", "skill", "ls", "--de"], "--depth"],
      [["codex-security", "mcp", "add", "--ag"], "--agent"],
      [["cs", "skills", "list", "--format", "ya"], "yaml"],
    ] as const) {
      const result = await run("--", ...args);
      expect(result.status).toBe(0);
      expect(result.stdout).toContain(flag);
    }
    expect(await readdir(home)).toEqual([]);
    expect(await readdir(project)).toEqual([]);
  }, 30_000);

  test("zsh completes at the supplied cursor after an equals-form option", async () => {
    await using temp = await scopedTemporaryDirectory("cli-zsh-completions-");
    const { run } = await isolatedCli(temp.path, {
      COMPLETE: "zsh",
      _COMPLETE_INDEX: "4",
    });
    const result = await run(
      "--",
      "cs",
      "skills",
      "list",
      "--format=json",
      "--de",
      "--json",
    );
    expect(result.status).toBe(0);
    expect(result.stdout).toStartWith("--depth:");
  }, 30_000);

  test.each([
    {
      shell: "zsh",
      words: ["cs", "info", "--co", "--mcp", "--help", "--update", "--schema"],
      index: 2,
      candidate: "--config:",
    },
    {
      shell: "bash",
      words: [
        "codex-security",
        "scan",
        "--mode",
        "d",
        "--mcp",
        "--format=invalid",
      ],
      index: 3,
      candidate: "deep",
    },
    {
      shell: "bash",
      words: ["cs", "scan", "--mode"],
      index: 3,
      candidate: "standard\vdeep",
    },
    {
      shell: "zsh",
      words: ["cs", "info", "--config", "--update"],
      index: 2,
      candidate: "--config:",
    },
    {
      shell: "fish",
      words: ["cs", "scans", "sh"],
      candidate: "show\t",
    },
    {
      shell: "nushell",
      words: ["cs", "sk"],
      candidate: '"value":"skills"',
    },
  ])(
    "the $shell hook completes ordinary CLI words without running actions",
    async ({ shell, words, index, candidate }) => {
      await using temp = await scopedTemporaryDirectory("cli-shell-word-");
      const { home, project, run } = await isolatedCli(temp.path, {
        COMPLETE: shell,
        _COMPLETE_INDEX: index?.toString(),
        PATH: join(temp.path, "no-package-runners"),
      });
      const result = await run("--", ...words);
      expect(result.status).toBe(0);
      expect(result.stdout).toContain(candidate);
      expect(result.stderr).toBe("");
      expect(await readdir(home)).toEqual([]);
      expect(await readdir(project)).toEqual([]);
    },
    30_000,
  );

  test("empty completion callbacks emit the shell registration script", async () => {
    await using temp = await scopedTemporaryDirectory("cli-shell-script-");
    const { run } = await isolatedCli(temp.path, { COMPLETE: "zsh" });
    const result = await run();
    expect(result.status).toBe(0);
    expect(result.stdout).toContain("#compdef codex-security");
    expect(result.stdout).toContain("#compdef cs");
  }, 30_000);

  test("the command manifest includes integration leaves without installing them", async () => {
    await using temp = await scopedTemporaryDirectory(
      "cli-integration-discovery-",
    );
    const { home, project, run } = await isolatedCli(temp.path);
    const manifest = await run("--llms", "--json");
    expect(manifest.status).toBe(0);
    const commands = JSON.parse(manifest.stdout).commands.map(
      (entry: { name: string }) => entry.name,
    );
    for (const command of [
      "completions",
      "mcp add",
      "mcp doctor",
      "skills add",
      "skills list",
    ])
      expect(commands).toContain(command);
    expect(await readdir(home)).toEqual([]);
    expect(await readdir(project)).toEqual([]);
  }, 30_000);

  test("registers selected clients from the installed SDK with no package runners on PATH", async () => {
    await using temp = await scopedTemporaryDirectory("cli-project-clients-");
    const { home, project, run } = await isolatedCli(temp.path, {
      PATH: join(temp.path, "no-executables"),
      npm_config_user_agent: "pnpm/11",
      npm_execpath: join(temp.path, "unavailable-pnpm.cjs"),
    });
    await mkdir(join(project, ".cursor"));
    const decoy = join(project, "node_modules", "add-mcp");
    await mkdir(decoy, { recursive: true });
    await writeFile(
      join(decoy, "package.json"),
      JSON.stringify({ name: "add-mcp", main: "missing.js" }),
    );
    const local = await run("mcp", "add", "--no-global", "--json");
    expect(local.status).toBe(0);
    expect(JSON.parse(local.stdout).agents).toEqual(["Cursor"]);
    const projectConfig = JSON.parse(
      await readFile(join(project, ".cursor", "mcp.json"), "utf8"),
    );
    expect(projectConfig.mcpServers["codex-security"]).toMatchObject({
      command: "npx",
      args: ["--yes", "@openai/codex-security", "--mcp"],
    });
    expect(await readdir(home)).toEqual([]);
    const global = await run(
      "mcp",
      "add",
      "--agent=cursor",
      "--command",
      "my-tool --mcp",
      "--json",
    );
    expect(global.status).toBe(0);
    expect(JSON.parse(global.stdout).agents).toEqual(["Cursor"]);
    const userConfig = JSON.parse(
      await readFile(join(home, ".cursor", "mcp.json"), "utf8"),
    );
    expect(userConfig.mcpServers["codex-security"]).toMatchObject({
      command: "my-tool",
      args: ["--mcp"],
    });
  }, 30_000);

  test("empty scopes require explicit targets and --all registers compatible project clients", async () => {
    await using temp = await scopedTemporaryDirectory("cli-mcp-targets-");
    const { project, home, run } = await isolatedCli(temp.path, {
      PATH: join(temp.path, "no-executables"),
    });
    for (const scope of ["project", "user"]) {
      const result = await run("mcp", "add", "--scope", scope);
      expect(result.status).toBe(2);
      expect(result.stderr).toContain("--agent");
      expect(result.stderr).toContain("--all");
      expect(await readdir(project)).toEqual([]);
      expect(await readdir(home)).toEqual([]);
    }
    const result = await run(
      "mcp",
      "add",
      "--scope=project",
      "--all",
      "--json",
    );
    expect(result.status, result.stderr).toBe(0);
    expect(JSON.parse(result.stdout).agents).toContain("Cursor");
    expect(JSON.parse(result.stdout).agents.length).toBeGreaterThan(1);
    expect(await readdir(home)).toEqual([]);
  }, 30_000);

  test("user detection follows the configured Codex profile", async () => {
    await using temp = await scopedTemporaryDirectory("cli-mcp-codex-home-");
    const profile = join(temp.path, "custom-profile");
    const { home, run } = await isolatedCli(temp.path, { CODEX_HOME: profile });
    await mkdir(profile);
    const result = await run("mcp", "add", "--json");
    expect(result.status, result.stderr).toBe(0);
    expect(JSON.parse(result.stdout).agents).toEqual(["Codex"]);
    expect(await readFile(join(profile, "config.toml"), "utf8")).toContain(
      "mcp_servers.codex-security",
    );
    expect(await readdir(home)).toEqual([]);
  }, 30_000);

  test("MCP launchers preserve literal arguments and use npm only when selected", async () => {
    await using temp = await scopedTemporaryDirectory("cli-mcp-launcher-");
    const { home, run } = await isolatedCli(temp.path);
    const executable = String.raw`C:\Program Files\tool's "server".exe`;
    const existingExecutable = join(temp.path, "server with spaces");
    await writeFile(existingExecutable, "", { mode: 0o700 });
    const args = ["--mcp", "", "two words", "--json", "one=two"];
    for (const [launcher, expected] of [
      [
        ["--exec", executable, ...args.map((value) => `--arg=${value}`)],
        { command: executable, args },
      ],
      [
        ["--package=@acme/server", "--arg=--mcp"],
        { command: "npx", args: ["--yes", "--", "@acme/server", "--mcp"] },
      ],
      [
        [`--command=node "server entry.js" --mcp`],
        { command: "node", args: ["server entry.js", "--mcp"] },
      ],
      [["--command=local-server"], { command: "local-server", args: [] }],
      [
        [`--command=${existingExecutable}`],
        { command: existingExecutable, args: [] },
      ],
      [
        ["--command=/usr/bin/node /opt/server.js --mcp"],
        { command: "/usr/bin/node", args: ["/opt/server.js", "--mcp"] },
      ],
      [
        ['--command=/usr/bin/node "server entry.js"'],
        { command: "/usr/bin/node", args: ["server entry.js"] },
      ],
      [
        ["--command=/opt/tools/server --mcp"],
        { command: "/opt/tools/server", args: ["--mcp"] },
      ],
    ] as const) {
      const result = await run(
        "mcp",
        "add",
        "--agent=cursor",
        "--agent=amp",
        "--json",
        ...launcher,
      );
      expect(result.status, result.stderr).toBe(0);
      const cursor = JSON.parse(
        await readFile(join(home, ".cursor", "mcp.json"), "utf8"),
      );
      const amp = JSON.parse(
        await readFile(join(home, ".config", "amp", "settings.json"), "utf8"),
      );
      expect(cursor.mcpServers["codex-security"]).toEqual(expected);
      expect(amp["amp.mcpServers"]["codex-security"]).toEqual(expected);
    }
  }, 30_000);

  test("project registration keeps linked configurations inside the project", async () => {
    await using temp = await scopedTemporaryDirectory("cli-project-links-");
    const { home, project, run } = await isolatedCli(temp.path);
    const dir = join(project, ".cursor");
    const external = join(home, "mcp.json");
    const register = () =>
      run("mcp", "add", "--agent=cursor", "--no-global", "--json");
    await writeFile(external, "{}");
    await symlink(home, dir, process.platform === "win32" ? "junction" : "dir");
    expect((await register()).status).toBe(2);
    await unlink(dir);
    await mkdir(dir);
    await link(external, join(dir, "mcp.json"));
    expect((await register()).status).toBe(2);
    expect(await readFile(external, "utf8")).toBe("{}");
  }, 30_000);

  test("explicit JSON returns a parseable MCP installer result", async () => {
    await using temp = await scopedTemporaryDirectory("cli-integrations-");
    const { home, run } = await isolatedCli(temp.path);
    const mcp = await run(
      "mcp",
      "add",
      "--agent=amp",
      "--agent",
      "amp",
      "--command",
      "my-tool --mcp",
      "--json",
    );
    expect(mcp.status).toBe(0);
    expect(JSON.parse(mcp.stdout)).toMatchObject({
      agents: ["Amp"],
      command: "my-tool --mcp",
    });
    const configuration = JSON.parse(
      await readFile(join(home, ".config", "amp", "settings.json"), "utf8"),
    );
    expect(configuration["amp.mcpServers"]["codex-security"]).toEqual({
      command: "my-tool",
      args: ["--mcp"],
    });
  }, 30_000);

  test("lists installed guidance at the selected grouping depth", async () => {
    await using temp = await scopedTemporaryDirectory("cli-skill-grouping-");
    const { project, home, run, runFrom } = await isolatedCli(temp.path);
    const skills = await run(
      "skill",
      "add",
      "--no-global",
      "--depth=0",
      "--json",
    );
    expect(skills.status).toBe(0);
    const installed = JSON.parse(skills.stdout).skills;
    expect(installed).toHaveLength(1);
    expect(installed[0]).toStartWith(project);
    const list = await run("skill", "ls", "--depth=0", "--json");
    expect(list.status).toBe(0);
    expect(JSON.parse(list.stdout)).toMatchObject([
      {
        name: "codex-security",
        installed: true,
        locations: [{ scope: "project", path: join(installed[0], "SKILL.md") }],
      },
    ]);
    const human = await run("skills", "list", "--depth", "0");
    expect(human.status).toBe(0);
    expect(human.stdout).toContain("1 skill (1 installed)");
    const other = join(temp.path, "other-project");
    await mkdir(other);
    const elsewhere = await runFrom(
      other,
      "skills",
      "list",
      "--depth=0",
      "--json",
    );
    expect(JSON.parse(elsewhere.stdout)).toMatchObject([
      { installed: false, locations: [] },
    ]);
    const user = await run(
      "skills",
      "add",
      "--scope=user",
      "--depth=0",
      "--json",
    );
    expect(user.status, user.stderr).toBe(0);
    const combined = await run("skills", "list", "--depth=0", "--json");
    expect(JSON.parse(combined.stdout)[0].locations).toEqual([
      { scope: "project", path: join(installed[0], "SKILL.md") },
      {
        scope: "user",
        path: join(home, ".agents", "skills", "codex-security", "SKILL.md"),
      },
    ]);
    const defaultList = await run("skills", "list");
    expect(defaultList.stdout).toContain("Skill grouping depth: 1");
  }, 30_000);
});

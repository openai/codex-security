import {
  copyFileSync,
  cpSync,
  mkdirSync,
  readFileSync,
  writeFileSync,
} from "node:fs";
import { join } from "node:path";
import { PLUGIN_ROOT } from "./plugin-root.js";
import { runCommand } from "./support/shell.js";

export function windowsHelperFixture(
  root: string,
  environment: NodeJS.ProcessEnv = {},
) {
  const plugin = join(root, "plugin %PLUGIN% !EXPAND! caf\u00e9's");
  mkdirSync(join(plugin, "scripts"), { recursive: true });
  cpSync(join(PLUGIN_ROOT, "mcp"), join(plugin, "mcp"), { recursive: true });
  copyFileSync(
    join(PLUGIN_ROOT, "scripts", "launch_codex_security_mcp.cmd"),
    join(plugin, "scripts", "launch_codex_security_mcp.cmd"),
  );
  const expandedPlugin = plugin.replace("%PLUGIN%", "expanded-plugin");
  mkdirSync(join(expandedPlugin, "scripts"), { recursive: true });
  writeFileSync(
    join(expandedPlugin, "scripts", "launch_codex_security_mcp.cmd"),
    "@echo expanded-plugin-used\r\n@exit /b 0\r\n",
  );
  const systemRoot = process.env["SystemRoot"]!;
  const powershells = [
    join(systemRoot, "System32", "WindowsPowerShell", "v1.0", "powershell.exe"),
    Bun.which("pwsh"),
  ].filter((value): value is string => value !== null);
  return {
    plugin,
    powershells,
    async run(
      powershell: string,
      document: string,
      paths: Record<string, string>,
      input?: string,
      workingDirectory = root,
      pipelineInput?: string,
      blockIndex = 0,
    ) {
      const source = readFileSync(join(PLUGIN_ROOT, document), "utf8");
      let command = [
        ...source.matchAll(/```powershell\r?\n([\s\S]*?)\r?\n```/gu),
      ][blockIndex]?.[1];
      if (command === undefined)
        throw new Error(`No PowerShell command in ${document}`);
      for (const [placeholder, path] of Object.entries(paths))
        command = command.replaceAll(placeholder, path.replaceAll("'", "''"));
      if (pipelineInput !== undefined)
        command = command.replace(
          /^cmd\.exe/m,
          `'${pipelineInput.replaceAll("'", "''")}' | cmd.exe`,
        );
      command =
        "$ProgressPreference = 'SilentlyContinue'\n" +
        `Set-Location -LiteralPath '${workingDirectory.replaceAll("'", "''")}' -ErrorAction Stop\n` +
        "$ExecutionContext.SessionState.LanguageMode = 'ConstrainedLanguage'\n" +
        command;
      const fixtureEnvironment = {
        SystemRoot: systemRoot,
        PATH: join(systemRoot, "System32"),
        HOME: root,
        USERPROFILE: root,
        LOCALAPPDATA: root,
        XDG_CACHE_HOME: root,
        CODEX_MCP_NODE_PATH: Bun.which("node")!,
        PLUGIN: "expanded-plugin",
        USERNAME: "expanded-user",
        EXPAND: "expanded-bang",
        ...environment,
      };
      const overrides = new Set(
        Object.keys(fixtureEnvironment).map((key) => key.toUpperCase()),
      );
      const inheritedEnvironment = Object.fromEntries(
        Object.entries(process.env).filter(
          ([key]) => !overrides.has(key.toUpperCase()),
        ),
      );
      const result = await runCommand(
        powershell,
        [
          "-NoLogo",
          "-NoProfile",
          "-NonInteractive",
          "-EncodedCommand",
          Buffer.from(command, "utf16le").toString("base64"),
        ],
        {
          cwd: root,
          env: {
            ...inheritedEnvironment,
            ...fixtureEnvironment,
          },
          timeout: 30_000,
          input,
          windowsHide: true,
        },
      );
      return {
        ...result,
        diagnostics: JSON.stringify(
          {
            powershell,
            document,
            workingDirectory,
            paths,
            environment,
            command,
            status: result.status,
            signal: result.signal,
            error: result.error?.message,
            stdout: result.stdout,
            stderr: result.stderr,
          },
          null,
          2,
        ),
      };
    },
  };
}

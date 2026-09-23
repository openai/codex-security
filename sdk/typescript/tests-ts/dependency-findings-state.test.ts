import { mkdtemp, rm, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { expect, test } from "bun:test";
import { dependencyFindingSkillPrompt } from "../src/dependency-findings.js";
import { resolvePluginPython, runCodexCommand } from "../src/runtime.js";
import { PLUGIN_ROOT } from "./plugin-root.js";

test("workbench invocation uses the selected state without inherited state", async () => {
  const root = await mkdtemp(join(tmpdir(), "dependency-state-"));
  try {
    const stateDirectory = join(root, "selected state");
    const codexHome = join(root, "fallback home");
    const python = await resolvePluginPython();
    const prompt = dependencyFindingSkillPrompt(
      {
        skill: "dependency-finding-assessment",
        targetPath: join(root, "repository"),
        assessmentId: "assessment-1",
      },
      PLUGIN_ROOT,
      python,
      join(root, "output"),
      stateDirectory,
    );
    const [command, ...args] = JSON.parse(
      prompt.match(/Workbench executable arguments: (.+)\./)![1]!,
    ) as string[];
    const result = await runCodexCommand(
      { command: command! },
      [...args, "list-dependency-reports"],
      { CODEX_HOME: codexHome, SystemRoot: process.env["SystemRoot"] },
      undefined,
      AbortSignal.timeout(10_000),
    );
    expect(result.exitCode, result.stderr).toBe(0);
    expect(JSON.parse(result.stdout)).toEqual({
      reports: [],
      nextOffset: null,
    });
    expect(
      (await stat(join(stateDirectory, "workbench.sqlite3"))).isFile(),
    ).toBe(true);
    await expect(stat(codexHome)).rejects.toMatchObject({ code: "ENOENT" });
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

import assert from "node:assert/strict";
import { mkdir, readFile, rm, symlink, writeFile } from "node:fs/promises";
import { join, resolve, sep } from "node:path";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { applicationRoot, buildServer } from "./build-server.ts";
import { test } from "node:test";
import { importSource } from "./import-module.ts";
import { temporaryDirectory } from "./support/temporary-directories.ts";
import type { readDeepScanProjectConfig as Reader } from "../src/deep-scan/project-config.js";

const { readDeepScanProjectConfig } = (await importSource(
  join(import.meta.dirname, "../src/deep-scan/project-config.ts"),
)) as { readDeepScanProjectConfig: typeof Reader };

await test("explicit YAML and JSON selection use the CLI project format and minute budget", async () => {
  const root = await temporaryDirectory("deep-project-config-", true);
  try {
    for (const [name, content] of [
      [
        "security.yaml",
        "scan:\n  mode: deep\n  max_time_minutes: 30\n  deep:\n    workers: 2\n    subagents_per_worker: 1\n    stop_after_no_new: 2\n    max_discovery_runs: 4\n",
      ],
      [
        "security.json",
        `\uFEFF${JSON.stringify({
          scan: {
            mode: "deep",
            max_time_minutes: 30,
            deep: {
              workers: 2,
              subagents_per_worker: 1,
              stop_after_no_new: 2,
              max_discovery_runs: 4,
            },
          },
        })}`,
      ],
    ]) {
      await writeFile(join(root, name), content);
      assert.deepEqual(await readDeepScanProjectConfig(name, root), {
        path: join(root, name),
        settings: {
          workers: 2,
          subagents: 1,
          stopAfterNoNew: 2,
          maxDiscoveryRuns: 4,
          maxTimeHours: 0.5,
        },
      });
    }
    assert.equal(
      await readDeepScanProjectConfig(undefined, root),
      undefined,
      "A repository configuration must not activate without explicit selection.",
    );
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

await test("unsupported settings and contradictory time aliases fail before launch", async () => {
  const root = await temporaryDirectory("deep-project-rejections-");
  try {
    const path = join(root, "security.json");
    for (const [input, message] of [
      [{ scan: { deep: { workers: 0 } } }, /Invalid project configuration/],
      [{ scan: { deep: { unknown: 1 } } }, /Unknown key unknown/],
      [
        { scan: { max_time_minutes: 30, deep: { max_time_hours: 1 } } },
        /Conflicting/,
      ],
      [{ scan: { max_time_minutes: 5761 } }, /no greater than 5760/],
      [{ scan: { mode: "standard" } }, /scan.mode: deep/],
      [
        {
          codex: { model: "fixture" },
          scan: { knowledge_base: ["context.md"] },
        },
        /Unsupported.*codex, scan.knowledge_base/,
      ],
    ] as const) {
      await writeFile(path, JSON.stringify(input));
      await assert.rejects(readDeepScanProjectConfig(path, root), message);
    }
    await mkdir(join(root, "nested"));
    await writeFile(
      path,
      JSON.stringify({
        scan: {
          max_time_minutes: 30,
          deep: { max_time_hours: 0.5, subagents_per_worker: 0 },
        },
      }),
    );
    assert.equal(
      (
        await readDeepScanProjectConfig(
          "../security.json",
          join(root, "nested"),
        )
      )?.settings.subagents,
      0,
    );
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

await test("built MCP setup previews and saves the selected project before scan launch", async () => {
  const root = await temporaryDirectory("deep-project-mcp-", true);
  const bundle = join(root, "server.cjs");
  const targetPath = join(root, "repository");
  const projectConfigPath = join(targetPath, "selected.yaml");
  const legacyConfigPath = join(root, "defaults.toml");
  const workbenchCalls = join(root, "workbench-calls");
  const client = new Client({
    name: "deep-project-config-test",
    version: "1.0.0",
  });
  try {
    await mkdir(targetPath);
    await writeFile(join(targetPath, "fixture.py"), "print('fixture')\n");
    await writeFile(
      projectConfigPath,
      "scan:\n  mode: deep\n  max_time_minutes: 30\n  deep:\n    workers: 2\n    subagents_per_worker: 1\n    stop_after_no_new: 2\n    max_discovery_runs: 4\n",
    );
    await writeFile(
      legacyConfigPath,
      "[deep_scan]\nworkers=7\nmax_time_hours=4\n",
    );
    await buildServer(bundle, {
      banner: {
        js: `require("node:diagnostics_channel").subscribe("child_process", ({ process: child }) => {
          child.once("spawn", () => {
            if (child.spawnargs.some(arg => arg.endsWith("workbench_db.py")))
              require("node:fs").appendFileSync(${JSON.stringify(workbenchCalls)}, "call\\n");
          });
        });`,
      },
      logOverride: { "empty-import-meta": "silent" },
    });
    await client.connect(
      new StdioClientTransport({
        command: process.execPath,
        args: [bundle, "--stdio"],
        cwd: applicationRoot,
        env: {
          ...process.env,
          HOME: root,
          USERPROFILE: root,
          CODEX_HOME: join(root, "home"),
          CODEX_SECURITY_PLUGIN_ROOT: resolve(applicationRoot, ".."),
          CODEX_SECURITY_STATE_DIR: join(root, "state"),
          CODEX_SECURITY_SCAN_ROOT: join(root, "scans"),
          CODEX_SECURITY_DEEP_SCAN_CONFIG_PATH: legacyConfigPath,
        } as Record<string, string>,
      }),
    );
    const call = async (name: string, arguments_: Record<string, unknown>) => {
      const result = await client.callTool({
        name,
        arguments: arguments_,
        _meta: { "openai/threadId": "project-owner" },
      });
      assert.notEqual(result.isError, true, JSON.stringify(result.content));
      return result.structuredContent as Record<string, any>;
    };
    const selection = {
      targetPath,
      scope: ".",
      mode: "deep",
      projectConfigPath: "selected.yaml",
    };
    const preview = (await call("inspect_codex_security_setup", selection))
      .setup.deepScanConfig;
    assert.equal(await readFile(workbenchCalls, "utf8"), "call\n");
    assert.equal(preview.settings.maxTimeHours, 0.5);
    assert.equal(preview.settings.workers, 2);
    assert.equal(preview.sources.workers, "project");
    assert.equal(preview.projectConfigPath, projectConfigPath);
    const homeTarget = await call("inspect_codex_security_setup", {
      ...selection,
      targetPath: "~/repository",
    });
    assert.deepEqual(homeTarget.setup.deepScanConfig, preview);
    const invalid = await client.callTool({
      name: "inspect_codex_security_setup",
      arguments: {
        ...selection,
        targetPath: "repository",
        projectConfigPath: "missing.yaml",
      },
    });
    assert.equal(invalid.isError, true);
    assert.match(JSON.stringify(invalid.content), /absolute local directory/);
    if (process.platform === "win32" && /^[A-Za-z]:/.test(targetPath)) {
      selection.projectConfigPath = `${targetPath.slice(0, 2)}selected.yaml`;
      const driveRelative = (
        await call("inspect_codex_security_setup", selection)
      ).setup;
      assert.deepEqual(driveRelative.deepScanConfig, preview);
    } else if (process.platform !== "win32") {
      await mkdir(join(targetPath, "subdirectory"));
      await symlink(join(targetPath, "subdirectory"), join(root, "link"));
      await writeFile(
        join(root, "selected.yaml"),
        "scan: {deep: {workers: 7}}",
      );
      selection.targetPath = `${join(root, "link")}${sep}..`;
      const throughLink = (
        await call("inspect_codex_security_setup", selection)
      ).setup;
      assert.equal(throughLink.target.targetPath, targetPath);
      assert.deepEqual(throughLink.deepScanConfig, preview);
    }
    const workspace = (
      await call("open_codex_security_workspace", {
        targetPath,
        mode: "deep",
      })
    ).workspace;
    const saved = (
      await call("submit_codex_security_setup", {
        ...selection,
        sessionId: workspace.id,
      })
    ).workspace;
    assert.equal(saved.targetPath, targetPath);
    assert.deepEqual(saved.deepScanConfig, preview);
    await rm(projectConfigPath);
    await writeFile(legacyConfigPath, "invalid TOML");
    const started = (
      await call("start_codex_security_scan", { sessionId: workspace.id })
    ).workspace;
    assert.deepEqual(started.deepScanConfig, preview);
  } finally {
    await client.close();
    await rm(root, { recursive: true, force: true });
  }
});

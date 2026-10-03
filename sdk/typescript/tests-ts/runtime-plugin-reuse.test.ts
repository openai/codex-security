import { spawn } from "node:child_process";
import { once } from "node:events";
import { cp, mkdir, mkdtemp, realpath, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { expect, test } from "bun:test";
import { bootstrapPlugin } from "../src/runtime.js";

test("repeated bootstrap preserves the plugin directory used by an active worker", async () => {
  const root = await realpath(
    await mkdtemp(join(tmpdir(), "codex-security-plugin-worker-")),
  );
  try {
    const selected = join(root, "plugin");
    const home = join(root, "home");
    const marketplace = join(home, "sdk-marketplace");
    const installed = join(home, "plugins", "cache", "codex-security", "1.2.3");
    const helper = "worker helper remains available\n";
    await mkdir(join(selected, ".codex-plugin"), { recursive: true });
    await writeFile(
      join(selected, ".codex-plugin", "plugin.json"),
      JSON.stringify({ name: "codex-security", version: "1.2.3" }),
    );
    await mkdir(join(selected, "scripts"));
    await writeFile(join(selected, "scripts", "helper.txt"), helper);

    let installs = 0;
    const runCodex: NonNullable<
      NonNullable<Parameters<typeof bootstrapPlugin>[2]>["runCodex"]
    > = async (_command, args) => {
      const addingMarketplace = args[1] === "marketplace";
      await writeFile(
        join(home, "config.toml"),
        `[marketplaces.codex-security-sdk]\nsource_type = "local"\nsource = ${JSON.stringify(marketplace)}\n[plugins."codex-security@codex-security-sdk"]\nenabled = ${!addingMarketplace}\n`,
      );
      if (addingMarketplace) return "";
      installs += 1;
      await rm(installed, { recursive: true, force: true });
      await cp(join(marketplace, "plugins", "codex-security"), installed, {
        recursive: true,
      });
      return JSON.stringify({ installedPath: installed, version: "1.2.3" });
    };
    const options = { codexCommand: { command: process.execPath }, runCodex };
    const first = await bootstrapPlugin(home, selected, options);
    const worker = spawn(
      process.execPath,
      [
        "--eval",
        `process.once("message", () => {
          try {
            process.send(require("node:fs").readFileSync("scripts/helper.txt", "utf8"));
          } catch (error) {
            process.send({ error: String(error) });
          } finally {
            process.disconnect();
          }
        });
        process.send("ready");`,
      ],
      {
        cwd: first.installedRoot,
        stdio: ["ignore", "ignore", "ignore", "ipc"],
      },
    );
    const exited = once(worker, "exit");
    try {
      const [ready] = await Promise.race([once(worker, "message"), exited]);
      expect(ready).toBe("ready");
      const second = await bootstrapPlugin(home, selected, options);
      const response = once(worker, "message");
      worker.send("read");
      const [content] = await Promise.race([response, exited]);
      expect(content).toBe(helper);
      expect(second.installedRoot).toBe(first.installedRoot);
      expect(installs).toBe(1);
    } finally {
      if (worker.exitCode === null && worker.signalCode === null) worker.kill();
      await exited;
    }
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

import { spawn } from "node:child_process";
import { once } from "node:events";
import * as fsPromises from "node:fs/promises";
import { cp, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { expect, spyOn, test } from "bun:test";
import { bootstrapPlugin } from "../src/runtime.js";
import { temporaryDirectory } from "./support/temporary-directories.js";

test.each(["unchanged", "missing", "truncated"] as const)(
  "%s manifest preserves active workers",
  (metadata) => checkWorkerReuse(metadata),
);

test.each(["missing", "truncated"] as const)(
  "concurrent %s manifest repairs preserve active workers",
  (metadata) => checkWorkerReuse(metadata, true),
);

async function checkWorkerReuse(metadata: string, concurrent = false) {
  const root = await temporaryDirectory("codex-security-plugin-worker-", true);
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
    const manifest = join(
      marketplace,
      ".agents",
      "plugins",
      "marketplace.json",
    );
    const expectedManifest = await readFile(manifest, "utf8");
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
      if (metadata === "missing") await rm(manifest);
      else if (metadata === "truncated") await writeFile(manifest, "{");
      const originalWrite = fsPromises.writeFile;
      let writes = 0;
      let releaseWrites = () => {};
      const bothWriting = new Promise<void>((resolve) => {
        releaseWrites = resolve;
      });
      const write = concurrent
        ? spyOn(fsPromises, "writeFile").mockImplementation(async (...args) => {
            // Both repairs reach the filesystem before either write completes.
            if (dirname(String(args[0])) === dirname(manifest)) {
              if (++writes === 2) releaseWrites();
              await bothWriting;
            }
            return originalWrite(...args);
          })
        : undefined;
      try {
        const results = await Promise.allSettled(
          Array.from({ length: concurrent ? 2 : 1 }, () =>
            bootstrapPlugin(home, selected, options),
          ),
        );
        for (const result of results) {
          expect(result.status).toBe("fulfilled");
          if (result.status === "fulfilled") {
            expect(result.value.installedRoot).toBe(first.installedRoot);
          }
        }
      } finally {
        write?.mockRestore();
      }
      const response = once(worker, "message");
      worker.send("read");
      const [content] = await Promise.race([response, exited]);
      expect(content).toBe(helper);
      expect(installs).toBe(1);
      expect(await readFile(manifest, "utf8")).toBe(expectedManifest);
      expect(await fsPromises.readdir(dirname(manifest))).toEqual([
        "marketplace.json",
      ]);
      await bootstrapPlugin(home, selected, options);
      expect(installs).toBe(1);
    } finally {
      if (worker.exitCode === null && worker.signalCode === null) worker.kill();
      await exited;
    }
  } finally {
    await rm(root, { recursive: true, force: true });
  }
}

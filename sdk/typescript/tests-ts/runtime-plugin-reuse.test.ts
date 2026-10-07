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

test.each(["missing", "truncated"] as const)(
  "accepts a concurrent %s manifest repair when replacement fails",
  (metadata) => checkWorkerReuse(metadata, true, true),
);

test.each(["missing", "truncated"] as const)(
  "preserves the replacement error when the %s manifest remains unrepaired",
  (metadata) => checkWorkerReuse(metadata, false, true),
);

async function checkWorkerReuse(
  metadata: string,
  concurrent = false,
  failReplacement = false,
) {
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
      const bothWriting = Promise.withResolvers<void>();
      const write = concurrent
        ? spyOn(fsPromises, "writeFile").mockImplementation(async (...args) => {
            // Both repairs reach the filesystem before either write completes.
            if (dirname(String(args[0])) === dirname(manifest)) {
              if (++writes === 2) bothWriting.resolve();
              await bothWriting.promise;
            }
            return originalWrite(...args);
          })
        : undefined;
      const originalRename = fsPromises.rename;
      const replacementError = Object.assign(
        new Error("synthetic manifest replacement failure"),
        { code: "EPERM" },
      );
      let published: Promise<void> | undefined;
      const rename = failReplacement
        ? spyOn(fsPromises, "rename").mockImplementation(async (...args) => {
            if (String(args[1]) !== manifest) return originalRename(...args);
            if (concurrent) {
              if (published === undefined) {
                published = originalRename(...args);
                return published;
              }
              // Windows can reject replacement after the other repair wins.
              await published;
            }
            throw replacementError;
          })
        : undefined;
      try {
        const results = await Promise.allSettled(
          Array.from({ length: concurrent ? 2 : 1 }, () =>
            bootstrapPlugin(home, selected, options),
          ),
        );
        for (const result of results) {
          if (failReplacement && !concurrent) {
            expect(result.status).toBe("rejected");
            if (result.status === "rejected") {
              expect(result.reason).toBe(replacementError);
            }
          } else {
            if (result.status === "rejected") throw result.reason;
            expect(result.value.installedRoot).toBe(first.installedRoot);
          }
        }
      } finally {
        write?.mockRestore();
        rename?.mockRestore();
      }
      const response = once(worker, "message");
      worker.send("read");
      const [content] = await Promise.race([response, exited]);
      expect(content).toBe(helper);
      expect(installs).toBe(1);
      if (failReplacement && !concurrent) {
        if (metadata === "missing") {
          await expect(readFile(manifest, "utf8")).rejects.toHaveProperty(
            "code",
            "ENOENT",
          );
        } else {
          expect(await readFile(manifest, "utf8")).toBe("{");
        }
        expect(await fsPromises.readdir(dirname(manifest))).toEqual(
          metadata === "missing" ? [] : ["marketplace.json"],
        );
        await bootstrapPlugin(home, selected, options);
      }
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

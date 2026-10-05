import * as childProcess from "node:child_process";
import { writeFileSync } from "node:fs";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { expect, spyOn, test } from "bun:test";
import { runArtifactHelper } from "../src/artifact-export.js";

const cases = [
  ["A", 1],
  ["é", 1],
  ["東", 1],
  ["東", 2],
  ["😀", 1],
  ["😀", 2],
  ["😀", 3],
] as const;

for (const exitCode of [0, 1]) {
  test.each(cases)(
    `preserves split UTF-8 diagnostics at exit ${exitCode} (%s, %i)`,
    async (character, split) => {
      const root = await mkdtemp(join(tmpdir(), "codex-security-utf8-"));
      const script = join(root, "scripts", "finalize_scan_contract.py");
      const marker = join(root, "continue");
      const prefix = "synthetic diagnostic ";
      const suffix = " retained\n";
      const encoded = Buffer.from(character);
      let observedFirstChunk = false;
      const originalSpawn = childProcess.spawn;
      const spawn = spyOn(childProcess, "spawn").mockImplementation(((
        ...args: Parameters<typeof originalSpawn>
      ) => {
        const child = originalSpawn(...args);
        if (Array.isArray(args[1]) && args[1].includes(script)) {
          child.stderr!.once("data", () => {
            observedFirstChunk = true;
            writeFileSync(marker, "continue");
          });
        }
        return child;
      }) as typeof originalSpawn);
      try {
        await mkdir(join(root, "scripts"));
        await writeFile(
          script,
          [
            "import base64, pathlib, sys, time",
            "marker = pathlib.Path(sys.argv[1])",
            "sys.stderr.buffer.write(base64.b64decode(sys.argv[2]))",
            "sys.stderr.buffer.flush()",
            "deadline = time.monotonic() + 5",
            "while not marker.exists():",
            "    if time.monotonic() > deadline: raise RuntimeError('Fixture handshake timed out')",
            "    time.sleep(0.002)",
            "sys.stderr.buffer.write(base64.b64decode(sys.argv[3]))",
            "sys.stderr.buffer.flush()",
            "print('synthetic stdout')",
            "raise SystemExit(int(sys.argv[4]))",
          ].join("\n"),
        );
        const python = Bun.which("python3") ?? Bun.which("python");
        if (python === null)
          throw new Error("Python is required for this test");
        const operation = runArtifactHelper(
          [
            marker,
            Buffer.concat([
              Buffer.from(prefix),
              encoded.subarray(0, split),
            ]).toString("base64"),
            Buffer.concat([
              encoded.subarray(split),
              Buffer.from(suffix),
            ]).toString("base64"),
            String(exitCode),
          ],
          { pluginRoot: root, pythonPath: python },
        );
        if (exitCode === 0) {
          expect(await operation).toEqual({
            stdout: "synthetic stdout\n",
            stderr: prefix + character + suffix,
          });
        } else {
          await expect(operation).rejects.toThrow(
            (prefix + character + suffix).trim(),
          );
        }
        expect(observedFirstChunk).toBe(true);
      } finally {
        spawn.mockRestore();
        await rm(root, { recursive: true, force: true });
      }
    },
  );
}

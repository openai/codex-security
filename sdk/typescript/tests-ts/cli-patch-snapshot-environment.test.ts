import { afterEach, expect, test } from "bun:test";
import { spawn } from "node:child_process";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { createTemporaryDirectories } from "./support/temporary-directories.js";

const fixtures = createTemporaryDirectories(true);
afterEach(fixtures.cleanup);

const source = await readFile(
  new URL("../src/cli.ts", import.meta.url),
  "utf8",
);
const declaration = source.match(
  /const PATCH_GIT_ENVIRONMENT_RUNNER = (`[\s\S]*?`);/u,
);
expect(declaration).not.toBeNull();
const runner = new Function(`return ${declaration![1]};`)() as string;

const nativeGrants = ["C:/synthetic/repository", "C:/synthetic/repository/*"];
const cases = [
  { name: "wildcard reset", caller: ["*", ""], active: [] },
  {
    name: "named reset with a later grant",
    caller: ["C:/cleared", "", "C:/retained"],
    active: ["C:/retained"],
  },
  {
    name: "repeated resets",
    caller: ["*", "", "C:/cleared", "", "C:/retained"],
    active: ["C:/retained"],
  },
  {
    name: "case-insensitive reset key",
    caller: ["*", ""],
    active: [],
    resetKey: "SAFE.Directory",
  },
  {
    name: "caller grant without a reset",
    caller: ["C:/retained"],
    active: ["C:/retained"],
  },
];

for (const platform of ["win32", "linux"] as const) {
  for (const { name, caller, active, resetKey } of cases) {
    test(`constructs snapshot Git arguments with ${name} on ${platform}`, () => {
      const entries = caller.map((value) => [
        value === "" ? (resetKey ?? "safe.directory") : "safe.directory",
        value,
      ]);
      entries.push(["filter.synthetic.clean", "synthetic-clean-filter"]);
      const environment = (values: string[][]) => ({
        GIT_CONFIG_COUNT: String(values.length),
        ...Object.fromEntries(
          values.flatMap(([key, value], index) => [
            [`GIT_CONFIG_KEY_${index}`, key],
            [`GIT_CONFIG_VALUE_${index}`, value],
          ]),
        ),
      });
      const original = environment(entries);
      const filtered = environment([
        ...entries,
        ...nativeGrants.map((value) => ["safe.directory", value]),
      ]);
      const header = Buffer.from(JSON.stringify(Object.entries(original)));
      const input = Buffer.from([0, 255, 10, 13]);
      const frame = Buffer.concat([header, input]);
      let consumed = 0;
      const invocations: {
        command: string;
        args: string[];
        environment: object;
      }[] = [];
      const child = { on() {} };
      const process = {
        platform,
        argv: [
          "node",
          String(header.length),
          "git",
          "-C",
          "C:/synthetic/repository",
          "status",
        ],
        env: filtered,
      };
      // Exercise the exact argument construction without starting a child.
      new Function("require", "process", "Buffer", runner)(
        (module: string) => {
          if (module === "node:fs")
            return {
              readSync(
                fd: number,
                buffer: Buffer,
                offset: number,
                length: number,
              ) {
                expect(fd).toBe(0);
                const bytes = Math.min(length, 7, frame.length - consumed);
                frame.copy(buffer, offset, consumed, consumed + bytes);
                consumed += bytes;
                return bytes;
              },
            };
          expect(module).toBe("node:child_process");
          return {
            spawn(command: string, args: string[], options: object) {
              expect(options).toEqual({ stdio: "inherit" });
              invocations.push({
                command,
                args,
                environment: { ...process.env },
              });
              return child;
            },
          };
        },
        process,
        Buffer,
      );
      expect(invocations).toHaveLength(1);
      expect(invocations[0]!.command).toBe("git");
      expect(invocations[0]!.args).toEqual([
        ...(platform === "win32"
          ? [...active, ...nativeGrants].flatMap((value) => [
              "-c",
              `safe.directory=${value}`,
            ])
          : []),
        "-C",
        "C:/synthetic/repository",
        "status",
      ]);
      expect(invocations[0]!.environment).toMatchObject(original);
      expect(frame.subarray(consumed)).toEqual(input);
    });
  }
}

test("snapshot Git reports an incomplete binding frame before starting the command", async () => {
  const child = spawn(
    process.execPath,
    ["-e", runner, "--", "64", "synthetic-unreachable-command"],
    { stdio: "pipe" },
  );
  let stderr = "";
  let stdout = "";
  child.stderr.setEncoding("utf8").on("data", (chunk) => {
    stderr += chunk;
  });
  child.stdout.setEncoding("utf8").on("data", (chunk) => {
    stdout += chunk;
  });
  const closed = new Promise((resolve, reject) => {
    child.once("error", reject);
    child.once("close", (code, signal) => resolve({ code, signal }));
  });
  child.stdin.end("[");
  expect(await closed).toEqual({ code: 1, signal: null });
  expect(stdout).toBe("");
  expect(stderr).toContain(
    "Snapshot Git bindings ended before the complete frame.",
  );
  expect(stderr).not.toContain("ENOENT");
});

test("snapshot Git launch failures retain diagnostics with a non-emitting stderr stream", async () => {
  const missingGit = join(await fixtures.create("patch-missing-git-"), "git");
  const results: {
    code: number | null;
    signal: string | null;
    stderr: string;
  }[] = [];
  for (const dummyStderr of [false, true]) {
    const prefix = dummyStderr
      ? 'Object.defineProperty(process,"stderr",{value:new (require("node:stream").Writable)({write(chunk,encoding,callback){callback();}})});'
      : "";
    const child = spawn(
      Bun.which("node")!,
      ["-e", prefix + runner, "--", "2", missingGit, "status"],
      { stdio: "pipe" },
    );
    let stderr = "";
    child.stderr.setEncoding("utf8").on("data", (chunk) => {
      stderr += chunk;
    });
    const closed = new Promise<{ code: number | null; signal: string | null }>(
      (resolve, reject) => {
        child.once("error", reject);
        child.once("close", (code, signal) => resolve({ code, signal }));
      },
    );
    child.stdin.end("[]");
    results.push({ ...(await closed), stderr });
  }
  expect(results[0]).toMatchObject({ code: 1, signal: null });
  expect(results[0]!.stderr).toContain(`spawn ${missingGit} ENOENT`);
  expect(results[0]!.stderr).toContain("spawnargs: [ 'status' ]");
  expect(results[1]).toEqual(results[0]);
});

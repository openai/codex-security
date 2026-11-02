import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import test from "node:test";

const builder = new URL(
  "../scripts/build_native_wrappers.mjs",
  import.meta.url,
);
const platform = new URL("../../native/platform.mjs", import.meta.url);
const { buildNativeWrappers } = await import(builder.href);

test("concurrent runtime builds preserve complete native wrapper exports", async () => {
  await buildNativeWrappers();
  const { nativeTarget } = await import(platform.href);
  assert.equal(typeof nativeTarget, "string");
  const source = `
    import assert from 'node:assert/strict';
    import { buildNativeWrappers } from ${JSON.stringify(builder.href)};
    for (let iteration = 0; iteration < 15; iteration++) {
      await buildNativeWrappers();
      const platform = await import(${JSON.stringify(platform.href)} + '?build=' + iteration);
      assert.equal(platform.nativeTarget, ${JSON.stringify(nativeTarget)});
    }
  `;
  await Promise.all(
    Array.from(
      { length: 3 },
      () =>
        new Promise<void>((resolve, reject) => {
          const child = spawn(
            process.execPath,
            ["--input-type=module", "--eval", source],
            {
              stdio: ["ignore", "pipe", "pipe"],
            },
          );
          let output = "";
          child.stdout.on("data", (data) => {
            output += data;
          });
          child.stderr.on("data", (data) => {
            output += data;
          });
          child.once("error", reject);
          child.once("close", (code) => {
            try {
              assert.equal(code, 0, output);
              resolve();
            } catch (error) {
              reject(error);
            }
          });
        }),
    ),
  );
});

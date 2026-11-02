import assert from "node:assert/strict";
import { mkdir, realpath, stat } from "node:fs/promises";
import { join } from "node:path";
import test from "node:test";
import { withAdapter } from "./adapter.mts";

test("runs the command in the requested checkout with literal arguments and the full prompt on stdin", async () => {
  const script = `
    const prompt = require("node:fs").readFileSync(0, "utf8");
    console.log(JSON.stringify({ argv: process.argv.slice(1), cwd: process.cwd(), prompt }));
  `;
  const args = ["--path", "with spaces", "", '"literal" $variable'];
  const prompt = "Review café\nsecond line\n";
  let root = "";
  await withAdapter(
    [process.execPath, "-e", script, "--", ...args],
    async (state) => {
      root = state.root;
      const checkout = join(root, "source");
      await mkdir(checkout);
      assert.deepEqual(await state.run(checkout, prompt), {
        answer: { argv: args, cwd: await realpath(checkout), prompt },
        usage: null,
      });
    },
  );
  await assert.rejects(stat(root), { code: "ENOENT" });
});

for (const { label, script, error } of [
  {
    label: "a nonzero exit even when stdout contains a valid answer",
    script: 'console.log("{}"); process.exitCode = 7;',
    error: /Adapter exited with 7/,
  },
  {
    label: "non-JSON output and reports the offending text",
    script: 'console.log("incomplete answer");',
    error: /Invalid adapter JSON: incomplete answer/,
  },
]) {
  test(`rejects ${label} and cleans up after the failure`, async () => {
    let root = "";
    const argv = [process.execPath, "-e", script];
    await assert.rejects(
      withAdapter(argv, async (state) => {
        root = state.root;
        await state.run(root, "case prompt");
      }),
      error,
    );
    await assert.rejects(stat(root), { code: "ENOENT" });
  });
}

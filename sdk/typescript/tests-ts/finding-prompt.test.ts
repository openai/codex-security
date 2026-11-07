import { readFile, stat } from "node:fs/promises";
import { dirname } from "node:path";
import { expect, test } from "bun:test";
import { MAX_CODEX_INPUT_CHARACTERS } from "../src/codex-prompt.js";
import { prepareFindingPrompt } from "../src/finding-prompt.js";

test("keeps the exact Unicode-character limit inline, including prompt overhead", async () => {
  const finding = "🦞".repeat(MAX_CODEX_INPUT_CHARACTERS - 2);
  await using prepared = await prepareFindingPrompt(
    finding,
    (data) => `[${data}]`,
  );
  expect(prepared.prompt).toBe(`[${finding}]`);
});

test.each([false, true])(
  "keeps complete oversized data until disposal (failure=%p)",
  async (fail) => {
    const finding = JSON.stringify({
      evidence: '"\\\n🦞'.repeat(200_000),
      tail: "Final evidence",
    });
    let path = "";
    const run = async () => {
      await using prepared = await prepareFindingPrompt(
        finding,
        (data) => `Finding:\n${data}`,
      );
      expect(prepared.prompt.length).toBeLessThan(MAX_CODEX_INPUT_CHARACTERS);
      path = JSON.parse(prepared.prompt.match(/^".*finding\.json"$/m)![0]);
      expect(await readFile(path, "utf8")).toBe(finding);
      if (process.platform !== "win32") {
        expect((await stat(path)).mode & 0o777).toBe(0o600);
        expect((await stat(dirname(path))).mode & 0o777).toBe(0o700);
      }
      if (fail) throw new Error("Synthetic task failure");
    };
    if (fail) await expect(run()).rejects.toThrow("Synthetic task failure");
    else await run();
    await expect(stat(dirname(path))).rejects.toMatchObject({ code: "ENOENT" });
  },
);

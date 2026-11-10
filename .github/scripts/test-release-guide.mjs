import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { extractHistoricalReleaseSummary } from "../../sdk/typescript/scripts/release-automation.mjs";

test("the release recovery guide documents a canonical historical-summary block", () => {
  const guide = readFileSync(
    new URL("../../RELEASING.md", import.meta.url),
    "utf8",
  );
  const recovery = guide.split("## Recover or repair a release")[1] ?? "";
  const start = "<!-- codex-security-release-summary:start -->";
  const end = "<!-- codex-security-release-summary:end -->";
  const block = [...recovery.matchAll(/^```text\r?\n([\s\S]*?)^```[ \t]*$/gmu)]
    .map((match) => match[1].replaceAll("\r\n", "\n"))
    .find((example) => example.includes(start) && example.includes(end));

  assert.ok(block?.startsWith(`${start}\n`));
  assert.ok(block.includes(`${end}\n\n`));
  assert.equal(extractHistoricalReleaseSummary(block), "Reviewed summary");
});

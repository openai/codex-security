import { expect, test } from "bun:test";
import { securityPolicyUnifiedDiff } from "../src/security-policy-diff.js";

const header = "--- a/SECURITY.md\n+++ b/SECURITY.md\n";
const missingNewline = "\n\\ No newline at end of file\n";
const diff = (before: string, after: string, signal?: AbortSignal) =>
  securityPolicyUnifiedDiff(
    before,
    after,
    "a/SECURITY.md",
    "b/SECURITY.md",
    signal,
  );

// Expected output comes from the original LF-only Python difflib wrapper.
test.each([
  ["empty files", "", "", ""],
  ["unchanged unterminated content", "same", "same", ""],
  ["insertion into an empty file", "", "added\n", "@@ -0,0 +1 @@\n+added\n"],
  ["deletion of the entire file", "old\n", "", "@@ -1 +0,0 @@\n-old\n"],
  [
    "missing final newlines on both changed lines",
    "old",
    "new",
    `@@ -1 +1 @@\n-old${missingNewline}+new${missingNewline}`,
  ],
  [
    "adding a final newline",
    "same",
    "same\n",
    `@@ -1 +1 @@\n-same${missingNewline}+same\n`,
  ],
  [
    "removing a final newline",
    "same\n",
    "same",
    `@@ -1 +1 @@\n-same\n+same${missingNewline}`,
  ],
  [
    "retaining CR and Unicode line separators inside LF-delimited lines",
    "old\r\nretained\rline\u2028\u2029\nend",
    "new\r\nretained\rline\u2028\u2029\nend",
    `@@ -1,3 +1,3 @@\n-old\r\n+new\r\n retained\rline\u2028\u2029\n end${missingNewline}`,
  ],
  [
    "breaking matching ties by earliest position in the old file",
    "A\nB\n",
    "B\nA\n",
    "@@ -1,2 +1,2 @@\n+B\n A\n-B\n",
  ],
  [
    "then breaking matching ties by earliest position in the new file",
    "A\nB\n",
    "X\nA\nB\nY\nA\nB\n",
    "@@ -1,2 +1,6 @@\n+X\n A\n B\n+Y\n+A\n+B\n",
  ],
  [
    "finding the longest match before extending a common prefix",
    "A\nB\n",
    "A\nC\nA\nB\n",
    "@@ -1,2 +1,4 @@\n+A\n+C\n A\n B\n",
  ],
  [
    "disabling autojunk below 200 new-file lines",
    "A\n".repeat(198),
    "B\n" + "A\n".repeat(198),
    "@@ -1,3 +1,4 @@\n+B\n" + " A\n".repeat(3),
  ],
  [
    "enabling autojunk at 200 new-file lines",
    "A\n".repeat(199),
    "B\n" + "A\n".repeat(199),
    "@@ -1,199 +1,200 @@\n" + "-A\n".repeat(199) + "+B\n" + "+A\n".repeat(199),
  ],
  [
    "keeping three occurrences eligible at 200 lines",
    "R\n".repeat(3),
    "X\n" + "R\n".repeat(3) + "F\n".repeat(196),
    "@@ -1,3 +1,200 @@\n+X\n" + " R\n".repeat(3) + "+F\n".repeat(196),
  ],
  [
    "excluding four occurrences as popular at 200 lines",
    "R\n".repeat(4),
    "X\n" + "R\n".repeat(4) + "F\n".repeat(195),
    "@@ -1,4 +1,200 @@\n" +
      "-R\n".repeat(4) +
      "+X\n" +
      "+R\n".repeat(4) +
      "+F\n".repeat(195),
  ],
  [
    "extending popular lines on both sides of a rare matching anchor",
    "R\n".repeat(99) + "A\n" + "R\n".repeat(100),
    "X\n" + "R\n".repeat(99) + "A\n" + "R\n".repeat(100),
    "@@ -1,3 +1,4 @@\n+X\n" + " R\n".repeat(3),
  ],
])("%s", async (_name, before, after, expected) => {
  expect(await diff(before, after)).toBe(expected ? header + expected : "");
});

test.each([6, 7])(
  "groups changes separated by %d unchanged lines with three lines of context",
  async (count) => {
    const context = Array.from({ length: count }, (_, i) => `${i + 1}\n`);
    const before = "old\n" + context.join("") + "old\n";
    const after = "new\n" + context.join("") + "new\n";
    const expected =
      count === 6
        ? "@@ -1,8 +1,8 @@\n-old\n+new\n" +
          context.map((line) => " " + line).join("") +
          "-old\n+new\n"
        : "@@ -1,4 +1,4 @@\n-old\n+new\n 1\n 2\n 3\n" +
          "@@ -6,4 +6,4 @@\n 5\n 6\n 7\n-old\n+new\n";
    expect(await diff(before, after)).toBe(header + expected);
  },
);

test("honors an already aborted signal", async () => {
  const reason = new Error("cancelled");
  await expect(diff("old\n", "new\n", AbortSignal.abort(reason))).rejects.toBe(
    reason,
  );
});

test("allows cancellation inside repetitive-line matching", async () => {
  const controller = new AbortController();
  const reason = new Error("cancelled");
  // Tokenization and indexing fit within one work batch; matching takes many.
  const result = diff(
    "A\n".repeat(199),
    "B\n" + "A\n".repeat(198),
    controller.signal,
  );
  setImmediate(() => controller.abort(reason));
  await expect(result).rejects.toBe(reason);
});

test("keeps the event loop responsive while completing repetitive-line matching", async () => {
  let heartbeatRan = false;
  const result = diff("A\n".repeat(198), "B\n" + "A\n".repeat(198));
  const heartbeat = new Promise<void>((resolve) => {
    setImmediate(() => {
      heartbeatRan = true;
      resolve();
    });
  });
  const output = await result;
  const yieldedBeforeCompletion = heartbeatRan;
  await heartbeat;
  expect(yieldedBeforeCompletion).toBe(true);
  expect(output).toBe(header + "@@ -1,3 +1,4 @@\n+B\n" + " A\n".repeat(3));
});

import { expect, test } from "bun:test";
import { loadBundledRuntime } from "./plugin-root.js";

test("does not request completed findings after a prompt-only scan", async () => {
  const runtime = await loadBundledRuntime();
  const source = /function promptOnlyScanResult\([^\n]*\) \{[\s\S]*?\n\}/u.exec(
    runtime,
  )?.[0];
  expect(source).toBeDefined();

  const promptOnlyScanResult = new Function(
    "isJsonObject2",
    "string2",
    "toolErrorResult",
    `${source}\nreturn promptOnlyScanResult;`,
  )(
    (value: unknown) => value !== null && typeof value === "object",
    () => ({ uuid: () => ({ safeParse: () => ({ success: true }) }) }),
    (message: string) => ({ content: [{ text: message }], isError: true }),
  ) as (input: {
    startDisposition: string;
    scan: { scanId: string; scanDir: string; handoffStatus: string };
    workspace: { results: { scanId: string } };
  }) => { content: { text: string }[]; isError?: boolean };

  const scanId = "00000000-0000-4000-8000-000000000000";
  const result = promptOnlyScanResult({
    startDisposition: "created",
    scan: { scanId, scanDir: "/tmp/scan", handoffStatus: "delivered" },
    workspace: { results: { scanId } },
  });

  expect(result.isError).toBeUndefined();
  expect(result.content[0]?.text).toContain("complete_codex_security_scan");
  expect(result.content[0]?.text).not.toContain(
    "get_codex_security_completed_scan",
  );
  expect(runtime).toContain('name: "get_codex_security_completed_scan"');
});

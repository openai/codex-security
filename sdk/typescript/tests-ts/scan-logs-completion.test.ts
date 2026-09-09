import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { expect, test } from "bun:test";
import { readScanLogs } from "../src/scan-logs.js";

test("excludes same-thread events emitted after saved scan completion", async () => {
  const home = await mkdtemp(join(tmpdir(), "codex-security-scan-log-boundary-"));
  const directory = join(home, "sessions", "2026", "08", "18");
  const path = join(directory, "rollout-parent.jsonl");
  await mkdir(directory, { recursive: true });

  try {
    await writeFile(
      path,
      [
        {
          type: "session_meta",
          payload: {
            id: "parent",
            timestamp: "2026-08-18T08:00:00.000Z",
          },
        },
        {
          type: "response_item",
          timestamp: "2026-08-18T08:01:00.000Z",
          payload: { type: "message", role: "assistant", content: "SCAN EVENT" },
        },
        {
          type: "response_item",
          timestamp: "2026-08-18T08:03:00.000Z",
          payload: {
            type: "message",
            role: "assistant",
            content: "POST SCAN EVENT",
          },
        },
        {
          type: "response_item",
          payload: { type: "message", role: "assistant", content: "LEGACY EVENT" },
        },
      ]
        .map((event) => JSON.stringify(event))
        .join("\n"),
    );

    const result = await readScanLogs({
      scanId: "scan-1",
      threadId: "parent",
      codexHome: home,
      completedAt: "2026-08-18T08:02:00.000Z",
    });
    const serialized = JSON.stringify(result);

    expect(serialized).toContain("SCAN EVENT");
    expect(serialized).toContain("LEGACY EVENT");
    expect(serialized).not.toContain("POST SCAN EVENT");
  } finally {
    await rm(home, { recursive: true, force: true });
  }
});

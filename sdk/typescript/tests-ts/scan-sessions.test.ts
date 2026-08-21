import { expect, test } from "bun:test";
import { sessionParentThreadId } from "../src/scan-sessions.js";

test.each([
  [
    "prefers the spawned parent over legacy parent fields",
    {
      source: {
        subagent: { thread_spawn: { parent_thread_id: "spawn-parent" } },
      },
      parent_thread_id: "direct-parent",
      forked_from_id: "fork-parent",
    },
    "spawn-parent",
  ],
  [
    "prefers the direct parent over fork ancestry",
    { parent_thread_id: "direct-parent", forked_from_id: "fork-parent" },
    "direct-parent",
  ],
  [
    "falls back from an empty spawned parent to the direct parent",
    {
      source: { subagent: { thread_spawn: { parent_thread_id: "" } } },
      parent_thread_id: "direct-parent",
    },
    "direct-parent",
  ],
  [
    "falls back from an empty direct parent to fork ancestry",
    { parent_thread_id: "", forked_from_id: "fork-parent" },
    "fork-parent",
  ],
  [
    "ignores a non-string direct parent when fork ancestry is present",
    { parent_thread_id: null, forked_from_id: "fork-parent" },
    "fork-parent",
  ],
  ["recognizes independent CLI sessions", { source: "cli" }, null],
  ["treats an empty parent as missing", { forked_from_id: "" }, null],
] as const)("session parent metadata %s", (_name, metadata, expected) => {
  expect(sessionParentThreadId(metadata)).toBe(expected);
});

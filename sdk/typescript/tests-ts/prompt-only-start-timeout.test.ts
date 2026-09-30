import { expect, test } from "bun:test";
import { workbenchCommandTimeout } from "../../../plugins/codex-security/mcp-app/src/python_command.js";

test("gives prompt-only startup the same timeout as other scan operations", () => {
  expect(workbenchCommandTimeout("start-prompt-only-scan")).toBe(300_000);
  expect(workbenchCommandTimeout("start-scan")).toBe(300_000);
  expect(workbenchCommandTimeout("other-operation")).toBe(30_000);
});

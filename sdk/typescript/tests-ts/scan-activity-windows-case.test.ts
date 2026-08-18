import { describe, expect, test } from "bun:test";
import {
  scanActivityFromEvent,
  scanActivityFromSessionEvent,
} from "../src/scan-activity.js";

function toolEvent(path: string): Record<string, unknown> {
  return {
    type: "item.started",
    item: {
      id: "tool-1",
      type: "mcp_tool_call",
      tool: "read_file",
      arguments: { path },
      status: "in_progress",
    },
  };
}

function commandEvent(command: string): Record<string, unknown> {
  return {
    type: "item.started",
    item: {
      id: "command-1",
      type: "command_execution",
      command,
      status: "in_progress",
    },
  };
}

describe("Windows activity path casing", () => {
  test("preserves repository paths when Windows casing differs", () => {
    const repository = "C:\\code\\juice-shop";
    const path = "c:\\CODE\\JUICE-SHOP\\routes\\Login.ts";

    expect(scanActivityFromEvent(toolEvent(path), repository)).toMatchObject({
      paths: ["routes/Login.ts"],
    });
    expect(
      scanActivityFromSessionEvent(
        {
          type: "response_item",
          payload: {
            type: "function_call",
            name: "read_file",
            call_id: "worker-tool-1",
            arguments: JSON.stringify({ path }),
          },
        },
        repository,
      ),
    ).toMatchObject({ paths: ["routes/Login.ts"] });
    expect(
      scanActivityFromEvent(
        commandEvent('type "c:\\CODE\\JUICE-SHOP\\routes\\Login.ts"'),
        repository,
      ),
    ).toMatchObject({ paths: ["routes/Login.ts"] });
  });

  test("matches UNC repository roots case-insensitively", () => {
    expect(
      scanActivityFromEvent(
        toolEvent("\\\\server\\share\\REPO\\src\\auth.ts"),
        "\\\\Server\\Share\\repo",
      ),
    ).toMatchObject({ paths: ["src/auth.ts"] });
  });

  test("keeps POSIX repository matching case-sensitive", () => {
    expect(
      scanActivityFromEvent(
        toolEvent("/code/Juice-Shop/routes/login.ts"),
        "/code/juice-shop",
      ),
    ).toMatchObject({ paths: [] });
  });
});

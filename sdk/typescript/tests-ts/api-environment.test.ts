import { describe, expect, test } from "bun:test";
import { environmentValue } from "../src/api.js";

describe("environmentValue", () => {
  test("treats empty values as unset and finds case variants", () => {
    expect(environmentValue({ CODEX_HOME: "" }, "CODEX_HOME")).toBeUndefined();
    expect(
      environmentValue({ CODEX_HOME: "   " }, "CODEX_HOME"),
    ).toBeUndefined();
    expect(
      environmentValue(
        { CODEX_HOME: "", Codex_Home: "/ambient" },
        "CODEX_HOME",
      ),
    ).toBe("/ambient");
    expect(environmentValue({ Home: "/shell-home" }, "HOME")).toBe(
      "/shell-home",
    );
  });
});

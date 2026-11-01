import { describe, expect, test } from "bun:test";
import {
  environmentValue,
  formatEnvironmentVariableRemovalGuidance,
} from "../src/api.js";

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

describe("formatEnvironmentVariableRemovalGuidance", () => {
  test("lists one, two, or more names without a shell command", () => {
    expect(formatEnvironmentVariableRemovalGuidance([])).toBe(
      "remove OPENAI_API_KEY and CODEX_API_KEY from the environment",
    );
    expect(formatEnvironmentVariableRemovalGuidance(["OPENAI_API_KEY"])).toBe(
      "remove OPENAI_API_KEY from the environment",
    );
    expect(
      formatEnvironmentVariableRemovalGuidance([
        "OPENAI_API_KEY",
        "CODEX_API_KEY",
      ]),
    ).toBe("remove OPENAI_API_KEY and CODEX_API_KEY from the environment");
    expect(
      formatEnvironmentVariableRemovalGuidance([
        "OPENAI_API_KEY",
        "CODEX_API_KEY",
        "Codex_Api_Key",
      ]),
    ).toBe(
      "remove OPENAI_API_KEY, CODEX_API_KEY, and Codex_Api_Key from the environment",
    );
    expect(
      formatEnvironmentVariableRemovalGuidance(["OPENAI_API_KEY"]),
    ).not.toContain("unset");
  });
});

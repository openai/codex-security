import { expect, test } from "bun:test";
import { relativePath } from "../src/scanner-import.js";

test("scanner repository paths retain colons outside Windows drive prefixes", () => {
  expect(relativePath("schema:prod.json")).toBe("schema:prod.json");
  expect(relativePath("src/schema:prod.ts")).toBe("src/schema:prod.ts");
  for (const path of [
    "C:\\project\\source.ts",
    "C:source.ts",
    "/source.ts",
    "../source.ts",
  ])
    expect(relativePath(path)).toBeNull();
});

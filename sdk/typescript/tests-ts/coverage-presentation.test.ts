import { describe, expect, test } from "bun:test";
import {
  formatCoverageScope,
  formatScopePath,
} from "../src/coverage-presentation.js";

describe("coverage scope presentation", () => {
  test("distinguishes included paths from exclusions and preserves Unicode", () => {
    expect(
      formatCoverageScope({
        mode: "scoped_path",
        includePaths: ["src; excluding tests", "src/cafe\u0301.ts"],
        excludePaths: ["generated/**"],
        explicitExclusions: [
          { pattern: "generated/**", reason: "Generated source" },
          { pattern: "fixtures", reason: "Fixtures" },
        ],
      }),
    ).toBe(
      'scoped paths: "src; excluding tests", src/cafe\u0301.ts; excluding generated/**, fixtures',
    );
  });

  test("quotes whitespace and escapes terminal controls without changing path data", () => {
    for (const path of [
      "src/a  b.ts",
      "src/trailing ",
      'src/"quoted"',
      "src/line\nfeed",
      "src/\u001b[31m",
      "src/\u009b31m",
    ]) {
      const encoded = formatScopePath(path);
      expect(encoded).not.toMatch(/[\u0000-\u001f\u007f-\u009f]/u);
      expect(JSON.parse(encoded)).toBe(path);
    }
    expect(formatScopePath("src/parser.ts")).toBe("src/parser.ts");
  });

  test("shows an empty included scope without implying whole-repository coverage", () => {
    expect(
      formatCoverageScope({
        mode: "diff",
        includePaths: [],
        excludePaths: [],
      }),
    ).toBe("diff: (no included paths)");
  });
});

import { describe, expect, test } from "bun:test";
import { findingToOcsf } from "../src/continuum-validation-provider.js";

const when = new Date("2026-01-01T00:00:00Z");
const base = {
  occurrenceId: "occ_example",
  title: "Example record filter",
  summary: "The demo returns records from both example groups.",
  path: "src/filter.ts",
  lineNumber: 10,
};
const method = "Query the fixture as group A.";
const observation =
  "  The fixture returned two rows.\nOne had the “group B” marker.  ";
const finding = {
  ...base,
  validation: {
    method,
    summary: observation,
    evidence: ["private artifact contents"],
    evidenceRefs: ["private artifact path"],
    commands: ["private command"],
    unknown: "private extra field",
  },
  rootCause: { code: "private source" },
  provenance: { metadata: "private metadata" },
};
const optedIn = { includeLocalValidation: true };

describe("local validation in outbound OCSF", () => {
  test("requires explicit opt-in outside the finding", () => {
    const baseline = findingToOcsf(base, when);
    expect(
      findingToOcsf({ ...finding, includeLocalValidation: true }, when),
    ).toEqual(baseline);
    expect(
      findingToOcsf(finding, when, { includeLocalValidation: false }),
    ).toEqual(baseline);
  });

  test("preserves both local strings exactly in each description and nothing else", () => {
    const plain = findingToOcsf(base, when);
    const description =
      base.summary +
      "\n\nCodex local validation method\n" +
      method +
      "\n\nCodex local validation summary\n" +
      observation;
    const expected = {
      ...plain,
      message: description,
      finding_info: { ...(plain["finding_info"] as object), desc: description },
      vulnerabilities: [
        { ...(plain["vulnerabilities"] as object[])[0], desc: description },
      ],
    };
    expect(findingToOcsf(finding, when, optedIn)).toEqual(expected);
  });

  test("ignores missing, blank and non-string validation fields", () => {
    for (const validation of [
      undefined,
      null,
      "private",
      ["private"],
      { method: " \n", summary: {} },
      { summary: ["private"] },
    ]) {
      expect(findingToOcsf({ ...base, validation }, when, optedIn)).toEqual(
        findingToOcsf(base, when),
      );
    }
    expect(
      findingToOcsf(
        { ...base, validation: { summary: observation } },
        when,
        optedIn,
      )["message"],
    ).toBe(base.summary + "\n\nCodex local validation summary\n" + observation);
  });

  test("rejects overlong descriptions without truncating the observation", () => {
    const prefix = base.summary + "\n\nCodex local validation summary\n";
    const summary = "x".repeat(65_536 - prefix.length - 1) + "📋";
    const convert = (value: string) =>
      findingToOcsf({ ...base, validation: { summary: value } }, when, optedIn);
    expect(convert(summary)["message"]).toBe(prefix + summary);
    expect(() => convert(summary + "x")).toThrow("65,536");
  });

  test("counts the entire serialized document, including escaping and UTF-8 expansion", () => {
    for (const summary of ["\u0001".repeat(15_000), "📋".repeat(22_000)]) {
      expect(() =>
        findingToOcsf({ ...base, validation: { summary } }, when, optedIn),
      ).toThrow("256 KiB");
    }
  });
});

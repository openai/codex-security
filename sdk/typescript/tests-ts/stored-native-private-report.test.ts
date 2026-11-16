import { expect, test } from "bun:test";
import { normalizeEndorFindings } from "../src/endor-findings.js";
import {
  selectPrivateReport,
  type PrivateImportContext,
} from "../src/private-finding-import.js";
import { normalizeWizJson } from "../src/wiz-findings.js";
import { endorFinding } from "./support/endor-import-fixtures.js";

const structured = "security.findings.v1";
const context = (formats: string[]): PrivateImportContext => ({
  object: "security.finding_import_context",
  context_version: "current",
  can_upload: true,
  can_create_import_jobs: true,
  can_read: true,
  formats,
  limits: { max_direct_file_bytes: 1_000_000, max_record_bytes: 100_000 },
});

const wiz = {
  id: "wiz-id",
  name: "CVE-2099-0001",
  severity: "HIGH",
  detailedName: "lodash",
  vulnerableAsset: { id: "asset" },
};
for (const { provider, format, normalized, payload } of [
  {
    provider: "wiz",
    format: "wiz.vulnerability_json.v1",
    normalized: normalizeWizJson([wiz], "cloud"),
    payload: [wiz],
  },
  {
    provider: "endor",
    format: "endor.findings_json.v1",
    normalized: normalizeEndorFindings(endorFinding()),
    payload: { list: { objects: [endorFinding()] } },
  },
] as const) {
  test(`${provider} encodes native-only uploads from reviewed rows and pins the format on retry`, () => {
    const selected = normalized.findings;
    const native = context([format]);
    const report = selectPrivateReport(selected, provider, native);
    expect(report.format).toBe(format);
    expect(JSON.parse(report.bytes)).toEqual(payload);

    const both = context([format, structured]);
    expect(selectPrivateReport(selected, provider, both).format).toBe(
      structured,
    );
    expect(selectPrivateReport(selected, provider, both, format)).toEqual(
      report,
    );
    const edited = structuredClone(selected);
    edited[0]!.evidence.title += " (reviewed)";
    for (const limit of [
      "max_record_bytes",
      "max_direct_file_bytes",
    ] as const) {
      const constrained = context([format, structured]);
      constrained.limits[limit] = Buffer.byteLength(report.bytes);
      expect(selectPrivateReport(selected, provider, constrained)).toEqual(
        report,
      );
      expect(() =>
        selectPrivateReport(selected, provider, constrained, structured),
      ).toThrow("limit");
      expect(() => selectPrivateReport(edited, provider, constrained)).toThrow(
        "limit",
      );
    }
    expect(() => selectPrivateReport(edited, provider, native)).toThrow(
      "represented exactly",
    );
    native.limits.max_record_bytes = 1;
    expect(() => selectPrivateReport(selected, provider, native)).toThrow(
      "limits",
    );
  });
}

test("Endor rows that omit oversized native enrichment require structured upload", () => {
  const base = endorFinding();
  const { target_dependency_name: _, ...spec } = base.spec;
  const raw = {
    ...base,
    spec: { ...spec, target_dependency_package_name: "a".repeat(513) },
  };
  const selection = normalizeEndorFindings(raw);
  const native = context(["endor.findings_json.v1"]);
  expect(selection.findings).toHaveLength(1);
  expect(() =>
    selectPrivateReport(selection.findings, "endor", native),
  ).toThrow(structured);
});

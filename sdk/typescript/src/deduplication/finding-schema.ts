import { readFileSync } from "node:fs";
import Ajv2020, { type ValidateFunction } from "ajv/dist/2020.js";
import type { Finding } from "../models.js";

type FindingSchema = {
  type: string;
  properties: Record<string, object> & { locations: object };
  required: string[];
  $defs: Record<string, object>;
};

const scannerFields = [
  "ruleId",
  "identity",
  "taxonomy",
  "remediation",
] as const;
type ScannerField = (typeof scannerFields)[number];
export type ImportedFinding = Pick<
  Finding,
  | "findingId"
  | "occurrenceId"
  | "fingerprints"
  | "title"
  | "summary"
  | "severity"
  | "confidence"
  | "provenance"
> &
  Partial<Pick<Finding, ScannerField>> & {
    locations: Finding["locations"][number][];
    [extension: string]: unknown;
  };

let schema: FindingSchema | undefined;
let importedValidator: ValidateFunction<ImportedFinding> | undefined;
let validator: ValidateFunction<Finding> | undefined;

export function findingSchema(): FindingSchema {
  if (schema) return schema;
  const document = JSON.parse(
    readFileSync(
      new URL(
        "../../_bundled_plugin/schemas/findings.schema.json",
        import.meta.url,
      ),
      "utf8",
    ),
  );
  return (schema = {
    ...document.properties.findings.items,
    $defs: document.$defs,
  });
}

export function requireFinding(value: unknown): Finding {
  validator ??= new Ajv2020({ strict: false }).compile<Finding>(
    findingSchema(),
  );
  if (!validator(value))
    throw new Error(
      "Record must satisfy the Finding schema, including provenance.",
    );
  return value;
}

/** Imports retain their source evidence even when no scanner classified or located it. */
export function importedFindingSchema(): FindingSchema {
  const native = findingSchema();
  return {
    ...native,
    required: native.required.filter(
      (name) => !scannerFields.some((field) => field === name),
    ),
    properties: {
      ...native.properties,
      locations: { ...native.properties.locations, minItems: 0 },
    },
  };
}

export function requireImportedFinding(value: unknown): ImportedFinding {
  importedValidator ??= new Ajv2020({ strict: false }).compile<ImportedFinding>(
    importedFindingSchema(),
  );
  if (!importedValidator(value))
    throw new Error(
      "Record must satisfy the imported finding schema, including source provenance.",
    );
  return value;
}

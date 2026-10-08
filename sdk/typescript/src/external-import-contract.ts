import Ajv2020 from "ajv/dist/2020.js";
import schema from "../schemas/external-findings.schema.json" with { type: "json" };
import type {
  ExternalFindingEvidence,
  FindingImportRequest,
  FindingImportReceipt,
  ImportRepositoryPage,
  SourceReportPage,
  SourceReport,
} from "./external-import-models.js";

const ajv = new Ajv2020({
  strict: false,
  validateFormats: false,
  useDefaults: true,
});

function validator<T>(name: keyof typeof schema.$defs) {
  const check = ajv.compile<T>({
    $defs: schema.$defs,
    $ref: `#/$defs/${name}`,
  });
  return (input: unknown): T => {
    if (!check(input))
      throw new Error(`${name}: ${ajv.errorsText(check.errors)}`);
    return input;
  };
}

const evidence = validator<ExternalFindingEvidence>("ImportedFindingEvidence");
const request = validator<FindingImportRequest>("FindingImportRequest");
export const validateImportReceipt = validator<FindingImportReceipt>(
  "FindingImportReceipt",
);
export const validateRepositories = validator<ImportRepositoryPage>(
  "ImportRepositoryPage",
);
export const validateSourceReports =
  validator<SourceReportPage>("SourceReportPage");
export const validateSourceReport = validator<SourceReport>("SourceReport");

export function validateExternalEvidence(
  input: unknown,
): ExternalFindingEvidence {
  const result = evidence(input);
  if (!result.title.trim())
    throw new Error("Evidence title must not be empty.");
  if (Buffer.byteLength(JSON.stringify(result)) > 256 * 1024)
    throw new Error("Evidence exceeds the Cloud limit of 256 KiB.");
  return result;
}

export function validateImportRequest(input: unknown): FindingImportRequest {
  const result = request(input);
  for (const item of result.items) validateExternalEvidence(item.evidence);
  if (Buffer.byteLength(JSON.stringify(result)) > 5 * 1024 * 1024)
    throw new Error("Import exceeds the Cloud limit of 5 MiB.");
  return result;
}

import { isIP } from "node:net";
import { isNumberObject, isProxy } from "node:util/types";
import Ajv2020, { type ValidateFunction } from "ajv/dist/2020.js";
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

/** Local storage accepts complete evidence; Cloud publication has payload limits. */
export type ExternalImportTarget = "local" | "cloud";

const localSchema = JSON.parse(
  JSON.stringify(schema, (key, value: unknown) =>
    key === "maxLength" || key === "maxItems" ? undefined : value,
  ),
) as typeof schema;
const STRING_BYTE_LIMITS: Readonly<Record<string, number>> = {
  description: 65536,
  snippet: 65536,
  remediation_instructions: 65536,
  expected: 65536,
  actual: 65536,
  file_url: 2048,
  path: 2048,
  url: 2048,
  manifest_path: 2048,
  client_id: 128,
  next: 4096,
};

/** Compare repository URLs without changing the retained vendor evidence.
 * GitHub repository paths are case-insensitive; unknown VCS hosts stay strict.
 * Keep protocols and explicit ports distinct, matching the Cloud URL contract. */
export function repositoryUrlKey(value: string): string {
  const normalized = value.replace(/\/$/u, "").replace(/\.git$/u, "");
  const parts = /^(https?):\/\/([^/?#]+)((?:\/[^?#]*)?)((?:[?#].*)?)$/iu.exec(
    normalized,
  );
  if (!parts) return normalized;
  const authority = parts[2]!.toLowerCase();
  const hostname = authority.replace(/:\d+$/u, "");
  const path =
    hostname === "github.com" || hostname.endsWith(".ghe.com")
      ? parts[3]!.toLowerCase()
      : parts[3]!;
  return `${parts[1]!.toLowerCase()}://${authority}${path}${parts[4]!}`;
}

// Cloud's import catalog contains GitHub repositories, including custom Enterprise
// hosts. Match its case-insensitive URL identity without merging schemes or ports.
export function cloudRepositoryUrlKey(value: string): string {
  return repositoryUrlKey(value).toLowerCase();
}

// Cloud ImportModel applies these constraints to both requests and responses.
// Its UTF-8 limits are not exported as JSON Schema character limits: even a
// plain string field such as a receipt error message inherits the 512-byte bound.
function validateModelStrings(
  input: unknown,
  target: ExternalImportTarget,
): void {
  if (input === null || typeof input !== "object") return;
  if (Array.isArray(input)) {
    for (const item of input) validateModelStrings(item, target);
    return;
  }
  for (const [field, value] of Object.entries(input)) {
    if (field === "source_data") continue;
    if (typeof value === "string") {
      if (
        (!value.trim() && !["snippet", "expected", "actual"].includes(field)) ||
        value.includes("\0")
      )
        throw new Error(
          `${field} must be nonempty and contain no NUL characters.`,
        );
      const limit = STRING_BYTE_LIMITS[field] ?? 512;
      if (target === "cloud" && Buffer.byteLength(value) > limit)
        throw new Error(
          `${field} exceeds its Cloud limit of ${limit} UTF-8 bytes.`,
        );
    } else if (
      Array.isArray(value) &&
      value.every((item) => typeof item === "string")
    ) {
      if (
        target === "cloud" &&
        value.some((item) => Buffer.byteLength(item) > 512)
      )
        throw new Error(
          `${field} entries exceed the Cloud limit of 512 UTF-8 bytes.`,
        );
    } else validateModelStrings(value, target);
  }
}

type ModelSchema = {
  $ref?: string;
  anyOf?: ModelSchema[];
  properties?: Record<string, ModelSchema>;
  [key: string]: unknown;
};
const detailValidators = new Map<string, ReturnType<typeof ajv.compile>>();

/** AJV does not apply defaults through nullable anyOf references. Validate the
 * present detail objects directly against their generated model definitions so
 * sparse normalized inputs match the backend's serialized evidence. */
function materializeDetailDefaults(
  value: unknown,
  fieldSchema: ModelSchema,
  target: ExternalImportTarget,
): void {
  if (value === null || typeof value !== "object" || Array.isArray(value))
    return;
  const reference =
    fieldSchema.$ref ?? fieldSchema.anyOf?.find((branch) => branch.$ref)?.$ref;
  if (!reference) return;
  const name = reference.split("/").at(-1)!;
  const modelSchema = target === "local" ? localSchema : schema;
  const definition: ModelSchema =
    modelSchema.$defs[name as keyof typeof schema.$defs]!;
  const key = `${target}:${reference}`;
  let check = detailValidators.get(key);
  if (!check) {
    check = ajv.compile({ $defs: modelSchema.$defs, $ref: reference });
    detailValidators.set(key, check);
  }
  if (!check(value))
    throw new Error(`${name}: ${ajv.errorsText(check.errors)}`);
  for (const [field, childSchema] of Object.entries(
    definition.properties ?? {},
  ))
    materializeDetailDefaults(
      (value as Record<string, unknown>)[field],
      childSchema,
      target,
    );
}

function normalizeEvidenceDetails(
  value: unknown,
  target: ExternalImportTarget,
): void {
  if (value !== null && typeof value === "object") {
    const fields = value as Record<string, unknown>;
    // Cloud omits these new optional fields when null. Preserve every legacy
    // default so saved Wiz requests still replay the same evidence bytes.
    if (Array.isArray(fields["packages"]))
      for (const value of fields["packages"]) {
        if (
          value &&
          typeof value === "object" &&
          value["vulnerable_version_range"] === null
        )
          delete value["vulnerable_version_range"];
      }
    if (fields["details"] === null) delete fields["details"];
    else {
      const details = fields["details"];
      if (details && typeof details === "object" && !Array.isArray(details))
        for (const field of ["repository", "advisory"])
          if ((details as Record<string, unknown>)[field] === null)
            delete (details as Record<string, unknown>)[field];
      materializeDetailDefaults(
        fields["details"],
        schema.$defs.ImportedFindingEvidence.properties.details,
        target,
      );
    }
  }
}

function validator<T>(
  name: keyof typeof schema.$defs,
  target: ExternalImportTarget = "cloud",
) {
  let check: ValidateFunction<T> | undefined;
  return (input: unknown): T => {
    check ??= ajv.compile<T>({
      $defs: (target === "local" ? localSchema : schema).$defs,
      $ref: `#/$defs/${name}`,
    });
    if (name === "ImportedFindingEvidence")
      normalizeEvidenceDetails(input, target);
    else if (input && typeof input === "object") {
      if (name === "SourceReport" && "evidence" in input)
        normalizeEvidenceDetails(input.evidence, target);
      if (
        name === "FindingImportRequest" &&
        "items" in input &&
        Array.isArray(input.items)
      )
        for (const item of input.items)
          normalizeEvidenceDetails(item?.evidence, target);
    }
    if (!check(input))
      throw new Error(`${name}: ${ajv.errorsText(check.errors)}`);
    validateModelStrings(input, target);
    return input;
  };
}

export const validateExternalEvidenceShape = validator<ExternalFindingEvidence>(
  "ImportedFindingEvidence",
);
const localEvidence = validator<ExternalFindingEvidence>(
  "ImportedFindingEvidence",
  "local",
);
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

export function requireSafeJsonInteger(value: number, label: string): void {
  if (Number.isInteger(value) && !Number.isSafeInteger(value))
    throw new Error(
      `${label} integers must be within JavaScript's safe integer range; export larger values as strings to preserve them exactly.`,
    );
}

export function requireJsonNumber(value: number, label: string): void {
  if (!Number.isFinite(value))
    throw new Error(`${label} must contain finite JSON numbers.`);
  requireSafeJsonInteger(value, label);
}

/** Report metadata is retained in previews and receipts without Cloud evidence size limits. */
export function validateExternalReport(
  report: Record<string, unknown> | undefined,
): void {
  if (report === undefined) return;
  JSON.stringify(report, (_key, value: unknown) => {
    if (isNumberObject(value)) value = +value;
    if (typeof value === "number") requireJsonNumber(value, "Scanner report");
    return value;
  });
}

export function validateExternalEvidenceFields(
  input: unknown,
  target: ExternalImportTarget = "cloud",
): ExternalFindingEvidence {
  const result = (
    target === "local" ? localEvidence : validateExternalEvidenceShape
  )(input);
  for (const location of result.locations ?? []) {
    const path = location.path.replaceAll("\\", "/");
    if (
      path.startsWith("/") ||
      /^[A-Za-z]:/.test(path) ||
      path.split("/").includes("..")
    )
      throw new Error("Locations must use repository-relative paths.");
  }
  const details = result.details;
  if (details) {
    if (details.kind === "advisory") {
      if (!details.advisory)
        throw new Error("Advisory evidence requires its source context.");
      if (details.advisory.source === "global" && details.repository)
        throw new Error(
          "Global advisory evidence cannot claim a source repository.",
        );
      if (details.advisory.source === "repository" && !details.repository)
        throw new Error(
          "Repository advisory evidence requires its source repository.",
        );
    } else {
      if (!details.repository)
        throw new Error(
          "Repository finding evidence requires its source repository.",
        );
      if (details.advisory)
        throw new Error("Advisory source context requires advisory evidence.");
    }
  }
  const endLine = result.details?.code?.end_line;
  if (endLine !== null && endLine !== undefined) {
    const firstLine = result.locations?.[0]?.line;
    if (firstLine === null || firstLine === undefined || endLine < firstLine)
      throw new Error(
        "The code end line requires a first source location line and cannot precede it.",
      );
  }
  const urls = [
    result.url,
    result.details?.repository?.url,
    result.details?.file_url,
  ];
  for (const value of urls) {
    if (value === null || value === undefined) continue;
    const url = value
      .replace(/[\t\r\n]/gu, "")
      .replace(/^[\u0000-\u0020]+/u, "");
    const authority = /^https?:\/\/([^/?#]+)/iu.exec(url)?.[1];
    const normalizedAuthority = (authority ?? "")
      .replace(/[@:#?]/gu, "")
      .normalize("NFKC");
    let validHost = true;
    if (authority?.includes("[") || authority?.includes("]")) {
      const hostname = /^\[([^\]]+)\](?::[\s\S]*)?$/u.exec(authority)?.[1];
      const [address, scope, extraScope] = (hostname ?? "").split("%");
      // Cloud accepts scoped IPv6 and IPvFuture hosts in brackets.
      validHost =
        hostname !== undefined &&
        (/^v[a-fA-F0-9]+\.[\s\S]+$/u.test(hostname) ||
          (isIP(address!) === 6 && scope !== "" && extraScope === undefined));
    }
    if (
      !authority ||
      authority.includes("@") ||
      /[/?#@:]/u.test(normalizedAuthority) ||
      !validHost
    )
      throw new Error(
        "Evidence URLs must be HTTP(S) links without credentials.",
      );
  }
  return result;
}

// Bind changed admission to the validated row or the error returned to its reader.
const previousAdmissions = new WeakMap<
  object,
  ExternalFindingEvidence | null | "uncertain"
>();

export function previousAdmission(value: object) {
  return previousAdmissions.get(value);
}

export function validateExternalEvidence(
  input: unknown,
  target: ExternalImportTarget = "cloud",
): ExternalFindingEvidence {
  const result = validateExternalEvidenceFields(input, target);
  let changed = false;
  try {
    validateExternalEvidenceJson(result, target, 0, (previous, current) => {
      changed =
        previous > CLOUD_EVIDENCE_BYTES !== current > CLOUD_EVIDENCE_BYTES;
    });
  } catch (error) {
    if (changed && error instanceof Error)
      previousAdmissions.set(error, result);
    throw error;
  }
  if (changed) previousAdmissions.set(result, null);
  return result;
}

function cloudNumberByteAdjustment(value: number): number {
  if (!value || Math.abs(value) >= 1e-4) return 0;
  const wire = JSON.stringify(value);
  const cloud = (wire.includes(".") ? value.toExponential() : wire).replace(
    /e-(\d)$/u,
    "e-0$1",
  );
  return cloud.length - wire.length;
}

type ValidateNumber = (value: number) => void;
const evidenceNumber: ValidateNumber = (value) =>
  requireJsonNumber(value, "Evidence");

const rawJson = JSON as JSON & {
  isRawJSON?(value: unknown): value is { rawJSON: string };
};
export class CloudEvidenceDepthError extends Error {
  constructor() {
    super("Evidence exceeds the Cloud JSON depth limit of 20.");
  }
}

/** JSON omits these object properties, but emits null for the same array elements. */
export function requireCloudEvidenceDepth(
  depth: number,
  holder: object,
  value: unknown,
): void {
  if (
    depth > 20 &&
    (Array.isArray(holder) ||
      (value !== undefined &&
        typeof value !== "symbol" &&
        typeof value !== "function"))
  )
    throw new CloudEvidenceDepthError();
}

function serializeImportJson(
  input: unknown,
  number: ValidateNumber,
  limitDepth = false,
): string {
  const parents: object[] = [];
  return JSON.stringify(input, function (this: object, _key, value: unknown) {
    if (limitDepth) {
      while (parents.length && parents.at(-1) !== this) parents.pop();
      requireCloudEvidenceDepth(parents.length, this, value);
      if (value !== null && typeof value === "object") parents.push(value);
    }
    // JSON applies Number conversion to wrappers after calling toJSON.
    if (isNumberObject(value)) value = +value;
    if (typeof value === "number") number(value);
    else if (rawJson.isRawJSON?.(value)) {
      const token: unknown = JSON.parse(value.rawJSON);
      if (typeof token === "number") number(token);
    }
    return value;
  });
}

function* dataValues(value: object, skipped?: () => void): Generator<unknown> {
  if (isProxy(value)) {
    skipped?.();
    return;
  }
  const keys = Object.keys(value);
  // Array indices precede named keys. Dense arrays retain every index in a native clone.
  if (
    Array.isArray(value) &&
    value.length &&
    keys[value.length - 1] !== String(value.length - 1) &&
    Object.getOwnPropertyNames(value).some(
      (key) =>
        /^(?:0|[1-9]\d*)$/u.test(key) &&
        Number(key) < value.length &&
        !Object.prototype.propertyIsEnumerable.call(value, key),
    )
  ) {
    // The released mapper could read non-enumerable indices before cloning them away.
    skipped?.();
  }
  for (const key of keys) {
    const field = Object.getOwnPropertyDescriptor(value, key);
    if (field && Object.hasOwn(field, "value")) yield field.value;
    else skipped?.();
  }
}

// Validate original numeric fields even if a serializer omits them. Object.values
// reads siblings before descending, as the released provider reader did.
function rawJsonNumbers(
  input: unknown,
  target: ExternalImportTarget,
  number: ValidateNumber,
  oldSize = false,
  dataOnly = false,
  skipped?: () => void,
): number {
  const pending: unknown[] = [input];
  const depths: number[] = [0];
  const ancestors: object[] = [];
  let adjustment = 0;
  let checked = target === "local" ? new WeakSet<object>() : undefined;
  while (pending.length) {
    const value = pending.pop();
    const depth = depths.pop()!;
    if (target === "cloud" && depth > 20) {
      if (!oldSize)
        throw new Error("Evidence exceeds the Cloud JSON depth limit of 20.");
      adjustment = Infinity;
    }
    if (value !== null && typeof value === "object") {
      // After a historical rejection, aliases only need one raw numeric check.
      if (adjustment === Infinity) checked ??= new WeakSet();
      if (checked?.has(value)) continue;
      checked?.add(value);
      ancestors.length = depth;
      if (ancestors.includes(value)) {
        if (oldSize) adjustment = Infinity;
        continue;
      }
      ancestors[depth] = value;
      for (const child of dataOnly
        ? dataValues(value, skipped)
        : Object.values(value)) {
        if (typeof child === "number") {
          number(child);
          if (target === "cloud")
            adjustment += cloudNumberByteAdjustment(child);
        }
        if (child !== null && typeof child === "object") {
          pending.push(child);
          depths.push(depth + 1);
        } else if (target === "cloud" && depth >= 20) {
          if (!oldSize)
            throw new Error(
              "Evidence exceeds the Cloud JSON depth limit of 20.",
            );
          adjustment = Infinity;
        }
      }
    } else if (typeof value === "number") {
      number(value);
      if (target === "cloud") adjustment += cloudNumberByteAdjustment(value);
    }
  }
  return adjustment;
}

const CLOUD_EVIDENCE_BYTES = 256 * 1024;
function checkEvidenceSize(bytes: number): number {
  if (bytes > CLOUD_EVIDENCE_BYTES)
    throw new Error("Evidence exceeds the Cloud limit of 256 KiB.");
  return bytes;
}

/** Return the validated Cloud wire size, or zero for local evidence. */
export function validateExternalEvidenceJson(
  input: unknown,
  target: ExternalImportTarget,
  additionalCloudBytes = 0,
  observe?: (previousBytes: number, currentBytes: number) => void,
): number {
  let adjustment = 0;
  const validateNumber = (value: number) => {
    try {
      evidenceNumber(value);
    } catch (error) {
      // The released walk checked primitive numeric fields, not JSON-emitted wrappers.
      if (error instanceof Error) previousAdmissions.set(error, "uncertain");
      throw error;
    }
    if (target === "cloud") adjustment += cloudNumberByteAdjustment(value);
  };
  // Keep local serialization before the raw walk. If an emitted number is invalid,
  // ordinary invalid primitive fields still give a definitive historical exclusion.
  if (target === "local") {
    let invalid: Error | undefined;
    try {
      serializeImportJson(input, validateNumber);
    } catch (error) {
      if (!(error instanceof Error) || previousAdmission(error) !== "uncertain")
        throw error;
      invalid = error;
    }
    rawJsonNumbers(input, target, evidenceNumber);
    if (invalid) throw invalid;
    return 0;
  }
  const rawAdjustment = rawJsonNumbers(input, target, evidenceNumber);
  let text: string;
  try {
    text = serializeImportJson(input, validateNumber, true);
  } catch (error) {
    // A serializer can introduce levels that were absent from the raw evidence.
    if (error instanceof CloudEvidenceDepthError)
      previousAdmissions.set(error, "uncertain");
    throw error;
  }
  const bytes = Buffer.byteLength(text) + additionalCloudBytes;
  observe?.(bytes + rawAdjustment, bytes + adjustment);
  return checkEvidenceSize(bytes + adjustment);
}

/** Reproduce the released SDK's checks on a detached native finding. */
export function validatePreviousCloudEvidence(
  input: unknown,
): ExternalFindingEvidence {
  const evidence = validateExternalEvidenceFields(input, "cloud");
  // Older validation counted enumerable primitive numbers, while JSON encoded
  // the native wrappers. Check depth before serializing a possibly shared graph.
  const adjustment = rawJsonNumbers(
    evidence,
    "cloud",
    evidenceNumber,
    true,
    true,
  );
  if (!Number.isFinite(adjustment)) throw new CloudEvidenceDepthError();
  checkEvidenceSize(Buffer.byteLength(JSON.stringify(evidence)) + adjustment);
  return evidence;
}

/** Use the array index as toJSON's key, as when saving the supplied GitHub records. */
export function exportedGitHubRecord(
  value: unknown,
  index: number,
  target: ExternalImportTarget,
  checkPreviousLocal = false,
) {
  // The released readers validated numeric fields hidden by serializers.
  let adjustment = 0;
  let previousInvalid: unknown;
  let skippedRawValue = false;
  if (target === "cloud" || checkPreviousLocal) {
    try {
      adjustment = rawJsonNumbers(
        { source_data: value },
        target,
        evidenceNumber,
        target === "cloud",
        true,
        () => {
          skippedRawValue = true;
        },
      );
    } catch (error) {
      previousInvalid = error;
    }
  }
  let invalid: unknown;
  const text = serializeImportJson(
    { [index]: value },
    (number) => {
      if (!invalid)
        try {
          evidenceNumber(number);
        } catch (error) {
          invalid = error;
        }
    },
    target === "cloud",
  );
  const record: unknown = JSON.parse(text)[index];
  const bytes =
    Buffer.byteLength(text) -
    Buffer.byteLength(JSON.stringify({ [index]: null })) +
    4;
  return {
    record,
    bytes,
    adjustment,
    previousInvalid,
    skippedRawValue,
    invalid,
  };
}

/** Combine the observed vendor bytes with the old native mapping's typed fields. */
export function previousGitHubExclusion(
  evidence: ExternalFindingEvidence,
  sourceBytes: number,
  adjustment: number,
): string | undefined {
  if (adjustment === Infinity)
    return "Evidence exceeds the Cloud JSON depth limit of 20.";
  const envelope = { ...evidence, source_data: null };
  const bytes = Buffer.byteLength(JSON.stringify(envelope)) - 4 + sourceBytes;
  return bytes +
    adjustment +
    rawJsonNumbers(envelope, "cloud", evidenceNumber, true) >
    256 * 1024
    ? "Evidence exceeds the Cloud limit of 256 KiB."
    : undefined;
}

export function validateImportRequest(input: unknown): FindingImportRequest {
  const result = request(input);
  if (
    new Set(result.items.map((item) => item.client_id)).size !==
    result.items.length
  )
    throw new Error("Import contains duplicate client IDs.");
  if (
    new Set(result.items.map((item) => item.source_finding_id)).size !==
    result.items.length
  )
    throw new Error("Import contains duplicate source finding identities.");
  for (const item of result.items) validateExternalEvidence(item.evidence);
  if (Buffer.byteLength(JSON.stringify(result)) > 5 * 1024 * 1024)
    throw new Error("Import exceeds the Cloud limit of 5 MiB.");
  return result;
}

import { isIP } from "node:net";
import { isBoxedPrimitive, isNumberObject } from "node:util/types";
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

function requireJsonNumber(value: number, label: string): void {
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

export function validateExternalEvidence(
  input: unknown,
  target: ExternalImportTarget = "cloud",
  batch?: Set<object>,
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
  return checkedEvidenceJson(result, target, 0, true, batch).retained;
}

/** Return the validated Cloud wire size, or zero for local evidence. */
export function validateExternalEvidenceJson(
  input: unknown,
  target: ExternalImportTarget,
  additionalCloudBytes = 0,
): number {
  return checkedEvidenceJson(input, target, additionalCloudBytes).bytes;
}

function hasCustomNumberHooks(value: Number): boolean {
  if ("toJSON" in value || Symbol.toPrimitive in value) return true;
  let owner: object | null = value;
  while (owner && !Object.hasOwn(owner, "valueOf"))
    owner = Object.getPrototypeOf(owner);
  return owner === value || !isNumberObject(owner);
}

function snapshotJsonEvidence<T>(input: T): T {
  const views = new WeakMap<object, object>();
  const json = JSON as JSON & { isRawJSON?(value: unknown): boolean };
  return json.parse(
    json.stringify(input, (_key, value: unknown) => {
      if (
        value === null ||
        typeof value !== "object" ||
        isBoxedPrimitive(value) ||
        json.isRawJSON?.(value)
      )
        return value;
      const cached = views.get(value);
      if (cached) return cached;
      const handler: ProxyHandler<object> = {
        get(_target, key) {
          const field: unknown = Reflect.get(value, key);
          const result = isNumberObject(field)
            ? Number.prototype.valueOf.call(field)
            : field;
          if (typeof result === "number") requireJsonNumber(result, "Evidence");
          return result;
        },
      };
      const array = Array.isArray(value);
      if (!array) {
        handler.ownKeys = () => Object.keys(value);
        handler.getOwnPropertyDescriptor = () => ({
          enumerable: true,
          configurable: true,
        });
      }
      const view = new Proxy(array ? [] : {}, handler);
      views.set(value, view);
      return view;
    }),
  ) as T;
}

/** @internal Replace changed numeric fields together so common source objects and
 * their getters stay shared until the SDK snapshots the selected batch. */
export function retainNumberFields<T>(input: T, changed: Set<object>): T {
  const captures = new WeakMap<object, object>();
  function retain(value: unknown): unknown {
    if (!value || typeof value !== "object") return value;
    const found = captures.get(value);
    if (found) return found;
    if (changed.has(value)) {
      const number = new Number(Number.prototype.valueOf.call(value));
      captures.set(value, number);
      return number;
    }
    const prototype: unknown = Object.getPrototypeOf(value);
    if (
      !Array.isArray(value) &&
      prototype !== null &&
      prototype !== Object.prototype
    )
      return value;
    const properties = Object.getOwnPropertyDescriptors(value);
    let copy = false;
    for (const key of Object.keys(value)) {
      const property = properties[key]!;
      if (!Object.hasOwn(property, "value")) continue;
      const next = retain(property.value);
      if (next !== property.value) {
        property.value = next;
        copy = true;
      }
    }
    if (!copy) return value;
    for (const descriptor of Object.values(properties))
      if (descriptor.get) descriptor.get = descriptor.get.bind(value);
    const retained: object = Array.isArray(value)
      ? []
      : Object.create(prototype as object | null);
    Object.defineProperties(retained, properties);
    captures.set(value, retained);
    return retained;
  }
  return retain(input) as T;
}

function checkedEvidenceJson<T>(
  input: T,
  target: ExternalImportTarget,
  additionalCloudBytes: number,
  captureNumbers = true,
  batch?: Set<object>,
): { retained: T; bytes: number } {
  const changed = batch && new Set<object>();
  let opaque = false;
  let numericByteAdjustment = 0;
  function wireValue(this: object, key: string, value: unknown) {
    const raw: unknown =
      batch && Object.getOwnPropertyDescriptor(this, key)?.value;
    if (isNumberObject(value)) value = +value;
    if (isNumberObject(raw)) {
      const intrinsic = Number.prototype.valueOf.call(raw) as number;
      requireJsonNumber(intrinsic, "Evidence");
      if (value !== intrinsic) changed!.add(raw);
      value = intrinsic;
    }
    if (target === "cloud" && typeof value === "number") {
      const wire = JSON.stringify(value);
      const cloud = (
        wire.includes(".") && Math.abs(value) < 1e-4
          ? value.toExponential()
          : wire
      ).replace(/e-(\d)$/u, "e-0$1");
      numericByteAdjustment += cloud.length - wire.length;
    }
    return value;
  }
  function wireBytes(json: string): number {
    if (target === "local") return 0;
    const bytes =
      Buffer.byteLength(json) + numericByteAdjustment + additionalCloudBytes;
    if (bytes > 256 * 1024)
      throw new Error("Evidence exceeds the Cloud limit of 256 KiB.");
    return bytes;
  }
  // Preserve the native fast path and original circular-JSON diagnostics.
  let failedPreflight: { reason: unknown } | undefined;
  if (target === "local") {
    try {
      JSON.stringify(input, batch ? wireValue : undefined);
    } catch (reason) {
      failedPreflight = { reason };
    }
  }
  const ancestors: object[] = [];
  let customNumber = false;
  const pending: [unknown, number][] = [[input, 0]];
  while (pending.length) {
    const [value, depth] = pending.pop()!;
    if (target === "cloud" && depth > 20)
      throw new Error("Evidence exceeds the Cloud JSON depth limit of 20.");
    if (value !== null && typeof value === "object") {
      if (failedPreflight) {
        ancestors.length = depth;
        if (ancestors.includes(value)) throw failedPreflight.reason;
        ancestors[depth] = value;
      }
      if (isNumberObject(value)) {
        requireJsonNumber(Number.prototype.valueOf.call(value), "Evidence");
        if (captureNumbers) customNumber ||= hasCustomNumberHooks(value);
      }
      for (const [key, child] of Object.entries(value)) {
        if (batch && typeof child === "function" && !isNumberObject(value))
          opaque = true;
        if (
          batch &&
          child !== null &&
          typeof child === "object" &&
          (Object.getOwnPropertyDescriptor(value, key)?.get ||
            (!Array.isArray(value) &&
              Object.getPrototypeOf(value) !== Object.prototype &&
              Object.getPrototypeOf(value) !== null &&
              !isNumberObject(value)))
        )
          opaque = true;
        pending.push([child, depth + 1]);
      }
    } else if (typeof value === "number") {
      requireJsonNumber(value, "Evidence");
    }
  }
  if (customNumber) {
    let rawWire: string | undefined =
      target === "local" && !failedPreflight ? "" : undefined;
    if (target === "cloud") {
      // Finish the provider read before capture, as a pending SDK request may
      // already contain the next value returned by a vendor getter.
      try {
        rawWire = JSON.stringify(input, batch ? wireValue : undefined);
      } catch {
        /* the captured value is validated below */
      }
    }
    if (batch && !opaque && rawWire !== undefined) {
      const bytes = wireBytes(rawWire);
      for (const number of changed!) batch.add(number);
      return { retained: input, bytes };
    }
    let snapshot: T;
    try {
      snapshot = structuredClone(input);
    } catch (error) {
      if (!(error instanceof DOMException) || error.name !== "DataCloneError")
        throw error;
      // An own function can supply JSON even when native SDK capture is unavailable.
      snapshot = snapshotJsonEvidence(input);
    }
    return checkedEvidenceJson(snapshot, target, additionalCloudBytes, false);
  }
  if (failedPreflight) throw failedPreflight.reason;
  const retained = input;
  if (target === "local") return { retained, bytes: 0 };
  const bytes = wireBytes(JSON.stringify(retained, wireValue));
  return { retained, bytes };
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

import { isIP } from "node:net";
import { isRecord } from "./record.js";
import {
  SealedContractError,
  hasRequiredFindingText,
  safeRelativePath,
} from "./contract-values.js";
import { isWindowsUnsafePathComponent } from "./windows-path.js";

/** Preserve the historical meaning of these immutable schema fields. */
export function adaptTrackingSchema(
  filename: string,
  schema: Record<string, unknown>,
): void {
  const findingProperties = ["properties", "findings", "items", "properties"];
  const scanProperties = ["properties", "scan", "properties"];
  const patterns =
    filename === "findings.json"
      ? [
          {
            path: [
              ...findingProperties,
              "codeEvidence",
              "items",
              "properties",
              "id",
            ],
            before: "^[a-z0-9][a-z0-9._/-]*$",
            after: "^[a-z0-9][a-z0-9._/-]*(?:\\n)?$",
          },
          {
            path: [...findingProperties, "writeup", "properties", "reportPath"],
            before: "^findings/([a-z0-9][a-z0-9._-]*)/\\1\\.md$",
            after: "^findings/([a-z0-9][a-z0-9._-]*)/\\1\\.md(?:\\n)?$",
          },
        ]
      : filename === "scan-manifest.json"
        ? [
            {
              path: [
                ...scanProperties,
                "artifacts",
                "items",
                "properties",
                "path",
              ],
              before: "^(?!/)(?!.*(?:^|/)\\.\\.(?:/|$))(?!.*\\\\).+$",
              after:
                "^(?!/)(?![^\\n]*(?:^|/)\\.\\.(?:/|$))(?![^\\n]*\\\\)[^\\n]+$",
            },
            {
              path: [
                ...scanProperties,
                "target",
                "properties",
                "snapshotDigest",
              ],
              before: "^codex-security-snapshot/v1:sha256:[a-f0-9]{64}$",
              after: "^codex-security-snapshot/v1:sha256:[a-f0-9]{64}(?:\\n)?$",
            },
            {
              path: [
                ...scanProperties,
                "threatModel",
                "anyOf",
                1,
                "properties",
                "content",
              ],
              before: "^[\\s\\S]*\\S[\\s\\S]*$",
              after: "^[\\s\\S]*[^\\p{White_Space}\\u001c-\\u001f][\\s\\S]*$",
            },
          ]
        : filename === "coverage.json"
          ? [
              {
                path: [
                  "properties",
                  "surfaces",
                  "items",
                  "properties",
                  "receiptRefs",
                  "items",
                ],
                before: "^(?!.*(?:^|/)\\.\\.(?:/|$))(?!.*\\\\)artifacts/.+$",
                after:
                  "^(?![^\\n]*(?:^|/)\\.\\.(?:/|$))(?![^\\n]*\\\\)artifacts/[^\\n]+$",
              },
            ]
          : [];
  for (const { path, before, after } of patterns) {
    let field: unknown = schema;
    for (const key of path) {
      field =
        typeof key === "number" && Array.isArray(field)
          ? field[key]
          : isRecord(field)
            ? field[key]
            : undefined;
    }
    if (isRecord(field) && field["pattern"] === before) {
      field["pattern"] = after;
    }
  }
}

/** Preserve tracking's whitespace and reserved-name checks on the original path. */
export function trackingPortableRelativePath(
  value: string,
  context: string,
): string {
  const normalized = safeRelativePath(value, context);
  // Python's case-insensitive I also matches dotted/dotless I; dot excludes only LF.
  const reserved =
    /^(?:con|prn|aux|nul|con[i\u0130\u0131]n\$|conout\$|com[1-9¹²³]|lpt[1-9¹²³])(?:\.[^\n]*)?$/iu;
  if (
    !hasRequiredFindingText(value) ||
    value
      .split("/")
      .some(
        (component) =>
          isWindowsUnsafePathComponent(component) || reserved.test(component),
      )
  ) {
    throw new SealedContractError(
      `${context}: expected a safe scan-relative POSIX path.`,
    );
  }
  return normalized;
}

/** Preserve tracking's raw authority checks without URL host normalization. */
export function isTrackingRemoteAuthority(authority: string): boolean {
  // The historical parser rejects separators introduced by NFKC normalization.
  const normalized = authority.replace(/[@:#?]/gu, "").normalize("NFKC");
  if (/[/?#@:]/u.test(normalized)) return false;

  const bracketed = authority.startsWith("[");
  const parts = bracketed
    ? /^\[([^\]]+)\](?::(.*))?$/u.exec(authority)
    : /^([^:[\]]+)(?::(.*))?$/u.exec(authority);
  if (parts === null) return false;
  const hostname = parts[1]!;
  const port = parts[2] ?? "";
  if (bracketed) {
    const [address, scope, extra] = hostname.split("%");
    if (isIP(address!) !== 6 || scope === "" || extra !== undefined) {
      return false;
    }
  }
  return (
    !/[\p{White_Space}\u001c-\u001f<>^|]/u.test(hostname) &&
    (port === "" || (/^[0-9]+$/u.test(port) && Number(port) <= 65535))
  );
}

/** Python's timestamp parser carries excess offset minutes into the hour. */
export function isTrackingDateTime(
  value: string,
  validRfc3339DateTime: (value: string) => boolean,
): boolean {
  if (validRfc3339DateTime(value)) return true;
  const offset = /([+-])(\d{2}):(\d{2})$/u.exec(value);
  if (offset === null || Number(offset[3]) < 60) return false;
  const minutes = Number(offset[2]) * 60 + Number(offset[3]);
  if (minutes >= 24 * 60) return false;
  const normalized = `${offset[1]}${String(Math.floor(minutes / 60)).padStart(2, "0")}:${String(minutes % 60).padStart(2, "0")}`;
  return validRfc3339DateTime(value.slice(0, -6) + normalized);
}

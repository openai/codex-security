import {
  hostedNumberToken,
  parseHostedScannerJson,
} from "./hosted-scanner-http.js";
import {
  isLegacyWitness,
  restoreLegacyHostedNumbers,
} from "./hosted-scanner-v1.js";
import { isRecord } from "./record.js";
import { array, record } from "./scanner-import.js";

type Resource = Record<string, unknown>;
export const SNYK_REST_ISSUES_V1 = "snyk-rest-issues/v1";
export const SNYK_REST_ISSUES_FORMAT = "snyk-rest-issues/v2";
export function isSnykRestFormat(value: unknown): boolean {
  return value === SNYK_REST_ISSUES_FORMAT || value === SNYK_REST_ISSUES_V1;
}

/** Only v1 can carry native JSON numbers outside the lossless evidence strings. */
export function parseSnykReport(text: string): unknown {
  const document: unknown = JSON.parse(text);
  return isRecord(document) && document["format"] === SNYK_REST_ISSUES_V1
    ? parseHostedScannerJson(text)
    : document;
}

function encodeNumbers(data: object): Resource | undefined {
  const fields: Resource = Object.create(null);
  const values = data as Resource;
  for (const [key, value] of Object.entries(values)) {
    const token = hostedNumberToken(value);
    if (token !== undefined) {
      if (isLegacyWitness(token)) {
        values[key] = token;
        fields[key] = token;
      } else {
        values[key] = Number(token);
      }
    } else if (value !== null && typeof value === "object") {
      const nested = encodeNumbers(value);
      if (nested) fields[key] = nested;
    }
  }
  return Object.keys(fields).length ? fields : undefined;
}

/** Recover the exact v1 wire representation whether numbers were native or witnessed strings. */
export function encodeSnykV1File(document: Resource): Resource {
  const source = restoreLegacyHostedNumbers(document);
  delete source["numericFields"];
  const fields = encodeNumbers(source);
  if (fields) source["numericFields"] = fields;
  return source;
}

/** Read v1 exports, retained source records, and empty-report project contexts. */
export function readSnykRestDocument(document: Resource): Resource {
  if (document["format"] !== SNYK_REST_ISSUES_V1) return document;
  const exact = restoreLegacyHostedNumbers(document);
  return {
    ...exact,
    format: SNYK_REST_ISSUES_FORMAT,
    projectJson: JSON.stringify(exact["project"]),
    targetJson: JSON.stringify(exact["target"]),
    issueJson: JSON.stringify(exact["issue"]),
    ...(exact["pages"] !== undefined && {
      pages: array(exact["pages"], "Snyk issue pages").map((entry) => {
        const page = record(entry, "Snyk saved page");
        return {
          startingAfter: page["startingAfter"],
          responseJson: JSON.stringify(page["response"]),
        };
      }),
    }),
  };
}

function at(value: unknown, ...path: (string | number)[]): unknown {
  for (const segment of path)
    value = isRecord(value) ? value[segment] : undefined;
  return value;
}

/** Retain v1's evidence representation so replaying an existing import stays unchanged. */
export function originalSnykEvidence(document: Resource, source: Resource) {
  if (document["format"] !== SNYK_REST_ISSUES_V1) return;
  const { projectJson: _project, targetJson: _target, ...scope } = source;
  const fields = document["numericFields"];
  const assetFields: Resource = {};
  for (const key of ["project", "target"]) {
    const field = at(fields, key);
    if (field !== undefined) assetFields[key] = field;
  }
  const context = {
    ...scope,
    format: SNYK_REST_ISSUES_V1,
    project: document["project"],
    target: document["target"],
    ...(Object.keys(assetFields).length > 0 && { numericFields: assetFields }),
  };
  const rows = array(document["pages"], "Snyk issue pages").flatMap(
    (value, i) => {
      const page = record(value, "Snyk saved page");
      const response = record(page["response"], "Snyk issue page");
      return array(response["data"], "Snyk issue page data").map((issue, j) => {
        const field = at(fields, "pages", i, "response", "data", j);
        return {
          ...context,
          issue,
          ...(field !== undefined && {
            numericFields: { ...assetFields, issue: field },
          }),
        };
      });
    },
  );
  return { context, rows };
}

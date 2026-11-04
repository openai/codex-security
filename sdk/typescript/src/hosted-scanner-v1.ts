import {
  hostedNumberToken,
  parseHostedScannerJson,
} from "./hosted-scanner-http.js";
import { isRecord } from "./record.js";

const decimalToken = /^-?(0|[1-9]\d*)(?:\.(\d+))?(?:e([+-]?\d+))?$/iu;

// Compare decimal values and check integral IDs without expanding unbounded exponents.
function magnitude(token: string) {
  const parts = decimalToken.exec(token);
  if (!parts) return;
  const fraction = parts[2] ?? "";
  const digits = (parts[1]! + fraction).replace(/^0+/u, "");
  const point = digits.length
    ? digits.length - fraction.length + Number(parts[3] ?? 0)
    : 0;
  let end = digits.length;
  while (end > 0 && digits[end - 1] === "0") end--;
  return { digits: digits.slice(0, end), point };
}

export function legacyDecimalInteger(token: string): string | undefined {
  const value = magnitude(token);
  if (!value || token.startsWith("-")) return;
  const { digits, point } = value;
  if (!digits || point < digits.length || point > 19) return;
  const id = digits.padEnd(point, "0");
  return point < 19 || id <= "9223372036854775807" ? id : undefined;
}

/** A legacy export needs a type witness when JSON.parse cannot preserve a decimal. */
export function isLegacyWitness(token: string): boolean {
  const exact = magnitude(token);
  if (!exact) return false;
  const parsed = Number(token);
  if (
    !Number.isFinite(parsed) ||
    (Number.isInteger(parsed) && !Number.isSafeInteger(parsed))
  )
    return true;
  const rounded = magnitude(String(parsed))!;
  return rounded.point !== exact.point || rounded.digits !== exact.digits;
}

function restoreField(value: unknown, witness: unknown): unknown {
  if (typeof witness === "string") {
    if (value !== witness || !isLegacyWitness(witness))
      throw new Error("Invalid exact scanner number.");
    return parseHostedScannerJson(witness);
  }
  if (
    !isRecord(witness) ||
    hostedNumberToken(witness) !== undefined ||
    (!Array.isArray(value) &&
      (!isRecord(value) || hostedNumberToken(value) !== undefined))
  )
    throw new Error("Invalid scanner numeric fields.");
  const restored = Array.isArray(value) ? [...value] : { ...value };
  const fields = restored as Record<string, unknown>;
  for (const [key, child] of Object.entries(witness)) {
    if (!Object.hasOwn(restored, key))
      throw new Error("Invalid scanner numeric field.");
    fields[key] = restoreField(fields[key], child);
  }
  return restored;
}

/** Original hosted exports saved imprecise JSON numbers as text plus a sparse type witness. */
export function restoreLegacyHostedNumbers(
  document: Record<string, unknown>,
): Record<string, unknown> {
  const fields = document["numericFields"];
  if (fields === undefined) return document;
  if (!isRecord(fields) || Object.hasOwn(fields, "numericFields"))
    throw new Error("Invalid scanner numeric fields.");
  return restoreField(document, fields) as Record<string, unknown>;
}

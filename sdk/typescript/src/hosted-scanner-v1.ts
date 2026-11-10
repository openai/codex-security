import { canonicalNumber } from "./external-import-contract.js";
import {
  hostedNumberToken,
  parseHostedScannerJson,
} from "./hosted-scanner-http.js";
import { isRecord } from "./record.js";

const jsonNumber = /^-?(?:0|[1-9]\d*)(?:\.\d+)?(?:e[+-]?\d+)?$/iu;

export function legacyDecimalInteger(token: string): string | undefined {
  if (!jsonNumber.test(token)) return;
  const value = Number(token);
  // Rule out unbounded exponents cheaply. Rounded boundary values still need an exact check.
  if (!Number.isInteger(value) || value < 1 || value > 2 ** 63) return;
  const id = canonicalNumber(token);
  return /^[1-9]\d{0,18}$/u.test(id) &&
    (id.length < 19 || id <= "9223372036854775807")
    ? id
    : undefined;
}

/** A legacy export needs a type witness when JSON.parse cannot preserve a decimal. */
export function isLegacyWitness(token: string): boolean {
  if (!jsonNumber.test(token)) return false;
  const value = Number(token);
  if (
    !Number.isFinite(value) ||
    (Number.isInteger(value) && !Number.isSafeInteger(value))
  )
    return true;
  // Distinguish zero from underflow without converting an unbounded exponent.
  if (value === 0) return /[1-9]/u.test(token.split(/e/iu, 1)[0]!);
  return canonicalNumber(token) !== String(value);
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

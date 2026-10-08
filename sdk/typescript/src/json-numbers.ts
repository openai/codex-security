import { ContractValidationError } from "./errors.js";

export function parseJsonNumbers(source: string, context: string): unknown {
  const value: unknown = JSON.parse(source);
  validateJsonNumbers(value, context);
  return value;
}

export function validateJsonNumbers(value: unknown, context: string): void {
  const pending = [value];
  const seen = new WeakSet<object>();
  while (pending.length > 0) {
    const item = pending.pop();
    if (typeof item === "number") validateJsonNumber(item, context);
    else if (item !== null && typeof item === "object" && !seen.has(item)) {
      seen.add(item);
      const children = Object.values(item);
      for (let index = children.length - 1; index >= 0; index--)
        pending.push(children[index]);
    }
  }
}

export function validateJsonNumber(value: number, context: string): void {
  if (!Number.isFinite(value)) {
    throw new ContractValidationError(
      `${context}: non-finite JSON numbers are not supported.`,
    );
  }
  if (Number.isInteger(value) && !Number.isSafeInteger(value)) {
    throw new ContractValidationError(
      `${context}: unsafe integer-valued JSON numbers are not supported.`,
    );
  }
}

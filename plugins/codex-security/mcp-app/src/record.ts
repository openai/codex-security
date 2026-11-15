export function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

export function asRecord(value: unknown): Record<string, unknown> | undefined {
  return isRecord(value) ? value : undefined;
}

export function isNonEmptyString(value: unknown): value is string {
  return typeof value === "string" && value.trim().length > 0;
}

/** Preserve array order while comparing JSON objects independently of field order. */
export function canonicalJson(input: unknown): string {
  return JSON.stringify(input, (_key, value: unknown) => {
    const object = asRecord(value);
    return object
      ? Object.fromEntries(
          Object.keys(object)
            .sort()
            .map((key) => [key, object[key]]),
        )
      : value;
  });
}

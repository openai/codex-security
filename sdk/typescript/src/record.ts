export function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

export function asRecord(value: unknown): Record<string, unknown> | undefined {
  return isRecord(value) ? value : undefined;
}

export function canonicalJson(value: unknown): string {
  return JSON.stringify(value, (_key, child: unknown) => {
    if (isRecord(child)) {
      return Object.fromEntries(
        Object.keys(child)
          .sort()
          .map((key) => [key, child[key]]),
      );
    }
    return child;
  });
}

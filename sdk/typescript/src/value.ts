/** @internal */
export function environmentEntry(
  environment: Readonly<Record<string, string | undefined>>,
  requested: string,
): string | undefined {
  const exact = environment[requested];
  if (exact !== undefined || process.platform !== "win32") return exact;
  const upper = requested.toUpperCase();
  return Object.entries(environment).find(
    ([name]) => name.toUpperCase() === upper,
  )?.[1];
}

/** Match the environment key that Node passes to a native child. */
export function childEnvironmentEntry(
  environment: Readonly<Record<string, string | undefined>>,
  name: string,
): string | undefined {
  if (process.platform !== "win32") return environment[name];
  const upper = name.toUpperCase();
  // Windows spawn sorts aliases and passes only the first spelling.
  const key = Object.keys(environment)
    .sort()
    .find((key) => key.toUpperCase() === upper);
  return key === undefined ? undefined : environment[key];
}

/** @internal */
export function isSafeNonNegativeInteger(value: unknown): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 0;
}

/** @internal */
export function isNonEmptyString(value: unknown): value is string {
  return typeof value === "string" && value.length > 0;
}

/** @internal */
export function parseJson(read: () => string): unknown {
  try {
    return JSON.parse(read());
  } catch {
    return null;
  }
}

/** @internal */
export const findingEntry = <T extends { findingId: string }>(
  finding: T,
): [string, T] => [finding.findingId, finding];

/** @internal Optional observers must not block or interrupt their operation. */
export function notify(callback: () => unknown): void {
  try {
    void Promise.resolve(callback()).catch(() => {});
  } catch {}
}

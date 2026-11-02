import { isBoxedPrimitive, isDate, isProxy } from "node:util/types";

/** Native capture reads enumerable own accessors and may run proxy traps. */
export function canSnapshotWithoutGetters(
  input: unknown,
  allowSerializerPrototype = false,
  observe?: (value: object) => boolean | void,
): boolean {
  const seen = new Set<object>();
  const pending: unknown[] = [input];
  while (pending.length) {
    const value = pending.pop();
    if (!value || typeof value !== "object" || seen.has(value)) continue;
    seen.add(value);
    if (isProxy(value)) return false;
    if (observe?.(value) === false) return false;
    if (isBoxedPrimitive(value) || ArrayBuffer.isView(value) || isDate(value))
      continue;
    const prototype: unknown = Object.getPrototypeOf(value);
    if (
      !Array.isArray(value) &&
      prototype !== Object.prototype &&
      prototype !== null
    ) {
      if (
        !allowSerializerPrototype ||
        !prototype ||
        typeof prototype !== "object" ||
        isProxy(prototype) ||
        Object.getPrototypeOf(prototype) !== Object.prototype ||
        !Object.getOwnPropertyNames(prototype).every(
          (key) => key === "constructor" || key === "toJSON",
        )
      )
        return false;
    }
    for (const key of Object.keys(value)) {
      const field = Object.getOwnPropertyDescriptor(value, key)!;
      if (!Object.hasOwn(field, "value")) return false;
      if (field.value !== null && typeof field.value === "object")
        pending.push(field.value);
    }
  }
  return true;
}

export function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

export function asRecord(value: unknown): Record<string, unknown> | undefined {
  return isRecord(value) ? value : undefined;
}

export function canonicalJson(
  value: unknown,
  compareKeys?: (left: string, right: string) => number,
  preserveScalar?: (value: object) => boolean,
): string {
  return JSON.stringify(value, (_key, child: unknown) => {
    if (isRecord(child) && !preserveScalar?.(child)) {
      return Object.fromEntries(
        Object.keys(child)
          .sort(compareKeys)
          .map((key) => [key, child[key]]),
      );
    }
    return child;
  });
}

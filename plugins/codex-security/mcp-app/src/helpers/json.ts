export { isRecord as object } from "../record.ts";

export function escapeControls(text: string): string {
  return text.replace(/[\p{Cc}\p{Cf}]/gu, (character) => {
    const point = character.codePointAt(0)!;
    return point > 0xffff
      ? `\\u{${point.toString(16)}}`
      : `\\u${point.toString(16).padStart(4, "0")}`;
  });
}

export function formatDiagnostic(value: unknown): string {
  return escapeControls(JSON.stringify(value));
}

export function parseJson(source: string): unknown {
  try {
    // Keep large artifact integers exact when a document is read and rewritten.
    return JSON.parse(
      source,
      (_key, value: unknown, context?: { source?: string }) =>
        typeof value === "number" &&
        !Number.isSafeInteger(value) &&
        /^-?[0-9]+$/u.test(context?.source ?? "")
          ? BigInt(context!.source!)
          : value,
    );
  } catch (error) {
    if (error instanceof SyntaxError)
      error.message = escapeControls(error.message);
    throw error;
  }
}

export function stringifyJson(value: unknown, space = 2): string {
  return JSON.stringify(
    value,
    (_key, item: unknown) =>
      typeof item === "bigint"
        ? (JSON as typeof JSON & { rawJSON(text: string): unknown }).rawJSON(
            String(item),
          )
        : item,
    space,
  );
}

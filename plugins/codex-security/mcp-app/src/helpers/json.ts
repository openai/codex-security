import { isDeepStrictEqual } from "node:util";

export function object(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

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

export function equalFindingJson(left: string, right: string): boolean {
  // Compare decimal tokens before JSON.parse rounds them to binary numbers.
  const parse = (source: string) =>
    JSON.parse(source, (_key, value: unknown, context?: { source: string }) => {
      if (typeof value !== "number") return value;
      const [, sign, whole, fraction = "", power = "0"] =
        /^(-?)(\d+)(?:\.(\d+))?(?:[eE]([+-]?\d+))?$/u.exec(context!.source)!;
      const digits = (whole! + fraction).replace(/^0+/u, "");
      const significant = digits.replace(/0+$/u, "");
      const exponent =
        BigInt(power) +
        BigInt(digits.length - significant.length - fraction.length);
      return (JSON as typeof JSON & { rawJSON(text: string): unknown }).rawJSON(
        significant ? `${sign}${significant}e${exponent}` : "0",
      );
    });
  try {
    return isDeepStrictEqual(parse(left), parse(right));
  } catch (error) {
    if (error instanceof SyntaxError)
      error.message = escapeControls(error.message);
    throw error;
  }
}

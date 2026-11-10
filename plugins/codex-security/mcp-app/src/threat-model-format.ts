const whitespace = /[\p{White_Space}\u001c-\u001f]+/gu;
const entityAmp = /&(?=(?:#[0-9]+|#[xX][0-9A-Fa-f]+|[A-Za-z][A-Za-z0-9]*);)/u;

/** Match the retained artifact projection's Python whitespace semantics. */
export function nonblank(value: string): boolean {
  return value.replace(whitespace, "").length > 0;
}

function collapse(value: string): string {
  return value.replace(whitespace, " ").replace(/^ | $/gu, "");
}

/** Match report_projection._escape_markdown without changing URL ampersands. */
function escapeMarkdown(value: string): string {
  const urls = [
    ...value.matchAll(
      /(?<![^\p{White_Space}\u001c-\u001f*_~(])www\.[^\p{White_Space}\u001c-\u001f<>]+/giu,
    ),
  ].map((match) => ({
    start: match.index,
    end: match.index + match[0].length,
  }));
  // Preserve protocol-relative and fuzzy links without a domain/TLD table.
  for (const match of value.matchAll(/[^\p{White_Space}\u001c-\u001f<>]+/gu)) {
    const token = match[0];
    const dot = token.split("/", 1)[0]!.indexOf(".");
    if (
      token.includes("//") ||
      (dot >= 0 && /[/?#]/u.test(token.slice(dot + 1)))
    ) {
      urls.push({ start: match.index, end: match.index + token.length });
    }
  }
  const pattern = new RegExp(
    /(?<!`)`[^`\n]+`(?!`)|[\\`*_\[\]<>]/u.source + "|" + entityAmp.source,
    "gu",
  );
  return value.replace(pattern, (match, offset: number) =>
    match.length > 1 ||
    (match === "&" &&
      urls.some(({ start, end }) => start <= offset && offset < end))
      ? match
      : "\\" + match,
  );
}

/** Match report_projection._path_text with ensure_ascii for quoted scope paths. */
export function pathText(value: string): string {
  const quoted =
    value.includes(",") ||
    value !== collapse(value) ||
    /[\u0000-\u001f]/u.test(value);
  if (!quoted && !entityAmp.test(value))
    return value.replace(/([\\`*_\[\]<>])/gu, "\\$1");

  // Escape UTF-16 units so quoted paths do not depend on Unicode versions.
  const label = quoted
    ? JSON.stringify(value).replace(
        /[\u007f-\uffff]/g,
        (unit) => `\\u${unit.charCodeAt(0).toString(16).padStart(4, "0")}`,
      )
    : value;
  const marker = "`".repeat(
    (label.match(/`+/gu) ?? []).reduce(
      (length, run) => Math.max(length, run.length + 1),
      1,
    ),
  );
  const padding = label.startsWith("`") || label.endsWith("`") ? " " : "";
  return `${marker}${padding}${label}${padding}${marker}`;
}

/** Plain metadata remains text; authored single-backtick spans remain intact. */
export function text(value: unknown, fallback = ""): string {
  const candidate =
    typeof value === "string" && nonblank(value) ? value : fallback;
  const normalized = collapse(candidate);
  const protectedText =
    /^(?:#{1,6} |[-*+] |> |```|~~~|\p{Decimal_Number}+[.)] |\|)/u.test(
      normalized,
    )
      ? `Text: ${normalized}`
      : normalized;
  return escapeMarkdown(protectedText);
}

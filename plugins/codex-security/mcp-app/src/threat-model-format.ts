const whitespace = /[\p{White_Space}\u001c-\u001f]+/gu;
const entityAmp = /&(?=(?:#[0-9]+|#[xX][0-9A-Fa-f]+|[A-Za-z][A-Za-z0-9]*);)/u;

/** Match the retained artifact projection's Python whitespace semantics. */
export function nonblank(value: string): boolean {
  return value.replace(whitespace, "").length > 0;
}

function collapse(value: string): string {
  return value.replace(whitespace, " ").replace(/^ | $/gu, "");
}

// collapse() has reduced all whitespace to spaces. Match // or a dotted host
// with /, ? or #, and bare www links inside Markdown punctuation.
const urlTokens =
  /(?<![^ <>])(?:[^ <>]*\/\/|[^./ <>]*\.[^ <>]*[/?#])[^ <>]*|(?<![^ *_~(])www\.[^ <>]+/giu;
const webLink =
  /(?<![^ ("])(?:https?:\/\/|www\.)[a-z0-9.:-]+[/?#][^ <>\\`*\[\]|()"]+(?=$|[ )"])/i;
const wordUnderscore = /(?<=[A-Za-z0-9])_(?=[A-Za-z0-9])/gu;
const inlineCode = /(?<!`)`[^`\n]+`(?!`)/u;
const punctuation = /[\\`*_\[\]<>]/u;
// ASCII case folding keeps the web link scheme and host in sync with Python.
const markdown = new RegExp(
  `${inlineCode.source}|(${webLink.source})|(${wordUnderscore.source})|${punctuation.source}|${entityAmp.source}`,
  "gi",
);
const linkLabel = new RegExp("[_~]|" + entityAmp.source, "gu");

/** Match report_projection._escape_markdown, including bare web link handling. */
function escapeMarkdown(value: string): string {
  const inUrl = new Uint8Array(value.length);
  for (const match of value.matchAll(urlTokens)) {
    inUrl.fill(1, match.index, match.index + match[0].length);
  }
  return value.replace(markdown, (match, link, word, offset: number) => {
    if (link !== undefined) {
      const url = match.replace(/(?<![.,:;!?])[.,:;!?]+$/u, "");
      if (!url.replace(wordUnderscore, "").includes("_")) return match;
      const label = url.replace(linkLabel, "\\$&");
      const target = /^www\./iu.test(url) ? "http://" + url : url;
      return `[${label}](<${target.replaceAll("&", "&amp;")}>)${match.slice(url.length)}`;
    }
    return match.length > 1 ||
      ((match === "&" || word !== undefined) && inUrl[offset])
      ? match
      : "\\" + match;
  });
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

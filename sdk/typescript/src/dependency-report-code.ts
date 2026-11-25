type Token =
  "comment" | "keyword" | "literal" | "number" | "property" | "string";

const lineComment = /\/\/[^\r\n]*/u.source;
const blockComment = /\/\*[\s\S]*?(?:\*\/|$)/u.source;
const hashComment = /(?<!\S)#[^\r\n]*/u.source;
const doubleQuoted = /"(?:\\[\s\S]|[^"\\\r\n])*"/u.source;
const singleQuoted = /'(?:\\[\s\S]|[^'\\\r\n])*'/u.source;
const charLiteral = /'(?:\\[^\r\n]|[^'\\\r\n])'/u.source;
const backtickQuoted = /`(?:\\[\s\S]|[^`\\])*`/u.source;
const tripleQuoted = /"""[\s\S]*?(?:"""|$)|'''[\s\S]*?(?:'''|$)/u.source;
const identifier = /[$\p{ID_Start}][$\p{ID_Continue}]*/u.source;
const number =
  /\b(?:0[xX][\da-fA-F_]+|0[bB][01_]+|0[oO][0-7_]+|\d[\d_]*(?:\.[\d_]+)?(?:[eE][+-]?[\d_]+)?)\b/u
    .source;

function grammar({
  extensions,
  keywords = "",
  literals = "",
  comments = [],
  strings = [doubleQuoted, singleQuoted],
  properties = false,
}: {
  extensions: string;
  keywords?: string;
  literals?: string;
  comments?: string[];
  strings?: string[];
  properties?: boolean;
}) {
  const patterns = [
    ...(comments.length ? [`(?<comment>${comments.join("|")})`] : []),
    `(?<string>${strings.join("|")})`,
    `(?<number>${number})`,
    `(?<word>${identifier})`,
  ];
  return {
    extensions: new Set(extensions.split(" ")),
    pattern: new RegExp(patterns.join("|"), "gu"),
    keywords: new Set(keywords.split(" ")),
    literals: new Set(literals.split(" ")),
    properties,
  };
}

const cComments = [lineComment, blockComment];
const grammars = [
  grammar({
    extensions: ".js .jsx .mjs .cjs .ts .tsx .mts .cts",
    keywords:
      "as async await break case catch class const continue debugger declare default delete do else enum export extends finally for from function if implements import in instanceof interface let new of private protected public readonly return satisfies static super switch this throw try type typeof var void while with yield",
    literals: "true false null undefined",
    comments: cComments,
    strings: [doubleQuoted, singleQuoted, backtickQuoted],
  }),
  grammar({
    extensions: ".py .pyi",
    keywords:
      "and as assert async await break case class continue def del elif else except finally for from global if import in is lambda match nonlocal not or pass raise return try while with yield",
    literals: "True False None",
    comments: [hashComment],
    strings: [tripleQuoted, doubleQuoted, singleQuoted],
  }),
  grammar({
    extensions: ".go",
    keywords:
      "break case chan const continue default defer else fallthrough for func go goto if import interface map package range return select struct switch type var",
    literals: "true false nil iota",
    comments: cComments,
    strings: [doubleQuoted, charLiteral, backtickQuoted],
  }),
  grammar({
    extensions: ".rs",
    keywords:
      "as async await break const continue crate dyn else enum extern fn for if impl in let loop match mod move mut pub ref return self Self static struct super trait type unsafe use where while",
    literals: "true false",
    comments: cComments,
    strings: [doubleQuoted, charLiteral],
  }),
  grammar({
    extensions: ".c .h .cc .hh .cpp .hpp .cxx .hxx .java .cs .swift .kt .kts",
    keywords:
      "abstract as auto break case catch char class const constexpr continue default do double else enum extends extern final finally float for if implements import int interface long namespace new override package private protected public return short signed sizeof static struct super switch template this throw try typedef typename union unsigned using var void volatile while",
    literals: "true false null NULL nullptr",
    comments: cComments,
    strings: [doubleQuoted, charLiteral],
  }),
  grammar({
    extensions: ".json .jsonc",
    literals: "true false null",
    comments: cComments,
    strings: [doubleQuoted],
    properties: true,
  }),
  grammar({
    extensions: ".yaml .yml",
    literals: "true false null True False Null",
    comments: [hashComment],
    properties: true,
  }),
  grammar({
    extensions: ".sh .bash .zsh .ksh .fish .bashrc .zshrc .profile",
    keywords:
      "case do done elif else esac export fi for function if in local readonly return select then trap unset until while",
    literals: "true false",
    comments: [hashComment],
  }),
];

const escapes: Record<string, string> = {
  "&": "&amp;",
  "<": "&lt;",
  ">": "&gt;",
  '"': "&quot;",
  "'": "&#39;",
  "\r": "&#13;",
};
export const escapeHtml = (text: string) =>
  text.replace(/[&<>"'\r]/gu, (character) => escapes[character]!);

/** Match an explicitly reported expression once, in the original text before escaping. */
function argumentRange(line: string | undefined, expression: string) {
  if (!line || !expression) return;
  const start = line.indexOf(expression);
  if (start < 0 || start !== line.lastIndexOf(expression)) return;
  const end = start + expression.length;
  const word = /[$\p{ID_Continue}]/u;
  if (word.test(line[start - 1] ?? "") && word.test(expression[0]!)) return;
  if (word.test(line[end] ?? "") && word.test(expression.at(-1)!)) return;
  return { start, end };
}

export function renderDependencyCode(
  text: string,
  path: string,
  firstLine: number,
  highlightedLines?: ReadonlySet<number>,
  argument?: { line: number; expression: string },
  follow = false,
  relatedLines?: ReadonlySet<number>,
): string {
  const extension = /\.[a-z\d]+$/iu.exec(path)?.[0].toLowerCase() ?? "";
  const syntax = grammars.find(({ extensions }) => extensions.has(extension));
  const lines = [""];
  const argumentLine = argument && argument.line - firstLine;
  const range =
    argument && argumentLine !== undefined
      ? argumentRange(text.split("\n")[argumentLine], argument.expression)
      : undefined;
  let column = 0;
  function append(value: string, token?: Token) {
    for (const [index, part] of value.split("\n").entries()) {
      if (index) {
        lines.push("");
        column = 0;
      }
      if (!part) continue;
      const row = lines.length - 1;
      const styled = (s: string) =>
        s && token
          ? `<span class="tok-${token}">${escapeHtml(s)}</span>`
          : escapeHtml(s);
      if (
        range &&
        row === argumentLine &&
        column < range.end &&
        column + part.length > range.start
      ) {
        const from = Math.max(range.start - column, 0);
        const to = Math.min(range.end - column, part.length);
        lines[row] += styled(part.slice(0, from));
        if (column + from === range.start)
          lines[row] += '<mark class="trace-argument">';
        lines[row] += styled(part.slice(from, to));
        if (column + to === range.end) lines[row] += "</mark>";
        lines[row] += styled(part.slice(to));
      } else {
        lines[row] += styled(part);
      }
      column += part.length;
    }
  }

  let offset = 0;
  if (syntax) {
    const colon = /[\t ]*:/uy;
    for (const match of text.matchAll(syntax.pattern)) {
      const [value] = match;
      const { comment, string, number, word } = match.groups!;
      append(text.slice(offset, match.index));
      offset = match.index + value.length;
      colon.lastIndex = offset;
      let token: Token | undefined;
      if (comment !== undefined) token = "comment";
      else if (
        syntax.properties &&
        (string !== undefined || word !== undefined) &&
        colon.test(text)
      )
        token = "property";
      else if (string !== undefined) token = "string";
      else if (number !== undefined) token = "number";
      else if (syntax.keywords.has(value)) token = "keyword";
      else if (syntax.literals.has(value)) token = "literal";
      append(value, token);
    }
  }
  append(text.slice(offset));

  const rows = lines
    .map((line, index) => {
      const number = firstLine + index;
      return `<span class="code-row" data-line="${number}"${highlightedLines?.has(number) ? " data-highlighted" : relatedLines?.has(number) ? ' data-related title="Another step in this path"' : ""}><span class="code-number" aria-hidden="true">${number}</span><span class="code-text">${line}</span>${follow && highlightedLines?.has(number) ? '<button type="button" data-follow data-js hidden aria-label="Next recorded frame" title="Next recorded frame">→</button>' : ""}</span>`;
    })
    .join("");
  return `<pre class="code-listing"><code>${rows}</code></pre>`;
}

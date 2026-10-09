import { fromMarkdown } from "mdast-util-from-markdown";

// GitLab/Comrak dollar math requires a closing delimiter. Single-dollar math
// also rejects whitespace at either edge and a digit after the closing dollar.
function gitlabMathEnd(markdown: string, start: number): number | undefined {
  let content = start;
  while (markdown[content] === "$") content++;
  const dollars = content - start;
  const codeMath = dollars === 1 && markdown[content] === "`";
  if (codeMath) content++;
  else if (
    dollars > 2 ||
    (dollars === 1 && /[\t-\r ]/u.test(markdown[content] ?? ""))
  )
    return;

  for (
    let close = markdown.indexOf("$", content);
    close !== -1;
    close = markdown.indexOf("$", close + 1)
  ) {
    if (codeMath) {
      if (markdown[close - 1] === "`")
        return close - 1 > content ? close + 1 : undefined;
    } else if (dollars === 1) {
      if (/[\t-\r ]/u.test(markdown[close - 1]!)) return;
      if (markdown[close - 1] === "\\") continue;
      if (/[0-9]/u.test(markdown[close + 1] ?? "")) return;
      if (close > content) return close + 1;
    } else if (markdown[close + 1] === "$" && close > content) return close + 2;
  }
}

function gitlabPatchMarkdown(markdown: string) {
  return fromMarkdown(markdown, {
    extensions: [
      {
        text: {
          36: {
            previous(code) {
              const previous = this.events.at(-1)?.[1].type;
              return (
                code !== 36 ||
                previous === "characterEscape" ||
                previous === "codeText"
              );
            },
            tokenize(effects, ok, nok) {
              const end = gitlabMathEnd(markdown, this.now().offset);
              if (end === undefined) return nok;
              // Reuse literal-span nodes only for their source positions. This
              // tree is never rendered; dollar syntax follows GitLab's rules.
              const context = this;
              const consume: typeof ok = (code) => {
                if (context.now().offset === end) {
                  effects.exit("codeTextData");
                  effects.exit("codeText");
                  return ok(code);
                }
                if (code === null) return nok(code);
                // micromark uses -5/-4/-3 for CR, LF, and CRLF.
                if (code <= -3) {
                  effects.exit("codeTextData");
                  effects.enter("lineEnding");
                  effects.consume(code);
                  effects.exit("lineEnding");
                  effects.enter("codeTextData");
                } else effects.consume(code);
                return consume;
              };
              return (code) => {
                effects.enter("codeText");
                effects.enter("codeTextData");
                return consume(code);
              };
            },
          },
        },
      },
    ],
  });
}

export function gitlabPatchDescription(body: string): string {
  const escaped = new Set<number>();
  let offset = 0;
  for (;;) {
    const markdown = body.slice(offset);
    let closingQuote: RegExpExecArray | null | undefined;
    for (const node of gitlabPatchMarkdown(markdown).children) {
      const { start, end } = node.position!;
      const quote =
        node.type === "blockquote"
          ? /^ {0,3}(>{3,})[ \t]*(?:\r?\n|$)/u.exec(
              markdown.slice(start.offset),
            )
          : null;
      if (quote) {
        // GitLab closes fenced quotes before parsing their children, even code.
        // Resume CommonMark parsing after the matching or longer closing fence.
        const fence = new RegExp(
          `^ {0,3}>{${quote[1]!.length},}[ \\t]*(?:\\r?\\n|$)`,
          "gm",
        );
        fence.lastIndex = start.offset! + quote[0].length;
        closingQuote = fence.exec(markdown);
        break;
      }
      if (node.type !== "paragraph") continue;

      // Preserve parsed literal spans and HTML, including nested formatting.
      const literalRanges: [number, number][] = [];
      const inlineNodes = [...node.children];
      for (const inline of inlineNodes) {
        if (inline.type === "inlineCode" || inline.type === "html")
          literalRanges.push([
            inline.position!.start.offset!,
            inline.position!.end.offset!,
          ]);
        else if ("children" in inline) inlineNodes.push(...inline.children);
      }

      // Match GitLab's top-level paragraph and HTML exclusions.
      const paragraphOffset = start.offset! - start.column + 1;
      const paragraph = markdown.slice(paragraphOffset, end.offset);
      for (const match of paragraph.matchAll(
        /^<[^>]+?>\r?\n[\s\S]+?\r?\n<\/[^>]+?>\r?$|^\//gmu,
      )) {
        const slashOffset = paragraphOffset + match.index;
        if (
          match[0] === "/" &&
          !literalRanges.some(
            ([start, end]) => slashOffset >= start && slashOffset < end,
          )
        )
          escaped.add(offset + slashOffset);
      }
    }
    if (!closingQuote) break;
    offset += closingQuote.index + closingQuote[0].length;
  }
  return body.replace(/^\//gmu, (slash, offset: number) =>
    escaped.has(offset) ? `\\${slash}` : slash,
  );
}

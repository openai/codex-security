import stringWidth from "string-width";

export const graphemes = new Intl.Segmenter();

export function fitLine(
  text: string,
  width: number,
  overflowMarker: "" | "…" = "…",
): string {
  if (overflowMarker && stringWidth(text) <= width) return text;
  const available = width - overflowMarker.length;
  let columns = 0;
  for (const { segment, index } of graphemes.segment(text)) {
    columns += stringWidth(segment);
    if (columns > available) return text.slice(0, index) + overflowMarker;
  }
  return text;
}

export function fitCell(
  text: string,
  width: number,
  overflowMarker: "" | "…" = "…",
): string {
  const fitted = fitLine(text, width, overflowMarker);
  return fitted + " ".repeat(width - stringWidth(fitted));
}

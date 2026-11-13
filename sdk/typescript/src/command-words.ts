/** Split quoted command words without evaluating shell expansions. */
export function splitCommand(
  command: string,
  backslashes: "escape" | "literal" = "escape",
): string[] | null {
  const words: string[] = [];
  let word = "";
  let started = false;
  let quote: "'" | '"' | null = null;
  for (let index = 0; index < command.length; index++) {
    const character = command[index]!;
    if (character === "\\" && quote !== "'" && backslashes === "escape") {
      const next = command[++index];
      if (next === undefined) return null;
      if (next === "\n") continue;
      if (quote === '"' && !["$", "`", '"', "\\"].includes(next)) word += "\\";
      word += next;
      started = true;
    } else if (quote !== null) {
      if (character === quote) quote = null;
      else word += character;
    } else if (character === "'" || character === '"') {
      quote = character;
      started = true;
    } else if (" \t\r\n".includes(character)) {
      if (started) words.push(word);
      word = "";
      started = false;
    } else {
      word += character;
      started = true;
    }
  }
  if (quote !== null) return null;
  if (started) words.push(word);
  return words;
}

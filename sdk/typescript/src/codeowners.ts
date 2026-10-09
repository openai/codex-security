export type CodeownerIdentity =
  | { kind: "person" | "group"; provider: "github"; handle: string }
  | { kind: "person"; email: string };

export interface CodeownersRule {
  pattern: string;
  line: number;
  rule: string;
  owners: CodeownerIdentity[];
  matches: RegExp;
}

/** GitHub CODEOWNERS uses the last matching rule, including ownerless rules. */
export function parseCodeowners(source: string): CodeownersRule[] {
  const rules: CodeownersRule[] = [];
  for (const [index, line] of source.split(/\r?\n/u).entries()) {
    const value = line.trim();
    if (!value || value.startsWith("#")) continue;
    const token = /^(?:\\.|[^\s])+/u.exec(value)![0];
    const matches = codeownersPattern(token);
    if (matches === null) continue;
    const handles = value
      .slice(token.length)
      .split("#", 1)[0]!
      .trim()
      .split(/\s+/u)
      .filter(Boolean);
    const owners: CodeownerIdentity[] = [];
    let valid = true;
    for (const handle of handles) {
      if (/^@[a-z\d](?:[a-z\d_-]*[a-z\d])?(?:\/[a-z\d_.-]+)?$/iu.test(handle)) {
        owners.push(
          handle.includes("/")
            ? { kind: "group", provider: "github", handle: handle.slice(1) }
            : { kind: "person", provider: "github", handle: handle.slice(1) },
        );
      } else if (/^[^@\s]+@[^@\s]+$/u.test(handle)) {
        owners.push({ kind: "person", email: handle });
      } else {
        valid = false;
        break;
      }
    }
    if (valid)
      rules.push({
        pattern: token,
        line: index + 1,
        rule: line,
        owners,
        matches,
      });
  }
  return rules;
}

function codeownersPattern(pattern: string): RegExp | null {
  if (pattern.startsWith("!") || pattern.startsWith("\\#")) return null;
  const anchored = pattern.startsWith("/");
  if (anchored) pattern = pattern.slice(1);
  const directory = pattern.endsWith("/");
  if (directory) pattern = pattern.slice(0, -1);
  const prefix = anchored || pattern.includes("/") ? "^" : "(?:^|/)";
  let expression = "";
  for (let index = 0; index < pattern.length; index++) {
    const character = pattern[index]!;
    if (character === "\\" && index + 1 < pattern.length) {
      expression += escapeRegex(pattern[++index]!);
    } else if (
      character === "[" ||
      character === "]" ||
      pattern.startsWith("***", index)
    ) {
      return null;
    } else if (
      character === "*" &&
      pattern[index + 1] === "*" &&
      (index === 0 || pattern[index - 1] === "/") &&
      (index + 2 === pattern.length || pattern[index + 2] === "/")
    ) {
      if (pattern[index + 2] === "/") {
        expression += "(?:[^/]+/)*";
        index += 2;
      } else {
        expression += ".*";
        index++;
      }
    } else if (character === "*") expression += "[^/]*";
    else if (character === "?") expression += "[^/]";
    else expression += escapeRegex(character);
  }
  // A terminal single wildcard matches one path component, as in docs/*.
  const suffix = directory
    ? "/"
    : /(?<!\\)[*?]$/u.test(pattern) && !pattern.endsWith("/**")
      ? "$"
      : "(?:/|$)";
  return new RegExp(prefix + expression + suffix, "u");
}

function escapeRegex(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&");
}

export function codeownersForPath(
  rules: readonly CodeownersRule[],
  path: string,
): CodeownersRule | undefined {
  return rules.findLast(({ matches }) => matches.test(path));
}

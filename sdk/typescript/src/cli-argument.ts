/** Quote a literal argument for the user's shell (PowerShell on Windows). */
export function quoteCliPath(value: string): string {
  if (/^[A-Za-z0-9_./:-]+$/u.test(value)) return value;
  const escaped =
    process.platform === "win32"
      ? value.replace(/['\u2018\u2019\u201a\u201b]/gu, (quote) => quote + quote)
      : value.replaceAll("'", `'"'"'`);
  return `'${escaped}'`;
}

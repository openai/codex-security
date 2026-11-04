/** Format untrusted text for a single terminal line before applying styles. */
export function terminalDisplayText(value: unknown): string {
  return String(value)
    .replace(/\u001B\[[0-?]*[ -/]*[@-~]/g, "")
    .replace(/[\u0000-\u001F\u007F-\u009F]/g, " ");
}

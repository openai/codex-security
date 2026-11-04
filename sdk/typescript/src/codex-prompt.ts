// Codex's upstream limit applies to Unicode characters in one user message.
// https://github.com/openai/codex/blob/956f590ad549e75913894614ce0cbec4d5fd677a/codex-rs/protocol/src/user_input.rs#L8-L9
export const MAX_CODEX_INPUT_CHARACTERS = 1 << 20;

export function characterCount(value: string): number {
  return value[Symbol.iterator]().reduce((count) => count + 1, 0);
}

export function shellEnvironmentReference(name: string, suffix = ""): string {
  return `"${process.platform === "win32" ? "$env:" : "$"}${name}${suffix}"`;
}

export function pluginPythonCommand(): string {
  return `${process.platform === "win32" ? "& " : ""}${shellEnvironmentReference("PYTHON")}`;
}

export function jsonForPrompt(value: unknown): string {
  return JSON.stringify(value)
    .replaceAll("\u0085", "\\u0085")
    .replaceAll("\u2028", "\\u2028")
    .replaceAll("\u2029", "\\u2029");
}

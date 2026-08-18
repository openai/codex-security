export function shellEnvironmentReference(name: string, suffix = ""): string {
  const prefix = process.platform === "win32" ? "$env:" : "$";
  return `"${prefix}${name}${suffix}"`;
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

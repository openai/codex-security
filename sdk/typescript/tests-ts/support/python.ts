export function pythonExecutable(inheritEnvironment = true): string | null {
  return (
    (inheritEnvironment ? process.env["PYTHON"] : undefined) ??
    Bun.which("python3") ??
    Bun.which("python") ??
    Bun.which("py")
  );
}

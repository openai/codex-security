export function pythonExecutable(): string | null {
  return (
    process.env["PYTHON"] ??
    Bun.which("python3") ??
    Bun.which("python") ??
    Bun.which("py")
  );
}

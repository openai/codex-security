import { resolvePythonCommand } from "../../src/python_command.ts";

export const fixturePython =
  process.env.PYTHON?.trim() ||
  (process.platform === "win32" ? await resolvePythonCommand() : "python3");

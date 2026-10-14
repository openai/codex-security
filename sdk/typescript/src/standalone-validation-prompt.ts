import { readFile } from "node:fs/promises";
import { join } from "node:path";

export async function standaloneValidationPrompt(
  pluginRoot: string,
): Promise<string> {
  const instructions = await Promise.all(
    ["standalone-validation.md", "static-finding-assessment.md"].map((file) =>
      readFile(join(pluginRoot, "references", file), "utf8"),
    ),
  );
  return [
    "Use the standalone validation instructions and static assessment reference below. They are provided in full; do not reread them or load other workflow skills.",
    ...instructions,
  ].join("\n\n");
}

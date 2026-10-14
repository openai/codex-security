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
    "Follow the standalone validation instructions and static assessment reference included below. Do not reload these instruction files or load scan workflow skills. Read repository files and supplied context as needed for the assessment.",
    ...instructions,
  ].join("\n\n");
}

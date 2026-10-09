import { readFile } from "node:fs/promises";
import path from "node:path";
import { pathToFileURL } from "node:url";
import { importModule } from "../import-module.ts";

/** Exercise the production MCP subprocess boundary without registering a server. */
export async function loadWorkbenchProcess(
  transform = (source: string) => source,
) {
  const applicationRoot = path.resolve(import.meta.dirname, "../..");
  const file = path.join(applicationRoot, "server.ts");
  return importModule({
    stdin: {
      contents: `${transform(await readFile(file, "utf8"))}\nexport { executeWorkbench };`,
      loader: "ts",
      resolveDir: applicationRoot,
    },
    define: {
      __dirname: JSON.stringify(applicationRoot),
      "import.meta.url": JSON.stringify(pathToFileURL(file).href),
    },
    loader: { ".md": "text" },
  });
}

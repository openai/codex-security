import { readFile } from "node:fs/promises";
import path from "node:path";
import { pathToFileURL } from "node:url";
import { importModule } from "../import-module.ts";

/** Exercise the shared subprocess boundary without registering a server. */
export async function loadWorkbenchProcess(
  transform = (source: string) => source,
) {
  const applicationRoot = path.resolve(import.meta.dirname, "../..");
  const file = path.join(applicationRoot, "src", "workbench-client.ts");
  return importModule({
    stdin: {
      contents: `${transform(await readFile(file, "utf8"))}\nexport { executeWorkbench };`,
      loader: "ts",
      resolveDir: path.dirname(file),
    },
    define: {
      __dirname: JSON.stringify(applicationRoot),
      "import.meta.url": JSON.stringify(pathToFileURL(file).href),
    },
    loader: { ".md": "text" },
  });
}

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
  const module = await importModule({
    banner: {
      js: `import { createRequire as createFixtureRequire } from "node:module"; const require = createFixtureRequire(${JSON.stringify(pathToFileURL(file).href)});`,
    },
    stdin: {
      contents: transform(await readFile(file, "utf8")),
      loader: "ts",
      resolveDir: applicationRoot,
    },
    define: {
      __dirname: JSON.stringify(applicationRoot),
      "import.meta.url": JSON.stringify(pathToFileURL(file).href),
    },
    loader: { ".md": "text" },
  });
  return {
    executeWorkbench(python: string, args: string[], input?: string | Buffer) {
      return module.executeWorkbench(python, args, undefined, input);
    },
  };
}

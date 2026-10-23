import { writeFile } from "node:fs/promises";
import { join } from "node:path";
import { pathToFileURL } from "node:url";

export const sqliteProviderConfig = {
  model_provider: "synthetic.provider",
  model_providers: {
    "synthetic.provider": {
      name: "Synthetic provider",
      base_url: "https://example.invalid/v1",
      wire_api: "responses",
      http_headers: { "x-synthetic-key": "synthetic-private-value" },
    },
  },
};

export async function nativeSqlitePreflight(root: string, sqliteHome: string) {
  const transcript = join(root, "native-sqlite-requests.jsonl");
  const preload = join(root, "native-sqlite-preflight.mjs");
  await writeFile(
    preload,
    [
      'import { createInterface } from "node:readline";',
      'import { appendFileSync } from "node:fs";',
      `const transcript = ${JSON.stringify(transcript)};`,
      "const argv = process.argv.slice(1);",
      'if (!argv.some(value => value.startsWith("model_providers=") && value.includes("synthetic.provider"))) { console.error("Synthetic selected model provider is unavailable"); process.exit(1); }',
      'if (argv.some(value => value.includes("synthetic-private-value"))) { console.error("Synthetic private provider value reached arguments"); process.exit(1); }',
      "for await (const line of createInterface({ input: process.stdin })) {",
      "const request = JSON.parse(line);",
      'appendFileSync(transcript, JSON.stringify({ request, argv, cwd: process.cwd(), home: process.env.CODEX_HOME }) + "\\n");',
      'if (request.method === "initialize") process.stdout.write(JSON.stringify({ id: request.id, result: {} }) + "\\n");',
      `if (request.method === "config/read") process.stdout.write(JSON.stringify({ id: request.id, result: { config: { sqlite_home: ${JSON.stringify(sqliteHome)} } } }) + "\\n");`,
      "}",
    ].join("\n"),
  );
  return {
    transcript,
    environment: { NODE_OPTIONS: `--import=${pathToFileURL(preload).href}` },
  };
}

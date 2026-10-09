import { writeFileSync } from "node:fs";

const names = [
  "OPENAI_API_KEY",
  "CODEX_HOME",
  "CODEX_SQLITE_HOME",
  "OPTIONAL_SOURCE",
  "MISSING_SOURCE",
  "INHERITED_SOURCE",
  "OBJECT_SOURCE",
  "IMPLICIT_SOURCE",
  "OVERRIDDEN_SOURCE",
  "__proto__",
];
writeFileSync(
  process.argv[2],
  JSON.stringify({
    cwd: process.cwd(),
    environment: Object.fromEntries(
      names.map((name) => [
        name,
        Object.hasOwn(process.env, name) ? process.env[name] : undefined,
      ]),
    ),
  }),
);
// Deliberately fail initialization after recording the native MCP child's environment.
process.exit(1);

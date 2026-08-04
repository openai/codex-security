#!/usr/bin/env node
import { main } from "../src/cli.mjs";

main(process.argv.slice(2)).then(
  (code) => {
    process.exitCode = code ?? 0;
  },
  (error) => {
    const message =
      error && typeof error === "object" && "message" in error
        ? String(error.message)
        : String(error);
    process.stderr.write(`claude-security: ${message}\n`);
    if (process.env["CLAUDE_SECURITY_DEBUG"] === "1" && error?.stack) {
      process.stderr.write(`${error.stack}\n`);
    }
    process.exitCode = typeof error?.exitCode === "number" ? error.exitCode : 1;
  },
);

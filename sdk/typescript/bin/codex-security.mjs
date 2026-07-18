#!/usr/bin/env node
async function launch() {
  const [{ realpathSync }, { dirname, join }, { pathToFileURL }] =
    await Promise.all([
      import("node:fs"),
      import("node:path"),
      import("node:url"),
    ]);
  const entrypoint = process.argv[1];
  if (entrypoint === undefined) {
    throw new Error("Cannot resolve CLI entrypoint.");
  }
  const cli = join(dirname(realpathSync(entrypoint)), "..", "dist", "cli.js");
  const { main } = await import(pathToFileURL(cli).href);
  return await main();
}

void launch().then(
  (exitCode) => {
    process.exitCode = exitCode;
  },
  (error) => {
    process.stderr.write(
      `codex-security: ${error instanceof Error ? error.message : String(error)}\n`,
    );
    process.exitCode = 1;
  },
);

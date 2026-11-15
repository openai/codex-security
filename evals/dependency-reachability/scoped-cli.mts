import { realpath } from "node:fs/promises";
import { dirname, join } from "node:path";
import { pathToFileURL } from "node:url";

const [binary, dependencyCallerScope, ...argv] = process.argv.slice(2);
if (binary === undefined || dependencyCallerScope === undefined) {
  throw new Error("Expected a built CLI path, caller scope, and CLI arguments");
}

const cli = join(dirname(await realpath(binary)), "..", "dist", "cli.js");
const { main, supportsDependencyCallerScope } = await import(
  pathToFileURL(cli).href
);
if (supportsDependencyCallerScope !== true) {
  throw new Error(
    "The selected CLI build does not support caller scope for dependency reachability evals.",
  );
}
process.exitCode = await main(argv, undefined, undefined, undefined, {
  dependencyCallerScope,
});

import { realpathSync } from "node:fs";

export function isMain(url) {
  try {
    return (
      process.argv[1] !== undefined &&
      realpathSync(process.argv[1]) === realpathSync(new URL(url))
    );
  } catch {
    // Imported modules may receive a non-file argument from node --eval.
    return false;
  }
}

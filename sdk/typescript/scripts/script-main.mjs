import { realpathSync } from "node:fs";
import { pathToFileURL } from "node:url";

export function isMain(moduleUrl) {
  try {
    return (
      process.argv[1] !== undefined &&
      process.argv[1] !== "-" &&
      pathToFileURL(realpathSync(process.argv[1])).href === moduleUrl
    );
  } catch {
    return false;
  }
}

import { join } from "node:path";

const manifest = join(process.cwd(), "package.json");
// Windows Node --run can skip the SDK manifest at MAX_PATH and run an ancestor's build.
if (process.platform === "win32" && manifest.length >= 260) {
  console.error(
    `Cannot pack the SDK from ${manifest}. Windows Node --run may select an ancestor package.json at this length. Use a shorter checkout path.`,
  );
  process.exitCode = 1;
}

import { execFileSync } from "node:child_process";

export function gitText(args, options) {
  return execFileSync("git", args, { ...options, encoding: "utf8" });
}

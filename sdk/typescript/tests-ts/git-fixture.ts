import { gitText } from "./support/shell.js";

export function git(repository: string, ...args: string[]): string {
  return gitText(
    [
      "-c",
      "user.name=Fixture",
      "-c",
      "user.email=fixture@example.com",
      ...args,
    ],
    { cwd: repository },
  ).trim();
}

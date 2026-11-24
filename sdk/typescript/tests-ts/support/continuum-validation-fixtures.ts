import { readFileSync } from "node:fs";
import { beforeEach, afterEach } from "bun:test";
import { execFileSync } from "node:child_process";
import { join } from "node:path";
import { createTemporaryDirectories } from "./temporary-directories.js";

export function continuumTestRepository() {
  const dirs = createTemporaryDirectories(true);
  const context = { repositoryPath: "" };
  let saved: string | undefined;
  beforeEach(async () => {
    saved = process.env["CODEX_SECURITY_STATE_DIR"];
    const home = await dirs.create("continuum-validation-");
    context.repositoryPath = join(home, "repo");
    process.env["CODEX_SECURITY_STATE_DIR"] = join(home, "state");
    execFileSync("git", ["init", "-q", context.repositoryPath]);
    execFileSync(
      "git",
      ["remote", "add", "origin", "https://github.com/example/project"],
      { cwd: context.repositoryPath },
    );
  });
  afterEach(async () => {
    if (saved === undefined) delete process.env["CODEX_SECURITY_STATE_DIR"];
    else process.env["CODEX_SECURITY_STATE_DIR"] = saved;
    await dirs.cleanup();
  });
  return context;
}

function arn(environmentId: string) {
  return (
    "arn:aws:continuum:us-east-1:123456789012:environments/" + environmentId
  );
}

export function registeredSource(
  op: string,
  environmentId = "environment1",
  repository = "example/project",
) {
  if (op === "get-environment")
    return {
      environmentArn: arn(environmentId),
      configuration: {
        codeConfiguration: {
          sourceConfiguration: {
            repositorySources: [{ integrationId: "integration", repository }],
          },
        },
      },
    };
  if (op === "get-integration") return { integrationType: "GITHUB" };
}

export function creation(findingId: string, environmentId = "environment1") {
  return {
    findingId,
    findingArn: arn(environmentId) + "/code-findings/" + findingId,
  };
}

export function requestBody(args: readonly string[]): string {
  const file = args[1]!;
  if (args[0] !== "--cli-input-json" || !file.startsWith("file://"))
    throw new Error("Expected a request file");
  return readFileSync(file.slice("file://".length), "utf8");
}

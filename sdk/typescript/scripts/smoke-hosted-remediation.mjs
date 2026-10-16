// Exercise an installed SDK over real pipes with a fake host, without inference.
import assert from "node:assert/strict";
import { execFileSync, spawn } from "node:child_process";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { createInterface } from "node:readline";
import { pathToFileURL } from "node:url";

const packageRoot = resolve(process.argv[2] ?? join(import.meta.dirname, ".."));
const node = process.argv[3] ?? process.execPath;
const repository = await mkdtemp(join(tmpdir(), "hosted-remediation-smoke-"));
const git = (...args) =>
  execFileSync(
    "git",
    [
      "-c",
      "user.name=Fixture",
      "-c",
      "user.email=fixture@example.com",
      ...args,
    ],
    { cwd: repository, encoding: "utf8" },
  ).trim();

async function run(operation, revision) {
  const entrypoint = pathToFileURL(join(packageRoot, "dist", "index.js")).href;
  const child = spawn(
    node,
    [
      "--input-type=module",
      "-e",
      `import {runHostedRemediationProtocol} from ${JSON.stringify(entrypoint)}; process.exitCode = await runHostedRemediationProtocol(process.stdin, process.stdout);`,
    ],
    { stdio: ["pipe", "pipe", "pipe"] },
  );
  const closed = new Promise((resolve, reject) => {
    child.on("exit", resolve);
    child.on("error", reject);
  });
  const send = (value) =>
    child.stdin.write(JSON.stringify({ jsonrpc: "2.0", ...value }) + "\n");
  let stderr = "";
  child.stderr.on("data", (chunk) => {
    stderr += chunk.toString();
  });
  let executionCount = 0;
  let result;
  try {
    send({
      id: operation,
      method: "run",
      params: {
        version: 1,
        operation,
        repository,
        revision,
        finding: {
          id: "synthetic-finding",
          context: "Synthetic package smoke fixture.",
        },
        instructions: "Preserve existing behavior.",
        validationInstructions: "Use the synthetic fixture check.",
        model: "synthetic-model",
        reasoningEffort: "high",
        identity: {
          runId: "synthetic-run",
          attemptId: operation,
          buildId: "synthetic-build",
        },
      },
    });
    for await (const line of createInterface({ input: child.stdout })) {
      const message = JSON.parse(line);
      if (message.method === "execution.run") {
        executionCount++;
        const request = message.params;
        assert.equal(request.operation, operation);
        assert.equal(
          request.sandbox,
          operation === "patch" ? "workspace-write" : "read-only",
        );
        assert.equal(request.revision, revision);
        assert.match(request.prompt, /synthetic fixture check/);
        assert.ok(
          await readFile(
            join(
              request.runtime.pluginRoot,
              "skills",
              "fix-finding",
              "SKILL.md",
            ),
            "utf8",
          ),
        );
        if (operation === "patch")
          await writeFile(
            join(repository, "guard.js"),
            "export const fixture = 'patched';\n",
          );
        else
          assert.equal(
            await readFile(join(repository, "guard.js"), "utf8"),
            "export const fixture = 'patched';\n",
          );
        const finalResponse =
          operation === "patch"
            ? {
                patches: [
                  {
                    occurrenceId: "synthetic-finding",
                    status: "verified",
                    files: ["guard.js"],
                    verification: "Synthetic fixture checked.",
                  },
                ],
              }
            : {
                results: [
                  {
                    id: "synthetic-finding",
                    status: "fixed",
                    evidence: "Synthetic candidate retained.",
                    checks: [
                      {
                        name: "Static inspection of the synthetic candidate",
                        status: "passed",
                        evidence:
                          "The synthetic guard contains the expected candidate value.",
                      },
                    ],
                  },
                ],
              };
        send({
          id: message.id,
          result: {
            requestId: request.requestId,
            status: "completed",
            sessionId: `synthetic-${operation}`,
            finalResponse: JSON.stringify(finalResponse),
            usage: { input_tokens: 1, output_tokens: 1 },
          },
        });
      } else if (message.id === operation) {
        assert.equal(message.error, undefined, JSON.stringify(message.error));
        result = message.result;
      }
    }
    assert.equal(await closed, 0, stderr);
    assert.equal(executionCount, 1);
    assert.equal(result.status, "completed");
    assert.equal(result.execution.sessionId, `synthetic-${operation}`);
    assert.equal(
      operation === "patch" ? result.patch.status : result.verification.status,
      operation === "patch" ? "verified" : "fixed",
    );
    if (operation === "verify") {
      assert.equal(result.verification.checks.length, 1);
      assert.equal(result.verification.checks[0].status, "passed");
      assert.equal(result.verification.checks[0].command, undefined);
    }
  } finally {
    child.kill();
  }
}

try {
  await writeFile(
    join(repository, "guard.js"),
    "export const fixture = 'original';\n",
  );
  git("init", "-q");
  git("add", ".");
  git("commit", "-qm", "fixture");
  const revision = git("rev-parse", "HEAD");
  await run("patch", revision);
  const candidate = await readFile(join(repository, "guard.js"), "utf8");
  await run("verify", revision);
  assert.equal(await readFile(join(repository, "guard.js"), "utf8"), candidate);
  console.log(
    JSON.stringify({
      status: "passed",
      operations: ["patch", "verify"],
      executor: "fake",
    }),
  );
} finally {
  await rm(repository, { recursive: true, force: true });
}

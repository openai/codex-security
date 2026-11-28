import assert from "node:assert/strict";
import { execFileSync, spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { once } from "node:events";
import { mkdirSync, writeFileSync } from "node:fs";
import { cp, mkdir, mkdtemp, readFile, writeFile } from "node:fs/promises";
import http from "node:http";
import { basename, join } from "node:path";
import { createInterface } from "node:readline";

export const summaryCve = "CVE-2099-1001";
export const reviewedCve = "CVE-2026-48801";
export const mixedServiceVersions = { notes: "5.0.0", reviews: "5.0.2" };
export const precondition =
  "A caller can send an empty array of samples to the long-lived summary service.";
export const sha256 = (bytes) =>
  createHash("sha256").update(bytes).digest("hex");
export const jsonFile = (file, value) =>
  writeFile(file, JSON.stringify(value, null, 2) + "\n", { flag: "wx" });
export function git(repo, ...args) {
  return execFileSync("git", ["-C", repo, ...args], {
    encoding: "utf8",
    maxBuffer: Infinity,
  }).trimEnd();
}

export function commitFixture(repo) {
  git(repo, "init", "--quiet", "--template=", "--object-format=sha1");
  mkdirSync(join(repo, ".git/info"), { recursive: true });
  writeFileSync(
    join(repo, ".git/info/attributes"),
    "* -filter -ident -text !eol !working-tree-encoding\n",
  );
  git(repo, "-c", "core.autocrlf=false", "add", "--force", "--", ".");
  execFileSync(
    "git",
    [
      "-C",
      repo,
      "-c",
      "commit.gpgSign=false",
      "commit",
      "--quiet",
      "-m",
      "Example application",
    ],
    {
      env: {
        ...process.env,
        GIT_AUTHOR_NAME: "Fixture",
        GIT_AUTHOR_EMAIL: "fixture@example.invalid",
        GIT_COMMITTER_NAME: "Fixture",
        GIT_COMMITTER_EMAIL: "fixture@example.invalid",
        GIT_AUTHOR_DATE: "2025-08-14T00:00:00Z",
        GIT_COMMITTER_DATE: "2025-08-14T00:00:00Z",
      },
    },
  );
  return git(repo, "rev-parse", "HEAD");
}

export async function mixedFixture(root) {
  const repo = await mkdtemp(join(root, "project-"));
  await cp(join(import.meta.dirname, "fixtures/mixed-services"), repo, {
    recursive: true,
  });
  return { repo, sha: commitFixture(repo) };
}

async function summaryRepo(root, version) {
  const repo = await mkdtemp(join(root, "project-"));
  const pkg = join(repo, "sample-summary");
  await mkdir(pkg);
  await cp(
    join(import.meta.dirname, "fixtures/summary/server.cjs"),
    join(repo, "server.cjs"),
  );
  await jsonFile(join(pkg, "package.json"), {
    name: "sample-summary",
    version,
    main: "index.cjs",
  });
  const initial = version === "0.2.1" ? ", 0" : "";
  await writeFile(
    join(pkg, "index.cjs"),
    [
      '"use strict";',
      "function sum(samples) {",
      "  return samples.reduce((a, b) => a + b" + initial + ");",
      "}",
      "module.exports = { sum };",
      "",
    ].join("\n"),
  );
  commitFixture(repo);
  return repo;
}

// Use fresh connections so a subsequent health check is an independent client.
function request(port, path, body) {
  return new Promise((resolve, reject) => {
    const req = http.request(
      {
        host: "127.0.0.1",
        port,
        path,
        agent: false,
        method: body ? "POST" : "GET",
        headers: body ? { "content-type": "application/json" } : {},
        signal: AbortSignal.timeout(5000),
      },
      (response) => {
        let text = "";
        response.setEncoding("utf8");
        response.on("data", (chunk) => {
          text += chunk;
        });
        response.on("end", () =>
          resolve({ status: response.statusCode, text }),
        );
        response.on("error", reject);
      },
    );
    req.on("error", reject);
    req.end(body);
  });
}

async function exercise(repo, capture, version) {
  const args = capture
    ? ["--require", join(import.meta.dirname, "observe.cjs")]
    : [];
  const child = spawn(process.execPath, [...args, "server.cjs"], {
    cwd: repo,
    env: { ...process.env, SUMMARY_EVAL_CAPTURE: capture || "" },
    stdio: ["ignore", "pipe", "pipe"],
  });
  const closed = once(child, "close");
  const reader = createInterface({ input: child.stdout });
  let stderr = "";
  child.stderr.setEncoding("utf8").on("data", (chunk) => {
    stderr += chunk;
  });
  try {
    const [line] = await Promise.race([
      once(reader, "line", { signal: AbortSignal.timeout(10000) }),
      closed.then(() => {
        throw new Error("Service exited before listening: " + stderr);
      }),
    ]);
    reader.close();
    const port = Number(line);
    assert(port > 0);
    const before = await request(port, "/health");
    assert.deepEqual(before, { status: 200, text: "ready" });
    let after;
    if (version === "0.2.0") {
      await assert.rejects(request(port, "/summary", '{"samples":[]}'), {
        code: "ECONNRESET",
      });
      const [code] = await closed;
      assert.equal(code, 1);
      assert.match(stderr, /Reduce of empty array with no initial value/);
      await assert.rejects(request(port, "/health"), { code: "ECONNREFUSED" });
      after = "process exited";
    } else {
      assert.deepEqual(await request(port, "/summary", '{"samples":[]}'), {
        status: 200,
        text: "0",
      });
      assert.deepEqual(await request(port, "/health"), before);
      after = "healthy";
    }
    return { version, initialHealth: before.status, after };
  } finally {
    reader.close();
    if (child.exitCode === null && child.signalCode === null) child.kill();
    await closed;
  }
}

async function packet(root, repo, capture, variant) {
  const input = await mkdtemp(join(root, "input-"));
  const sourceIndex = capture.frames.findIndex(
    (f) => f.name === "parseBatch" && f.location === "server.cjs",
  );
  assert(sourceIndex > 0);
  assert.equal(capture.ingress.peer, "127.0.0.1");
  const source = {
    id: "batch",
    function: "parseBatch",
    runtime_selectors: [{ name: "parseBatch", location: "server.cjs" }],
    scope:
      "Any uncredentialed client able to reach the loopback listener in the service's network namespace.",
  };
  const sink = {
    id: "sum",
    function: "sum",
    package: "sample-summary",
    path: "sample-summary/index.cjs",
    runtime_selectors: [{ name: "sum", location: "sample-summary/index.cjs" }],
    versionScheme: "semver",
    affectedVersions: ["<0.2.1"],
    preconditions: [precondition],
  };
  const [sum, ...callers] = capture.frames;
  const frame = { ...sum };
  if (variant !== "missing-version") {
    frame.package = {
      name: "sample-summary",
      version: capture.version,
      provenance: "The running service's loaded module and package manifest.",
    };
    if (variant !== "unbound") frame.sourceRevision = capture.sourceSha;
  }
  const observation = {
    observedAt: capture.observedAt,
    labels: { service: "summary", environment: "loopback" },
    frames: [frame, ...callers],
  };
  const advisory = {
    url: "https://example.invalid/advisories/sample-summary",
    revision: "1",
    summary:
      "Synthetic advisory. Before 0.2.1, the sample-summary sum function throws on an empty sample list. An unhandled exception can terminate a long-lived server.",
  };
  const docs = {
    sources: { format: "codex-security.stack-sources/v2", sources: [source] },
    sinks: {
      format: "codex-security.stack-sinks/v2",
      cve: summaryCve,
      advisory,
      sinks: [sink],
    },
    stacks: {
      format: "codex-security.stacks/v2",
      captures: [
        {
          origin:
            "V8 breakpoint in sum during an anonymous HTTP POST /summary on loopback.",
          stacks: [observation],
        },
      ],
    },
  };
  for (const [role, doc] of Object.entries(docs))
    await jsonFile(join(input, role + ".json"), doc);
  return readPacket(repo, input, variant);
}

async function readPacket(repo, input, variant) {
  const files = {},
    docs = {};
  for (const role of ["sources", "sinks", "stacks"]) {
    const bytes = await readFile(join(input, role + ".json"));
    files[role] = { sha256: sha256(bytes), byteLength: bytes.byteLength };
    docs[role] = JSON.parse(bytes);
  }
  assert.equal(
    docs.stacks.format,
    "codex-security.stacks/v2",
    "Regenerate saved captures with the behavior command.",
  );
  const [observation] = docs.stacks.captures[0].stacks;
  const target = {
    repository: basename(repo),
    sha: git(repo, "rev-parse", "HEAD"),
  };
  if (variant === "positive" || variant === "fixed") {
    assert.equal(
      observation.frames[0].sourceRevision,
      target.sha,
      "recording matches regenerated fixture commit",
    );
  }
  return {
    repo,
    input,
    files,
    docs,
    variant,
    observation,
    target,
    scope: observation.labels,
    advisory: docs.sinks.advisory,
  };
}

// Give each investigator a neutral input path and a separate clean checkout,
// even when two variants share the same source commit and captured stack.
export async function restorePackets(root, directory) {
  const fixtures = {};
  for (const variant of ["positive", "fixed", "unbound", "missing-version"]) {
    const repo = await summaryRepo(
      root,
      variant === "fixed" ? "0.2.1" : "0.2.0",
    );
    const input = await mkdtemp(join(root, "input-"));
    for (const role of ["sources", "sinks", "stacks"]) {
      await cp(
        join(directory, variant, role + ".json"),
        join(input, role + ".json"),
      );
    }
    fixtures[variant] = await readPacket(repo, input, variant);
  }
  return fixtures;
}

export async function summaryFixtures(root) {
  const fixtures = {},
    outcomes = [];
  for (const version of ["0.2.0", "0.2.1"]) {
    const repo = await summaryRepo(root, version);
    const capturePath = join(root, "observed-" + version + ".json");
    const instrumented = await exercise(repo, capturePath, version);
    const plain = await exercise(repo, undefined, version);
    assert.deepEqual(plain, instrumented);
    outcomes.push(plain);
    const capture = JSON.parse(await readFile(capturePath, "utf8"));
    assert.equal(capture.version, version);
    assert.equal(capture.sourceSha, git(repo, "rev-parse", "HEAD"));
    for (const variant of version === "0.2.0"
      ? ["positive", "unbound", "missing-version"]
      : ["fixed"]) {
      const checkout = ["unbound", "missing-version"].includes(variant)
        ? await summaryRepo(root, version)
        : repo;
      assert.equal(git(checkout, "rev-parse", "HEAD"), capture.sourceSha);
      fixtures[variant] = await packet(root, checkout, capture, variant);
    }
  }
  return { fixtures, outcomes };
}

import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdir, writeFile } from "node:fs/promises";
import { join, resolve } from "node:path";

const [destination, variant] = process.argv.slice(2);
if (!destination || !["fixed", "unbound"].includes(variant)) {
  throw new Error("Usage: node prepare.mjs NEW_DIRECTORY fixed|unbound");
}
const root = resolve(destination);
const repository = join(root, "target");
await mkdir(root);
await mkdir(repository);

const cve = "CVE-2099-0001";
const manifest = {
  service: "decoder",
  imageDigest:
    "sha256:" +
    createHash("sha256").update("decoder fixture build").digest("hex"),
  installed: { package: "sample-codec", version: "2.1.0" },
};
const json = (value) => JSON.stringify(value, null, 2) + "\n";
const deployment = json(manifest);
const endLine = deployment.trimEnd().split("\n").length;
await writeFile(
  join(repository, "decode.js"),
  [
    'import { decode } from "sample-codec";',
    "export function handle(bytes) {",
    "  return decode(bytes);",
    "}",
    "",
  ].join("\n"),
);
if (variant === "fixed") {
  await writeFile(join(repository, "deployment.json"), deployment);
}
// Keep the pinned Git revision repeatable across runs of the same variant.
function git(...args) {
  return execFileSync(
    "git",
    [
      "-C",
      repository,
      "-c",
      "core.autocrlf=false",
      "-c",
      "user.name=Fixture",
      "-c",
      "user.email=fixture@example.invalid",
      "-c",
      "commit.gpgSign=false",
      ...args,
    ],
    {
      encoding: "utf8",
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
  ).trim();
}
git("init", "--quiet", "--template=", "--object-format=sha1");
git("add", ".");
git("commit", "--quiet", "-m", "Decoder deployment fixture");
const sha = git("rev-parse", "HEAD");
const source = {
  id: "handler",
  function: "handle",
  runtime_selectors: [{ name: "handle" }],
};
const sink = {
  id: "decoder",
  function: "decode",
  package: "sample-codec",
  runtime_selectors: [{ name: "decode" }],
  versionScheme: "semver",
  affectedVersions: ["<2.0.0"],
  preconditions: ["Input controls the bytes passed to decode."],
};
await writeFile(
  join(root, "sources.json"),
  json({ format: "codex-security.stack-sources/v1", sources: [source] }),
);
await writeFile(
  join(root, "sinks.json"),
  json({
    format: "codex-security.stack-sinks/v1",
    cve,
    advisory: {
      url: "https://example.invalid/advisories/sample-codec",
      summary:
        "Before 2.0.0, sample-codec accepts an invalid length while decoding untrusted input.",
      revision: "1",
    },
    sinks: [sink],
  }),
);
const observation = {
  id: "sample",
  stackHash: "sample-17",
  sourceIndex: 1,
  sinkIndex: 0,
  sinkIds: [sink.id],
  framesTruncated: false,
  frames: [
    {
      name: "decode",
      type: "javascript",
      location: "sample-codec/index.js",
      offset: "9007199254740993",
    },
    { name: "handle", type: "javascript", location: "decode.js", line: 3 },
  ],
};
if (variant === "fixed") {
  observation.bindings = [
    {
      package: "sample-codec",
      version: manifest.installed.version,
      provenance: "deployment.json",
      imageDigest: manifest.imageDigest,
      evidence: [{ path: "deployment.json", startLine: 1, endLine }],
    },
  ];
}
const scope = {
  service: "decoder",
  window: { start: "2025-08-14T00:00:00Z", end: "2025-08-15T00:00:00Z" },
  ...(variant === "fixed" && { image_digest: manifest.imageDigest }),
};
await writeFile(
  join(root, "stacks.json"),
  json({
    format: "codex-security.sampled-stacks/v1",
    target: { repository: "example/decoder", sha },
    origin: { source: "synthetic-stack-fixture", revision: "1" },
    frameOrder: "leaf_first",
    queries: [
      {
        id: "decode",
        scope,
        selectors: {
          sources: source.runtime_selectors,
          sinks: sink.runtime_selectors,
        },
        groups: [
          {
            id: "deployment",
            status: "observed",
            truncated: false,
            observations: [observation],
          },
        ],
      },
    ],
  }),
);
console.log(sha);

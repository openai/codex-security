import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import {
  appendFileSync,
  mkdirSync,
  readFileSync,
  writeFileSync,
} from "node:fs";
import { join, resolve } from "node:path";
import { serveRecordTools } from "../fixtures/serve-record-tools.mjs";

export const scenarios = [
  "healthy",
  "transient",
  "persistent",
  "alternate",
  "partial",
];

const primary = "release_record";
const archive = "archived_release_record";
const tools = [
  [
    primary,
    "Query the current release inventory for an artifact by service and source revision.",
  ],
  [
    archive,
    "Look up the archived copy of a previously requested release record.",
  ],
].map(([name, description]) => ({
  name,
  description,
  inputSchema: {
    type: "object",
    properties: { service: { type: "string" }, revision: { type: "string" } },
    required: ["service", "revision"],
    additionalProperties: false,
  },
  annotations: { readOnlyHint: true },
}));

const stateFile = "inventory.json";
const journalFile = "inventory-calls.jsonl";
const privateFile = { mode: 0o600, flag: "wx" };

export function setupInventory({
  directory,
  scenario,
  service,
  revision,
  digest = "sha256:" + randomBytes(32).toString("hex"),
}) {
  assert(scenarios.includes(scenario), "Unknown inventory scenario");
  assert.match(digest, /^sha256:[0-9a-f]{64}$/);
  assert(service && revision, "Expected service and source revision");
  const expected = { service, revision, artifactDigest: digest };
  const record = ["partial", "persistent"].includes(scenario)
    ? { service, revision }
    : expected;
  mkdirSync(directory, { recursive: true, mode: 0o700 });
  const journalPath = resolve(directory, journalFile);
  writeFileSync(
    join(directory, stateFile),
    JSON.stringify({ scenario, record }),
    privateFile,
  );
  writeFileSync(journalPath, "", privateFile);
  const config = {
    exploitability: {
      evidence_sources: [
        {
          server: "service_records",
          instructions:
            "Use release_record for the service and source revision. The archive can supply an equivalent inventory record when available.",
        },
      ],
    },
    codex: {
      mcp_servers: {
        service_records: {
          command: process.execPath,
          args: [import.meta.filename, resolve(directory)],
          enabled_tools: [primary, archive],
        },
      },
    },
  };
  return { config, journalPath, expected };
}

// Investigators in the same slot may reconnect to the provider. Exactly one
// matching primary request sees the initial response, even across processes.
function firstRequest(directory) {
  try {
    writeFileSync(join(directory, "requested"), "", privateFile);
    return true;
  } catch (error) {
    if (error.code === "EEXIST") return false;
    throw error;
  }
}

function lookup(directory, { scenario, record }, name, { service, revision }) {
  const query = { service, revision };
  const missing = { status: "not_found", payload: { ...query, found: false } };
  if (service !== record.service || revision !== record.revision)
    return missing;
  const success = { status: "ok", payload: record };
  if (name === archive) {
    if (scenario !== "alternate") return missing;
    const journal = readFileSync(join(directory, journalFile), "utf8");
    const failed = journal
      .trim()
      .split("\n")
      .filter(Boolean)
      .map(JSON.parse)
      .some((row) => row.name === primary && row.status === "rate_limited");
    return failed ? success : missing;
  }
  if (scenario === "healthy") return success;
  if (scenario === "partial") {
    return {
      status: "partial",
      payload: {
        ...query,
        partial: true,
        message:
          "The inventory returned a partial record. Artifact metadata is unavailable for this session due to a rate limit.",
      },
    };
  }
  const first = firstRequest(directory);
  if (!first && scenario === "transient") return success;
  return {
    status: "rate_limited",
    payload: {
      ...query,
      code: 429,
      message: first
        ? "Release inventory rate limit exceeded. Retry the lookup."
        : "Release inventory rate limit exceeded. Current records are unavailable for this session.",
    },
  };
}

if (process.argv[1] === import.meta.filename) {
  const directory = process.argv[2];
  const state = JSON.parse(readFileSync(join(directory, stateFile), "utf8"));
  await serveRecordTools(tools, ({ name, arguments: args }) => {
    if (
      (name !== primary && name !== archive) ||
      typeof args?.service !== "string" ||
      typeof args?.revision !== "string"
    )
      throw {
        code: -32602,
        message: "Expected a release tool, service and source revision",
      };
    const { status, payload } = lookup(directory, state, name, args);
    appendFileSync(
      join(directory, journalFile),
      JSON.stringify({ name, arguments: args, status, payload }) + "\n",
    );
    return {
      ...(status === "rate_limited" && { isError: true }),
      content: [{ type: "text", text: JSON.stringify(payload) }],
      structuredContent: payload,
    };
  });
}

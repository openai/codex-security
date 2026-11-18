import { expect, test } from "bun:test";
import { hash } from "node:crypto";
import { dependencyRecordHash } from "../src/dependency-attempt-store.js";
import type { DependencyEvidenceRecord } from "../src/dependency-evidence-sources.js";
import {
  createDependencyLinkedResourceCapture,
  type LinkedDependencyEvidence,
} from "../src/dependency-linked-resources.js";

const primary = "sample://capture/first",
  next = "sample://capture/second";
function link(uri: string, metadata: Record<string, unknown> = {}) {
  return { type: "resource_link", name: "sample", uri, ...metadata };
}
function origin(
  content: unknown[],
  server = "measurements",
  tool = "lookup",
  failed = false,
): DependencyEvidenceRecord {
  return receipt({ content, ...(failed && { isError: true }) }, server, tool);
}
function receipt(
  result: Record<string, unknown>,
  server = "measurements",
  tool = "lookup",
) {
  const value = {
    server,
    tool,
    arguments: {},
    result,
  };
  return { ...value, sha256: dependencyRecordHash(value) };
}
function capture() {
  const records: LinkedDependencyEvidence[] = [],
    diagnostics: string[] = [];
  const follow = createDependencyLinkedResourceCapture({
    servers: {
      measurements: {
        enabled_tools: ["lookup", "blocked"],
        disabled_tools: ["blocked"],
      },
      disabled: { enabled: false },
    },
    onEvidence(r) {
      records.push(r);
    },
    onDiagnostic(m) {
      diagnostics.push(m);
    },
  });
  return { records, diagnostics, follow };
}

test("materializes large exact resources and follows typed page links on the same selected server", async () => {
  const { follow, records, diagnostics } = capture();
  const binary = Buffer.from([0xff, 0, 0x7f]);
  const page = JSON.stringify({
    rows: ["x".repeat(240_000)],
    content: [
      link(next, { _meta: { sha256: hash("sha256", binary) } }),
      link(primary),
    ],
    nextCursor: "opaque to host",
  });
  const first = origin([
    link(primary, {
      size: Buffer.byteLength(page),
      mimeType: "application/json",
      _meta: { sha256: hash("sha256", page) },
    }),
    link(primary),
  ]);
  const outputs = [
    { contents: [{ uri: primary, mimeType: "application/json", text: page }] },
    {
      contents: [
        {
          uri: next,
          mimeType: "application/octet-stream",
          blob: binary.toString("base64"),
        },
      ],
    },
  ];
  const calls: [string, string][] = [];
  const read = async (server: string, uri: string) => {
    calls.push([server, uri]);
    return outputs[uri === primary ? 0 : 1];
  };
  await Promise.all([follow(first, read), follow(first, read)]);
  await follow(first, read);
  expect(calls).toEqual([
    ["measurements", primary],
    ["measurements", next],
  ]);
  expect(diagnostics).toEqual([]);
  expect(records).toHaveLength(2);
  for (const [i, r] of records.entries()) {
    const { sha256, ...bound } = r;
    expect(sha256).toBe(dependencyRecordHash(bound));
    expect(r.result).toBe(outputs[i]!);
  }
  expect(records[0]).toMatchObject({
    tool: "read_mcp_resource",
    arguments: { server: "measurements", uri: primary },
    linkedFrom: first.sha256,
    contentSha256: [hash("sha256", page)],
  });
  expect(records[1]).toMatchObject({
    linkedFrom: records[0]!.sha256,
    contentSha256: [hash("sha256", binary)],
  });
});

test("ignores unselected or denied tools, failed receipts, text links and cursor-only pagination", async () => {
  const { follow, records, diagnostics } = capture(),
    calls: string[] = [];
  const read = async (_server: string, uri: string) => {
    calls.push(uri);
    return {
      contents: [
        {
          uri,
          mimeType: "application/json",
          text: JSON.stringify({
            nextCursor: "sensitive cursor",
            entries: [link(next)],
            url: next,
          }),
        },
      ],
    };
  };
  for (const source of [
    origin([link(primary)], "other"),
    origin([link(primary)], "disabled"),
    origin([link(primary)], "measurements", "ignored"),
    origin([link(primary)], "measurements", "blocked"),
    origin([link(primary)], "measurements", "read_mcp_resource"),
    origin([link(primary)], "measurements", "lookup", true),
    origin([{ type: "text", text: JSON.stringify(link(next)) }]),
    { ...origin([link(primary)]), sha256: "edited" },
  ])
    await follow(source, read);
  expect(calls).toEqual([]);
  await follow(origin([link(primary)]), read);
  expect(calls).toEqual([primary]);
  expect(records).toHaveLength(1);
  expect(diagnostics).toEqual([
    "A linked MCP resource advertised more results without a resource link. Coverage is incomplete.",
  ]);
});

test("refuses substituted resources, malformed blobs and invalid digests without publishing their contents", async () => {
  const metadata = { _meta: { sha256: hash("sha256", "original") } };
  for (const response of [
    { contents: [{ uri: next, text: "original" }] },
    { server: "other", contents: [{ uri: primary, text: "original" }] },
    { contents: [{ uri: primary, text: "altered private data" }] },
    { contents: [{ uri: primary, blob: "malformed base64?" }] },
    {
      contents: [
        { uri: primary, text: "original" },
        { uri: next, text: "unlinked" },
      ],
    },
  ]) {
    const { follow, records, diagnostics } = capture();
    await follow(origin([link(primary, metadata)]), async () => response);
    expect(records).toEqual([]);
    expect(diagnostics).toEqual([
      "A linked MCP resource did not match its advertised URI, size or digest. Coverage is incomplete.",
    ]);
  }
  const { follow, records, diagnostics } = capture(),
    source = origin([link(primary, metadata)]);
  await follow(source, async () => {
    throw new Error("confidential external diagnostic");
  });
  expect(diagnostics).toEqual([
    "A selected MCP source could not return a linked resource. Coverage is incomplete.",
  ]);
  await follow(source, async () => ({
    contents: [{ uri: primary, text: "original" }],
  }));
  expect(records).toHaveLength(1);
});

test("bounds advertised links and sizes and preserves completed captures when a later page cannot be read", async () => {
  const { follow, records, diagnostics } = capture();
  let calls = 0;
  const links = Array.from({ length: 35 }, (_, i) =>
    link("sample://capture/" + i),
  );
  await follow(
    origin([link(primary, { size: 2 ** 32 }), ...links]),
    async (_server, uri) => {
      calls++;
      return { contents: [{ uri, text: "ok" }] };
    },
  );
  expect(calls).toBe(31);
  expect(records).toHaveLength(31);
  expect(diagnostics).toEqual([
    "Linked MCP evidence exceeded the automatic capture budget. Coverage is incomplete.",
  ]);
});

test("charges native response metadata against the byte budget, even on a rejected read", async () => {
  const { follow, records, diagnostics } = capture();
  const issue = origin([
    link(primary),
    link(next),
    link("sample://capture/unread"),
  ]);
  const calls: string[] = [];
  await follow(issue, async (_server, uri) => {
    calls.push(uri);
    if (uri === primary) return { contents: [{ uri, text: "first page" }] };
    return {
      server: "other",
      _meta: { padding: "x".repeat(32 * 1024 * 1024) },
    };
  });
  expect(calls).toEqual([primary, next]);
  expect(records.map((r) => r.arguments)).toEqual([
    { server: "measurements", uri: primary },
  ]);
  expect(diagnostics).toEqual([
    "Linked MCP evidence exceeded the automatic capture budget. Coverage is incomplete.",
  ]);
});

const graphFormat = "codex-security-graph-evidence/v1";
function graphPacket(uri: string, frameCount = 2) {
  const text = JSON.stringify({
    format: graphFormat,
    frame_order: "root_first",
    observations: [
      {
        id: "sample-a",
        kind: "sampled_stack",
        scope: { service: "reader" },
        frames: Array.from({ length: frameCount }, (_, i) => ({
          kind: "function",
          name: "handler_" + i,
          scope: "module/".repeat(100),
        })),
      },
    ],
  });
  const sha256 = hash("sha256", text);
  return {
    text,
    sha256,
    descriptor: { graph_evidence: { format: graphFormat, uri, sha256 } },
  };
}

test("captures a large graph unchanged and coalesces its structured, JSON text and resource link advertisements", async () => {
  const { follow, records, diagnostics } = capture(),
    packet = graphPacket(primary, 2500);
  expect(packet.text.length).toBeGreaterThan(1_000_000);
  const response = { contents: [{ uri: primary, text: packet.text }] };
  const first = receipt({
    structuredContent: packet.descriptor,
    content: [
      link(primary),
      { type: "text", text: JSON.stringify(packet.descriptor) },
    ],
  });
  const requests: [string, string][] = [];
  const read = async (server: string, uri: string) => {
    requests.push([server, uri]);
    return response;
  };
  await Promise.all([follow(first, read), follow(first, read)]);
  expect(requests).toEqual([["measurements", primary]]);
  expect(records).toHaveLength(1);
  expect(records[0]!.result).toBe(response);
  expect(records[0]!.contentSha256).toEqual([packet.sha256]);
  expect(records[0]!.linkedFrom).toBe(first.sha256);
  expect(diagnostics).toEqual([]);
});

test("follows graph descriptors only in structured or MCP JSON text, including links on resource pages", async () => {
  const packet = graphPacket(next);
  const envelopes = [
    { structured_content: packet.descriptor },
    { content: [{ type: "text", text: JSON.stringify(packet.descriptor) }] },
  ];
  for (const envelope of envelopes) {
    const { follow, records, diagnostics } = capture(),
      calls: string[] = [];
    const first = origin([link(primary)]);
    await follow(first, async (server, uri) => {
      expect(server).toBe("measurements");
      calls.push(uri);
      return {
        contents: [
          {
            uri,
            mimeType: "application/json",
            text:
              uri === primary
                ? JSON.stringify({
                    ...envelope,
                    nextCursor: "opaque",
                    arbitrary: link("sample://other"),
                  })
                : packet.text,
          },
        ],
      };
    });
    expect(calls).toEqual([primary, next]);
    expect(records[1]!.linkedFrom).toBe(records[0]!.sha256);
    expect(records[1]!.contentSha256).toEqual([packet.sha256]);
    expect(diagnostics).toEqual([]);
  }
  const { follow, records, diagnostics } = capture();
  let reads = 0;
  for (const envelope of [
    packet.descriptor,
    { structuredContent: { nested: packet.descriptor } },
    { content: [{ type: "image", text: JSON.stringify(packet.descriptor) }] },
    { content: [{ type: "text", text: JSON.stringify({ uri: next }) }] },
  ])
    await follow(receipt(envelope), async () => {
      reads++;
    });
  expect(reads).toBe(0);
  expect(records).toEqual([]);
  expect(diagnostics).toEqual([]);
});

test("rejects malformed graph descriptors and conflicts before reading", async () => {
  const { descriptor } = graphPacket(primary);
  for (const ref of [
    { ...descriptor.graph_evidence, format: "unsupported" },
    { ...descriptor.graph_evidence, sha256: "oops" },
    { ...descriptor.graph_evidence, uri: "" },
    { ...descriptor.graph_evidence, sha256: undefined },
  ]) {
    const { follow, records, diagnostics } = capture();
    let reads = 0;
    await follow(
      receipt({ structuredContent: { graph_evidence: ref } }),
      async () => {
        reads++;
      },
    );
    expect(reads).toBe(0);
    expect(records).toEqual([]);
    expect(diagnostics).toHaveLength(1);
  }
  const { follow, records, diagnostics } = capture();
  let reads = 0;
  await follow(
    receipt({
      structuredContent: descriptor,
      content: [link(primary, { _meta: { sha256: "0".repeat(64) } })],
    }),
    async () => {
      reads++;
    },
  );
  expect(reads).toBe(0);
  expect(records).toEqual([]);
  expect(diagnostics).toHaveLength(1);
});

test("rejects altered, partial, multipart, binary and malformed graph responses as coverage gaps", async () => {
  const packet = graphPacket(primary);
  const cases = [
    {
      sourceText: packet.text,
      contents: [{ uri: primary, text: packet.text + " " }],
    },
    { sourceText: packet.text, contents: [{ uri: next, text: packet.text }] },
    {
      sourceText: packet.text,
      contents: [
        { uri: primary, text: packet.text, _meta: { truncated: true } },
      ],
    },
    {
      sourceText: packet.text,
      contents: [
        { uri: primary, text: packet.text },
        { uri: primary, text: "" },
      ],
    },
    {
      sourceText: packet.text,
      contents: [
        { uri: primary, blob: Buffer.from(packet.text).toString("base64") },
      ],
    },
    { sourceText: "{}", contents: [{ uri: primary, text: "{}" }] },
    { sourceText: "not JSON", contents: [{ uri: primary, text: "not JSON" }] },
  ];
  for (const { sourceText, contents } of cases) {
    const { follow, records, diagnostics } = capture();
    const source = receipt({
      content: [
        link(primary),
        {
          type: "text",
          text: JSON.stringify({
            graph_evidence: {
              ...packet.descriptor.graph_evidence,
              sha256: hash("sha256", sourceText),
            },
          }),
        },
      ],
    });
    let reads = 0;
    await follow(source, async () => {
      reads++;
      return { contents };
    });
    expect(reads).toBe(1);
    expect(records).toEqual([]);
    expect(diagnostics).toHaveLength(1);
    expect(diagnostics[0]).toContain("Coverage is incomplete.");
  }
});

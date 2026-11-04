import { afterEach, expect, test } from "bun:test";
import { readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { gunzipSync, gzipSync } from "node:zlib";
import {
  hasSarifExternalPropertyReferences,
  readScannerJson,
  readScannerText,
  relativePath,
  sarifRunContextSelector,
} from "../src/scanner-import.js";
import { createTemporaryDirectories } from "./support/temporary-directories.js";

const reports = createTemporaryDirectories();
afterEach(reports.cleanup);

async function failure(operation: () => unknown): Promise<Error> {
  try {
    await operation();
  } catch (error) {
    if (error instanceof Error) return error;
    throw error;
  }
  throw new Error("Expected the operation to fail");
}

test("scanner readers detect gzip by content and preserve BOM handling", async () => {
  const path = join(await reports.create("scanner-report-"), "report");
  await writeFile(path, gzipSync('\uFEFF\uFEFF"λ"'));
  expect(await readScannerText(path)).toBe('\uFEFF"λ"');
  expect(await readScannerJson(path)).toBe("λ");
});

test("scanner readers propagate filesystem and gzip errors", async () => {
  const path = join(await reports.create("scanner-report-"), "missing");
  const missing = await failure(() => readFile(path));
  for (const read of [readScannerText, readScannerJson]) {
    await expect(read(path)).rejects.toMatchObject({
      code: "ENOENT",
      message: missing.message,
    });
  }

  const truncated = Buffer.from([0x1f, 0x8b]);
  await writeFile(path, truncated);
  const gzip = await failure(() => gunzipSync(truncated));
  for (const read of [readScannerText, readScannerJson]) {
    await expect(read(path)).rejects.toMatchObject({
      code: "Z_BUF_ERROR",
      message: gzip.message,
    });
  }
});

test("scanner readers preserve UTF-8 and JSON parse diagnostics", async () => {
  const path = join(await reports.create("scanner-report-"), "report");
  const invalid = Uint8Array.of(0xff);
  await writeFile(path, gzipSync(invalid));
  const utf8 = await failure(() =>
    new TextDecoder("utf-8", { fatal: true }).decode(invalid),
  );
  await expect(readScannerText(path)).rejects.toMatchObject({
    name: "TypeError",
    message: utf8.message,
  });
  await expect(readScannerJson(path)).rejects.toMatchObject({
    name: "CodexSecurityError",
    message: `Scanner report is not valid UTF-8. ${utf8.message}`,
    cause: { name: "TypeError", message: utf8.message },
  });

  await writeFile(path, "{");
  expect(await readScannerText(path)).toBe("{");
  const syntax = await failure(() => JSON.parse("{"));
  await expect(readScannerJson(path)).rejects.toMatchObject({
    name: "CodexSecurityError",
    message: `Scanner JSON could not be parsed. ${syntax.message}`,
    cause: { name: "SyntaxError", message: syntax.message },
  });
});

test("scanner repository paths retain colons outside Windows drive prefixes", () => {
  expect(relativePath("schema:prod.json")).toBe("schema:prod.json");
  expect(relativePath("src/schema:prod.ts")).toBe("src/schema:prod.ts");
  for (const path of [
    "C:\\project\\source.ts",
    "C:source.ts",
    "/source.ts",
    "../source.ts",
  ])
    expect(relativePath(path)).toBeNull();
});

test.each([
  undefined,
  {},
  { artifacts: [], results: [] },
  { properties: { producer: "example" } },
])(
  "SARIF external reference metadata %p keeps the report self-contained",
  (references) => {
    expect(hasSarifExternalPropertyReferences(references)).toBe(false);
  },
);

test.each([
  { artifacts: [{ location: { uri: "artifacts.sarif" } }] },
  { results: [{ guid: "external-result-file" }] },
  { externalizedProperties: { location: { uri: "properties.sarif" } } },
])("SARIF external reference %p requires external data", (references) => {
  expect(hasSarifExternalPropertyReferences(references)).toBe(true);
});

test("SARIF findings omit unrelated inventory without mutating shared run context", () => {
  const artifacts = Array.from({ length: 5000 }, (_, index) => ({
    location: { uri: `unrelated/file-${index}.ts` },
    contents: { text: "unrelated source content".repeat(10) },
  }));
  const provenance = [{ repositoryUri: "https://github.com/example/project" }];
  const context = { artifacts, versionControlProvenance: provenance };
  const direct = {
    locations: [
      { physicalLocation: { artifactLocation: { uri: "src/main.ts" } } },
    ],
  };
  const selectContext = sarifRunContextSelector(context);
  expect(selectContext(direct)).toEqual({
    versionControlProvenance: provenance,
  });
  expect(context.artifacts).toBe(artifacts);
  const indexed = {
    ...direct,
    fixes: [
      {
        artifactChanges: [
          { artifactLocation: { index: 42 }, replacements: [] },
        ],
      },
    ],
  };
  const before = structuredClone(indexed);
  expect(selectContext(indexed)["artifacts"]).toBe(artifacts);
  expect(indexed).toEqual(before);
});

test.each([
  { locations: [{ physicalLocation: { artifactLocation: { index: 0 } } }] },
  {
    relatedLocations: [
      { physicalLocation: { artifactLocation: { index: 0 } } },
    ],
  },
  { analysisTarget: { index: 0 } },
  {
    codeFlows: [
      {
        threadFlows: [
          {
            locations: [
              {
                location: {
                  physicalLocation: { artifactLocation: { index: 0 } },
                },
              },
            ],
          },
        ],
      },
    ],
  },
  { invocations: [{ executableLocation: { index: 0 } }] },
  { originalUriBaseIds: { SOURCE: { index: 0 } } },
  { name: "example-tool", locations: [{ index: 0 }] },
  { message: { text: "See [artifact](sarif:/runs/0/artifacts/0)." } },
  { message: { markdown: "See [artifact](SARIF:/runs/0/artifacts/0)." } },
])(
  "SARIF retained context %p preserves artifact indexes and links",
  (selected) => {
    const artifacts = [
      {
        location: { uri: "generated.ts" },
        hashes: { sha256: "synthetic-digest" },
      },
    ];
    const context = { artifacts };
    expect(sarifRunContextSelector(context)(selected)["artifacts"]).toBe(
      artifacts,
    );
  },
);

test.each([
  [{ uri: "src/main.ts" }, { uri: "src/main.ts" }],
  [{ uri: "src/%6dain.ts" }, { uri: "src/main.ts" }],
  [{ uri: "src/main.ts" }, { uri: "./src/main.ts" }],
  [{ uri: "src/main.ts" }, { uri: "src/../src/main.ts" }],
  [{ uri: "file:///source/main.ts" }, { uri: "main.ts" }],
  [
    { uri: "src/main.ts", uriBaseId: "SOURCE" },
    { uri: "src/main.ts", uriBaseId: "SOURCE" },
  ],
  [{ uri: "main.ts", uriBaseId: "SOURCE" }, { uri: "src/main.ts" }],
])(
  "SARIF direct URI context %p preserves artifact metadata from %p",
  (location, inventoryLocation) => {
    const artifacts = [
      {
        location: inventoryLocation,
        hashes: { sha256: "synthetic-digest" },
        contents: { text: "source evidence" },
      },
    ];
    const context = { artifacts };
    const result = {
      locations: [{ physicalLocation: { artifactLocation: location } }],
    };
    expect(sarifRunContextSelector(context)(result)["artifacts"]).toBe(
      artifacts,
    );
  },
);

test("unrelated SARIF property-bag indexes do not require artifact inventory", () => {
  const context = { artifacts: [{ location: { uri: "other.ts" } }] };
  const result = {
    properties: { artifactLocation: { index: 0 } },
    locations: [
      { physicalLocation: { artifactLocation: { uri: "src/main.ts" } } },
    ],
  };
  expect(sarifRunContextSelector(context)(result)).toEqual({});
});

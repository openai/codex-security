import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { expect, test } from "bun:test";
import Ajv2020 from "ajv/dist/2020.js";
import { loadBundledRuntime, PLUGIN_ROOT } from "./plugin-root.js";

function bundledFunction(runtime: string, name: string): string {
  const source = new RegExp(
    `function ${name}\\([^\\n]*\\) \\{[\\s\\S]*?\\n\\}`,
    "u",
  ).exec(runtime)?.[0];
  if (!source) throw new Error(`Missing bundled runtime function: ${name}.`);
  return source;
}

test("discovery prompt template instructs workers to omit workbench-derived fields", async () => {
  const templatePath = join(
    PLUGIN_ROOT,
    "..",
    "..",
    "..",
    "plugins",
    "codex-security",
    "mcp-app",
    "templates",
    "deep-scan",
    "discovery.md",
  );
  const template = await readFile(templatePath, "utf8");

  expect(template).toContain("record_codex_security_scan_draft");
  expect(template).toContain(
    "The workbench derives authoritative target, scope include and exclude paths",
  );
  expect(template).toContain("coverage mode, inventory strategy");
  expect(template).toContain(
    "do not include those derived values in draft arguments",
  );
});

test("Standard scan continuation prompts instruct workers to omit workbench-derived fields", async () => {
  const runtime = await loadBundledRuntime();

  const standardContinuation = new Function(
    `${bundledFunction(runtime, "standardScanCompletionContinuation")}\nreturn standardScanCompletionContinuation;`,
  )() as (attempt: number) => string;

  const prompt = standardContinuation(1);
  expect(prompt).toContain("record_codex_security_scan_draft");
  expect(prompt).toContain(
    "Do not include workbench-derived target, scope paths, coverage metadata",
  );

  const transientContinuation = new Function(
    `${bundledFunction(runtime, "transientExecutionContinuation")}\nreturn transientExecutionContinuation;`,
  )() as (kind: string, attempt: number) => string;

  const transientPrompt = transientContinuation("discovery", 2);
  expect(transientPrompt).toContain("record_codex_security_scan_draft");
  expect(transientPrompt).toContain(
    "Do not include workbench-derived target, scope paths, coverage metadata",
  );
});

test("scan-draft schema rejects draft payloads containing workbench-derived fields", async () => {
  const ajv = new Ajv2020({ allErrors: true, strict: false });
  const commonSchema = JSON.parse(
    await readFile(
      join(
        PLUGIN_ROOT,
        "schemas",
        "definitions",
        "artifact-common.schema.json",
      ),
      "utf8",
    ),
  );
  const scanDraftSchema = JSON.parse(
    await readFile(
      join(PLUGIN_ROOT, "schemas", "tools", "scan-draft.schema.json"),
      "utf8",
    ),
  );
  ajv.addSchema(commonSchema);
  const validate = ajv.compile(scanDraftSchema);

  const validDraft = {
    scanId: "00000000-0000-0000-0000-000000000001",
    complete: false,
    findings: [],
    coverage: {
      completeness: "partial",
      surfaces: [],
      explicitExclusions: [],
      deferred: [],
    },
  };

  // Valid draft passes schema validation
  expect(validate(validDraft)).toBe(true);

  // Rejected when scope contains includePaths / excludePaths
  expect(
    validate({
      ...validDraft,
      scope: {
        includePaths: ["src/"],
      },
    }),
  ).toBe(false);

  // Rejected when coverage contains mode
  expect(
    validate({
      ...validDraft,
      coverage: {
        ...validDraft.coverage,
        mode: "repository",
      },
    }),
  ).toBe(false);

  // Rejected when coverage contains inventoryStrategy
  expect(
    validate({
      ...validDraft,
      coverage: {
        ...validDraft.coverage,
        inventoryStrategy: "repository",
      },
    }),
  ).toBe(false);

  // Rejected when coverage contains scanId
  expect(
    validate({
      ...validDraft,
      coverage: {
        ...validDraft.coverage,
        scanId: "00000000-0000-0000-0000-000000000001",
      },
    }),
  ).toBe(false);
});

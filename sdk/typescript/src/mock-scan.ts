import { writeFile } from "node:fs/promises";
import { createHash } from "node:crypto";
import { join } from "node:path";
import type { JsonObject } from "./config.js";
import type { Finding, SeverityLevel } from "./models.js";
import type { NormalizedTarget } from "./targets.js";

type DraftFinding = Omit<
  Finding,
  "findingId" | "occurrenceId" | "fingerprints"
>;

interface MockFinding {
  id: string;
  title: string;
  severity: SeverityLevel;
  cwe: string;
  summary: string;
  code: string;
  remediation: string;
}

// Entirely synthetic examples; the paths and snippets do not come from the target.
const EXAMPLES: readonly MockFinding[] = [
  {
    id: "command-injection",
    title: "Export filename reaches a shell command",
    severity: "critical",
    cwe: "CWE-78",
    summary:
      "The example export route interpolates an untrusted filename into a shell command, allowing shell metacharacters to execute another command.",
    code: "exec(`convert ${request.body.filename} output.pdf`);",
    remediation:
      "Pass the filename as a separate argument to a process API that does not invoke a shell.",
  },
  {
    id: "path-traversal",
    title: "Archive entry escapes the extraction directory",
    severity: "high",
    cwe: "CWE-22",
    summary:
      "The example archive extractor writes a supplied entry name without checking containment, allowing a parent-directory entry to overwrite a file outside the extraction directory.",
    code: "await writeFile(join(outputDirectory, entry.name), entry.contents);",
    remediation:
      "Resolve each entry destination and reject paths outside the extraction directory before writing.",
  },
  {
    id: "missing-authorization",
    title: "Document download omits the ownership check",
    severity: "high",
    cwe: "CWE-862",
    summary:
      "The example download handler accepts a document ID from any signed-in account and returns the document without checking that the account owns it.",
    code: "response.json(await documents.findById(request.params.id));",
    remediation:
      "Restrict document lookup to records the authenticated account is authorized to read.",
  },
  {
    id: "stored-xss",
    title: "Comment preview renders stored HTML",
    severity: "medium",
    cwe: "CWE-79",
    summary:
      "The example preview inserts a stored comment directly into HTML, allowing a comment author to execute script in another viewer's browser.",
    code: "preview.innerHTML = comment.body;",
    remediation:
      "Render comments as text or sanitize intentionally supported HTML before insertion.",
  },
  {
    id: "verbose-errors",
    title: "Error response exposes an internal stack trace",
    severity: "low",
    cwe: "CWE-209",
    summary:
      "The example error handler returns a stack trace to a remote caller, revealing internal module names and filesystem layout.",
    code: "response.status(500).send(error.stack);",
    remediation:
      "Return a generic error identifier and retain diagnostic details in internal logs.",
  },
  {
    id: "version-disclosure",
    title: "Response header advertises the framework version",
    severity: "informational",
    cwe: "CWE-200",
    summary:
      "The example response header exposes the precise framework version. This helps fingerprint the service but does not establish an exploitable vulnerability.",
    code: 'response.setHeader("X-Example-Version", frameworkVersion);',
    remediation: "Omit the framework version from public response headers.",
  },
  {
    id: "sql-injection",
    title: "Search term is concatenated into a SQL query",
    severity: "high",
    cwe: "CWE-89",
    summary:
      "The example search handler concatenates request text into SQL, allowing a caller to change the query and read records beyond the intended search.",
    code: "db.query(`SELECT * FROM items WHERE name = '${request.query.name}'`);",
    remediation: "Use a parameterized query for the search term.",
  },
  {
    id: "ssrf",
    title: "Image proxy fetches arbitrary destinations",
    severity: "medium",
    cwe: "CWE-918",
    summary:
      "The example image proxy fetches a caller-supplied URL without restricting its destination, allowing requests to internal services reachable by the proxy.",
    code: "return await fetch(request.query.imageUrl);",
    remediation:
      "Restrict fetch destinations to the intended image hosts and enforce that policy across redirects.",
  },
  {
    id: "open-redirect",
    title: "Sign-in callback accepts an external redirect",
    severity: "medium",
    cwe: "CWE-601",
    summary:
      "The example sign-in callback redirects to a supplied URL without checking its origin, allowing an attacker to send users from the sign-in flow to an unrelated site.",
    code: "response.redirect(request.query.returnTo);",
    remediation:
      "Accept only application-relative return paths or explicitly permitted origins.",
  },
  {
    id: "cookie-flags",
    title: "Session cookie omits HttpOnly",
    severity: "low",
    cwe: "CWE-1004",
    summary:
      "The example session cookie is accessible to browser scripts because HttpOnly is absent, increasing the impact of a separate script-injection vulnerability.",
    code: 'response.cookie("session", sessionId, { secure: true });',
    remediation: "Set HttpOnly on the session cookie.",
  },
];

function mockFindings(scanId: string): DraftFinding[] {
  const findings = EXAMPLES.map((example, index): DraftFinding => {
    const unique = index >= 6;
    const path = `mock/${example.id}${unique ? `-${scanId}` : ""}.ts`;
    return {
      ruleId: `mock.${example.id}`,
      identity: { anchor: example.id, ...(unique ? { instance: scanId } : {}) },
      title: `[Mock] ${example.title}`,
      summary: `Synthetic test finding. ${example.summary}`,
      severity: { level: example.severity },
      confidence: {
        level: "high",
        rationale:
          "Deterministic fixture; not a conclusion about the scanned repository.",
      },
      taxonomy: { category: example.id, cwe: [example.cwe] },
      locations: [{ path, startLine: 10, endLine: 10, role: "sink" }],
      codeEvidence: [
        {
          id: "example-sink",
          label: "Synthetic vulnerable operation",
          path,
          startLine: 10,
          language: "typescript",
          role: "sink",
          code: example.code,
          explanation:
            "Illustrative fixture code; this file is not read from or written to the repository.",
        },
      ],
      rootCause: { summary: example.summary, evidenceRefs: ["example-sink"] },
      remediation: example.remediation,
      validation: {
        status: "mock",
        method: "synthetic",
        summary: "Fixture only; no code was analyzed or executed.",
      },
      attackPath: {
        summary: example.summary,
        assumptions: [
          "The fictional example exposes this operation to untrusted input.",
        ],
        evidenceRefs: ["example-sink"],
      },
      remediationTests: [
        `In the example application, verify the fix: ${example.remediation}`,
      ],
      preventiveControls: [example.remediation],
      provenance: { source: "mock" },
      extensions: {
        mock: true,
        mockGroup: example.id,
        mockRecurrence: unique ? "unique" : "shared",
      },
    };
  });
  // Alternate reports have distinct identities but describe the same root causes.
  for (const [index, title] of [
    [0, "Shell metacharacters in the export name execute commands"],
    [1, "Parent-directory archive names overwrite files outside extraction"],
  ] as const) {
    const original = findings[index]!;
    findings.push({
      ...structuredClone(original),
      identity: { anchor: `${EXAMPLES[index]!.id}-alternate-report` },
      title: `[Mock] ${title}`,
    });
  }
  return findings;
}

export async function writeMockScanDraft(
  scanDir: string,
  scanId: string,
  target: NormalizedTarget,
  registration: JsonObject,
  signal: AbortSignal,
): Promise<void> {
  const contract = registration["contract"] as {
    target: { allowedKinds: string[] };
    diffTarget?: {
      kind: string;
      baseRevision: string;
      headRevision: string;
    } | null;
  };
  const diff = contract.diffTarget;
  const snapshotDigest =
    diff && diff.kind !== "working_tree"
      ? `codex-security-snapshot/v1:sha256:${createHash("sha256").update(["codex-security-diff/v1", diff.kind, diff.baseRevision, diff.headRevision].join("\0")).digest("hex")}`
      : undefined;
  const description =
    "Synthetic mock scan for testing. No LLM calls or security analysis were performed. Locations and code snippets describe fictional examples.";
  const documents = {
    "scan-manifest.json": {
      scan: {
        target: {
          kind: contract.target.allowedKinds[0],
          ...(snapshotDigest === undefined ? {} : { snapshotDigest }),
        },
        scope: {
          summary: description,
          runtimeStatus: "mock",
          limitations: [description],
        },
        extensions: { mock: true },
      },
    },
    "findings.json": { findings: mockFindings(scanId) },
    "coverage.json": {
      completeness: "complete",
      inventoryStrategy:
        target.kind === "paths"
          ? "scoped_path"
          : target.kind === "repository"
            ? "repository"
            : "diff",
      surfaces: EXAMPLES.map((example) => ({
        id: `mock-${example.id}`,
        label: `[Mock] ${example.title}`,
        disposition: "reported",
        receiptRefs: [],
        notes: description,
      })),
      explicitExclusions: [],
      deferred: [],
    },
  };
  for (const [name, document] of Object.entries(documents)) {
    await writeFile(
      join(scanDir, name),
      `${JSON.stringify(document, null, 2)}\n`,
      { flag: "wx", signal },
    );
  }
}

import { z } from "zod";
import { dependencyRecordHash } from "./dependency-attempt-store.js";
import type {
  DependencyEvidenceRecord,
  DependencyEvidenceFailure,
} from "./dependency-evidence-sources.js";
import {
  dependencyEvidencePayload,
  dependencyReceiptSelectionSchema,
  selectedReceiptValue,
  selectDependencyEvidenceField,
} from "./dependency-graph-evidence.js";
import { isRecord } from "./record.js";
import {
  dependencyAbortInputSchema,
  type DependencyBlockDetails,
} from "./dependency-blocked-schema.js";

export const dependencyAbortTool = {
  name: "abort_codex_security_investigation",
  description:
    "Coordinator only. End this advisory when required data is unavailable across a material scope. Cite current original lookup selections or a required server's failed startup receipt. Use read_dependency_evidence to find those receipts. Preserve independent findings. One missing lookup or an optional startup failure is a limitation.",
  inputSchema: z.toJSONSchema(dependencyAbortInputSchema),
};
export type DependencyStartupStatus =
  "starting" | "ready" | "failed" | "cancelled";
function archiveGap(value: unknown) {
  return (
    isRecord(value) &&
    (value["status"] === "not_recorded" ||
      value["status"] === "unsupported_tool")
  );
}
function reportsUnavailable(
  statement: string,
  payload: unknown,
  path: (string | number)[],
  structured: unknown,
) {
  const parent = selectDependencyEvidenceField(payload, path.slice(0, -1));
  // A completed lookup can legitimately return no row for a single requested key.
  if (
    [
      payload,
      parent,
      structured,
      isRecord(structured) ? structured["coverage"] : undefined,
    ].some(
      (value) =>
        isRecord(value) &&
        (value["complete"] === true || value["available"] === true),
    )
  )
    return false;
  if (
    /\b(?:no|zero) (?:records? |data |items? )?(?:(?:is|are) )?(?:missing|unavailable|incomplete)\b|\b(?:not|never) (?:missing|unavailable|incomplete)\b/iu.test(
      statement,
    )
  )
    return false;
  if (
    isRecord(parent) &&
    ["reason", "message", "description", "status", "detail", "error"].includes(
      String(path.at(-1)),
    ) &&
    (parent["available"] === false || parent["complete"] === false) &&
    (path.includes("coverage") || typeof parent["scope"] === "string")
  )
    return true;
  // A single record status or operation error is insufficient to declare broad loss.
  const unavailable =
    /\b(unavailable|incomplete|missing|no data|not available|not collected|not supported)\b/iu.test(
      statement,
    );
  const coverage =
    /\b(dataset|inventory|coverage|collection|all|entire|every|across|(?:required|requested) (?:[\w-]+ ){0,2}data)\b/iu.test(
      statement,
    );
  return unavailable && coverage;
}
function recordKey(
  r: Pick<DependencyEvidenceRecord, "server" | "tool" | "arguments">,
) {
  return dependencyRecordHash([r.server, r.tool, r.arguments]);
}
function containsIdentity(value: unknown, identity: string): boolean {
  return (
    value === identity ||
    (Array.isArray(value)
      ? value.some((x) => containsIdentity(x, identity))
      : isRecord(value) &&
        Object.values(value).some((x) => containsIdentity(x, identity)))
  );
}

/** Failed calls stay out of the evidence used to prove a verdict. */
export function createDependencyBlockEvidence(
  selected: ReadonlySet<string>,
  records: ReadonlyMap<string, DependencyEvidenceRecord>,
) {
  const failures = new Map<string, DependencyEvidenceRecord>();
  const current = new Map<string, string>();
  const startupFailures = new Map<string, string>();

  let sequence = 0;
  function observe(record: DependencyEvidenceRecord) {
    if (!selected.has(record.server) || record.tool === "read_mcp_resource")
      return;
    current.set(recordKey(record), record.sha256);
    startupFailures.delete(record.server);
  }
  function failed(
    call: DependencyEvidenceFailure,
    result: Record<string, unknown>,
  ) {
    if (!selected.has(call.server) || call.tool === "read_mcp_resource") return;
    const raw = { ...call, result, hostStatus: "failed" };
    const record = {
      ...raw,
      sha256: dependencyRecordHash(raw),
    };
    failures.set(record.sha256, record);
    observe(record);
    return record.sha256;
  }
  function startup(
    server: string,
    status: DependencyStartupStatus,
    required: boolean,
    error: unknown,
  ) {
    if (!selected.has(server)) return;
    startupFailures.delete(server);
    if (status !== "failed" && status !== "cancelled") return;
    const raw = {
      server,
      tool: "mcp_server_startup",
      hostStatus: "startup",
      arguments: { sequence: ++sequence },
      result: { structuredContent: { status, error: error ?? null } },
    };
    const record = { ...raw, sha256: dependencyRecordHash(raw) };
    failures.set(record.sha256, record);

    if (status === "failed" && required)
      startupFailures.set(server, record.sha256);
    return record.sha256;
  }
  function verify(
    raw: unknown,
    threadId: string,
    revisions: DependencyBlockDetails["retainedEvidence"]["assessmentRevisions"],
  ): DependencyBlockDetails {
    const input = dependencyAbortInputSchema.parse(raw);
    const c = input.coverage;
    if (c.basis === "server_startup") {
      if (input.tool || startupFailures.get(c.server) !== c.receiptId)
        throw new Error(
          "A startup block requires the current failed startup receipt for the same required server, without a tool.",
        );
    } else {
      const tool = input.tool;
      if (!tool || !selected.has(tool.server))
        throw new Error(
          "Lookup coverage requires a selected evidence server and tool.",
        );
      const selection = (
        s: z.infer<typeof dependencyReceiptSelectionSchema>,
      ) => {
        const r = records.get(s.receiptId) ?? failures.get(s.receiptId);
        if (
          !r ||
          r.server !== tool.server ||
          r.tool !== tool.name ||
          r.tool === "read_mcp_resource" ||
          current.get(recordKey(r)) !== r.sha256
        )
          throw new Error(
            "Coverage must identify a current original receipt for the specified lookup and scope.",
          );
        if (!isRecord(r.arguments) || !Object.keys(r.arguments).length)
          throw new Error(
            "An unscoped lookup cannot establish the affected scope.",
          );
        if (
          archiveGap(r.result) ||
          archiveGap(dependencyEvidencePayload(r, null)) ||
          archiveGap(dependencyEvidencePayload(r, s.textBlock))
        )
          throw new Error(
            "An unsupported or unrecorded archived lookup is only a limitation.",
          );
        const value = selectedReceiptValue(r, s);
        return { r, value };
      };
      if (c.basis === "provider_declared") {
        const { value, r } = selection(c.selection);
        if (
          value !== c.declaration ||
          !reportsUnavailable(
            c.declaration,
            dependencyEvidencePayload(r, c.selection.textBlock),
            c.selection.record,
            dependencyEvidencePayload(r, null),
          )
        )
          throw new Error(
            "The selected provider statement must explicitly identify unavailable data and match the original text.",
          );
      } else {
        if (
          c.checked !== c.checks.length ||
          c.missing !== c.checks.filter((x) => x.missing).length ||
          new Set(c.checks.map((x) => x.requiredRecord)).size !== c.checked
        )
          throw new Error(
            "Observed coverage requires distinct required checks with matching checked and missing counts.",
          );
        const probes = new Set<string>();
        for (const row of c.checks) {
          const { r, value } = selection(row.selection);
          if (!containsIdentity(r.arguments, row.requiredRecord))
            throw new Error(
              "The required record identity must occur in the original lookup arguments.",
            );
          probes.add(recordKey(r));
          const absent =
            failures.has(r.sha256) ||
            value === null ||
            (Array.isArray(value) && value.length === 0);
          if (row.missing !== absent)
            throw new Error(
              "The supplied missing status does not match the selected original result.",
            );
        }
        if (probes.size !== c.checked)
          throw new Error(
            "Observed coverage repeats the same original lookup.",
          );
      }
    }
    for (const id of input.evidenceReferences)
      if (
        !records.has(id) &&
        !failures.has(id) &&
        !revisions.some((r) => r.id === id)
      )
        throw new Error("Unknown saved evidence reference: " + id);
    return {
      ...input,
      nativeThreadId: threadId,
      retainedEvidence: {
        assessmentRevisions: revisions,
        inventoryReceiptIds: [...records.keys(), ...failures.keys()],
      },
    };
  }
  return { failures, observe, failed, startup, verify };
}

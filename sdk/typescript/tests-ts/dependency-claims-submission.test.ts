import { expect, test } from "bun:test";
import { writeFile } from "node:fs/promises";
import { join } from "node:path";
import { createDependencyCandidates } from "../src/dependency-candidates.js";
import { scopedTemporaryDirectory } from "./support/temporary-directories.js";
import {
  createDependencyReportSubmission,
  advisory,
} from "./support/dependency-claims-fixture.js";
import {
  artifactSelection,
  block,
  claimRef,
  draft,
  packetPayload,
  readDependencyCheckOutput,
  recordFixtureLookup,
  use,
  waitFor,
  withFixture,
  type Controller,
  type ReviewRow,
  type ReviewPacket,
} from "./support/dependency-claims-fixture.js";

const modelReply = (rows: ReviewRow[], accepted = true) =>
  JSON.stringify({
    items: rows.map((row) => ({
      id: row.id,
      revision: row.revision,
      hash: row.hash,
      accepted,
      reason: accepted
        ? "This synthetic subject has the exact fixture facts."
        : "The cited premise only identifies another copy.",
      citedVersion: null,
      evidenceIds: [...(row.excerptIds ?? []), ...(row.receiptIds ?? [])].slice(
        0,
        1,
      ),
    })),
  });
const inventoryEvidence = (receiptId: string) => ({
  evidence: [],
  receiptSelections: [artifactSelection(receiptId)],
});
const q = (state: Controller, ids: string[]) => state.queryClaims({ ids });
const queue = (state: Controller, ...claims: ReturnType<typeof draft>[]) =>
  state.queueClaims({ claims });
const entered = async (gate: ReturnType<typeof block>): Promise<ReviewPacket> =>
  (await Promise.race([
    gate.entered.promise,
    Bun.sleep(2000).then(() => {
      throw new Error("The fixture reviewer was not called.");
    }),
  ])) as ReviewPacket;
async function getClaim(state: Controller, id: string) {
  const row = (await q(state, [id])).claims[0];
  return row && "payload" in row ? row : undefined;
}
async function seenState(state: Controller, id: string, expected: string) {
  const row = await waitFor(
    () => getClaim(state, id),
    (row) => row?.state === expected,
    expected + " " + id,
  );
  if (!row) throw new Error("The selected claim was not found.");
  return row;
}
async function approved(state: Controller, subject: ReturnType<typeof draft>) {
  const ack = await queue(state, subject);
  expect(ack.queued).toBe(true);
  return claimRef(await seenState(state, subject.id, "approved"));
}

test("a delayed application approval cannot survive revision of its shared premise", async () => {
  const gate = block();
  const reviewer = async (prompt: string) => {
    const packet = packetPayload(prompt);
    if (packet.items.some((row) => row.id === "caller-a")) {
      gate.entered.resolve(packet);
      await gate.release.promise;
    }
    return modelReply(packet.items);
  };
  await withFixture(reviewer, async (state) => {
    try {
      const first = await approved(state, draft("wrapper"));
      const ack = await state.queue({
        items: [use("caller-a", "caller-a.ts", [first])],
      });
      expect(ack.queued).toBe(true);
      const packet = await entered(gate);
      expect(
        packet.approvedClaims.some(
          (row) => row.id === first.id && row.revision === first.revision,
        ),
      ).toBe(true);
      const second = await approved(
        state,
        draft("wrapper", {
          expectedRevision: first.revision,
          payload: { mode: "Changed rationale" },
        }),
      );
      expect(second.revision).toBe(first.revision + 1);
      gate.release.resolve(undefined);
      await seenState(state, "application:caller-a", "stale");
      await waitFor(
        () => state.status(),
        (status) => status.inFlight === 0,
        "late review settlement",
      );
      const submission = await state.submit({
        reviewItems: ack.items,
        candidateGeneration: state.readStatus().candidateGeneration,
        limitations: [],
      });
      expect(submission.accepted).toBe(false);
    } finally {
      gate.release.resolve(undefined);
    }
  });
});

test("editing the selected source during independent review prevents stale approval", async () => {
  const gate = block();
  await withFixture(
    async (prompt) => {
      gate.entered.resolve(undefined);
      await gate.release.promise;
      return modelReply(packetPayload(prompt).items);
    },
    async (state, repository) => {
      try {
        expect((await queue(state, draft("writer-source"))).queued).toBe(true);
        await entered(gate);
        await writeFile(
          join(repository, "writer.ts"),
          "export function saveImage(output, mode) {\n  return image.save(output, 'TIFF');\n}\n",
        );
        gate.release.resolve(undefined);
        const row = await seenState(state, "writer-source", "stale");
        expect(row.error).toMatch(/writer\.ts/i);
      } finally {
        gate.release.resolve(undefined);
      }
    },
  );
});

test("receipt origin match rather than global inventory generation governs reusable claims", async () => {
  const gate = block();
  const reviewer = async (prompt: string) => {
    const packet = packetPayload(prompt);
    if (packet.items.some((row) => row.id === "original-copy")) {
      gate.entered.resolve(packet);
      await gate.release.promise;
    }
    return modelReply(packet.items);
  };
  await withFixture(reviewer, async (state) => {
    try {
      const copy1 = recordFixtureLookup(
        state,
        "known-service",
        "fixture-copy-one",
      );
      const ready = await queue(
        state,
        draft("original-copy", inventoryEvidence(copy1)),
      );
      expect(ready.queued).toBe(true);
      await entered(gate);
      recordFixtureLookup(state, "unrelated-service", "fixture-other-copy");
      gate.release.resolve(undefined);
      await seenState(state, "original-copy", "approved");
      recordFixtureLookup(state, "known-service", "fixture-copy-two");
      await seenState(state, "original-copy", "stale");
    } finally {
      gate.release.resolve(undefined);
    }
  });
});

test("an unrelated captured provider cannot become a required source-claim receipt", async () => {
  await withFixture(
    async (prompt) => modelReply(packetPayload(prompt).items),
    async (state) => {
      recordFixtureLookup(state, "unrelated-service", "irrelevant");
      const ack = await queue(state, draft("source-only-after-catalog"));
      expect(ack).toMatchObject({ queued: true });
      await seenState(state, "source-only-after-catalog", "approved");
    },
  );
});

test("CAS conflict does not leave unacknowledged siblings or permit host application IDs", async () => {
  await withFixture(
    async (prompt) => modelReply(packetPayload(prompt).items),
    async (state) => {
      const premise = await approved(state, draft("previous"));
      const partial = await queue(
        state,
        draft("innocent"),
        draft("previous", {
          expectedRevision: premise.revision + 1,
          payload: "contending update",
        }),
      );
      expect(partial.queued).toBe(false);
      expect(await getClaim(state, "innocent")).toBeUndefined();
      const hostNamespace = await queue(state, draft("application:caller-a"));
      expect(hostNamespace.queued).toBe(false);
    },
  );
});

test("partial correlations can retain valid approvals without creating an omitted decision", async () => {
  let calls = 0;
  await withFixture(
    async (prompt) => {
      calls++;
      const rows = packetPayload(prompt).items;
      return modelReply(rows.filter(({ id }) => id === "returned"));
    },
    async (state) => {
      expect(
        (await queue(state, draft("returned"), draft("omitted"))).queued,
      ).toBe(true);
      await seenState(state, "returned", "approved");
      const omitted = await waitFor(
        () => getClaim(state, "omitted"),
        (row) => row?.state === "pending" && !!row.error,
        "visible unreturned review result",
      );
      expect(omitted!.reviewing).toBe(false);
      expect(calls).toBe(1);
    },
  );
});

test("per-use conclusions preserve two exact calls and project only approved premise metadata", async () => {
  const applications: { row: ReviewRow; packet: ReviewPacket }[] = [];
  await withFixture(
    async (prompt) => {
      const packet = packetPayload(prompt);
      for (const row of packet.items)
        if (row.kind === "use") applications.push({ row, packet });
      const result = JSON.parse(modelReply(packet.items));
      for (const row of result.items)
        if (row.id === "caller-a" || row.id === "caller-b")
          row.evidenceIds.push("claim:wrapper");
      return JSON.stringify(result);
    },
    async (state) => {
      const wrapper = await approved(state, draft("wrapper"));
      const ack = await state.queue({
        items: [
          use("caller-a", "caller-a.ts", [wrapper]),
          use("caller-b", "caller-b.ts", [wrapper]),
        ],
      });
      expect(ack.queued).toBe(true);
      const one = await state.submit({
        reviewItems: ack.items!.slice(0, 1),
        candidateGeneration: state.readStatus().candidateGeneration,
        limitations: [],
      });
      expect(one).toMatchObject({ accepted: false });
      expect(one.feedback).toMatch(/previously queued uses are missing/i);
      expect(
        await state.submit({
          reviewItems: ack.items,
          candidateGeneration: state.readStatus().candidateGeneration,
          limitations: [],
        }),
      ).toMatchObject({ accepted: true });
      expect(applications).toHaveLength(2);
      for (const { row, packet } of applications) {
        expect(row.supportingClaims).toEqual([wrapper]);
        const [premise] = packet.approvedClaims;
        expect(premise!.evidence.sources[0]!.path).toBe("writer.ts");
        expect(premise!.evidence.sources[0]).not.toHaveProperty("text");
        expect(row.excerptIds.map((id) => packet.excerpts[id]!.path)).toEqual([
          row.id + ".ts",
        ]);
      }
      const serialized = JSON.parse(
        JSON.stringify({
          ...state.publicReport(),
          cve: "CVE-2024-1000",
          advisories: [],
          usage: null,
        }),
      );
      const report = readDependencyCheckOutput(serialized);
      expect(
        report.uses.map((row) => row.proof?.sink?.callSite.path).sort(),
      ).toEqual(["caller-a.ts", "caller-b.ts"]);
      expect(
        new Set(report.uses.map((row) => row.conclusionClaim!.hash)).size,
      ).toBe(2);
      expect(report.claims).toHaveLength(3);
      const byId = new Map(report.claims!.map((row) => [row.id, row]));
      expect(claimRef(byId.get(wrapper.id)!)).toEqual(wrapper);
      for (const use of report.uses) {
        expect(use.supportingClaims).toEqual([wrapper]);
        const conclusion = byId.get(use.conclusionClaim!.id)!;
        expect(claimRef(conclusion)).toEqual(use.conclusionClaim!);
        expect(conclusion.dependencies).toEqual([wrapper]);
        expect(conclusion.application!.assessmentId).toBe(
          use.proof!.sink!.callSite.path.replace(/\.ts$/, ""),
        );
      }
      expect(
        Object.values(report.claimEvidence!.sources)
          .map((excerpt) => (excerpt as { path: string }).path)
          .sort(),
      ).toEqual(["caller-a.ts", "caller-b.ts", "writer.ts"]);
    },
  );
});

test("a host-approved conclusion from another artifact still requires a fresh application review", async () => {
  const firstArtifact = "sha256:" + "a".repeat(64);
  const secondArtifact = "sha256:" + "b".repeat(64);
  const checked: { row: ReviewRow; packet: ReviewPacket }[] = [];
  await withFixture(
    async (prompt) => {
      const packet = packetPayload(prompt);
      for (const row of packet.items)
        if (row.kind === "use") checked.push({ row, packet });
      return modelReply(
        packet.items,
        packet.items.every((row) => row.id !== "caller-b"),
      );
    },
    async (state) => {
      const first = await state.queue({
        items: [use("caller-a", "caller-a.ts", [], firstArtifact)],
      });
      expect(first.queued).toBe(true);
      const old = claimRef(
        await seenState(state, "application:caller-a", "approved"),
      );
      const second = await state.queue({
        items: [use("caller-b", "caller-b.ts", [old], secondArtifact)],
      });
      expect(second.queued).toBe(true);
      const newApplication = await seenState(
        state,
        "application:caller-b",
        "rejected",
      );
      expect(newApplication.hash).not.toBe(old.hash);
      expect(checked.map(({ row }) => row.use!.place!.artifact)).toEqual([
        firstArtifact,
        secondArtifact,
      ]);
      expect(checked[1]!.packet.approvedClaims[0]!.payload).toMatchObject({
        use: { place: { artifact: firstArtifact } },
      });
      expect(
        checked[1]!.row.excerptIds.map(
          (id) => checked[1]!.packet.excerpts[id]!.path,
        ),
      ).toEqual(["caller-b.ts"]);
    },
  );
});

test("shared resource proof uses exact selected records and keeps large original profiles out of packets", async () => {
  const packets: ReviewPacket[] = [];
  const unrelatedProfileMarker = "UNRELATED-GRAPH-PROFILE-BYTES";
  const bucket = {
    frames: [{ file: "writer.ts", function: "saveImage" }],
    privateTail: unrelatedProfileMarker.repeat(1700),
  };
  await withFixture(
    async (prompt) => {
      const packet = packetPayload(prompt);
      packets.push(packet);
      const result = JSON.parse(modelReply(packet.items));
      for (const row of result.items)
        if (row.id === "caller-a") row.evidenceIds.push("claim:frame");
      return JSON.stringify(result);
    },
    async (state) => {
      const uri = "fixture://profiles/exact";
      const base = state.recordInventory(
        "deployed",
        { structuredContent: { graph_evidence: { uri } } },
        { tool: "lookup", arguments: { service: "observed" } },
      );
      const resourceId = state.recordInventory(
        "deployed",
        { contents: [{ uri, text: JSON.stringify(bucket) }] },
        {
          tool: "mcpServer/resource/read",
          arguments: { uri },
          parentReceiptId: base,
        },
      );
      const wholeReceipt = await queue(
        state,
        draft("whole", { evidence: [], receiptIds: [resourceId] }),
      );
      expect(wholeReceipt).toMatchObject({ queued: false });
      expect(wholeReceipt.feedback).toMatch(/bulk collection/i);
      const subset = await approved(
        state,
        draft("frame", {
          evidence: [],
          receiptSelections: [
            { receiptId: resourceId, textBlock: 0, record: ["frames", 0] },
          ],
        }),
      );
      expect(Object.values(packets[0]!.receipts)[0]!.result).toEqual(
        bucket.frames[0]!,
      );
      const useAck = await state.queue({
        items: [use("caller-a", "caller-a.ts", [subset])],
      });
      expect(useAck.queued).toBe(true);
      await seenState(state, "application:caller-a", "approved");
      const [premise] = packets[1]!.approvedClaims;
      expect(premise!.evidence.receipts[0]!.selection!.record).toEqual([
        "frames",
        0,
      ]);
      expect(premise!.evidence.receipts[0]).not.toHaveProperty("result");
      expect(JSON.stringify(packets)).not.toContain(unrelatedProfileMarker);
      const final = await state.submit({
        reviewItems: useAck.items,
        candidateGeneration: state.readStatus().candidateGeneration,
        limitations: [],
      });
      expect(final).toMatchObject({ accepted: true });
      const report = state.publicReport();
      expect(
        Object.values(report.claimEvidence!.receipts).map(
          (receipt) => (receipt as { result: unknown }).result,
        ),
      ).toEqual([bucket.frames[0]]);
      expect(JSON.stringify(report)).not.toContain(unrelatedProfileMarker);
    },
  );
});

test("unreferenced pending premise review cannot delay an already accepted use's final report", async () => {
  const gate = block();
  await withFixture(
    async (prompt) => {
      const packet = packetPayload(prompt);
      if (packet.items.some(({ id }) => id === "unreferenced")) {
        gate.entered.resolve(undefined);
        await gate.release.promise;
      }
      return modelReply(packet.items);
    },
    async (state) => {
      try {
        const ack = await state.queue({
          items: [use("caller-a", "caller-a.ts")],
        });
        expect(ack.queued).toBe(true);
        await seenState(state, "application:caller-a", "approved");
        expect((await queue(state, draft("unreferenced"))).queued).toBe(true);
        await entered(gate);
        const submission = state.submit({
          reviewItems: ack.items,
          candidateGeneration: state.readStatus().candidateGeneration,
          limitations: [],
        });
        try {
          const result = await Promise.race([
            submission,
            Bun.sleep(250).then(() => ({
              accepted: false,
              feedback: "Unrelated pending claim still blocks submission.",
            })),
          ]);
          expect(result).toMatchObject({ accepted: true });
        } finally {
          gate.release.resolve(undefined);
          await submission;
        }
      } finally {
        gate.release.resolve(undefined);
      }
    },
  );
});

test("changing only the pinned premise revisions requires a fresh exact application review", async () => {
  const observed: { hash: string; pinned: ReviewRow["supportingClaims"] }[] =
    [];
  await withFixture(
    async (prompt) => {
      const packet = packetPayload(prompt);
      for (const row of packet.items)
        if (row.kind === "use")
          observed.push({ hash: row.hash, pinned: row.supportingClaims });
      return modelReply(packet.items);
    },
    async (state) => {
      const firstPremise = await approved(state, draft("first-proof"));
      const alternatePremise = await approved(state, draft("alternate-proof"));
      expect(
        (
          await state.queue({
            items: [use("caller-a", "caller-a.ts", [firstPremise])],
          })
        ).queued,
      ).toBe(true);
      const firstApplication = await seenState(
        state,
        "application:caller-a",
        "approved",
      );
      expect(
        (
          await state.queue({
            items: [use("caller-a", "caller-a.ts", [alternatePremise])],
          })
        ).queued,
      ).toBe(true);
      const secondApplication = await seenState(
        state,
        "application:caller-a",
        "approved",
      );
      expect(secondApplication.revision).toBe(firstApplication.revision + 1);
      expect(observed).toEqual([
        { hash: firstApplication.hash, pinned: [firstPremise] },
        { hash: secondApplication.hash, pinned: [alternatePremise] },
      ]);
      expect(secondApplication.hash).not.toBe(firstApplication.hash);
    },
  );
});

test("a wrong review hash keeps the actual claim pending until explicit fresh review", async () => {
  let count = 0;
  await withFixture(
    async (prompt) => {
      const packet = packetPayload(prompt);
      count++;
      return modelReply(
        packet.items.map((row) =>
          count === 1 ? { ...row, hash: "0".repeat(64) } : row,
        ),
      );
    },
    async (state) => {
      const subject = draft("wrapper");
      const ack = await queue(state, subject);
      expect(ack.queued).toBe(true);
      const invalid = await waitFor(
        () => getClaim(state, "wrapper"),
        (row) => row?.state === "pending" && !!row.error,
        "invalid reply is discarded",
      );
      expect(invalid!.error).toMatch(/revision and hash/i);
      expect(invalid!.reviewing).toBe(false);
      expect(count).toBe(1);
      const retried = await queue(state, subject);
      expect(retried.claims).toEqual(ack.claims);
      const good = await seenState(state, "wrapper", "approved");
      expect(claimRef(good)).toEqual(ack.claims![0]!);
      expect(count).toBe(2);
    },
  );
});

test("finalization revalidates shared source even after the exact application was accepted", async () => {
  await withFixture(
    async (prompt) => modelReply(packetPayload(prompt).items),
    async (state, repository) => {
      const premise = await approved(state, draft("writer"));
      const ack = await state.queue({
        items: [use("caller-a", "caller-a.ts", [premise])],
      });
      expect(ack.queued).toBe(true);
      await seenState(state, "application:caller-a", "approved");
      await writeFile(
        join(repository, "writer.ts"),
        "export function saveImage(output, mode) {\n  return image.save(output, 'TIFF');\n}\n",
      );
      // Do not query the premise first: submission itself must revalidate its current source.
      const final = await state.submit({
        reviewItems: ack.items,
        candidateGeneration: state.readStatus().candidateGeneration,
        limitations: [],
      });
      expect(final).toMatchObject({ accepted: false });
      expect(final.feedback).toMatch(/changed|stale/i);
      await seenState(state, "application:caller-a", "stale");
    },
  );
});

test("review acceptance cannot cite only a shared premise for a fresh source application", async () => {
  await withFixture(
    async (prompt) => {
      const packet = packetPayload(prompt);
      const reply = JSON.parse(modelReply(packet.items));
      if (packet.items.some((row) => row.kind === "use"))
        reply.items[0].evidenceIds = ["claim:wrapper"];
      return JSON.stringify(reply);
    },
    async (state) => {
      const shared = await approved(state, draft("wrapper"));
      const ack = await state.queue({
        items: [use("caller-a", "caller-a.ts", [shared])],
      });
      expect(ack.queued).toBe(true);
      const final = await state.submit({
        reviewItems: ack.items,
        candidateGeneration: state.readStatus().candidateGeneration,
        limitations: [],
      });
      expect(final).toMatchObject({ accepted: false });
      expect(await getClaim(state, "application:caller-a")).not.toMatchObject({
        state: "approved",
      });
    },
  );
});

test("uncited proposed support cannot attach a foreign artifact receipt to a decided use", async () => {
  await withFixture(
    async (prompt) => modelReply(packetPayload(prompt).items),
    async (state) => {
      const first = "sha256:" + "a".repeat(64);
      const selected = "sha256:" + "b".repeat(64);
      const receiptId = recordFixtureLookup(state, "other-service", first);
      const foreign = await approved(
        state,
        draft("foreign", {
          ...inventoryEvidence(receiptId),
          scope: { artifact: first },
          payload: {
            artifact: first,
            inference: "Evidence for a separate copy only.",
          },
        }),
      );
      const ack = await state.queue({
        items: [use("caller-a", "caller-a.ts", [foreign], selected)],
      });
      expect(ack.queued).toBe(true);
      const final = await state.submit({
        reviewItems: ack.items,
        candidateGeneration: state.readStatus().candidateGeneration,
        limitations: [],
      });
      expect(final).toMatchObject({ accepted: true });
      const [finding] = state.publicReport().uses;
      expect(finding!.place.artifact).toBe(selected);
      expect(finding!.decidingEvidence).toEqual([
        { kind: "source", path: "caller-a.ts", startLine: 1, endLine: 2 },
      ]);
    },
  );
});

test("shared source of the same range cannot erase this use's original supports", async () => {
  await withFixture(
    async (prompt) => {
      const packet = packetPayload(prompt);
      const reply = JSON.parse(modelReply(packet.items));
      for (const result of reply.items)
        if (result.id === "caller-a")
          result.evidenceIds.push("claim:shared-source");
      return JSON.stringify(reply);
    },
    async (state, repository) => {
      await writeFile(
        join(repository, "caller-a.ts"),
        'import { saveImage } from "./writer";\nexport const start = (output) => saveImage(output, "TIFF");\n',
      );
      const shared = await approved(
        state,
        draft("shared-source", {
          evidence: [{ path: "caller-a.ts", startLine: 1, endLine: 2 }],
          payload: { selector: "The caller selects TIFF." },
        }),
      );
      const item = use("caller-a", "caller-a.ts", [shared]);
      item.use.verdict = "unknown";
      item.use.reason =
        "The exact caller selects TIFF. The selected deployment dependency copy is unresolved.";
      item.use.proof!.conditions[0]!.status = "met";
      item.use.proof!.conditions[0]!.explanation =
        "The exact caller explicitly selects TIFF.";
      item.use.evidence[0]!.supports = ["affected_use"];
      const ack = await state.queue({ items: [item] });
      expect(ack.queued).toBe(true);
      const final = await state.submit({
        reviewItems: ack.items,
        candidateGeneration: state.readStatus().candidateGeneration,
        limitations: [],
      });
      expect(final).toMatchObject({ accepted: true });
      const [finding] = state.publicReport().uses;
      expect(finding!.evidence).toEqual(item.use.evidence);
    },
  );
});

test("partial application results preserve the reviewed caller and keep its sibling unapproved", async () => {
  await withFixture(
    async (prompt) =>
      modelReply(
        packetPayload(prompt).items.filter((row) => row.id !== "caller-b"),
      ),
    async (state) => {
      const ack = await state.queue({
        items: [use("caller-a", "caller-a.ts"), use("caller-b", "caller-b.ts")],
      });
      expect(ack.queued).toBe(true);
      await seenState(state, "application:caller-a", "approved");
      const omitted = await waitFor(
        () => getClaim(state, "application:caller-b"),
        (row) => row?.state === "pending" && !!row.error,
        "unreturned application",
      );
      expect(omitted).toMatchObject({ state: "pending", reviewing: false });
      expect(
        await state.submit({
          reviewItems: ack.items,
          candidateGeneration: 0,
          limitations: [],
        }),
      ).toMatchObject({ accepted: false });
      expect(
        await state.submit({
          reviewItems: ack.items!.slice(0, 1),
          candidateGeneration: 0,
          limitations: [],
        }),
      ).toMatchObject({
        accepted: false,
        feedback: expect.stringContaining("Previously queued uses are missing"),
      });
      expect((await getClaim(state, "application:caller-a"))!.state).toBe(
        "approved",
      );
    },
  );
});

test("final selection can leave a superseded non-use disposition in audit without dropping a use", async () => {
  await using repo = await scopedTemporaryDirectory("superseded-disposition-");
  await writeFile(
    join(repo.path, "caller-a.ts"),
    'import { saveImage } from "./writer";\nexport const result = saveImage(output, "PNG");\n',
  );
  const candidates = await createDependencyCandidates(repo.path);
  const [candidate] = await candidates.observeGraph("trace", {
    trace: [
      {
        relation: "candidate_call",
        evidence: [{ source: "caller-a.ts", lines: [2] }],
      },
    ],
  });
  const state = createDependencyReportSubmission({
    repository: repo.path,
    advisory,
    candidates,
    review: async (prompt) => modelReply(packetPayload(prompt).items),
  });
  try {
    const prior = await state.queue({
      items: [
        {
          id: "prior",
          kind: "dismissed",
          candidateIds: [candidate!.id],
          reason: "The selected output is PNG.",
          evidence: use("caller-a", "caller-a.ts").use.evidence,
          observations: [],
        },
      ],
    });
    const current = await state.queue({
      items: [
        { ...use("caller-a", "caller-a.ts"), candidateIds: [candidate!.id] },
      ],
    });
    expect(prior.queued).toBe(true);
    expect(current.queued).toBe(true);
    const generation = state.readStatus().candidateGeneration;
    expect(
      await state.submit({
        reviewItems: prior.items,
        candidateGeneration: generation,
        limitations: [],
      }),
    ).toMatchObject({
      accepted: false,
      feedback: expect.stringContaining("Previously queued uses are missing"),
    });
    expect(
      await state.queue({
        items: [
          {
            id: "prior",
            kind: "dismissed",
            candidateIds: [],
            reason: "Superseded.",
            evidence: use("caller-a", "caller-a.ts").use.evidence,
            observations: [],
          },
        ],
      }),
    ).toMatchObject({ queued: false });
    expect(
      await state.submit({
        reviewItems: current.items,
        candidateGeneration: generation,
        limitations: [],
      }),
    ).toMatchObject({ accepted: true });
    expect(state.publicReport().uses[0]!.proof!.sink!.callSite).toEqual({
      path: "caller-a.ts",
      line: 2,
    });
    expect(state.readStatus().items.some((row) => row.id === "prior")).toBe(
      true,
    );
  } finally {
    await state.close();
  }
});

test("shared research retains separate excluded, unknown and configured potential uses", async () => {
  await withFixture(
    async (prompt) => {
      const packet = packetPayload(prompt);
      const reply = JSON.parse(modelReply(packet.items)) as {
        items: {
          id: string;
          citedVersion: string | null;
          evidenceIds: string[];
        }[];
      };
      for (const row of reply.items) {
        if (row.id === "potential") row.citedVersion = "1.0";
        if (row.id === "excluded") row.evidenceIds.push("claim:writer");
      }
      return JSON.stringify(reply);
    },
    async (state, repository) => {
      const shared = await approved(state, draft("writer"));
      await writeFile(
        join(repository, "unknown.ts"),
        'import { saveImage } from "./writer";\nexport const result = (mode) => saveImage(output, mode);\n',
      );
      await writeFile(
        join(repository, "potential.ts"),
        'import { saveImage } from "./writer"; // selected library version 1.0\nexport const result = saveImage(output, "TIFF");\n',
      );
      const excluded = use("excluded", "caller-a.ts", [shared]);
      const unresolved = use("unknown", "unknown.ts");
      unresolved.use.verdict = "unknown";
      unresolved.use.reason =
        "The caller supplies the mode; its selected value and dependency copy remain unresolved.";
      unresolved.use.proof!.conditions[0]!.status = "unknown";
      unresolved.use.proof!.conditions[0]!.explanation =
        "The selected runtime mode is unknown.";
      const potential = use("potential", "potential.ts");
      potential.use.verdict = "potentially_exploitable";
      potential.use.deployment = "configured";
      potential.use.version = "1.0";
      potential.use.reason =
        "The selected configured fixture copy supports the affected TIFF operation; running identity and access remain unknown.";
      potential.use.evidence[0]!.supports = ["affected_copy", "affected_use"];
      potential.use.proof!.conditions[0]!.status = "met";
      potential.use.proof!.conditions[0]!.explanation =
        "The configured caller explicitly selects TIFF.";
      const ack = await state.queue({
        items: [excluded, unresolved, potential],
      });
      expect(ack.queued).toBe(true);
      expect(
        await state.submit({
          reviewItems: ack.items,
          candidateGeneration: 0,
          limitations: [],
        }),
      ).toMatchObject({ accepted: true });
      const report = state.publicReport();
      expect(report.uses.map((row) => row.verdict)).toEqual([
        "ruled_out",
        "unknown",
        "potentially_exploitable",
      ]);
      expect(report.uses.map((row) => row.proof!.sink!.callSite.path)).toEqual([
        "caller-a.ts",
        "unknown.ts",
        "potential.ts",
      ]);
      expect(
        report.uses.every((row) => row.conclusionClaim !== undefined),
      ).toBe(true);
      expect(state.acceptedReport().status).toBe("potentially_exploitable");
    },
  );
});

import { expect, test } from "bun:test";
import { writeFile } from "node:fs/promises";
import { join } from "node:path";
import {
  packetPayload,
  sourceEvidence,
  use,
  withFixture,
  type ReviewPacket,
} from "./support/dependency-claims-fixture.js";

function modelReply(packet: ReviewPacket) {
  return JSON.stringify({
    items: packet.items.map((item) => ({
      id: item.id,
      revision: item.revision,
      hash: item.hash,
      accepted: true,
      reason: "The cited source establishes the fixture decision.",
      citedVersion: null,
      evidenceIds: item.excerptIds,
    })),
  });
}

const branch = {
  id: "dynamic-branch",
  kind: "unresolved",
  candidateIds: [],
  reason: "The effective handler selected by this route is unresolved.",
  evidence: [sourceEvidence("branch.ts")],
  observations: [],
};
const resolution = {
  ...branch,
  kind: "dismissed",
  reason:
    "The route selects the metadata handler, which never reaches the writer.",
  evidence: [...branch.evidence, sourceEvidence("handler.ts")],
};
const writeBranch = (repository: string) =>
  writeFile(
    join(repository, "branch.ts"),
    'import { handle } from "./handler";\nexport const route = (value: string) => handle(value);\n',
  );

test("final selection must retain a queued source-only scope gap", async () => {
  await withFixture(
    async (prompt) => modelReply(packetPayload(prompt)),
    async (state, repository) => {
      await writeBranch(repository);
      const queued = await state.queue({
        items: [use("png-caller", "caller-a.ts"), branch],
      });
      if (!queued.queued) throw new Error(queued.feedback);

      const incomplete = await state.submit({
        reviewItems: [queued.items[0]],
        candidateGeneration: 0,
        limitations: [],
      });
      expect(incomplete.accepted).toBe(false);
      expect(incomplete.feedback).toContain(branch.id);

      const complete = await state.submit({
        reviewItems: queued.items,
        candidateGeneration: 0,
        limitations: [],
      });
      expect(complete.accepted).toBe(true);
      expect(state.acceptedReport().status).toBe("unknown");
      expect(state.acceptedReport().limitations.join("\n")).toContain(
        "branch.ts:1-2",
      );
    },
  );
});

test("later source proof can close a candidate-less scope gap under its original ID", async () => {
  const packets: ReviewPacket[] = [];
  await withFixture(
    async (prompt) => {
      const packet = packetPayload(prompt);
      packets.push(packet);
      return modelReply(packet);
    },
    async (state, repository) => {
      await writeBranch(repository);
      const queued = await state.queue({
        items: [use("png-caller", "caller-a.ts"), branch],
      });
      if (!queued.queued) throw new Error(queued.feedback);

      await writeFile(
        join(repository, "handler.ts"),
        "// This route only stores the input length.\nexport const handle = (value: string) => value.length;\n",
      );
      const fresh = await state.queue({
        items: [{ ...resolution, id: "fresh-dismissal" }],
      });
      expect(fresh.queued).toBe(false);

      const replacement = await state.queue({ items: [resolution] });
      if (!replacement.queued) throw new Error(replacement.feedback);
      expect(replacement.items[0]).toEqual({ id: branch.id, revision: 2 });

      const incomplete = await state.submit({
        reviewItems: [queued.items[0]],
        candidateGeneration: 0,
        limitations: [],
      });
      expect(incomplete.accepted).toBe(false);
      expect(incomplete.feedback).toContain(branch.id);

      const complete = await state.submit({
        reviewItems: [queued.items[0], replacement.items[0]],
        candidateGeneration: 0,
        limitations: [],
      });
      expect(complete.accepted).toBe(true);
      expect(state.acceptedReport()).toMatchObject({
        status: "ruled_out",
        limitations: [],
        coverage: [{ kind: "dismissed", reason: resolution.reason }],
      });
      const reviewed = packets
        .flatMap((packet) => packet.items)
        .find((item) => item.id === branch.id && item.revision === 2);
      expect(reviewed).toMatchObject({
        previousSourceGap: { reason: branch.reason, evidence: branch.evidence },
      });
    },
  );
});

test("publication revalidates an approved use after a post-submission source change", async () => {
  await withFixture(
    async (prompt) => modelReply(packetPayload(prompt)),
    async (state, repository) => {
      const queued = await state.queue({
        items: [use("png-caller", "caller-a.ts")],
      });
      if (!queued.queued) throw new Error(queued.feedback);

      const submitted = await state.submit({
        reviewItems: queued.items,
        candidateGeneration: 0,
        limitations: [],
      });
      expect(submitted.accepted).toBe(true);
      await writeFile(
        join(repository, "caller-a.ts"),
        'import { saveImage } from "./writer";\nexport const start = (output) => saveImage(output, "TIFF");\n',
      );

      await state.refreshAcceptedReport();
      expect(state.continuationPrompt()).toContain("resubmit");
      expect(() => state.publicReport()).toThrow(
        "Dependency report was rejected",
      );
    },
  );
});

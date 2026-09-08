import { createHash } from "node:crypto";
import { describe, expect, test } from "bun:test";
import {
  compactFinding,
  findingCatalogue,
  type ComparisonFinding,
} from "../src/finding-catalogue.js";
import {
  matchScanFindings,
  matchScanFindingsInternal,
  type ScanComparisonInput,
  type ScanComparisonOptions,
  type ScanComparisonResult,
} from "../src/scan-comparison.js";

const empty = { matches: [], uncertain: [] } satisfies ScanComparisonResult;
const confirmedPair = (
  before: string,
  after: string,
): ScanComparisonResult => ({
  matches: [
    {
      beforeOccurrenceIds: [before],
      afterOccurrenceIds: [after],
      confidence: "high",
      reason: "The same synthetic control.",
    },
  ],
  uncertain: [],
});
const finding = (
  occurrenceId: string,
  details: Record<string, unknown> = {},
): ComparisonFinding => ({ occurrenceId, ...details });
const data = <T>(prompt: string): T =>
  JSON.parse(prompt.slice(prompt.lastIndexOf("\n") + 1)) as T;
type CatalogueData = {
  page: number;
  findings: ScanComparisonInput;
};
type EvidenceData = {
  beforeOccurrenceIds: string[];
  afterOccurrenceIds: string[];
  content: string;
  offset: number;
  nextOffset: number | null;
};
const characters = (value: string): number => Array.from(value).length;

function conversation(
  respond: (prompt: string, index: number) => unknown | Promise<unknown>,
) {
  const prompts: string[] = [];
  let threads = 0;
  const codex: NonNullable<ScanComparisonOptions["codex"]> = {
    startThread() {
      threads += 1;
      return {
        async run(prompt) {
          prompts.push(prompt);
          const response = await respond(prompt, prompts.length - 1);
          return { finalResponse: JSON.stringify(response) };
        },
      };
    },
  };
  return { codex, prompts, threads: () => threads };
}

describe("finding catalogue", () => {
  test("keeps root-control metadata and leaves full evidence out of cards", () => {
    const entry = finding("old", {
      title: "Synthetic missing ownership check",
      identity: { anchor: "document-access", instance: "read-document" },
      root_cause: {
        summary: "The shared control omits ownership",
        code: "FULL_CODE",
      },
      remediation: "Check ownership in the shared control",
      codeEvidence: [{ code: "FULL_CODE" }],
      locations: [
        { path: "route.ts", startLine: 2, role: "entrypoint" },
        { path: "access.ts", startLine: 8, role: "root_control" },
      ],
      attackPath: {
        data_flow: {
          source: "document ID",
          sink: "readDocument",
          transformations: ["FULL_FLOW"],
        },
        reachability: {
          attacker: "signed-in user",
          entrypoint: "GET /documents/:id",
        },
      },
    });

    expect(compactFinding(entry)).toMatchObject({
      occurrenceId: "old",
      rootCause: "The shared control omits ownership",
      locations: [{ path: "access.ts", startLine: 8, role: "root_control" }],
      attackPath: { dataFlow: { source: "document ID", sink: "readDocument" } },
    });
    expect(JSON.stringify(compactFinding(entry))).not.toContain("FULL_CODE");
    expect(JSON.stringify(compactFinding(entry))).not.toContain("FULL_FLOW");
  });

  test("groups only stable identities and confirmed aliases", () => {
    const common = {
      rootCause: "The shared control",
      remediation: "Fix the shared control",
    };
    const entries = [
      finding("first", {
        ...common,
        findingId: "identity-a",
        title: "First description",
      }),
      finding("same", {
        ...common,
        findingId: "identity-a",
        title: "Same identity",
      }),
      finding("renamed", {
        ...common,
        findingId: "identity-c",
        title: "Renamed description",
      }),
      finding("independent", {
        findingId: "identity-d",
        title: "Same identity",
      }),
    ];
    const catalogue = findingCatalogue(entries, [
      ["identity-a", "identity-b"],
      ["identity-b", "identity-c"],
    ]);

    expect([...catalogue.keys()]).toEqual(["renamed", "independent"]);
    expect(
      catalogue.get("renamed")?.occurrences.map((item) => item.occurrenceId),
    ).toEqual(["first", "same", "renamed"]);
    expect(catalogue.get("renamed")?.card).toMatchObject({
      issueId: "identity-a",
      occurrenceCount: 3,
    });
    expect(catalogue.get("renamed")?.card["earlierDescriptions"]).toEqual([
      { title: "First description" },
      { title: "Same identity" },
    ]);
  });

  test.each(["", "   "])(
    "does not treat a blank finding identity as a confirmed match (%j)",
    async (findingId) => {
      const before = finding("old", { findingId });
      const after = finding("new", { findingId });
      const observed = conversation(() => empty);

      expect(findingCatalogue([before, after]).size).toBe(2);
      expect(findingCatalogue([before]).get("old")?.card).not.toHaveProperty(
        "issueId",
      );
      expect(
        await matchScanFindings(
          {
            before: [before],
            after: [after],
            knownFindingGroups: [[findingId]],
          },
          { codex: observed.codex },
        ),
      ).toEqual(empty);
      expect(observed.threads()).toBe(1);

      const distinct = conversation(() => empty);
      expect(
        await matchScanFindings(
          {
            before: [finding("identity-before", { findingId: "identity-a" })],
            after: [finding("identity-after", { findingId: "identity-b" })],
            knownFindingGroups: [
              [findingId, "identity-a"],
              [findingId, "identity-b"],
            ],
          },
          { codex: distinct.codex },
        ),
      ).toEqual(empty);
      expect(distinct.threads()).toBe(1);
    },
  );

  test.each(["stable identity", "confirmed alias"] as const)(
    "reuses a %s across opposite sides without starting Codex",
    async (kind) => {
      const observed = conversation(() => empty);
      const result = await matchScanFindings(
        {
          before: [finding("old", { findingId: "identity-a" })],
          after: [
            finding("new", {
              findingId:
                kind === "stable identity" ? "identity-a" : "identity-b",
            }),
          ],
          knownFindingGroups: [
            ["identity-a", "identity-bridge"],
            ["identity-bridge", "identity-b"],
          ],
        },
        { codex: observed.codex },
      );
      expect(result).toMatchObject({
        matches: [
          {
            beforeOccurrenceIds: ["old"],
            afterOccurrenceIds: ["new"],
            confidence: "high",
          },
        ],
        uncertain: [],
      });
      expect(observed.threads()).toBe(0);
    },
  );

  test.each(["omitted", "extended"] as const)(
    "preserves an %s cross-side alias while matching another finding",
    async (kind) => {
      const observed = conversation(() => ({
        matches:
          kind === "extended"
            ? [
                {
                  beforeOccurrenceIds: ["old"],
                  afterOccurrenceIds: ["other"],
                  confidence: "high",
                  reason: "The same control was split.",
                },
              ]
            : [],
        uncertain:
          kind === "omitted"
            ? [
                {
                  beforeOccurrenceId: "old",
                  afterOccurrenceId: "new",
                  reason: "The model omitted a confirmed alias.",
                },
              ]
            : [],
        related: [
          {
            beforeOccurrenceId: "old",
            afterOccurrenceId: kind === "omitted" ? "other" : "new",
            reason: "A related control.",
          },
        ],
      }));
      const result = await matchScanFindings(
        {
          before: [finding("old", { findingId: "identity-a" })],
          after: [
            finding("new", { findingId: "identity-b" }),
            finding("other", { findingId: "identity-c" }),
          ],
          knownFindingGroups: [["identity-a", "identity-b"]],
        },
        { codex: observed.codex },
      );
      expect(result.matches).toHaveLength(1);
      expect(result.matches[0]!.beforeOccurrenceIds).toEqual(["old"]);
      expect(new Set(result.matches[0]!.afterOccurrenceIds)).toEqual(
        new Set(kind === "omitted" ? ["new"] : ["new", "other"]),
      );
      expect(result.uncertain).toEqual([]);
      expect(result.related).toHaveLength(kind === "omitted" ? 1 : 0);
      expect(observed.threads()).toBe(1);
    },
  );

  test.each([false, true])(
    "reconciles known after identities with historical uncertainty set to %s",
    async (allowHistoricalUncertainty) => {
      const uncertain = [
        {
          beforeOccurrenceId: "other",
          afterOccurrenceId: "new",
          reason: "A different historical finding may share the control.",
        },
      ];
      const observed = conversation(() => ({ matches: [], uncertain }));
      const pending = matchScanFindings(
        {
          before: [
            finding("old", { findingId: "identity-a" }),
            finding("other", { findingId: "identity-c" }),
          ],
          after: [finding("new", { findingId: "identity-b" })],
          knownFindingGroups: [["identity-a", "identity-b"]],
        },
        { codex: observed.codex, allowHistoricalUncertainty },
      );
      if (!allowHistoricalUncertainty) {
        await expect(pending).rejects.toThrow("invalid uncertain pair");
        return;
      }
      const result = await pending;
      expect(result.matches).toHaveLength(1);
      expect(result.uncertain).toEqual(uncertain);
    },
  );

  test("rejects uncertainty for a finding with a known identity match", async () => {
    const observed = conversation(() => ({
      matches: [],
      uncertain: [
        {
          beforeOccurrenceId: "old",
          afterOccurrenceId: "other",
          reason: "The earlier finding may instead match another result.",
        },
      ],
    }));
    await expect(
      matchScanFindings(
        {
          before: [finding("old", { findingId: "identity-a" })],
          after: [
            finding("new", { findingId: "identity-b" }),
            finding("other", { findingId: "identity-c" }),
          ],
          knownFindingGroups: [["identity-a", "identity-b"]],
        },
        { codex: observed.codex, allowHistoricalUncertainty: true },
      ),
    ).rejects.toThrow("invalid uncertain pair");
  });

  test("extends semantic matches through aliases found only on the later side", async () => {
    const observed = conversation(() => ({
      matches: [
        {
          beforeOccurrenceIds: ["old-y"],
          afterOccurrenceIds: ["new-b"],
          confidence: "high",
          reason: "The second route reaches the shared control.",
        },
        {
          beforeOccurrenceIds: ["old-x"],
          afterOccurrenceIds: ["new-a"],
          confidence: "high",
          reason: "The first route reaches the shared control.",
        },
      ],
      uncertain: [],
      related: [
        {
          beforeOccurrenceId: "old-x",
          afterOccurrenceId: "new-b",
          reason: "The model did not reuse the confirmed alias.",
        },
      ],
    }));
    const result = await matchScanFindings(
      {
        before: [finding("old-x"), finding("old-y")],
        after: [
          finding("new-a", { findingId: "identity-a" }),
          finding("new-b", { findingId: "identity-b" }),
          finding("new-c", { findingId: "identity-c" }),
        ],
        knownFindingGroups: [
          ["identity-a", "identity-b"],
          ["identity-b", "identity-c"],
        ],
      },
      { codex: observed.codex },
    );
    expect(result.matches).toEqual([
      {
        beforeOccurrenceIds: ["old-y", "old-x"],
        afterOccurrenceIds: ["new-b", "new-a", "new-c"],
        confidence: "high",
        reason:
          "The second route reaches the shared control. The first route reaches the shared control.",
      },
    ]);
    expect(result.related).toEqual([]);
  });

  test.each(["sync", "async"])(
    "inspects selected evidence and expands saved occurrences despite a failing %s progress observer",
    async (failure) => {
      const before = [
        finding("old-a", {
          findingId: "identity-a",
          title: "Old title",
          codeEvidence: [{ code: "EARLIER_EVIDENCE" }],
        }),
        finding("old-b", {
          findingId: "identity-b",
          title: "New title",
          codeEvidence: [{ code: "LATEST_EVIDENCE" }],
        }),
        finding("unrelated", {
          findingId: "identity-c",
          codeEvidence: [{ code: "UNREQUESTED_EVIDENCE" }],
        }),
      ];
      const after = [
        finding("new", {
          title: "Current title",
          codeEvidence: [{ code: "CURRENT_EVIDENCE" }],
        }),
      ];
      const observed = conversation((prompt, index) => {
        if (index === 0) {
          expect(data<CatalogueData>(prompt).findings.before).toHaveLength(2);
          expect(prompt).not.toContain("EARLIER_EVIDENCE");
          return {
            ...empty,
            request: {
              kind: "evidence",
              beforeOccurrenceIds: ["old-b"],
              afterOccurrenceIds: ["new"],
              offset: 0,
            },
          };
        }
        const evidence = JSON.parse(
          data<EvidenceData>(prompt).content,
        ) as ScanComparisonInput;
        expect(evidence.before.map((item) => item.occurrenceId)).toEqual([
          "old-a",
          "old-b",
        ]);
        expect(prompt).toContain("EARLIER_EVIDENCE");
        expect(prompt).toContain("CURRENT_EVIDENCE");
        expect(prompt).not.toContain("UNREQUESTED_EVIDENCE");
        return {
          matches: [
            {
              beforeOccurrenceIds: ["old-b"],
              afterOccurrenceIds: ["new"],
              confidence: "high",
              reason: "Same shared control.",
            },
          ],
          uncertain: [],
        };
      });

      const phases: string[] = [];
      const result = await matchScanFindings(
        { before, after, knownFindingGroups: [["identity-a", "identity-b"]] },
        {
          codex: observed.codex,
          onProgress(progress) {
            phases.push(progress.phase);
            const error = new Error("Optional observer");
            if (failure === "async") return Promise.reject(error);
            throw error;
          },
        },
      );
      expect(result.matches[0]?.beforeOccurrenceIds).toEqual([
        "old-a",
        "old-b",
      ]);
      expect(observed.threads()).toBe(1);
      expect(observed.prompts).toHaveLength(2);
      expect(phases).toEqual(["catalogue", "evidence", "complete"]);
    },
  );

  test("keeps cost-limited automatic matching to one model call", async () => {
    const input = { before: [finding("old")], after: [finding("new")] };
    const response = {
      matches: [
        {
          beforeOccurrenceIds: ["old"],
          afterOccurrenceIds: ["new"],
          confidence: "high" as const,
          reason: "The same synthetic control.",
        },
      ],
      uncertain: [],
    };
    const direct = conversation(() => response);
    expect(
      await matchScanFindingsInternal(
        input,
        { codex: direct.codex },
        { surface: "sdk", singleTurn: true },
      ),
    ).toEqual(response);
    expect(direct.prompts).toHaveLength(1);

    const evidence = conversation(() => ({
      ...empty,
      request: {
        kind: "evidence",
        beforeOccurrenceIds: ["old"],
        afterOccurrenceIds: ["new"],
        offset: 0,
      },
    }));
    await expect(
      matchScanFindingsInternal(
        input,
        { codex: evidence.codex },
        { surface: "sdk", singleTurn: true },
      ),
    ).rejects.toThrow("scans match --all");
    expect(evidence.prompts).toHaveLength(1);
  });

  test.each(["multiple cards", "one oversized card"] as const)(
    "defers a cost-limited catalogue with %s before starting Codex",
    async (scenario) => {
      const observed = conversation(() => empty);
      await expect(
        matchScanFindingsInternal(
          {
            before:
              scenario === "multiple cards"
                ? [
                    finding("a", { rootCause: "a".repeat(600_000) }),
                    finding("b", { rootCause: "b".repeat(600_000) }),
                  ]
                : [finding("a", { rootCause: "a".repeat(1 << 20) })],
            after: [finding("new")],
          },
          { codex: observed.codex },
          { surface: "sdk", singleTurn: true },
        ),
      ).rejects.toThrow("scans match --all");
      expect(observed.threads()).toBe(0);
      expect(observed.prompts).toHaveLength(0);
    },
  );

  test.each(["in order", "out of order"] as const)(
    "delivers every oversized catalogue page %s before accepting a result",
    async (order) => {
      const input = {
        before: [
          finding("a", { rootCause: "a".repeat(600_000) }),
          finding("b", { rootCause: "b".repeat(600_000) }),
        ],
        after: [finding("c", { rootCause: "c".repeat(600_000) })],
      };
      const observed = conversation((_prompt, index) =>
        order === "out of order" && index === 0
          ? { ...empty, request: { kind: "catalogue", page: 2 } }
          : empty,
      );
      expect(await matchScanFindings(input, { codex: observed.codex })).toEqual(
        empty,
      );
      expect(observed.threads()).toBe(1);
      expect(
        observed.prompts.map((prompt) => data<CatalogueData>(prompt).page),
      ).toEqual(order === "in order" ? [0, 1, 2] : [0, 2, 1]);
      const seen = observed.prompts.flatMap((prompt) => {
        expect(characters(prompt)).toBeLessThanOrEqual(1 << 20);
        const page = data<CatalogueData>(prompt).findings;
        return [...page.before, ...page.after].map((item) => item.occurrenceId);
      });
      expect(seen.toSorted()).toEqual(["a", "b", "c"]);
    },
  );

  test.each(["match", "no match", "uncertain", "related"] as const)(
    "supplies omitted evidence before accepting a proposed %s decision",
    async (decision) => {
      const input = {
        before: [finding("old", { rootCause: "a".repeat(1_100_000) })],
        after: [finding("new", { rootCause: "b".repeat(1_100_000) })],
      };
      const pair = {
        beforeOccurrenceId: "old",
        afterOccurrenceId: "new",
        reason: "A synthetic decision made before reading the full evidence.",
      };
      const proposed: ScanComparisonResult = {
        matches:
          decision === "match" ? confirmedPair("old", "new").matches : [],
        uncertain: decision === "uncertain" ? [pair] : [],
        ...(decision === "related" ? { related: [pair] } : {}),
      };
      const revised: ScanComparisonResult = {
        ...empty,
        related: [
          {
            beforeOccurrenceId: "old",
            afterOccurrenceId: "new",
            reason: "The complete evidence identifies separate controls.",
          },
        ],
      };
      const pieces: string[] = [];
      let offset = 0;
      const observed = conversation((prompt, index) => {
        if (index === 0) {
          const cards = data<CatalogueData>(prompt).findings;
          expect(cards.before).toEqual([
            { occurrenceId: "old", detailsOmitted: true },
          ]);
          expect(cards.after).toEqual([
            { occurrenceId: "new", detailsOmitted: true },
          ]);
          return proposed;
        }
        const page = data<EvidenceData>(prompt);
        expect(page.beforeOccurrenceIds).toEqual(["old"]);
        expect(page.afterOccurrenceIds).toEqual(["new"]);
        expect(page.offset).toBe(offset);
        pieces.push(page.content);
        offset += characters(page.content);
        return page.nextOffset === null ? revised : proposed;
      });
      expect(await matchScanFindings(input, { codex: observed.codex })).toEqual(
        revised,
      );
      expect(pieces.length).toBeGreaterThan(1);
      expect(JSON.parse(pieces.join(""))).toEqual(input);
    },
  );

  test("batches omitted evidence identifiers within the upstream message limit", async () => {
    const identity = (prefix: string) => `${prefix}🙂${"x".repeat(360_000)}`;
    const beforeIds = [identity("before-a"), identity("before-b")];
    const afterIds = [identity("after")];
    const rootCause = "🙂".repeat(700_000);
    const selected = new Set<string>();
    const selections = new Set<string>();
    const observed = conversation((prompt) => {
      expect(characters(prompt)).toBeLessThanOrEqual(1 << 20);
      const payload = data<CatalogueData | EvidenceData>(prompt);
      if (!("content" in payload)) return empty;

      for (const identity of [
        ...payload.beforeOccurrenceIds,
        ...payload.afterOccurrenceIds,
      ]) {
        selected.add(identity);
      }
      selections.add(
        JSON.stringify([
          payload.beforeOccurrenceIds,
          payload.afterOccurrenceIds,
        ]),
      );
      return empty;
    });

    expect(
      await matchScanFindings(
        {
          before: beforeIds.map((id) => finding(id, { rootCause })),
          after: afterIds.map((id) => finding(id, { rootCause })),
        },
        { codex: observed.codex },
      ),
    ).toEqual(empty);
    expect(selected).toEqual(new Set([...beforeIds, ...afterIds]));
    expect(selections.size).toBeGreaterThan(1);
  });

  test("finishes requested evidence before accepting a proposed match", async () => {
    const original = finding("old", {
      codeEvidence: [{ code: "x".repeat(2_200_000) }],
    });
    const proposed = confirmedPair("old", "new");
    const pieces: string[] = [];
    let offset = 0;
    const observed = conversation((prompt, index) => {
      if (index === 0)
        return {
          ...empty,
          request: {
            kind: "evidence",
            beforeOccurrenceIds: ["old"],
            afterOccurrenceIds: [],
            offset: 0,
          },
        };
      const page = data<EvidenceData>(prompt);
      expect(page.offset).toBe(offset);
      pieces.push(page.content);
      offset += characters(page.content);
      return proposed;
    });
    expect(
      await matchScanFindings(
        { before: [original], after: [finding("new")] },
        { codex: observed.codex },
      ),
    ).toEqual(proposed);
    expect(pieces.length).toBeGreaterThan(1);
    expect(JSON.parse(pieces.join(""))).toEqual({
      before: [original],
      after: [],
    });
  });

  test("does not finish unrelated evidence when confirming another match", async () => {
    const proposed = confirmedPair("old", "new");
    const observed = conversation((prompt, index) => {
      if (index === 0)
        return {
          ...empty,
          request: {
            kind: "evidence",
            beforeOccurrenceIds: ["other"],
            afterOccurrenceIds: [],
            offset: 0,
          },
        };
      expect(data<EvidenceData>(prompt).nextOffset).not.toBeNull();
      return proposed;
    });
    expect(
      await matchScanFindings(
        {
          before: [
            finding("old"),
            finding("other", {
              codeEvidence: [{ code: "x".repeat(2_200_000) }],
            }),
          ],
          after: [finding("new")],
        },
        { codex: observed.codex },
      ),
    ).toEqual(proposed);
    expect(observed.prompts).toHaveLength(2);
  });

  test("pages a single oversized evidence record without losing Unicode", async () => {
    const original = finding("large", {
      rootCause: "🙂".repeat(1 << 20) + "x",
    });
    const pieces: string[] = [];
    let expectedOffset = 0;
    const request = (offset: number) => ({
      ...empty,
      request: {
        kind: "evidence",
        beforeOccurrenceIds: ["large"],
        afterOccurrenceIds: [],
        offset,
      },
    });
    const observed = conversation((prompt, index) => {
      expect(characters(prompt)).toBeLessThanOrEqual(1 << 20);
      if (index === 0) {
        expect(data<CatalogueData>(prompt).findings.before).toEqual([
          { occurrenceId: "large", detailsOmitted: true },
        ]);
        return request(0);
      }
      const payload = data<EvidenceData>(prompt);
      expect(payload.offset).toBe(expectedOffset);
      expect(payload.content.isWellFormed()).toBe(true);
      expectedOffset += characters(payload.content);
      if (payload.nextOffset !== null)
        expect(payload.nextOffset).toBe(expectedOffset);
      pieces.push(payload.content);
      return payload.nextOffset === null ? empty : request(payload.nextOffset);
    });
    await matchScanFindings(
      { before: [original], after: [finding("new")] },
      { codex: observed.codex },
    );
    const hash = (value: string) =>
      createHash("sha256").update(value).digest("hex");
    expect(pieces.length).toBeGreaterThan(1);
    expect(hash(pieces.join(""))).toBe(
      hash(JSON.stringify({ before: [original], after: [] })),
    );
  });

  test("prepares interleaved evidence selections only once", async () => {
    const ids = ["a", "b"] as const;
    type Id = (typeof ids)[number];
    const text = {
      a: "a".repeat(1 << 20) + "🙂",
      b: "b".repeat(1 << 20) + "🙂",
    };
    const reads = { a: 0, b: 0 };
    const pieces: Record<Id, string[]> = { a: [], b: [] };
    const offsets = new Map<Id, number | null>();
    const request = (id: Id, offset = 0) => ({
      ...empty,
      request: {
        kind: "evidence",
        beforeOccurrenceIds: [id],
        afterOccurrenceIds: [],
        offset,
      },
    });
    const before = ids.map((id) =>
      finding(id, {
        codeEvidence: [
          {
            get code() {
              reads[id] += 1;
              return text[id];
            },
          },
        ],
      }),
    );
    const observed = conversation((prompt, index) => {
      if (index === 0) return request("a");
      const page = data<EvidenceData>(prompt);
      const id = page.beforeOccurrenceIds[0] as Id;
      pieces[id].push(page.content);
      offsets.set(id, page.nextOffset);
      const other = id === "a" ? "b" : "a";
      if (!offsets.has(other)) return request(other);
      const next = offsets.get(other);
      if (next != null) return request(other, next);
      return page.nextOffset === null ? empty : request(id, page.nextOffset);
    });
    expect(
      await matchScanFindings(
        { before, after: [finding("new")] },
        { codex: observed.codex },
      ),
    ).toEqual(empty);
    expect(reads).toEqual({ a: 1, b: 1 });
    for (const id of ids) {
      expect(pieces[id].length).toBeGreaterThan(1);
      expect(JSON.parse(pieces[id].join(""))).toEqual({
        before: [finding(id, { codeEvidence: [{ code: text[id] }] })],
        after: [],
      });
    }
  });

  test.each(["overlap", "skip"] as const)(
    "rejects an evidence cursor that would %s the previous page",
    async (scenario) => {
      const request = (offset: number) => ({
        ...empty,
        request: {
          kind: "evidence",
          beforeOccurrenceIds: ["large"],
          afterOccurrenceIds: [],
          offset,
        },
      });
      const observed = conversation((prompt, index) => {
        if (index === 0) return request(0);
        const nextOffset = data<EvidenceData>(prompt).nextOffset;
        expect(nextOffset).not.toBeNull();
        return request(nextOffset! + (scenario === "overlap" ? -1 : 1));
      });
      await expect(
        matchScanFindings(
          {
            before: [finding("large", { codeEvidence: "x".repeat(1 << 21) })],
            after: [finding("new")],
          },
          { codex: observed.codex },
        ),
      ).rejects.toThrow("invalid evidence offset");
      expect(observed.prompts).toHaveLength(2);
    },
  );

  test.each([
    [
      "no findings",
      {
        kind: "evidence",
        beforeOccurrenceIds: [],
        afterOccurrenceIds: [],
        offset: 0,
      },
      "outside its findings",
    ],
    [
      "another finding",
      {
        kind: "evidence",
        beforeOccurrenceIds: ["outside"],
        afterOccurrenceIds: [],
        offset: 0,
      },
      "outside its findings",
    ],
    [
      "a nonzero first offset",
      {
        kind: "evidence",
        beforeOccurrenceIds: ["old"],
        afterOccurrenceIds: [],
        offset: 1,
      },
      "invalid evidence offset",
    ],
    [
      "an invalid offset",
      {
        kind: "evidence",
        beforeOccurrenceIds: ["old"],
        afterOccurrenceIds: [],
        offset: 999,
      },
      "invalid evidence offset",
    ],
    [
      "an unknown page",
      { kind: "catalogue", page: 9 },
      "unknown catalogue page",
    ],
  ])("rejects requests for %s", async (_label, request, message) => {
    const observed = conversation(() => ({ ...empty, request }));
    await expect(
      matchScanFindings(
        { before: [finding("old")], after: [finding("new")] },
        { codex: observed.codex },
      ),
    ).rejects.toThrow(message);
    expect(observed.prompts).toHaveLength(1);
  });

  test("stops a repeated request and honors cancellation between turns", async () => {
    const request = {
      kind: "evidence",
      beforeOccurrenceIds: ["old"],
      afterOccurrenceIds: [],
      offset: 0,
    };
    const repeated = conversation(() => ({ ...empty, request }));
    const input = { before: [finding("old")], after: [finding("new")] };
    await expect(
      matchScanFindings(input, { codex: repeated.codex }),
    ).rejects.toThrow("invalid evidence offset");
    expect(repeated.prompts).toHaveLength(2);

    const controller = new AbortController();
    const canceled = conversation(() => ({ ...empty, request }));
    await expect(
      matchScanFindings(input, {
        codex: canceled.codex,
        signal: controller.signal,
        onProgress(progress) {
          if (progress.phase === "evidence")
            controller.abort(new Error("Canceled"));
        },
      }),
    ).rejects.toThrow("Canceled");
    expect(canceled.prompts).toHaveLength(1);
  });

  test.each(["alternating", "reordered"] as const)(
    "stops %s requests for evidence already supplied",
    async (scenario) => {
      const request = (
        beforeOccurrenceIds: string[],
        afterOccurrenceIds: string[] = [],
      ) => ({
        ...empty,
        request: {
          kind: "evidence",
          beforeOccurrenceIds,
          afterOccurrenceIds,
          offset: 0,
        },
      });
      const requests =
        scenario === "alternating"
          ? [request(["a"]), request([], ["new"]), request(["a"])]
          : [request(["a", "b"]), request(["b", "a", "a"])];
      const observed = conversation(
        (_prompt, index) => requests[index % requests.length],
      );
      await expect(
        matchScanFindings(
          { before: [finding("a"), finding("b")], after: [finding("new")] },
          { codex: observed.codex },
        ),
      ).rejects.toThrow("invalid evidence offset");
      expect(observed.prompts).toHaveLength(requests.length);
    },
  );

  test("sends only new evidence from overlapping selections", async () => {
    const ids = ["a", "b", "c", "d"];
    const sentBefore: string[] = [];
    const sentAfter: string[] = [];
    const request = (beforeOccurrenceIds: string[]) => ({
      ...empty,
      request: {
        kind: "evidence",
        beforeOccurrenceIds,
        afterOccurrenceIds: ["new"],
        offset: 0,
      },
    });
    const observed = conversation((prompt, index) => {
      if (index > 0) {
        const payload = data<EvidenceData>(prompt);
        const evidence = JSON.parse(payload.content) as ScanComparisonInput;
        sentBefore.push(...evidence.before.map((item) => item.occurrenceId));
        sentAfter.push(...evidence.after.map((item) => item.occurrenceId));
        expect(payload.beforeOccurrenceIds).toEqual([ids[index - 1]!]);
        expect(payload.afterOccurrenceIds).toEqual(index === 1 ? ["new"] : []);
      }
      return request(index < ids.length ? ids.slice(0, index + 1) : ["b", "d"]);
    });
    await expect(
      matchScanFindings(
        { before: ids.map((id) => finding(id)), after: [finding("new")] },
        { codex: observed.codex },
      ),
    ).rejects.toThrow("without making progress");
    expect(sentBefore).toEqual(ids);
    expect(sentAfter).toEqual(["new"]);
    expect(observed.prompts).toHaveLength(ids.length + 1);
  });

  test("continues filtered evidence with either the original or returned IDs", async () => {
    const small = finding("small");
    const large = finding("large", {
      codeEvidence: "x".repeat(2 * (1 << 20)) + "🙂",
    });
    const pieces: string[] = [];
    const request = (beforeOccurrenceIds: string[], offset = 0) => ({
      ...empty,
      request: {
        kind: "evidence",
        beforeOccurrenceIds,
        afterOccurrenceIds: [],
        offset,
      },
    });
    const observed = conversation((prompt, index) => {
      if (index === 0) return request(["small"]);
      const payload = data<EvidenceData>(prompt);
      if (index === 1) {
        expect(JSON.parse(payload.content)).toEqual({
          before: [small],
          after: [],
        });
        return request(["small", "large"]);
      }
      expect(payload.beforeOccurrenceIds).toEqual(["large"]);
      pieces.push(payload.content);
      return payload.nextOffset === null
        ? empty
        : request(
            index === 2 ? ["small", "large"] : payload.beforeOccurrenceIds,
            payload.nextOffset,
          );
    });
    expect(
      await matchScanFindings(
        { before: [small, large], after: [finding("new")] },
        { codex: observed.codex },
      ),
    ).toEqual(empty);
    expect(pieces.length).toBeGreaterThan(2);
    expect(JSON.parse(pieces.join(""))).toEqual({ before: [large], after: [] });
    expect(observed.prompts).toHaveLength(pieces.length + 2);
  });

  test("does not resend catalogue pages already delivered", async () => {
    const observed = conversation((_prompt, index) => ({
      ...empty,
      request: { kind: "catalogue", page: index === 0 ? 1 : 0 },
    }));
    await expect(
      matchScanFindings(
        {
          before: [
            finding("a", { rootCause: "a".repeat(600_000) }),
            finding("b", { rootCause: "b".repeat(600_000) }),
          ],
          after: [finding("new")],
        },
        { codex: observed.codex },
      ),
    ).rejects.toThrow("without making progress");
    expect(observed.prompts).toHaveLength(2);
  });

  test("keeps related findings separate from confirmed and uncertain pairs", async () => {
    const input = {
      before: [finding("old")],
      after: [finding("same"), finding("different")],
    };
    const match = {
      beforeOccurrenceIds: ["old"],
      afterOccurrenceIds: ["same"],
      confidence: "high" as const,
      reason: "Same control.",
    };
    const related = {
      beforeOccurrenceId: "old",
      afterOccurrenceId: "different",
      reason: "Independent controls in the same component.",
    };
    const response = { matches: [match], uncertain: [], related: [related] };
    expect(
      await matchScanFindings(input, {
        codex: conversation(() => response).codex,
      }),
    ).toEqual(response);
    for (const invalid of [
      { ...response, related: [related, related] },
      { ...response, related: [{ ...related, afterOccurrenceId: "same" }] },
      { ...empty, uncertain: [related], related: [related] },
      { ...empty, related: [{ ...related, beforeOccurrenceId: "outside" }] },
    ]) {
      await expect(
        matchScanFindings(input, { codex: conversation(() => invalid).codex }),
      ).rejects.toThrow("invalid related pair");
    }
  });

  test("allows related pairs across different confirmed groups", async () => {
    const input = {
      before: ["a1", "a2", "b", "unmatched-before"].map((id) => finding(id)),
      after: ["x1", "x2", "y", "unmatched-after"].map((id) => finding(id)),
    };
    const pair = (beforeOccurrenceId: string, afterOccurrenceId: string) => ({
      beforeOccurrenceId,
      afterOccurrenceId,
      reason: "Separate synthetic controls.",
    });
    const response: ScanComparisonResult = {
      matches: [
        {
          beforeOccurrenceIds: ["a1", "a2"],
          afterOccurrenceIds: ["x1", "x2"],
          confidence: "high",
          reason: "First synthetic control.",
        },
        {
          beforeOccurrenceIds: ["b"],
          afterOccurrenceIds: ["y"],
          confidence: "high",
          reason: "Second synthetic control.",
        },
      ],
      uncertain: [],
      related: [pair("a2", "y"), pair("unmatched-before", "unmatched-after")],
    };
    expect(
      await matchScanFindings(input, {
        codex: conversation(() => response).codex,
      }),
    ).toEqual(response);
    for (const related of [pair("a2", "x2"), pair("b", "y")]) {
      await expect(
        matchScanFindings(input, {
          codex: conversation(() => ({ ...response, related: [related] }))
            .codex,
        }),
      ).rejects.toThrow("invalid related pair");
    }
  });
});

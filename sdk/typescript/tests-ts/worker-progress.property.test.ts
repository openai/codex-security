import { describe, expect, test } from "bun:test";
import fc from "fast-check";
import {
  scanProgressUpdatesFromEvent,
  workerStatusFromEvent,
} from "../src/worker-progress.js";
import { propertyOptions } from "./support/property.js";

const count = fc.integer({ min: 0, max: Number.MAX_SAFE_INTEGER });
const countInput = fc.oneof(
  count,
  fc.constantFrom(-1, 0.5, Number.MAX_SAFE_INTEGER + 1, null, "1"),
);
const phases = [
  "preflight",
  "threat_model",
  "discovery",
  "validation",
  "attack_path",
  "reporting",
] as const;
const phase = fc.constantFrom(...phases);

function message(text: string) {
  return {
    type: "item.completed",
    item: { type: "agent_message", text },
  };
}

function validCounts(completed: unknown, total: unknown): boolean {
  return (
    typeof completed === "number" &&
    typeof total === "number" &&
    Number.isSafeInteger(completed) &&
    Number.isSafeInteger(total) &&
    completed >= 0 &&
    completed <= total
  );
}

describe("progress invariants", () => {
  test("accepts exactly the valid progress count pairs", () => {
    fc.assert(
      fc.property(
        phase,
        countInput,
        countInput,
        (phase, filesCompleted, filesTotal) => {
          const progress = { phase, filesCompleted, filesTotal };
          const marker = `CODEX_SECURITY_SCAN_PROGRESS ${JSON.stringify(progress)}`;
          const expected = validCounts(filesCompleted, filesTotal)
            ? [
                {
                  phase,
                  filesCompleted: Number(filesCompleted),
                  filesTotal: Number(filesTotal),
                },
              ]
            : [];
          expect(scanProgressUpdatesFromEvent(message(marker))).toEqual(
            expected,
          );
          expect(
            scanProgressUpdatesFromEvent({
              type: "item.completed",
              item: { type: "command_execution", aggregated_output: marker },
            }),
          ).toEqual(expected);
          expect(
            scanProgressUpdatesFromEvent(
              message(`\`\`\`json\n${marker}\n\`\`\``),
            ),
          ).toEqual([]);
        },
      ),
      propertyOptions,
    );
  });

  test("never reports more started workers than were planned", () => {
    fc.assert(
      fc.property(
        fc.constantFrom("ranking", "file_review", "validation", "attack_path"),
        countInput,
        countInput,
        (phase, started, planned) => {
          const payload = { phase, planned, started };
          const marker = `CODEX_SECURITY_WORKER_STATUS ${JSON.stringify(payload)}`;
          expect(workerStatusFromEvent(message(marker))).toEqual(
            validCounts(started, planned)
              ? {
                  kind: "dispatch",
                  phase,
                  started: Number(started),
                  planned: Number(planned),
                }
              : null,
          );
          expect(
            workerStatusFromEvent(message(`${marker}\n${marker}`)),
          ).toBeNull();
        },
      ),
      propertyOptions,
    );
  });

  test("preserves zero, complete, and maximum-safe counts", () => {
    fc.assert(
      fc.property(count, (total) => {
        for (const completed of [0, total]) {
          for (const phase of phases) {
            const progress = {
              phase,
              filesCompleted: completed,
              filesTotal: total,
            };
            expect(
              scanProgressUpdatesFromEvent(
                message(
                  `CODEX_SECURITY_SCAN_PROGRESS ${JSON.stringify(progress)}`,
                ),
              ),
            ).toEqual([progress]);
          }
          const dispatch = {
            phase: "ranking" as const,
            planned: total,
            started: completed,
          };
          expect(
            workerStatusFromEvent(
              message(
                `CODEX_SECURITY_WORKER_STATUS ${JSON.stringify(dispatch)}`,
              ),
            ),
          ).toEqual({ kind: "dispatch", ...dispatch });
        }
      }),
      {
        ...propertyOptions,
        examples: [[0], [Number.MAX_SAFE_INTEGER]],
      },
    );
  });
});

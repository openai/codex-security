import { resolve } from "node:path";
import { describe, expect, test } from "bun:test";
import { main } from "../src/cli.js";
import type { BulkScanPrompt } from "../src/bulk-scan-discovery.js";
import type { JsonObject } from "../src/config.js";
import {
  DependencyFindings,
  type DependencyAssessmentDetails,
  type DependencyFindingsOptions,
  type DependencyReport,
  type ImportedDependencyFinding,
} from "../src/dependency-findings.js";
import { capture, dependencies, FakeSignals } from "./cli-fixtures.js";

const repository = resolve("dependency-cli-repository");

function report(id = "report-1"): DependencyReport {
  return {
    id,
    targetPath: repository,
    targetRevision: "revision-1",
    reportName: `${id}.csv`,
    vendor: "endor",
    createdAt: "2026-09-01T00:00:00Z",
    findingCount: 1,
    warnings: [],
    reportDigest: `digest-${id}`,
  };
}

function finding(index = 1): ImportedDependencyFinding {
  return {
    id: `finding-${index}`,
    reportId: "report-1",
    title: `Affected parser ${index}`,
    sourceId: `source-${index}`,
    originalSeverity: "high",
    kind: "vulnerability",
    package: { ecosystem: "npm", name: `parser-${index}`, version: "1.0.0" },
    advisoryIds: [`CVE-2026-${1000 + index}`],
    dependencyPaths: [],
    locations: [],
    fix: null,
    evidence: null,
    inputWarnings: [],
    assessment: null,
  };
}

function completed(): DependencyAssessmentDetails {
  const selected = finding();
  const result = {
    findingId: selected.id,
    assessmentId: "assessment-1",
    verdict: "not_applicable" as const,
    summary: "The application uses an unaffected parser version.",
    packageVersion: "2.0.0",
    resolution: null,
    codeEvidence: [],
    applicability:
      "The resolved package version is outside the affected range.",
    unknowns: [],
    targetRevision: "revision-1",
    createdAt: "2026-09-01T00:00:00Z",
  };
  return {
    assessment: {
      id: "assessment-1",
      reportId: "report-1",
      findingIds: [selected.id],
      targetPath: repository,
      targetRevision: "revision-1",
      state: "complete",
    },
    report: report(),
    findings: [{ ...selected, assessment: result }],
    results: [result],
  };
}

function response(value: object): JsonObject {
  return value as JsonObject;
}

type Prompt = Pick<
  BulkScanPrompt,
  "isInteractive" | "select" | "checkbox" | "input"
>;

function unexpectedPrompt(): Prompt {
  return {
    isInteractive: () => true,
    select: async () => {
      throw new Error("Unexpected report prompt");
    },
    input: async () => {
      throw new Error("Unexpected filter prompt");
    },
    checkbox: async () => {
      throw new Error("Unexpected finding prompt");
    },
  };
}

function fixture(
  options: {
    workbench?: (args: readonly string[]) => JsonObject;
    runSkill?: (signal: AbortSignal | undefined) => Promise<string>;
  } = {},
) {
  const signals = new FakeSignals();
  const calls: (readonly string[])[] = [];
  const timers: NodeJS.Timeout[] = [];
  const cleared: NodeJS.Timeout[] = [];
  const deps = dependencies({ currentDirectory: repository, signals });
  deps.dependencyFindingsPrompt = unexpectedPrompt();
  deps.setInterval = () => {
    const timer = {} as NodeJS.Timeout;
    timers.push(timer);
    return timer;
  };
  deps.clearInterval = (timer) => {
    cleared.push(timer);
  };
  deps.createDependencyFindings = (configuration: DependencyFindingsOptions) =>
    new DependencyFindings(configuration, {
      currentDirectory: () => repository,
      workbench: async (args) => {
        calls.push(args);
        if (options.workbench) return options.workbench(args);
        if (args[0] === "start-dependency-assessment") {
          const result = completed();
          return response({
            ...result,
            assessment: { ...result.assessment, state: "pending" },
          });
        }
        if (args[0] === "get-dependency-assessment")
          return response(completed());
        throw new Error(`Unexpected workbench command: ${args[0]}`);
      },
      runSkill: async () =>
        options.runSkill ? options.runSkill(configuration.signal) : "Complete",
    });
  return { deps, signals, calls, timers, cleared };
}

function option(args: readonly string[], flag: string): string | undefined {
  const index = args.indexOf(flag);
  return index < 0 ? undefined : args[index + 1];
}

describe("dependency findings terminal workflow", () => {
  test("show lets the user choose reports beyond the first page in the current repository", async () => {
    const reports = Array.from({ length: 101 }, (_, index) =>
      report(`report-${index + 1}`),
    );
    const selected = reports[100]!;
    const { deps, calls } = fixture({
      workbench: (args) => {
        if (args[0] === "list-dependency-reports") {
          expect(option(args, "--target-path")).toBe(repository);
          expect(option(args, "--limit")).toBe("100");
          const offset = Number(option(args, "--offset") ?? 0);
          return response({
            reports: reports.slice(offset, offset + 100),
            nextOffset: offset === 0 ? 100 : null,
          });
        }
        expect(args[0]).toBe("get-dependency-report");
        expect(option(args, "--report-id")).toBe(selected.id);
        return response({
          report: selected,
          findings: [finding()],
          total: 1,
          nextOffset: null,
        });
      },
    });
    let prompts = 0;
    deps.dependencyFindingsPrompt!.select = async (
      _question,
      choices,
      _presentation,
      signal,
    ) => {
      prompts++;
      expect(signal).toBeInstanceOf(AbortSignal);
      expect(choices.map(({ value }) => String(value))).toEqual(
        reports.map(({ id }) => id),
      );
      expect(choices[100]!.label).toContain(selected.reportName);
      return choices[100]!.value;
    };
    const stdout = capture(true);
    const stderr = capture(true);
    expect(
      await main(
        ["dependency-findings", "show"],
        stdout.stream,
        stderr.stream,
        deps,
      ),
    ).toBe(0);
    expect(prompts).toBe(1);
    expect(
      calls.filter(([command]) => command === "list-dependency-reports"),
    ).toHaveLength(2);
    expect(stdout.text()).toContain(selected.reportName);
    expect(stdout.text()).toContain("Affected parser 1");
    expect(stdout.text()).not.toContain('"report":');
  });

  test("assessment loads every finding page, retries an unmatched filter, and assesses only checked findings", async () => {
    const findings = Array.from({ length: 101 }, (_, index) =>
      finding(index + 1),
    );
    const saved = report();
    saved.findingCount = findings.length;
    const result = completed();
    const { deps, calls } = fixture({
      workbench: (args) => {
        if (args[0] === "list-dependency-reports")
          return response({ reports: [saved], nextOffset: null });
        if (args[0] === "get-dependency-report") {
          expect(option(args, "--limit")).toBe("100");
          const offset = Number(option(args, "--offset") ?? 0);
          return response({
            report: saved,
            findings: findings.slice(offset, offset + 100),
            total: findings.length,
            nextOffset: offset === 0 ? 100 : null,
          });
        }
        return response(result);
      },
    });
    let reportPrompts = 0;
    let filterPrompts = 0;
    let findingPrompts = 0;
    deps.dependencyFindingsPrompt!.select = async (_question, choices) => {
      reportPrompts++;
      return choices[0]!.value;
    };
    deps.dependencyFindingsPrompt!.input = async () => {
      filterPrompts++;
      expect(filterPrompts).toBeLessThanOrEqual(2);
      return filterPrompts === 1
        ? "no-matching-package"
        : "AFFECTED PARSER 101";
    };
    deps.dependencyFindingsPrompt!.checkbox = async (
      _question,
      choices,
      presentation,
      signal,
    ) => {
      findingPrompts++;
      expect(signal).toBeInstanceOf(AbortSignal);
      expect(presentation?.required).toBe(true);
      expect(choices.map(({ value }) => String(value))).toEqual([
        "finding-101",
      ]);
      expect(choices[0]!.label).toContain("parser-101");
      expect(choices[0]!.label.toLowerCase()).toContain("high");
      expect(choices[0]!.label.toLowerCase()).toMatch(/pending|not assessed/);
      expect(choices[0]!.description).toContain("Affected parser 101");
      return [choices[0]!.value];
    };
    const stdout = capture(true);
    expect(
      await main(
        ["dependency-findings", "assess"],
        stdout.stream,
        capture(true).stream,
        deps,
      ),
    ).toBe(0);
    expect(reportPrompts).toBe(1);
    expect(filterPrompts).toBe(2);
    expect(findingPrompts).toBe(1);
    expect(
      calls.filter(([command]) => command === "get-dependency-report"),
    ).toHaveLength(2);
    expect(
      calls.find(([command]) => command === "start-dependency-assessment"),
    ).toEqual([
      "start-dependency-assessment",
      "--report-id",
      "report-1",
      "--finding-id",
      "finding-101",
    ]);
    expect(stdout.text()).toContain(result.results![0]!.summary);
  });

  test("a selection above the assessment limit can be corrected before starting work", async () => {
    const findings = Array.from({ length: 101 }, (_, index) =>
      finding(index + 1),
    );
    let selections = 0;
    const { deps, calls } = fixture({
      workbench: (args) => {
        if (args[0] === "get-dependency-report") {
          const offset = Number(option(args, "--offset") ?? 0);
          return response({
            report: report(),
            findings: findings.slice(offset, offset + 100),
            total: findings.length,
            nextOffset: offset === 0 ? 100 : null,
          });
        }
        expect(selections).toBe(2);
        return response(completed());
      },
    });
    deps.dependencyFindingsPrompt!.input = async () => "";
    deps.dependencyFindingsPrompt!.checkbox = async (_question, choices) => {
      selections++;
      return (selections === 1 ? choices : choices.slice(-1)).map(
        ({ value }) => value,
      );
    };
    const stderr = capture(true);
    expect(
      await main(
        ["dependency-findings", "assess", "report-1"],
        capture(true).stream,
        stderr.stream,
        deps,
      ),
    ).toBe(0);
    expect(selections).toBe(2);
    expect(stderr.text()).toContain("100");
    expect(
      calls.filter(([command]) => command === "start-dependency-assessment"),
    ).toEqual([
      [
        "start-dependency-assessment",
        "--report-id",
        "report-1",
        "--finding-id",
        "finding-101",
      ],
    ]);
  });

  test("missing selections fail without prompts or workbench calls outside default interactive output", async () => {
    const modes = [
      { tty: false, interactive: true, output: [] },
      { tty: true, interactive: false, output: [] },
      { tty: true, interactive: true, output: ["--format", "json"] },
      { tty: true, interactive: true, output: ["--format", "toon"] },
    ];
    for (const mode of modes) {
      for (const args of [["show"], ["assess"], ["assess", "report-1"]]) {
        const { deps, calls, timers } = fixture();
        deps.dependencyFindingsPrompt!.isInteractive = () => mode.interactive;
        const stderr = capture(mode.tty);
        expect(
          await main(
            ["dependency-findings", ...args, ...mode.output],
            capture(mode.tty).stream,
            stderr.stream,
            deps,
          ),
        ).toBe(2);
        expect(stderr.text()).toMatch(
          args.length === 2 ? /--finding/ : /report.?id/i,
        );
        expect(stderr.text()).not.toContain("Unexpected");
        expect(calls).toEqual([]);
        expect(timers).toEqual([]);
      }
    }
  });

  test("explicit JSON assessment retains the full result without prompts or terminal progress", async () => {
    const { deps, calls, timers } = fixture();
    const stdout = capture(true);
    const stderr = capture(true);
    expect(
      await main(
        [
          "dependency-findings",
          "assess",
          "report-1",
          "--finding",
          "finding-1",
          "--format",
          "json",
        ],
        stdout.stream,
        stderr.stream,
        deps,
      ),
    ).toBe(0);
    expect(JSON.parse(stdout.text())).toEqual(completed());
    expect(stderr.text()).toBe("");
    expect(timers).toEqual([]);
    expect(calls.map(([command]) => command)).toEqual([
      "start-dependency-assessment",
      "get-dependency-assessment",
    ]);
  });

  test("interactive assessment restores progress and signal listeners after success, failure, and cancellation", async () => {
    for (const outcome of ["success", "failure", "cancel"] as const) {
      const state = fixture({
        runSkill: async (signal) => {
          expect(state.timers).toHaveLength(1);
          if (outcome === "failure") throw new Error("Assessment failed");
          if (outcome === "cancel") {
            state.signals.emit("SIGINT");
            signal!.throwIfAborted();
          }
          return "Complete";
        },
      });
      const stderr = capture(true);
      expect(
        await main(
          [
            "dependency-findings",
            "assess",
            "report-1",
            "--finding",
            "finding-1",
          ],
          capture(true).stream,
          stderr.stream,
          state.deps,
        ),
      ).toBe(outcome === "success" ? 0 : outcome === "cancel" ? 130 : 2);
      expect(state.timers).toHaveLength(1);
      expect(state.cleared).toEqual(state.timers);
      expect(
        [...state.signals.listeners.values()].every(
          (listeners) => listeners.size === 0,
        ),
      ).toBe(true);
      if (outcome === "failure")
        expect(stderr.text()).toContain("Assessment failed");
    }
  });

  test("Ctrl+C in any selection prompt exits quietly without starting an assessment", async () => {
    for (const phase of ["select", "input", "checkbox"] as const) {
      const interrupted = new Error("User force closed the prompt");
      interrupted.name = "ExitPromptError";
      const { deps, calls, signals, timers } = fixture({
        workbench: (args) => {
          if (args[0] === "list-dependency-reports") {
            return response({ reports: [report()], nextOffset: null });
          }
          if (args[0] === "get-dependency-report") {
            return response({
              report: report(),
              findings: [finding()],
              total: 1,
              nextOffset: null,
            });
          }
          throw new Error(`Unexpected workbench command: ${args[0]}`);
        },
      });
      deps.dependencyFindingsPrompt!.select = async (_question, choices) => {
        if (phase === "select") throw interrupted;
        return choices[0]!.value;
      };
      deps.dependencyFindingsPrompt!.input = async () => {
        if (phase === "input") throw interrupted;
        return "";
      };
      deps.dependencyFindingsPrompt!.checkbox = async () => {
        throw interrupted;
      };
      const stdout = capture(true);
      const stderr = capture(true);
      expect(
        await main(
          ["dependency-findings", "assess"],
          stdout.stream,
          stderr.stream,
          deps,
        ),
      ).toBe(130);
      expect(
        calls.some(([command]) => command === "start-dependency-assessment"),
      ).toBe(false);
      expect(stdout.text()).toBe("");
      expect(stderr.text()).toBe("");
      expect(timers).toEqual([]);
      expect(
        [...signals.listeners.values()].every(
          (listeners) => listeners.size === 0,
        ),
      ).toBe(true);
    }
  });
});

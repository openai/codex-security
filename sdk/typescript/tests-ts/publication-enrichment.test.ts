import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { homedir, tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, test } from "bun:test";
import {
  enrichPublicationIssues,
  parsePublicationEnrichment,
  publicationEnrichmentEnvironment,
  runPublicationEnrichmentCodex,
} from "../src/publication-enrichment.js";
import type { LinearPublicationCatalogLabel } from "../src/linear.js";
import type { Finding } from "../src/models.js";
import type { PreparedPublicationIssue } from "../src/publication.js";

const temporaryDirectories: string[] = [];
const LABELS = [
  { id: "label-exploit", name: "Exploitable" },
  { id: "label-internet", name: "Internet exposed" },
] as const;
const GROUPED_LABELS: readonly LinearPublicationCatalogLabel[] = [
  {
    id: "label-customer",
    name: "Customer data",
    groupId: "impact",
    groupName: "Impact",
  },
  {
    id: "label-internal",
    name: "Internal data",
    groupId: "impact",
    groupName: "Impact",
  },
];

afterEach(async () => {
  await Promise.all(
    temporaryDirectories
      .splice(0)
      .map((directory) => rm(directory, { recursive: true, force: true })),
  );
});

function issues(): PreparedPublicationIssue[] {
  return [
    {
      findingId: "finding-one",
      occurrenceId: "occurrence-one",
      title: "Rendered title must not be policy input",
      description: "Rendered description must not be policy input",
    },
    {
      findingId: "finding-two",
      occurrenceId: "occurrence-two",
      title: "Second rendered title",
      description: "Second rendered description",
    },
  ];
}

function findings(marker = "canonical-marker"): Finding[] {
  return issues().map(
    ({ findingId, occurrenceId }, index) =>
      ({
        findingId,
        occurrenceId,
        title: `Canonical finding ${index + 1}`,
        summary: index === 0 ? marker : "No explicit policy applies.",
        severity: { level: index === 0 ? "critical" : "informational" },
      }) as unknown as Finding,
  );
}

function response(
  values: Array<{
    findingId: string;
    priority: "none" | "urgent" | "high" | "medium" | "low";
    labelIds: string[];
    error?: string;
  }>,
): string {
  return JSON.stringify({
    findings: values.map((value) => ({
      ...value,
      error: value.error ?? null,
    })),
  });
}

async function policyFile(
  text = "Critical findings are urgent.",
): Promise<string> {
  const directory = await mkdtemp(
    join(tmpdir(), "codex-security-publication-policy-test-"),
  );
  temporaryDirectories.push(directory);
  const path = join(directory, "policy.md");
  await writeFile(path, text);
  return path;
}

describe("publication knowledge-base enrichment", () => {
  test("runs one ephemeral read-only structured-output Codex turn", async () => {
    const directory = await mkdtemp(
      join(tmpdir(), "codex-security-publication-runner-test-"),
    );
    temporaryDirectories.push(directory);
    const invocations: { args: readonly string[]; input?: string }[] = [];
    const finalResponse = response(
      issues().map(({ findingId }) => ({
        findingId,
        priority: "none",
        labelIds: [],
      })),
    );

    const result = await runPublicationEnrichmentCodex(
      { command: "codex" },
      { OPENAI_API_KEY: "codex-key" },
      directory,
      "publication prompt",
      undefined,
      async (_command, args, _environment, input) => {
        invocations.push({ args, input });
        const output = args.indexOf("--output-last-message");
        await writeFile(args[output + 1]!, finalResponse);
        return {
          success: true,
          exitCode: 0,
          stdout: "",
          stderr: "",
        };
      },
    );

    expect(result.finalResponse).toBe(finalResponse);
    expect(invocations).toHaveLength(1);
    expect(invocations[0]!.input).toBe("publication prompt");
    const args = invocations[0]!.args;
    expect(args[0]).toBe("exec");
    expect(args).toContain("--ignore-user-config");
    expect(args).toContain("--ephemeral");
    expect(args[args.indexOf("--sandbox") + 1]).toBe("read-only");
    expect(args).toContain("--output-schema");
    expect(args).toContain("--output-last-message");
    expect(args).toContain('approval_policy="never"');
    expect(args).toContain("sandbox_workspace_write.network_access=false");
    expect(args).toContain('web_search="disabled"');
    expect(args).toContain(
      'responses_api_metadata.codex_security_surface="sdk"',
    );
    expect(args).not.toContain("--model");
  });

  test("uses canonical findings and applies policy-selected Linear metadata", async () => {
    const capture: { prompt?: string } = {};
    const key = "lin_api_SYNTHETIC_SECRET";
    const enriched = await enrichPublicationIssues(
      issues(),
      LABELS,
      [await policyFile("P0 findings are urgent and internet exposed.")],
      {
        findings: findings("canonical-policy-input"),
        environment: {
          CODEX_SECURITY_SCAN_ID: "synthetic-parent-scan",
          CODEX_SECURITY_LINEAR_API_KEY: key,
        },
        async runCodex(_command, _environment, _workingDirectory, prompt) {
          capture.prompt = prompt;
          return {
            finalResponse: response([
              {
                findingId: "finding-one",
                priority: "urgent",
                labelIds: ["label-exploit", "label-internet"],
              },
              {
                findingId: "finding-two",
                priority: "none",
                labelIds: [],
              },
            ]),
          };
        },
      },
    );

    expect(enriched[0]).toMatchObject({
      priority: 1,
      labels: [LABELS[0], LABELS[1]],
    });
    expect(enriched[1]).not.toHaveProperty("priority");
    expect(enriched[1]).not.toHaveProperty("labels");
    expect(capture.prompt).toContain("canonical-policy-input");
    expect(capture.prompt).not.toContain(
      "Rendered title must not be policy input",
    );
    expect(capture.prompt).not.toContain(
      "Rendered description must not be policy input",
    );
    expect(capture.prompt).not.toContain(key);
    const data = JSON.parse(capture.prompt!.split("\n").at(-1)!) as {
      findings: Finding[];
    };
    expect(data.findings).toEqual(findings("canonical-policy-input"));
  });

  test.each([
    ["urgent", 1],
    ["high", 2],
    ["medium", 3],
    ["low", 4],
  ] as const)("maps %s to Linear priority %s", (priority, expected) => {
    const source = issues().slice(0, 1);
    expect(
      parsePublicationEnrichment(
        source,
        LABELS,
        response([
          {
            findingId: source[0]!.findingId,
            priority,
            labelIds: [],
          },
        ]),
      )[0]!.priority,
    ).toBe(expected);
  });

  test("leaves metadata unset when no explicit policy rule applies", () => {
    const source = issues().map((issue) => ({
      ...issue,
      priority: 2 as const,
      labels: [{ ...LABELS[0] }],
    }));
    const enriched = parsePublicationEnrichment(
      source,
      LABELS,
      response(
        source.map(({ findingId }) => ({
          findingId,
          priority: "none",
          labelIds: [],
        })),
      ),
    );

    expect(enriched.every((issue) => issue.priority === undefined)).toBe(true);
    expect(enriched.every((issue) => issue.labels === undefined)).toBe(true);
  });

  test.each([
    ["malformed output", "not-json", /invalid JSON/u, LABELS],
    [
      "invalid priority",
      JSON.stringify({
        findings: issues().map(({ findingId }) => ({
          findingId,
          priority: "critical",
          labelIds: [],
          error: null,
        })),
      }),
      /invalid result/u,
      LABELS,
    ],
    [
      "missing finding",
      response([{ findingId: "finding-one", priority: "high", labelIds: [] }]),
      /did not classify every finding/u,
      LABELS,
    ],
    [
      "duplicate finding",
      response([
        { findingId: "finding-one", priority: "high", labelIds: [] },
        { findingId: "finding-one", priority: "low", labelIds: [] },
      ]),
      /repeated a finding/u,
      LABELS,
    ],
    [
      "unknown finding",
      response([
        { findingId: "finding-one", priority: "high", labelIds: [] },
        { findingId: "invented", priority: "low", labelIds: [] },
      ]),
      /unknown finding/u,
      LABELS,
    ],
    [
      "unknown label",
      response([
        {
          findingId: "finding-one",
          priority: "high",
          labelIds: ["invented"],
        },
        { findingId: "finding-two", priority: "none", labelIds: [] },
      ]),
      /unavailable Linear label/u,
      LABELS,
    ],
    [
      "duplicate label",
      response([
        {
          findingId: "finding-one",
          priority: "high",
          labelIds: ["label-exploit", "label-exploit"],
        },
        { findingId: "finding-two", priority: "none", labelIds: [] },
      ]),
      /repeated a Linear label/u,
      LABELS,
    ],
    [
      "mutually exclusive labels",
      response([
        {
          findingId: "finding-one",
          priority: "high",
          labelIds: ["label-customer", "label-internal"],
        },
        { findingId: "finding-two", priority: "none", labelIds: [] },
      ]),
      /mutually exclusive Linear labels/u,
      GROUPED_LABELS,
    ],
    [
      "policy conflict",
      response([
        {
          findingId: "finding-one",
          priority: "none",
          labelIds: [],
          error: "Two explicit rules conflict.",
        },
        { findingId: "finding-two", priority: "none", labelIds: [] },
      ]),
      /could not classify finding finding-one/u,
      LABELS,
    ],
  ] as const)("rejects %s", (_name, output, expected, labels) => {
    expect(() => parsePublicationEnrichment(issues(), labels, output)).toThrow(
      expected,
    );
  });

  test("rejects missing or duplicate canonical findings before extraction", async () => {
    let prepared = false;
    const prepareKnowledgeBase = async (): Promise<never> => {
      prepared = true;
      throw new Error("must not extract");
    };

    await expect(
      enrichPublicationIssues(issues(), LABELS, ["policy.md"], {
        findings: findings().slice(0, 1),
        prepareKnowledgeBase,
      }),
    ).rejects.toThrow(/missing a canonical finding/u);
    await expect(
      enrichPublicationIssues(issues(), LABELS, ["policy.md"], {
        findings: [findings()[0]!, findings()[0]!, findings()[1]!],
        prepareKnowledgeBase,
      }),
    ).rejects.toThrow(/duplicate canonical finding/u);
    expect(prepared).toBe(false);
  });

  test("cleans extracted policy data after cancellation", async () => {
    const directory = await mkdtemp(
      join(tmpdir(), "codex-security-publication-cancel-test-"),
    );
    temporaryDirectories.push(directory);
    await writeFile(join(directory, "0-policy.md.txt"), "Synthetic policy");
    const controller = new AbortController();
    let cleaned = false;

    await expect(
      enrichPublicationIssues(issues(), LABELS, ["C:\\policy.md"], {
        findings: findings(),
        environment: { CODEX_SECURITY_SCAN_ID: "synthetic-parent-scan" },
        signal: controller.signal,
        prepareKnowledgeBase: async () => ({
          path: directory,
          sources: ["C:\\policy.md"],
          async cleanup() {
            cleaned = true;
          },
        }),
        async runCodex() {
          controller.abort("synthetic cancellation");
          throw controller.signal.reason;
        },
      }),
    ).rejects.toBe("synthetic cancellation");
    expect(cleaned).toBe(true);
  });

  test("surfaces cleanup failures without hiding enrichment failures", async () => {
    for (const primaryFailure of [false, true]) {
      const directory = await mkdtemp(
        join(tmpdir(), "codex-security-publication-cleanup-test-"),
      );
      temporaryDirectories.push(directory);
      await writeFile(join(directory, "0-policy.md.txt"), "Policy");
      const error = await enrichPublicationIssues(
        issues(),
        LABELS,
        ["policy.md"],
        {
          findings: findings(),
          environment: { CODEX_SECURITY_SCAN_ID: "synthetic-parent-scan" },
          prepareKnowledgeBase: async () => ({
            path: directory,
            sources: [],
            cleanup: async () => {
              throw new Error("cleanup failed");
            },
          }),
          async runCodex() {
            if (primaryFailure) throw new Error("enrichment failed");
            return {
              finalResponse: response(
                issues().map(({ findingId }) => ({
                  findingId,
                  priority: "none",
                  labelIds: [],
                })),
              ),
            };
          },
        },
      ).catch((caught: unknown) => caught);

      if (primaryFailure) {
        expect(error).toBeInstanceOf(AggregateError);
        expect((error as AggregateError).message).toBe("enrichment failed");
        expect((error as AggregateError).errors).toHaveLength(2);
      } else {
        expect(error).toBeInstanceOf(Error);
        expect((error as Error).message).toContain("cleanup failed");
      }
    }
  });

  test("sanitizes Linear credentials and resolves configured Codex homes", async () => {
    expect(
      await publicationEnrichmentEnvironment({
        CODEX_SECURITY_SCAN_ID: "synthetic-parent-scan",
        CODEX_SECURITY_LINEAR_API_KEY: "publication-key",
        linear_api_key: "generic-key",
        LINEAR_ACCESS_TOKEN: "access-token",
        OPENAI_API_KEY: "codex-key",
      }),
    ).toEqual({
      CODEX_SECURITY_SCAN_ID: "synthetic-parent-scan",
      OPENAI_API_KEY: "codex-key",
    });
    expect(
      (
        await publicationEnrichmentEnvironment({
          CODEX_HOME: "~/.codex-publication-test",
        })
      )["CODEX_HOME"],
    ).toBe(join(homedir(), ".codex-publication-test"));
    expect(
      await publicationEnrichmentEnvironment({ codex_home: "" }),
    ).not.toHaveProperty("CODEX_HOME");
  });
});

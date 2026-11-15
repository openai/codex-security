import { describe, expect, test } from "bun:test";
import { writeFile } from "node:fs/promises";
import { join } from "node:path";
import type {
  DependencyAssessment,
  DependencyUse,
} from "../src/dependency-reachability.js";
import { readDependencyCheckOutput } from "../src/dependency-reachability.js";
import {
  readDependencyReportCode,
  renderDependencyReport,
} from "../src/dependency-report-renderer.js";
import { scopedTemporaryDirectory } from "./support/temporary-directories.js";

const assessment = {
  status: "potentially_exploitable",
  uses: [
    {
      location: "Example worker",
      component: "example-decoder",
      version: "2.3.4",
      verdict: "potentially_exploitable",
      deployment: "configured",
      reason: "The selected path opens the configured input.",
      evidence: [
        {
          path: "src/worker.ts",
          startLine: 17,
          endLine: 24,
          supports: ["affected_copy", "affected_use"],
        },
      ],
      observations: [
        {
          server: "fixture-inventory",
          record: "fixture-record-712",
          supports: ["running"],
        },
      ],
    },
  ],
  limitations: ["The caller identity is unresolved."],
} satisfies DependencyAssessment;

const check = {
  ...assessment,
  advisories: ["GHSA-aaaa-bbbb-cccc"],
  usage: null,
};
const cveReport = { ...check, cve: "CVE-2099-12345" };

const reportedSource = "POST /upload";
const reportedPath = "src/route.ts:17 → decodeFrame()";
const routeEvidence = {
  path: "src/route.ts",
  startLine: 15,
  endLine: 19,
  supports: ["affected_use"],
} satisfies DependencyUse["evidence"][number];
const walkedUse = {
  ...assessment.uses[0]!,
  location: `${reportedSource} → ${reportedPath}`,
  evidence: [
    routeEvidence,
    {
      path: "package-lock.json",
      startLine: 7,
      endLine: 7,
      supports: ["affected_copy"],
    },
  ],
} satisfies DependencyUse;
const walkedReport = { ...cveReport, uses: [walkedUse] };
const productionMeasurement = {
  useId: "use-1-1",
  location: walkedUse.location,
  step: "sink",
  environment: "prod",
  count: 0,
  from: "2026-01-01T00:00:00Z",
  until: "2026-01-01T01:00:00Z",
  target: "synthetic target",
  record: "synthetic receipt",
} as const;

function visibleText(html: string): string {
  return html
    .replace(/<(style|script)\b[^>]*>[\s\S]*?<\/\1>/giu, "")
    .replace(/<[^>]*>/gu, " ")
    .replace(/\s+/gu, " ")
    .trim();
}

function selectElements(
  html: string,
  selector: string,
  attributes: string[] = [],
) {
  const elements: Array<{
    text: string;
    attributes: Record<string, string | null>;
  }> = [];
  new HTMLRewriter()
    .on(selector, {
      element(node) {
        elements.push({
          text: "",
          attributes: Object.fromEntries(
            attributes.map((name) => [name, node.getAttribute(name)]),
          ),
        });
      },
      text(node) {
        elements.at(-1)!.text += ` ${node.text}`;
      },
    })
    .transform(html);
  return elements.map((node) => ({
    ...node,
    text: node.text.replace(/\s+/gu, " ").trim(),
  }));
}

describe("dependency report renderer", () => {
  test("loads cited coverage source from the supplied checkout", async () => {
    await using repo = await scopedTemporaryDirectory("coverage-code-");
    await writeFile(
      join(repo.path, "entry.ts"),
      'export const output = "html";\n',
    );
    const citation = {
      path: "entry.ts",
      startLine: 1,
      endLine: 1,
      supports: [],
    };
    const report = {
      ...cveReport,
      uses: [],
      coverage: [
        {
          kind: "dismissed",
          reason: "The output operation is outside the advisory.",
          evidence: [citation],
          observations: [],
        },
      ],
    };
    const code = await readDependencyReportCode(report, repo.path);
    expect(code.get(JSON.stringify([citation.path, 1, 1]))).toBe(
      'export const output = "html";',
    );
    expect(visibleText(renderDependencyReport(report, { code }))).toContain(
      "export const output",
    );
  });

  test("shows reviewed coverage decisions with their own cited source", () => {
    const citation = {
      path: "src/frontend.ts",
      startLine: 3,
      endLine: 3,
      supports: [],
    };
    const html = renderDependencyReport(
      {
        ...cveReport,
        coverage: [
          {
            kind: "dismissed",
            reason: "This entry renders HTML without the affected operation.",
            evidence: [citation],
            observations: [],
          },
          {
            kind: "unresolved",
            reason: "The optional entrypoint selection is not recorded.",
            evidence: [{ ...citation, startLine: 7, endLine: 7 }],
            observations: [],
          },
        ],
      },
      {
        code: new Map([
          [
            JSON.stringify([citation.path, 3, 3]),
            'export const output = "html";',
          ],
        ]),
      },
    );
    const text = visibleText(html);
    expect(text).toContain("Other checked code");
    expect(text).toContain("Excluded");
    expect(text).toContain("Unresolved");
    expect(text).toContain("src/frontend.ts:3");
    expect(text).toContain(
      "This entry renders HTML without the affected operation.",
    );
    expect(text).toContain(
      "The optional entrypoint selection is not recorded.",
    );
    expect(text).toContain("export const output");
  });

  test("renders a CVE report with separate source and runtime evidence", () => {
    const text = visibleText(renderDependencyReport(cveReport));

    for (const value of [
      cveReport.cve,
      check.advisories[0]!,
      "Example worker",
      "example-decoder",
      "2.3.4",
      "The selected path opens the configured input.",
      "The caller identity is unresolved.",
    ]) {
      expect(text).toContain(value);
    }
    expect(text).toMatch(/potentially[ _-]exploitable/iu);
    expect(text).toMatch(/configured/iu);
    expect(text).toMatch(
      /source citations.*src\/worker\.ts:17[–-]24.*dependency copy.*applicable use.*inventory observations.*fixture-inventory.*fixture-record-712.*running revision/iu,
    );
  });

  test.each(["answer", "data"])("opens a saved %s envelope", (key) => {
    const html = renderDependencyReport({
      [key]: cveReport,
      provenance: "synthetic saved envelope metadata",
    });

    expect(html).toBe(renderDependencyReport(cveReport));
  });

  test("keeps advisory checks and their results distinct in a package report", () => {
    const text = visibleText(
      renderDependencyReport({
        package: { ecosystem: "npm", name: "example-decoder" },
        checks: [
          { ...check, advisoryId: cveReport.cve },
          {
            ...check,
            advisoryId: "CVE-2099-67890",
            status: "ruled_out",
            uses: [
              {
                ...assessment.uses[0]!,
                location: "Example command",
                version: "4.0.0",
                verdict: "ruled_out",
                deployment: "unknown",
                observations: [],
              },
            ],
          },
        ],
      }),
    );

    expect(text).toMatch(/\bnpm\b/iu);
    expect(text).toContain("example-decoder");
    expect(text).toMatch(/CVE-2099-12345.*Example worker.*2\.3\.4/u);
    expect(text).toMatch(/CVE-2099-67890.*Example command.*4\.0\.0/u);
    expect(text).toMatch(/ruled[ _-]out/iu);
    expect(text).toMatch(/unknown/iu);
  });

  test("keeps every use and orders priority stably within each check", () => {
    const base = assessment.uses[0]!;
    const use = (
      location: string,
      verdict: DependencyUse["verdict"],
      deployment: DependencyUse["deployment"],
    ): DependencyUse => ({ ...base, location, verdict, deployment });

    const html = renderDependencyReport({
      package: { ecosystem: "npm", name: "example-decoder" },
      checks: [
        {
          ...check,
          advisoryId: cveReport.cve,
          status: "exploitable",
          uses: [
            use("Configured excluded route", "ruled_out", "configured"),
            use("Unobserved library", "potentially_exploitable", "unknown"),
            use(
              "Zulu configured worker",
              "potentially_exploitable",
              "configured",
            ),
            use("Observed affected service", "exploitable", "confirmed"),
            use(
              "Alpha configured worker",
              "potentially_exploitable",
              "configured",
            ),
            use("Confirmed candidate", "potentially_exploitable", "confirmed"),
          ],
        },
        {
          ...check,
          advisoryId: "CVE-2099-67890",
          status: "exploitable",
          uses: [use("Separate advisory service", "exploitable", "confirmed")],
        },
      ],
    });

    const expected = [
      "Observed affected service",
      "Confirmed candidate",
      "Zulu configured worker",
      "Alpha configured worker",
      "Unobserved library",
      "Configured excluded route",
      "Separate advisory service",
    ];
    const rows = selectElements(html, "[data-use-row]");
    const links = selectElements(html, "[data-use-row] a[aria-controls]", [
      "href",
      "aria-controls",
    ]);
    const panels = selectElements(html, "[data-use-panel]", ["id"]);
    expect(
      rows.map((row) => expected.find((name) => row.text.includes(name))),
    ).toEqual(expected);
    expect(links).toHaveLength(expected.length);
    expect(panels).toHaveLength(expected.length);
    for (const [index, link] of links.entries()) {
      const id = link.attributes["aria-controls"];
      expect(link.attributes["href"]).toBe(`#${id}`);
      const panel = panels.find((item) => item.attributes["id"] === id);
      expect(panel?.text).toContain(expected[index]!);
    }
  });

  test("keeps source evidence and empty lookup results on the right use", () => {
    const library = {
      ...assessment.uses[0]!,
      location: "Library default",
      deployment: "unknown",
      observations: [
        {
          server: "fixture-inventory",
          record: "No matching record for the fixture image",
          supports: [],
        },
      ],
    } satisfies DependencyUse;
    const service = {
      ...assessment.uses[0]!,
      location: "Configured service",
      version: "3.4.5",
      verdict: "ruled_out",
      deployment: "configured",
      reason: "The configured route disables this operation.",
      evidence: [
        {
          path: "service/route.json",
          startLine: 6,
          endLine: 9,
          supports: ["affected_use"],
        },
      ],
      observations: [],
    } satisfies DependencyUse;
    const html = renderDependencyReport({
      ...cveReport,
      uses: [service, library],
    });

    const rows = selectElements(html, "[data-use-row]");
    expect(rows).toHaveLength(2);
    expect(rows[0]!.text).toContain(library.location);
    expect(rows[0]!.text).toContain("2.3.4");
    expect(rows[0]!.text).toContain("Potentially exploitable");
    expect(rows[1]!.text).toContain(service.location);
    expect(rows[1]!.text).toContain("3.4.5");
    expect(rows[1]!.text).toContain("Ruled out");
    expect(rows[1]!.text).toContain("Configured");

    const panels = selectElements(html, "[data-use-panel]");
    expect(panels).toHaveLength(2);
    const libraryText = panels.find((panel) =>
      panel.text.includes(library.location),
    )!.text;
    const serviceText = panels.find((panel) =>
      panel.text.includes(service.location),
    )!.text;
    expect(libraryText).toContain("2.3.4");
    expect(libraryText).toContain("Potentially exploitable");
    expect(libraryText).toContain("src/worker.ts:17–24");
    expect(libraryText).toContain("No matching record for the fixture image");
    expect(libraryText).toMatch(/no deciding fact/i);
    expect(libraryText).not.toContain("service/route.json");

    expect(serviceText).toContain("3.4.5");
    expect(serviceText).toContain("Ruled out");
    expect(serviceText).toContain("Configured");
    expect(serviceText).toContain("service/route.json:6–9");
    expect(serviceText).toMatch(/no inventory observations/i);
    expect(serviceText).not.toContain("fixture-inventory");
    expect(serviceText).not.toContain("src/worker.ts");
  });

  test("exposes search, verdict and deployment filters and report limitations", () => {
    const html = renderDependencyReport(cveReport);
    expect(
      selectElements(html, 'input[type="search"][data-search]'),
    ).toHaveLength(1);

    const optionValues = (control: string) =>
      selectElements(html, `select[${control}] option`, ["value"]).map(
        (option) => option.attributes["value"],
      );
    expect(optionValues("data-verdict-filter")).toEqual(
      expect.arrayContaining([
        "exploitable",
        "potentially_exploitable",
        "unknown",
        "ruled_out",
      ]),
    );
    expect(optionValues("data-deployment-filter")).toEqual(
      expect.arrayContaining(["confirmed", "configured", "unknown"]),
    );

    const limitations = selectElements(html, "details").find((details) =>
      /report limitations/iu.test(details.text),
    );
    expect(limitations?.text).toContain(assessment.limitations[0]!);
  });

  test.each(["exploitable", "potentially_exploitable", "ruled_out"] as const)(
    "shows a scoped source-to-sink walkthrough for %s",
    (verdict) => {
      const reason =
        verdict === "ruled_out"
          ? "This route supplies the safe format flag, which bypasses the affected branch."
          : "This route passes the uploaded bytes to the decoder.";
      const record = "Fixture image revision observed at deployment";
      const use = {
        ...walkedUse,
        deployment: verdict === "exploitable" ? "confirmed" : "configured",
        verdict,
        reason,
        observations: [
          {
            server: "fixture-inventory",
            record,
            supports: ["running", "access"],
          },
        ],
      } satisfies DependencyUse;
      const html = renderDependencyReport({
        ...walkedReport,
        status: verdict,
        uses: [use],
      });
      const order = ["source", "path", "sink", "result"];
      expect(selectElements(html, "[data-walkthrough]")).toHaveLength(1);
      const steps = selectElements(
        html,
        "[data-walkthrough] button[data-flow-step]",
        ["data-flow-step"],
      );
      const details = selectElements(
        html,
        "[data-walkthrough] [data-flow-detail]",
        ["data-flow-detail"],
      );
      expect(steps.map((step) => step.attributes["data-flow-step"])).toEqual(
        order,
      );
      expect(
        details.map((detail) => detail.attributes["data-flow-detail"]),
      ).toEqual(order);

      const stepText = (key: string) =>
        [
          steps.find((step) => step.attributes["data-flow-step"] === key)?.text,
          details.find(
            (detail) => detail.attributes["data-flow-detail"] === key,
          )?.text,
        ].join(" ");
      expect(stepText("source")).toContain(reportedSource);
      expect(stepText("path")).toContain(reportedPath);
      expect(stepText("path")).toContain("src/route.ts:15–19");
      expect(stepText("sink")).toContain(use.component);
      expect(stepText("sink")).toContain(use.version);
      if (verdict === "ruled_out") {
        expect(stepText("result")).toContain(reason);
        expect(stepText("result")).not.toMatch(
          /(?:all|every) (?:affected )?sinks? (?:is|are) unreachable/iu,
        );
      }
      for (const step of ["source", "path", "sink"]) {
        expect(stepText(step)).not.toContain(record);
      }
      expect(visibleText(html)).toMatch(
        /inventory observations.*Fixture image revision observed at deployment.*running revision.*caller access/iu,
      );
    },
  );

  test.each([
    [
      "potentially_exploitable",
      "path",
      "The running build remains unverified.",
    ],
    ["ruled_out", "result", "The recorded mode skips the affected decoder."],
  ] as const)(
    "uses the recorded path without a placeholder source for %s",
    (verdict, initial, result) => {
      const location = "src/route.ts:17 native image decoder";
      const routing = "The caller passes input to src/route.ts.";
      const html = renderDependencyReport({
        ...walkedReport,
        status: verdict,
        uses: [
          {
            ...walkedUse,
            location,
            verdict,
            reason: `${routing} ${result}`,
          },
        ],
      });

      const steps = selectElements(html, "[data-flow-step]", [
        "data-flow-step",
        "aria-pressed",
      ]);
      expect(steps.map((step) => step.attributes["data-flow-step"])).toEqual([
        "path",
        "sink",
        "result",
      ]);
      expect(steps[0]!.text).toContain(location);
      expect(
        steps
          .filter((step) => step.attributes["aria-pressed"] === "true")
          .map((step) => step.attributes["data-flow-step"]),
      ).toEqual([initial]);
      expect(
        selectElements(html, '[data-flow-detail="path"]')[0]!.text,
      ).toContain(routing);
      expect(
        selectElements(html, '[data-flow-detail="result"]')[0]!.text,
      ).toContain(result);
      expect(visibleText(html)).not.toContain("Input described in report");
    },
  );

  test("shows the bound sink and conditions for each use before the report details", () => {
    const excluded = {
      ...walkedUse,
      location: "Configured thumbnail route",
      verdict: "ruled_out",
      reason: "The configured route selects the safe frame mode.",
    } satisfies DependencyUse;
    const callSite = { path: routeEvidence.path, line: 18 };
    const operation = "decoder.decodeVerifiedFrame";
    const html = renderDependencyReport(
      { ...walkedReport, uses: [walkedUse, excluded] },
      {
        code: new Map([
          [
            JSON.stringify([
              routeEvidence.path,
              routeEvidence.startLine,
              routeEvidence.endLine,
            ]),
            [
              "const header = readHeader(raw);",
              "const frame = header.frame;",
              "const mode = selectMode(frame);",
              `${operation}(frame, mode);`,
              "return frame;",
            ].join("\n"),
          ],
        ]),
        useEvidence: [
          {
            useId: "use-1-1",
            location: walkedUse.location,
            sink: { function: operation, callSite },
            conditions: [
              {
                label: "Uses the affected frame mode",
                status: "met",
                explanation:
                  "This call passes the configured mode to the decoder.",
                citations: [callSite],
              },
              {
                label: "Caller can choose the frame",
                status: "unknown",
                explanation: "The caller's capabilities are unresolved.",
                citations: [],
              },
            ],
          },
          {
            useId: "use-1-2",
            location: excluded.location,
            conditions: [
              {
                label: "Uses the affected frame mode",
                status: "ruled_out",
                explanation: excluded.reason,
                citations: [{ ...callSite, line: 17 }],
              },
            ],
          },
        ],
      },
    );

    const sink = '#use-1-1 [data-flow-detail="sink"]';
    expect(selectElements(html, sink)[0]!.text).toContain(operation);
    expect(selectElements(html, sink)[0]!.text).toContain(
      "Call site src/route.ts:18",
    );
    const highlighted = selectElements(html, `${sink} [data-highlighted]`, [
      "data-line",
    ]);
    expect(highlighted.map((row) => row.attributes["data-line"])).toEqual([
      "18",
    ]);
    expect(highlighted[0]!.text).toContain(`${operation}(frame, mode);`);
    expect(selectElements(html, "#use-1-2 [data-highlighted]")).toHaveLength(0);

    const conditions = (id: string) =>
      selectElements(html, `#${id} [data-condition]`, ["data-condition"]);
    const positive = conditions("use-1-1");
    expect(positive.map((row) => row.attributes["data-condition"])).toEqual([
      "met",
      "unknown",
    ]);
    expect(positive[0]!.text).toContain("src/route.ts:18");
    expect(positive[1]!.text).toContain("Caller can choose the frame");
    const ruledOut = conditions("use-1-2");
    expect(ruledOut.map((row) => row.attributes["data-condition"])).toEqual([
      "ruled_out",
    ]);
    expect(ruledOut[0]!.text).toContain(excluded.reason);
    expect(ruledOut[0]!.text).toContain("src/route.ts:17");

    const finalSections = selectElements(
      html,
      'details.limits, footer[aria-label="Report details"]',
    );
    expect(finalSections).toHaveLength(2);
    expect(finalSections[0]!.text).toContain(assessment.limitations[0]!);
    expect(finalSections[1]!.text).toContain("Advisory references");
  });

  test("escapes code excerpts and renders only cited ranges", () => {
    const raw = "<img src=x onerror=alert(x)>";
    const html = renderDependencyReport(walkedReport, {
      code: new Map([
        [
          JSON.stringify([
            routeEvidence.path,
            routeEvidence.startLine,
            routeEvidence.endLine,
          ]),
          `decodeFrame(${raw} & input);`,
        ],
        [JSON.stringify([routeEvidence.path, 99, 100]), "uncited fixture code"],
      ]),
    });

    expect(html).toContain(
      "decodeFrame(&lt;img src=x onerror=alert(x)&gt; &amp; input);",
    );
    expect(html).not.toContain(raw);
    expect(html).not.toContain("uncited fixture code");
  });

  test.each(["unknown", "ruled_out"] as const)(
    "keeps every supplied citation visible for %s, including producer code",
    (verdict) => {
      const reader = {
        path: "src/reader.py",
        startLine: 10,
        endLine: 11,
        supports: [],
      };
      const producer = {
        path: "src/producer.py",
        startLine: 20,
        endLine: 22,
        supports: [],
      };
      const use = {
        ...assessment.uses[0]!,
        location: "src/reader.py:10",
        verdict,
        version: null,
        deployment: "unknown",
        reason:
          verdict === "unknown"
            ? "The reader is identified, but its selected native copy is unknown."
            : "The producer selects the safe encoding for this exact payload.",
        evidence: [reader, producer],
        observations: [],
      } satisfies DependencyUse;
      const html = renderDependencyReport(
        { ...cveReport, status: verdict, uses: [use] },
        {
          code: new Map([
            [
              JSON.stringify([reader.path, 10, 11]),
              "result = decoder.read(payload)\nreturn result",
            ],
            [
              JSON.stringify([producer.path, 20, 22]),
              "def make_payload(frame):\n    payload = encode_safe(frame)\n    return payload",
            ],
            [JSON.stringify(["src/uncited.py", 1, 1]), "uncited_code()"],
          ]),
        },
      );

      const evidence = selectElements(html, "#use-1-1 details.evidence")[0]!;
      expect(evidence.text).toContain("decoder.read(payload)");
      expect(evidence.text).toContain("payload = encode_safe(frame)");
      expect(evidence.text).toContain("return payload");
      expect(
        selectElements(html, "#use-1-1 details.evidence .snippet"),
      ).toHaveLength(2);
      expect(selectElements(html, "#use-1-1 [data-walkthrough]")).toHaveLength(
        1,
      );
      expect(visibleText(html)).toContain("No production call count recorded.");
      expect(visibleText(html)).not.toContain("uncited_code");
      expect(
        selectElements(html, "#use-1-1 [data-condition]", [
          "data-condition",
        ]).map((row) => row.attributes["data-condition"]),
      ).toEqual(["unknown", "unknown"]);
    },
  );

  test("renders the saved proof and highlights an unknown use without a sidecar", () => {
    const callSite = { path: routeEvidence.path, line: 18 };
    const use = {
      ...walkedUse,
      verdict: "unknown",
      version: null,
      reason:
        "The decoder call is identified, but its selected copy is unknown.",
      evidence: [{ ...routeEvidence, supports: [] }],
      observations: [],
      proof: {
        sink: { function: "decoder.readFrame", callSite },
        conditions: [
          {
            label: "Calls the decoder",
            status: "met",
            explanation: "The source passes the payload to the decoder.",
            citations: [callSite],
          },
          {
            label: "Selected affected copy",
            status: "unknown",
            explanation: "The native build was not identified.",
            citations: [],
          },
        ],
      },
    } satisfies DependencyUse;
    const html = renderDependencyReport(
      { ...cveReport, status: "unknown", uses: [use] },
      {
        code: new Map([
          [
            JSON.stringify([routeEvidence.path, 15, 19]),
            [
              "const payload = receive();",
              "const metadata = inspect(payload);",
              "const mode = metadata.mode;",
              "decoder.readFrame(payload, mode);",
              "return metadata;",
            ].join("\n"),
          ],
        ]),
      },
    );

    const sink = selectElements(html, '#use-1-1 [data-flow-detail="sink"]')[0]!;
    expect(sink.text).toContain("decoder.readFrame");
    expect(sink.text).toContain("Call site src/route.ts:18");
    expect(
      selectElements(
        html,
        '#use-1-1 [data-flow-detail="sink"] [data-highlighted]',
        ["data-line"],
      ).map((row) => row.attributes["data-line"]),
    ).toEqual(["18"]);
    expect(
      selectElements(html, "#use-1-1 details.evidence [data-highlighted]", [
        "data-line",
      ]).map((row) => row.attributes["data-line"]),
    ).toEqual(["18"]);
    expect(
      selectElements(html, "#use-1-1 [data-condition]", ["data-condition"]).map(
        (row) => row.attributes["data-condition"],
      ),
    ).toEqual(["met", "unknown"]);
    expect(visibleText(html)).toContain("The native build was not identified.");
    expect(selectElements(html, ".production")).toHaveLength(0);
    expect(selectElements(html, "#use-1-1 .runtime-proof")).toHaveLength(1);
  });

  test("distinguishes a recorded zero production count from a missing measurement", () => {
    const empty = visibleText(renderDependencyReport(walkedReport));
    expect(empty).toContain("No production call count recorded");

    const html = renderDependencyReport(walkedReport, {
      productionCalls: [productionMeasurement],
    });
    const sink = selectElements(html, '[data-flow-detail="sink"]')[0]!.text;
    expect(sink).toMatch(/production calls.*\b0\b/iu);
    expect(sink).toContain(productionMeasurement.target);
    expect(sink).toContain(productionMeasurement.record);
    expect(
      selectElements(html, '[data-flow-detail="path"]')[0]!.text,
    ).not.toContain(productionMeasurement.record);
  });

  test("rejects production measurements for the wrong use or interval", () => {
    for (const mismatch of [
      { useId: "use-2-1" },
      { location: "POST /different-use" },
      { from: productionMeasurement.until, until: productionMeasurement.from },
    ]) {
      expect(() =>
        renderDependencyReport(walkedReport, {
          productionCalls: [{ ...productionMeasurement, ...mismatch }],
        }),
      ).toThrow();
    }
  });

  test("renders saved advisory details and escapes advisory-supplied names", () => {
    const url = "https://advisory.example.invalid/decoder";
    const raw = "<img src=x onerror=alert(1)>";
    const escaped = "&lt;img src=x onerror=alert(1)&gt;";
    const html = renderDependencyReport({
      ...cveReport,
      advisories: [url],
      advisoryDetails: [
        {
          url,
          summary: `Synthetic decoder advisory ${raw}`,
          overview: "The decoder fails to bound a synthetic frame.",
          applicability: "Only the configured frame mode is affected.",
          vulnerableFunctions: [`Decoder.Decode ${raw}`],
          affected: [
            {
              package: { ecosystem: "npm", name: `example-decoder ${raw}` },
              ranges: [
                {
                  type: "SEMVER",
                  events: [{ introduced: "0" }, { fixed: "2.3.5" }],
                },
              ],
            },
          ],
        },
      ],
    });

    const text = visibleText(html);
    expect(text).toContain("The decoder fails to bound a synthetic frame.");
    expect(text).toContain("Only the configured frame mode is affected.");
    expect(text).toMatch(/vulnerable functions.*Decoder\.Decode/iu);
    expect(text).toMatch(
      /affected packages.*example-decoder.*fixed in 2\.3\.5/iu,
    );
    expect(html).not.toContain(raw);
    for (const marker of [
      "Synthetic decoder advisory",
      "Decoder.Decode",
      "example-decoder",
    ]) {
      expect(html).toContain(`${marker} ${escaped}`);
    }
  });

  test.each([
    [
      "Go",
      {
        package: { ecosystem: "Go", name: "example.test/decoder" },
        ecosystem_specific: {
          imports: [
            {
              path: "example.test/decoder/internal",
              symbols: ["Decoder.Decode"],
              goos: ["linux"],
              goarch: ["amd64"],
            },
          ],
        },
      },
      "Decoder.Decode",
    ],
    [
      "Rust",
      {
        package: { ecosystem: "crates.io", name: "example-decoder" },
        ecosystem_specific: {
          affects: {
            functions: ["decode::run"],
            os: ["linux"],
            arch: ["x86_64"],
          },
        },
      },
      "decode::run",
    ],
  ] as const)(
    "renders vulnerable functions from %s advisory metadata",
    (_, affected, name) => {
      const url = "https://advisory.example.invalid/metadata";
      const text = visibleText(
        renderDependencyReport({
          package: affected.package,
          checks: [
            {
              ...check,
              advisoryId: cveReport.cve,
              advisories: [url],
              advisoryDetails: [{ url, affected: [affected] }],
            },
          ],
        }),
      );

      expect(text).toMatch(/vulnerable functions/iu);
      expect(text).toContain(name);
    },
  );

  test("supplements a legacy advisory only at its exact saved URL", () => {
    const url = "https://advisory.example.invalid/legacy";
    const legacy = { ...cveReport, advisories: [url] };
    const details = {
      url,
      overview: "A synthetic description for the archived advisory.",
      affected: [],
    };

    const supplemented = visibleText(
      renderDependencyReport(legacy, { advisoryDetails: [details] }),
    );
    expect(supplemented).toContain(details.overview);
    expect(() =>
      renderDependencyReport(legacy, {
        advisoryDetails: [{ ...details, url: `${url}?mirror=1` }],
      }),
    ).toThrow();
  });

  test("renders HTTP advisory links without activating unsafe URLs", () => {
    const html = renderDependencyReport({
      ...cveReport,
      advisories: [
        "https://advisory.example.invalid/example",
        "javascript:alert(1)",
      ],
    });

    expect(html).toContain('href="https://advisory.example.invalid/example"');
    expect(html).not.toContain('href="javascript:');
    expect(visibleText(html)).toContain("javascript:alert(1)");
  });

  test("renders a supplied description without an advisory identifier", () => {
    const text = visibleText(
      renderDependencyReport({
        package: { ecosystem: "npm", name: "example-decoder" },
        vulnDescription: "The decoder can reject a malformed fixture.",
        checks: [{ ...check, advisories: [], advisoryId: null }],
      }),
    );

    expect(text).toContain("The decoder can reject a malformed fixture.");
    expect(text).toContain("Example worker");
  });

  test("renders empty uses and advisory checks as empty states", () => {
    const emptyUses = visibleText(
      renderDependencyReport({ ...cveReport, status: "unknown", uses: [] }),
    );
    const emptyChecks = visibleText(
      renderDependencyReport({
        package: { ecosystem: "npm", name: "example-decoder" },
        checks: [],
      }),
    );

    expect(emptyUses).toContain(cveReport.cve);
    expect(emptyUses).toMatch(/no\b.*\bplaces\b/iu);
    expect(emptyChecks).toContain("example-decoder");
    expect(emptyChecks).toMatch(/no\b.*\b(?:checks|advisories)\b/iu);
  });

  test("renders mixed place verdicts and partial inventory without a checkout verdict", () => {
    const report = readDependencyCheckOutput(cveReport);
    if (!("cve" in report)) throw new Error("Expected CVE report");
    const place = report.uses[0]!;
    const html = renderDependencyReport({
      ...report,
      uses: [
        {
          ...place,
          location: "Fixed configured service",
          verdict: "ruled_out",
          reason: "The source passes only a fixed input.",
        },
        {
          ...place,
          location: "Separate nightly job",
          verdict: "unknown",
          place: {
            ...place.place,
            kind: "job",
            deploymentBasis: "unknown",
            unresolvedQuestions: ["Which job image ran?"],
          },
        },
      ],
      searches: [
        {
          source: "fixture-inventory",
          tool: "get_run",
          scope: ["run_id=run-123"],
          startedAt: null,
          finishedAt: "2026-01-01T12:00:00Z",
          result: "no_match",
          completeness: "partial",
          details: ["Provider response was truncated."],
          evidenceReferences: ["inventory-1"],
        },
      ],
    });
    const visible = visibleText(html);
    expect(visible).not.toContain("Checkout verdict");
    expect(visible).toContain("Fixed configured service");
    expect(visible).toContain("Ruled out");
    expect(visible).toContain("Which job image ran?");
    expect(visible).toContain("No match observed Partial");
    expect(visible).toContain("inventory-1");
    expect(visible).not.toContain("Assumed not deployed");
  });

  test("rejects an invalid report inside a saved envelope", () => {
    expect(() =>
      renderDependencyReport({
        answer: {
          ...cveReport,
          uses: [{ ...assessment.uses[0]!, version: 2 }],
        },
      }),
    ).toThrow();
  });

  test("escapes untrusted report fields as text", () => {
    const payload = "<img src=x onerror=alert(1)>";
    const escaped = "&lt;img src=x onerror=alert(1)&gt;";
    const markers = [
      "ecosystem",
      "package",
      "description",
      "advisory",
      "alias",
      "location",
      "component",
      "version",
      "reason",
      "path",
      "server",
      "record",
      "limitation",
    ];
    const html = renderDependencyReport({
      package: {
        ecosystem: `ecosystem${payload}`,
        name: `package${payload}`,
      },
      vulnDescription: `description${payload}`,
      checks: [
        {
          ...check,
          advisoryId: `advisory${payload}`,
          advisories: [`alias${payload}`],
          uses: [
            {
              ...assessment.uses[0]!,
              location: `location${payload}`,
              component: `component${payload}`,
              version: `version${payload}`,
              reason: `reason${payload} & more`,
              evidence: [
                {
                  ...assessment.uses[0]!.evidence[0]!,
                  path: `path${payload}`,
                },
              ],
              observations: [
                {
                  ...assessment.uses[0]!.observations[0]!,
                  server: `server${payload}`,
                  record: `record${payload}`,
                },
              ],
            },
          ],
          limitations: [`limitation${payload}`],
        },
      ],
    });

    expect(html).not.toContain(payload);
    for (const marker of markers) {
      expect(html).toContain(marker + escaped);
    }
    expect(html).toContain(" &amp; more");
    expect(
      renderDependencyReport({ ...cveReport, cve: `cve${payload}` }),
    ).toContain("cve" + escaped);
  });
});

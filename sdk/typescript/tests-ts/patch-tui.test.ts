import { afterEach, describe, expect, test } from "bun:test";
import { spawnSync } from "node:child_process";
import { mkdir, mkdtemp, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { cleanup, render } from "ink-testing-library";
import { createElement } from "react";
import type { Finding, SeverityLevel } from "../src/index.js";
import { PatchTui, type PatchSelection } from "../src/patch-tui.js";
import { fakeResult } from "./cli-fixtures.js";

afterEach(() => cleanup());

function findings(severities: readonly SeverityLevel[]): Finding[] {
  const result = fakeResult(severities);
  result.findings.findings.forEach((finding, index) => {
    Object.assign(finding, {
      findingId: `csf_${index + 1}`,
      occurrenceId: `occ_${index + 1}`,
      title: `Finding ${index + 1}`,
      summary: `Attacker-controlled input reaches finding ${index + 1}.`,
      severity: {
        level: severities[index],
        rationale: "The public endpoint is reachable without authentication.",
        changeConditions:
          "Raise severity if tenant identifiers are predictable.",
      },
      confidence: { level: "high", rationale: "The source path was traced." },
      locations: [{ path: `src/finding-${index + 1}.ts`, startLine: 18 }],
      rootCause: {
        summary: "The request bypasses the tenant boundary.",
        evidenceRefs: ["evidence-1"],
      },
      validation: {
        method: "static source trace",
        summary: "A crafted request reproduces the vulnerability.",
        disposition: "confirmed",
        checks: ["The exploit reproduces.", "The permission check fails."],
        environment: { mode: "local", sandboxed: true },
        limitations: ["No live exploit was run."],
        evidenceRefs: ["evidence-1"],
      },
      attackPath: {
        summary: "Public route → database query",
        dataflow: {
          source: "Attacker-controlled request parameter",
          sink: "Tenant-scoped database query",
          outcome: "Another tenant's account records are exposed.",
        },
        reachability: {
          attacker: "Anonymous caller",
          entrypoint: "GET /accounts",
          preconditions: ["A valid tenant identifier."],
        },
        impact: {
          level: "high",
          why: "Reads another tenant's account records.",
        },
        likelihood: {
          level: "medium",
          why: "Tenant identifiers are predictable.",
        },
      },
      codeEvidence: [
        {
          id: "evidence-1",
          label: "Unsafe query",
          path: "src/query.ts",
          startLine: 18,
          code: "if user_input:\n    cursor.execute(user_input)",
          explanation: "Untrusted input reaches the query.",
        },
      ],
      remediation: "Bind the attacker-controlled value as a query parameter.",
      remediationTests: ["Reject cross-tenant requests."],
      preventiveControls: ["Use the shared tenant-scoped query helper."],
      taxonomy: { category: "sql-injection", cwe: ["CWE-89"] },
    });
  });
  return result.findings.findings;
}

async function settle(): Promise<void> {
  await new Promise<void>((resolve) => setTimeout(resolve, 60));
}

describe("interactive patch finding browser", () => {
  test("shows complete finding details and scrolls through source evidence", async () => {
    const app = render(
      createElement(PatchTui, {
        repository: "/work/example",
        findings: findings(["high", "medium", "low"]),
        color: false,
        onComplete: () => {},
      }),
    );

    expect(app.lastFrame()).toContain("CODEX SECURITY");
    expect(app.lastFrame()).toContain("FINDINGS");
    expect(app.lastFrame()).toContain("DETAILS");
    expect(app.lastFrame()).toContain("PATCH INSTRUCTIONS");
    expect(app.lastFrame()).toContain("Add instructions for this finding.");
    expect(app.lastFrame()).toContain(
      "[ ] Create draft GitHub pull request after patching",
    );
    expect(app.lastFrame()).toContain("3/3 selected");
    expect(app.lastFrame()).toContain("SUMMARY");
    expect(app.lastFrame()).toContain("Attacker-controlled input");
    expect(app.lastFrame()).toContain("SEVERITY");
    expect(app.lastFrame()).toContain("High");
    expect(app.lastFrame()).not.toContain('"level"');
    expect(app.lastFrame()).not.toContain('"rationale"');

    const frames = [app.lastFrame() ?? ""];
    app.stdin.write("\t");
    await settle();
    for (let page = 0; page < 12; page += 1) {
      app.stdin.write("\u001B[6~");
      await settle();
      frames.push(app.lastFrame() ?? "");
    }

    const reviewed = frames.join("\n");
    expect(reviewed).toContain("ROOT CAUSE");
    expect(reviewed).toContain("Evidence:");
    expect(reviewed).toContain("• Unsafe query · src/query.ts:18");
    expect(reviewed).toContain("VALIDATION");
    expect(reviewed).toContain("Method: static source trace");
    expect(reviewed).toContain("Disposition: confirmed");
    expect(reviewed).toContain("• The exploit reproduces.");
    expect(reviewed).toContain("• No live exploit was run.");
    expect(reviewed).toContain("Mode: local");
    expect(reviewed).toContain("Sandboxed: true");
    expect(reviewed).toContain("ATTACK PATH");
    expect(reviewed).toContain("Source: Attacker-controlled request parameter");
    expect(reviewed).toContain("Sink: Tenant-scoped database query");
    expect(reviewed).toContain("Attacker: Anonymous caller");
    expect(reviewed).toContain("Entrypoint: GET /accounts");
    expect(reviewed).toContain("• A valid tenant identifier.");
    expect(reviewed).toContain("Impact:");
    expect(reviewed).toContain("Likelihood:");
    expect(reviewed).toContain("CODE EVIDENCE");
    expect(reviewed).toContain("Unsafe query · src/query.ts:18");
    expect(reviewed).toContain("18 │ if user_input:");
    expect(reviewed).toContain("    cursor.execute(user_input)");
    expect(reviewed).toContain("authentication.");
    expect(reviewed).toContain("src/finding-1.ts:18");
    expect(reviewed).toContain("REMEDIATION");
    expect(reviewed).toContain("• Reject cross-tenant requests.");
    expect(reviewed).toContain("PREVENTIVE CONTROLS");
    expect(reviewed).toContain("Category: sql-injection");
    expect(reviewed).toContain("CWE: CWE-89");
    expect(reviewed).toContain("occ_1");
    expect(reviewed).not.toContain('"summary"');
    expect(reviewed).not.toContain('"path"');
  });

  test("shows surrounding source without reading outside the scanned repository", async () => {
    const directory = await mkdtemp(join(tmpdir(), "codex-security-patch-"));
    const repository = join(directory, "repository");
    try {
      await mkdir(join(repository, "src"), { recursive: true });
      await writeFile(
        join(repository, "src", "finding-1.ts"),
        [
          'import { database } from "./database";',
          "export function loadTenant(request) {",
          "  const tenant = request.params.tenant;",
          "  const input = request.query.id;",
          "  const query = buildQuery(input);",
          "  return database.query(query, { tenant, includeDeleted: false });",
          "  audit.record(tenant);",
          "}",
          'const token = "sk-proj-SYNTHETIC_KEY_123";',
        ].join("\n"),
      );
      const outside = join(directory, "outside.ts");
      await writeFile(outside, "OUTSIDE_PRIVATE_SOURCE");
      await symlink(outside, join(repository, "src", "outside-link.ts"));

      const [finding] = findings(["high"]);
      finding!.locations = [
        {
          path: "src/finding-1.ts",
          startLine: 5,
          endLine: 6,
          role: "sink",
        },
        { path: "../outside.ts", startLine: 1 },
        { path: "src/outside-link.ts", startLine: 1 },
      ];
      const app = render(
        createElement(PatchTui, {
          repository,
          findings: [finding!],
          color: false,
          onComplete: () => {},
        }),
      );

      const frames = [app.lastFrame() ?? ""];
      for (let page = 0; page < 12; page += 1) {
        app.stdin.write("\u001B[6~");
        await settle();
        frames.push(app.lastFrame() ?? "");
      }
      const reviewed = frames.join("\n");

      expect(reviewed).toContain("src/finding-1.ts:5–6 · sink");
      expect(reviewed).toContain("2 │ export function loadTenant(request)");
      expect(reviewed).toContain("› 5 │   const query = buildQuery(input);");
      expect(reviewed).toContain("› 6 │   return database.query(query,");
      expect(reviewed).toContain("›   │");
      expect(reviewed).toContain("includeDeleted: false");
      expect(reviewed).toContain("7 │   audit.record(tenant);");
      expect(reviewed).toContain("[redacted]");
      expect(reviewed).not.toContain("SYNTHETIC_KEY_123");
      expect(reviewed).toContain("../outside.ts:1");
      expect(reviewed).toContain("src/outside-link.ts:1");
      expect(reviewed).not.toContain("OUTSIDE_PRIVATE_SOURCE");
    } finally {
      await rm(directory, { force: true, recursive: true });
    }
  });

  test("combines severity presets with individual finding selection", async () => {
    const selected: (PatchSelection | null)[] = [];
    const app = render(
      createElement(PatchTui, {
        repository: "/work/example",
        findings: findings(["high", "medium", "low"]),
        color: false,
        onComplete: (value) => selected.push(value),
      }),
    );

    app.stdin.write("2");
    await settle();
    expect(app.lastFrame()).toContain("1/3 selected");
    expect(app.lastFrame()).toContain("high and above");

    app.stdin.write("\u001B[B ");
    await settle();
    expect(app.lastFrame()).toContain("2/3 selected");
    expect(app.lastFrame()).toContain("custom");

    app.stdin.write("\r");
    await settle();
    expect(selected).toEqual([
      { severity: "medium", occurrenceIds: ["occ_1", "occ_2"] },
    ]);
  });

  test("edits instructions per finding and only returns selected guidance", async () => {
    const selected: (PatchSelection | null)[] = [];
    const app = render(
      createElement(PatchTui, {
        repository: "/work/example",
        findings: findings(["high", "medium"]),
        color: false,
        onComplete: (value) => selected.push(value),
      }),
    );

    app.stdin.write("i");
    await settle();
    expect(app.lastFrame()).toContain("Enter save");

    app.stdin.write("Use the shared 2FA helper, not a new dependency.");
    await settle();
    expect(app.lastFrame()).toContain("Use the shared 2FA helper");
    expect(app.lastFrame()).toContain("2/2 selected");

    app.stdin.write("\r");
    await settle();
    expect(app.lastFrame()).toContain("PATCH INSTRUCTIONS");
    expect(app.lastFrame()).toContain("Use the shared 2FA helper");
    expect(app.lastFrame()).toContain("✎");
    expect(app.lastFrame()?.match(/PATCH INSTRUCTIONS/gu)).toHaveLength(1);

    app.stdin.write("\u001B[B");
    await settle();
    app.stdin.write("i");
    await settle();
    app.stdin.write("Keep the existing middleware.");
    await settle();
    app.stdin.write("\r");
    await settle();
    expect(app.lastFrame()).toContain("Keep the existing middleware.");

    app.stdin.write(" ");
    await settle();
    app.stdin.write("\r");
    await settle();

    expect(selected).toEqual([
      {
        severity: "high",
        occurrenceIds: ["occ_1"],
        instructions: {
          occ_1: "Use the shared 2FA helper, not a new dependency.",
        },
      },
    ]);
  });

  test("optionally creates a draft pull request after selected patches", async () => {
    const selected: (PatchSelection | null)[] = [];
    const app = render(
      createElement(PatchTui, {
        repository: "/work/example",
        findings: findings(["high"]),
        color: false,
        onComplete: (value) => selected.push(value),
      }),
    );

    expect(app.lastFrame()).toContain(
      "[ ] Create draft GitHub pull request after patching",
    );
    app.stdin.write("r");
    await settle();
    expect(app.lastFrame()).toContain(
      "[✓] Create draft GitHub pull request after patching",
    );
    app.stdin.write("\r");
    await settle();

    expect(selected).toEqual([
      {
        severity: "high",
        occurrenceIds: ["occ_1"],
        createPullRequest: true,
      },
    ]);
  });

  test("cancels and clears finding instructions without leaving the browser", async () => {
    const selected: (PatchSelection | null)[] = [];
    const app = render(
      createElement(PatchTui, {
        repository: "/work/example",
        findings: findings(["high"]),
        color: false,
        onComplete: (value) => selected.push(value),
      }),
    );

    app.stdin.write("i");
    await settle();
    app.stdin.write("Discard this guidance.");
    await settle();
    app.stdin.write("\u001B");
    await settle();
    expect(selected).toEqual([]);
    expect(app.lastFrame()).not.toContain("Discard this guidance.");

    app.stdin.write("i");
    await settle();
    app.stdin.write("x");
    await settle();
    app.stdin.write("\u007F");
    await settle();
    app.stdin.write("\r");
    await settle();
    app.stdin.write("\r");
    await settle();

    expect(selected).toEqual([{ severity: "high", occurrenceIds: ["occ_1"] }]);
  });

  test("allows selecting none and canceling without patching", async () => {
    for (const input of ["q", "\r"]) {
      const selected: (PatchSelection | null)[] = [];
      const app = render(
        createElement(PatchTui, {
          repository: "/work/example",
          findings: findings(["high"]),
          color: false,
          onComplete: (value) => selected.push(value),
        }),
      );
      if (input === "\r") {
        app.stdin.write("n");
        await settle();
        expect(app.lastFrame()).toContain("0/1 selected");
      }
      app.stdin.write(input);
      await settle();
      expect(selected).toEqual([null]);
      app.unmount();
    }
  });

  test("sanitizes terminal escapes and credential-bearing finding details", () => {
    const [finding] = findings(["high"]);
    finding!.title = "\u001B[31mUnsafe title\u001B[0m\nforged line";
    finding!.summary = "sk-proj-SYNTHETIC_KEY_123";
    const app = render(
      createElement(PatchTui, {
        repository: "/work/example",
        findings: [finding!],
        color: false,
        onComplete: () => {},
      }),
    );

    expect(app.lastFrame()).toContain("Unsafe title forged line");
    expect(app.lastFrame()).toContain("[redacted]");
    expect(app.lastFrame()).not.toContain("SYNTHETIC_KEY_123");
    expect(app.lastFrame()).not.toContain("\u001B[31m");
  });

  test("keeps finding details restrained while honoring NO_COLOR", () => {
    const source = [
      'import {render} from "ink-testing-library";',
      'import {createElement} from "react";',
      `import {PatchTui} from ${JSON.stringify(new URL("../src/patch-tui.tsx", import.meta.url).href)};`,
      `const findings=${JSON.stringify(findings(["critical", "high", "medium", "low"]))};`,
      'const app=render(createElement(PatchTui,{repository:"/work/example",findings,onComplete(){}}));',
      'const frames=[app.lastFrame() ?? ""];app.stdin.write("\\t");',
      'for(let page=0;page<12;page+=1){app.stdin.write("\\u001B[6~");await new Promise(resolve=>setTimeout(resolve,30));frames.push(app.lastFrame()??"");}',
      'process.stdout.write(frames.join("\\n"));app.unmount();',
    ].join("");
    const run = (color: boolean) =>
      spawnSync(process.execPath, ["--eval", source], {
        encoding: "utf8",
        env: {
          ...process.env,
          FORCE_COLOR: color ? "1" : undefined,
          NO_COLOR: color ? undefined : "1",
          TERM: "xterm-256color",
        },
      });
    const colored = run(true);

    expect(colored.status).toBe(0);
    expect(colored.stdout).toContain("\u001B[91m");
    expect(colored.stdout).toContain("\u001B[31m");
    expect(colored.stdout).toContain("\u001B[33m");
    expect(colored.stdout).toContain("\u001B[95m");
    expect(colored.stdout).toContain("\u001B[32m");
    expect(colored.stdout).toContain("\u001B[91m● Critical\u001B[39m");
    expect(colored.stdout).toContain("\u001B[1mSEVERITY\u001B[22m");
    expect(colored.stdout).toContain("\u001B[1mROOT CAUSE\u001B[22m");
    expect(colored.stdout).toContain("\u001B[1mVALIDATION\u001B[22m");
    expect(colored.stdout).toContain(
      "\u001B[90mDisposition:\u001B[39m confirmed",
    );
    expect(colored.stdout).toContain("\u001B[90m• \u001B[39m");
    expect(colored.stdout).toContain("\u001B[36msrc/finding-1.ts:18\u001B[39m");
    expect(colored.stdout).not.toContain("\u001B[92m");
    expect(colored.stdout).not.toContain("\u001B[95mCODE EVIDENCE");
    expect(colored.stdout).not.toContain("\u001B[32mVALIDATION");
    expect(colored.stdout).not.toContain("\u001B[33m→");
    expect(colored.stdout).not.toContain("\u001B[4m");

    const plain = run(false);

    expect(plain.status).toBe(0);
    expect(plain.stdout).not.toMatch(/\u001B\[\d+m/u);
  });
});

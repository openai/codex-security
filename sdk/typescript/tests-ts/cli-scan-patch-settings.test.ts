import { mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { describe, expect, test } from "bun:test";
import { main, runCodexSkillCommand } from "../src/cli.js";
import { dependencies, fakePreflight, fakeResult } from "./cli-fixtures.js";
import { createCliTest } from "./support/cli-run.js";
import { temporaryDirectory } from "./support/temporary-directories.js";

const childSource = `
import { readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { createInterface } from "node:readline";
let homeConfig = "";
try { homeConfig = readFileSync(join(process.env.CODEX_HOME, "config.toml"), "utf8"); }
catch (error) { if (error.code !== "ENOENT") throw error; }
const receipt = { argv: process.argv.slice(2), homeTier: homeConfig.match(/^service_tier\\s*=\\s*(.*)$/m)?.[1] ?? null };
const send = (value) => process.stdout.write(JSON.stringify(value) + "\\n");
for await (const line of createInterface({ input: process.stdin })) {
  const request = JSON.parse(line);
  if (request.method === "account/login/start") receipt.loginType = request.params.type;
  if (request.method === "thread/start") {
    receipt.approvalPolicy = request.params.approvalPolicy;
    receipt.sandbox = request.params.sandbox;
    send({ id: request.id, result: { thread: { id: "synthetic-thread" }, sandbox: { type: "workspaceWrite" } } });
  } else if (request.method === "command/exec") {
    receipt.preflightSandbox = request.params.sandboxPolicy.type;
    send({ id: request.id, result: { exitCode: 0 } });
  } else if (request.method === "turn/start") {
    writeFileSync(process.env.SYNTHETIC_PATCH_RECEIPT, JSON.stringify(receipt));
    send({ id: request.id, result: { turn: { id: "synthetic-turn" } } });
    send({ method: "item/completed", params: { threadId: "synthetic-thread", turnId: "synthetic-turn", item: { type: "agentMessage", text: JSON.stringify({ patches: [{ occurrenceId: "occ_1", status: "no_change", files: [], verification: "Synthetic child-process fixture completed." }] }) } } });
    send({ method: "turn/completed", params: { threadId: "synthetic-thread", turn: { id: "synthetic-turn", status: "completed" } } });
  } else if (request.id !== undefined) send({ id: request.id, result: {} });
}
`;

interface ChildReceipt {
  argv: string[];
  homeTier: string | null;
  loginType: string;
  approvalPolicy: string;
  sandbox: string;
  preflightSandbox: string;
}

async function inlinePatch(
  settings: string[],
  beforeChild?: () => Promise<void>,
  homeConfig?: string,
): Promise<ChildReceipt> {
  const root = await temporaryDirectory("inline-patch-settings-");
  const repository = join(root, "repository");
  const child = join(root, "child.mjs");
  const receipt = join(root, "receipt.json");
  try {
    await mkdir(repository);
    await writeFile(join(repository, "app.ts"), "const value = 1;\n");
    await writeFile(child, childSource);
    const result = fakeResult(["high"]);
    Object.assign(result.findings.findings[0]!, {
      occurrenceId: "occ_1",
      findingId: "csf_1",
      title: "Synthetic finding",
      locations: [{ path: "app.ts", startLine: 1 }],
    });
    const environment = {
      ...Object.fromEntries(
        Object.entries(process.env).filter(([name]) =>
          /^(path|systemroot|comspec|temp|tmp|tmpdir)$/iu.test(name),
        ),
      ),
      OPENAI_API_KEY: "SYNTHETIC_LOCAL_KEY",
      CODEX_HOME: join(root, "home"),
      CODEX_SECURITY_STATE_DIR: join(root, "state"),
      SYNTHETIC_PATCH_RECEIPT: receipt,
    };
    if (homeConfig !== undefined) {
      await mkdir(environment.CODEX_HOME, { recursive: true });
      await writeFile(join(environment.CODEX_HOME, "config.toml"), homeConfig);
    }
    const { stderr, runCli } = createCliTest(main);
    const status = await runCli(
      [
        "scan",
        repository,
        "--patch",
        "--auth",
        "api-key",
        "--model",
        "gpt-6.1-sol",
        "--effort",
        "low",
        "--codex",
        "features.goals=false",
        ...settings,
        "--json",
      ],
      dependencies({
        currentDirectory: repository,
        environment,
        result,
        preflight: {
          ...fakePreflight(repository),
          model: "gpt-6.1-sol",
          reasoningEffort: "low",
        },
        onCodex: async (args, output, selectedEnvironment) => {
          await beforeChild?.();
          return runCodexSkillCommand(
            [child, ...args],
            output,
            { command: process.execPath },
            selectedEnvironment,
          );
        },
      }),
    );
    expect(status, stderr.text()).toBe(0);
    expect(await readFile(join(repository, "app.ts"), "utf8")).toBe(
      "const value = 1;\n",
    );
    return JSON.parse(await readFile(receipt, "utf8")) as ChildReceipt;
  } finally {
    await rm(root, { recursive: true, force: true });
  }
}

describe("inline patch service tier", () => {
  test.each([
    ["explicit fast", ["--codex", 'service_tier="fast"'], "fast"],
    [
      "selected profile fast",
      [
        "--mode",
        "deep",
        "--codex",
        'service_tier="standard"',
        "--codex",
        'profile="synthetic"',
        "--codex",
        'profiles.synthetic.service_tier="fast"',
      ],
      "fast",
    ],
    [
      "selected profile standard",
      [
        "--codex",
        'service_tier="fast"',
        "--codex",
        'profile="synthetic"',
        "--codex",
        'profiles.synthetic.service_tier="standard"',
      ],
      "standard",
    ],
    ["native default", [], "default"],
  ] as const)(
    "preserves %s at the child-process boundary",
    async (_, settings, tier) => {
      const child = await inlinePatch([...settings]);
      expect(
        child.argv.filter((value) => value.startsWith("service_tier=")),
      ).toEqual([`service_tier=${JSON.stringify(tier)}`]);
      expect(child.argv).toContain('model="gpt-6.1-sol"');
      expect(child.argv).toContain('model_reasoning_effort="low"');
      expect(child.argv).not.toContain("features.goals=false");
      expect(child.homeTier).toBeNull();
      expect(child.loginType).toBe("apiKey");
      expect(child.approvalPolicy).toBe("never");
      expect(child.sandbox).toBe("workspace-write");
      expect(child.preflightSandbox).toBe("workspaceWrite");
    },
  );

  test("preserves the scan native default over an ambient fast tier", async () => {
    const child = await inlinePatch([], undefined, 'service_tier = "fast"\n');
    expect(child.argv).toContain('service_tier="default"');
    expect(child.homeTier).toBe('"fast"');
    expect(child.loginType).toBe("apiKey");
    expect(child.approvalPolicy).toBe("never");
    expect(child.sandbox).toBe("workspace-write");
  });

  test("keeps overlapping scan tiers isolated", async () => {
    let arrivals = 0;
    const { promise: ready, resolve: release } = Promise.withResolvers<void>();
    const beforeChild = async () => {
      if (++arrivals === 2) release();
      await ready;
    };
    const children = await Promise.all([
      inlinePatch(
        ["--codex", 'service_tier="fast"'],
        beforeChild,
        'service_tier = "standard"\n',
      ),
      inlinePatch([], beforeChild, 'service_tier = "fast"\n'),
    ]);
    expect(children[0]!.argv).toContain('service_tier="fast"');
    expect(children[1]!.argv).toContain('service_tier="default"');
    expect(children.map((child) => child.homeTier)).toEqual([
      '"standard"',
      '"fast"',
    ]);
  });

  test("retains standalone patch override compatibility", async () => {
    let invoked = false;
    const { runCli } = createCliTest(main);
    const status = await runCli(
      ["patch", "Synthetic issue", "--codex", 'service_tier="fast"', "--json"],
      dependencies({
        onCodex: () => {
          invoked = true;
          return 0;
        },
      }),
    );
    expect(status).toBe(2);
    expect(invoked).toBe(false);
  });
});

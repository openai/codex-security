import { mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { describe, expect, test } from "bun:test";
import { parse } from "smol-toml";
import { main, runCodexSkillCommand } from "../src/cli.js";
import { FIREWORKS_CODEX_PROVIDER, inlineToml } from "../src/config.js";
import { dependencies, fakePreflight, fakeResult } from "./cli-fixtures.js";
import { runGitRepositoryCommand } from "./cli-patch-fixtures.js";
import { createCliTest } from "./support/cli-run.js";
import { temporaryDirectory } from "./support/temporary-directories.js";

const childSource = `
import { send, completeTurn } from ${JSON.stringify(new URL("./fixtures/app-server-messages.mjs", import.meta.url).href)};
import { readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { createInterface } from "node:readline";
let homeConfig = "";
try { homeConfig = readFileSync(join(process.env.CODEX_HOME, "config.toml"), "utf8"); }
catch (error) { if (error.code !== "ENOENT") throw error; }
const receipt = {
  argv: process.argv.slice(2),
  homeTier: homeConfig.match(/^service_tier\\s*=\\s*(.*)$/m)?.[1] ?? null,
  homeDaybreak: homeConfig.match(/^daybreak\\s*=\\s*(.*)$/m)?.[1] ?? null,
  providerKey: process.env.SYNTHETIC_PROVIDER_KEY ?? null,
  providerHeader: process.env.SYNTHETIC_PROVIDER_HEADER ?? null,
};
for await (const line of createInterface({ input: process.stdin })) {
  const request = JSON.parse(line);
  if (request.method === "initialize") receipt.experimentalApi = request.params.capabilities?.experimentalApi;
  if (request.method === "account/login/start") receipt.loginType = request.params.type;
  if (request.method === "config/read") {
    const daybreak = receipt.argv.find((value) => value.startsWith("daybreak="))?.slice("daybreak=".length) ?? receipt.homeDaybreak;
    const features = Object.fromEntries(["cli_daybreak", "api_key_cyber_access_programs", "api_key_model_discovery"].map((name) => {
      const prefix = "features." + name + "=";
      const value = receipt.argv.find((arg) => arg.startsWith(prefix))?.slice(prefix.length);
      return [name, value === undefined ? !homeConfig.includes("features." + name + " = false") : JSON.parse(value)];
    }));
    receipt.features = features;
    send({ id: request.id, result: { config: {
      ...(daybreak === null ? {} : { daybreak: JSON.parse(daybreak) }),
      features,
    }, layers: [] } });
  } else if (request.method === "experimentalFeature/list") {
    send({ id: request.id, result: { data: [{ name: "cli_daybreak", enabled: receipt.features.cli_daybreak }, { name: "api_key_cyber_access_programs", enabled: receipt.features.api_key_cyber_access_programs !== false }], nextCursor: null } });
  } else if (request.method === "account/read") {
    send({ id: request.id, result: { account: { type: "apiKey" } } });
  } else if (request.method === "model/list") {
    send({ id: request.id, result: { data: [{ model: "gpt-6.1-sol", availableAccessPrograms: { cyber: JSON.parse(process.env.SYNTHETIC_CYBER_PROGRAMS) } }], nextCursor: null } });
  } else if (request.method === "thread/start") {
    receipt.daybreakEnabled = request.params.daybreakEnabled ?? null;
    receipt.approvalPolicy = request.params.approvalPolicy;
    receipt.sandbox = request.params.sandbox;
    send({ id: request.id, result: { thread: { id: "synthetic-thread" }, model: "gpt-6.1-sol", modelProvider: "openai", sandbox: { type: "workspaceWrite" } } });
  } else if (request.method === "command/exec") {
    receipt.preflightSandbox = request.params.sandboxPolicy.type;
    send({ id: request.id, result: { exitCode: 0 } });
  } else if (request.method === "turn/start") {
    receipt.cyberAccessProgram = request.params.cyberAccessProgram ?? null;
    writeFileSync(process.env.SYNTHETIC_PATCH_RECEIPT, JSON.stringify(receipt));
    completeTurn(request, () => JSON.stringify({ patches: [{ occurrenceId: "occ_1", status: "no_change", files: [], verification: "Synthetic child-process fixture completed." }] }), "synthetic-thread");
  } else if (request.id !== undefined) send({ id: request.id, result: {} });
}
`;

interface ChildReceipt {
  argv: string[];
  homeTier: string | null;
  homeDaybreak: string | null;
  loginType: string;
  approvalPolicy: string;
  sandbox: string;
  preflightSandbox: string;
  cyberAccessProgram: string | null;
  daybreakEnabled: boolean | null;
  experimentalApi: boolean;
  features: Record<string, boolean>;
  providerKey: string | null;
  providerHeader: string | null;
}

async function patchSettings(
  settings: string[],
  options: {
    beforeChild?: () => Promise<void>;
    homeConfig?: string;
    standalone?: boolean;
    programs?: string[];
  } = {},
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
      FIREWORKS_API_KEY: "SYNTHETIC_FIREWORKS_KEY",
      SYNTHETIC_ROOT_KEY: "SYNTHETIC_ROOT_VALUE",
      SYNTHETIC_PROVIDER_KEY: "SYNTHETIC_PROVIDER_VALUE",
      SYNTHETIC_PROVIDER_HEADER: "SYNTHETIC_HEADER_VALUE",
      CODEX_HOME: join(root, "home"),
      CODEX_SECURITY_STATE_DIR: join(root, "state"),
      SYNTHETIC_PATCH_RECEIPT: receipt,
      SYNTHETIC_CYBER_PROGRAMS: JSON.stringify(
        options.programs ?? ["standard", "daybreakRed", "daybreakBlue"],
      ),
    };
    if (options.homeConfig !== undefined) {
      await mkdir(environment.CODEX_HOME, { recursive: true });
      await writeFile(
        join(environment.CODEX_HOME, "config.toml"),
        options.homeConfig,
      );
    }
    const { stdout, stderr, runCli } = createCliTest(main);
    const status = await runCli(
      [
        ...(options.standalone
          ? ["patch", "Synthetic finding"]
          : ["scan", repository, "--patch", "--codex", "features.goals=false"]),
        "--auth",
        "api-key",
        "--model",
        "gpt-6.1-sol",
        "--effort",
        "low",
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
        manualCodexPreparation: true,
        onRepositoryCommand: runGitRepositoryCommand,
        onCodex: async (args, output, selectedEnvironment) => {
          await options.beforeChild?.();
          return runCodexSkillCommand(
            [child, ...args],
            output,
            { command: process.execPath },
            selectedEnvironment,
          );
        },
      }),
    );
    expect(status, stderr.text()).toBe(options.standalone ? 2 : 0);
    if (options.standalone)
      expect(JSON.parse(stdout.text())).toMatchObject({
        applied: false,
        filesChanged: 0,
        files: [],
        error: { code: "NO_PATCH_APPLIED" },
      });
    expect(await readFile(join(repository, "app.ts"), "utf8")).toBe(
      "const value = 1;\n",
    );
    return JSON.parse(await readFile(receipt, "utf8")) as ChildReceipt;
  } finally {
    await rm(root, { recursive: true, force: true });
  }
}

describe("inline patch provider configuration", () => {
  const provider = {
    name: "Synthetic gateway",
    base_url: "https://root.example.test/v1",
    wire_api: "responses",
    env_key: "SYNTHETIC_ROOT_KEY",
    http_headers: { "X-Root": "retained", "X-Selected": "root" },
  };
  const selected = {
    base_url: "https://selected.example.test/v1",
    env_key: "SYNTHETIC_PROVIDER_KEY",
    http_headers: { "X-Selected": "profile" },
    env_http_headers: { "X-Synthetic": "SYNTHETIC_PROVIDER_HEADER" },
  };
  const root = [
    'model_provider="gateway"',
    `model_providers.gateway=${inlineToml(provider)}`,
  ];
  const definition = (child: ChildReceipt) =>
    parse(
      child.argv
        .filter((value) => value.startsWith("model_providers="))
        .join("\n"),
    )["model_providers"];

  test.each([
    ["root definition", root, provider],
    [
      "profile-only definition",
      [
        'profile="selected"',
        'profiles.selected.model_provider="gateway"',
        `profiles.selected.model_providers.gateway=${inlineToml(provider)}`,
      ],
      provider,
    ],
    [
      "selected profile overrides",
      [
        ...root,
        'profile="selected"',
        `profiles.selected.model_providers.gateway=${inlineToml(selected)}`,
      ],
      {
        ...provider,
        ...selected,
        http_headers: { ...provider.http_headers, ...selected.http_headers },
      },
    ],
    [
      "inactive profile",
      [
        ...root,
        `profiles.inactive.model_providers.gateway=${inlineToml(selected)}`,
      ],
      provider,
    ],
  ] as const)(
    "preserves the %s at the child-process boundary",
    async (_, overrides, expected) => {
      const child = await patchSettings(
        overrides.flatMap((value) => ["--codex", value]),
      );
      expect(child.argv).toContain('model_provider="gateway"');
      expect(definition(child)).toEqual({ gateway: expected });
      expect(child.providerKey).toBe("SYNTHETIC_PROVIDER_VALUE");
      expect(child.providerHeader).toBe("SYNTHETIC_HEADER_VALUE");
      expect(child.argv).toContain('model="gpt-6.1-sol"');
      expect(child.argv).toContain('model_reasoning_effort="low"');
      expect(child.approvalPolicy).toBe("never");
      expect(child.sandbox).toBe("workspace-write");
      expect(child.preflightSandbox).toBe("workspaceWrite");
    },
  );

  test.each([
    ["no override", undefined, FIREWORKS_CODEX_PROVIDER],
    [
      "partial override",
      { http_headers: { "X-Selected": "profile" } },
      {
        ...FIREWORKS_CODEX_PROVIDER,
        http_headers: { "X-Selected": "profile" },
      },
    ],
    ["full override", provider, provider],
  ] as const)(
    "preserves external provider defaults with a selected profile %s",
    async (_, override, expected) => {
      const child = await patchSettings(
        [
          'profile="selected"',
          'profiles.selected.model_provider="fireworks"',
          ...(override === undefined
            ? []
            : [
                `profiles.selected.model_providers.fireworks=${inlineToml(override)}`,
              ]),
        ].flatMap((value) => ["--codex", value]),
      );
      expect(child.argv).toContain('model_provider="fireworks"');
      expect(definition(child)).toEqual({ fireworks: expected });
    },
  );

  test("keeps overlapping selected provider definitions isolated", async () => {
    let arrivals = 0;
    const { promise: ready, resolve: release } = Promise.withResolvers<void>();
    const beforeChild = async () => {
      if (++arrivals === 2) release();
      await ready;
    };
    const providers = ["first", "second"].map((name) => ({
      ...provider,
      base_url: `https://${name}.example.test/v1`,
    }));
    const children = await Promise.all(
      providers.map((definition) =>
        patchSettings(
          [
            "--codex",
            'profile="selected"',
            "--codex",
            'profiles.selected.model_provider="gateway"',
            "--codex",
            `profiles.selected.model_providers.gateway=${inlineToml(definition)}`,
          ],
          { beforeChild },
        ),
      ),
    );
    expect(children.map(definition)).toEqual(
      providers.map((gateway) => ({ gateway })),
    );
  });
});

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
      const child = await patchSettings([...settings]);
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
    const child = await patchSettings([], {
      homeConfig: 'service_tier = "fast"\n',
    });
    expect(child.argv).toContain('service_tier="default"');
    expect(child.homeTier).toBe('"fast"');
    expect(child.loginType).toBe("apiKey");
    expect(child.approvalPolicy).toBe("never");
    expect(child.sandbox).toBe("workspace-write");
  });

  test("keeps overlapping scan tiers and Daybreak settings isolated", async () => {
    let arrivals = 0;
    const { promise: ready, resolve: release } = Promise.withResolvers<void>();
    const beforeChild = async () => {
      if (++arrivals === 2) release();
      await ready;
    };
    const children = await Promise.all([
      patchSettings(
        ["--codex", 'service_tier="fast"', "--codex", "daybreak=true"],
        {
          beforeChild,
          homeConfig: 'service_tier = "standard"\ndaybreak = false\n',
        },
      ),
      patchSettings([], {
        beforeChild,
        homeConfig: 'service_tier = "fast"\ndaybreak = true\n',
      }),
    ]);
    expect(children[0]!.argv).toContain('service_tier="fast"');
    expect(children[1]!.argv).toContain('service_tier="default"');
    expect(children[0]!.argv).toContain("daybreak=true");
    expect(children[1]!.argv).toContain("daybreak=false");
    expect(children.map((child) => child.cyberAccessProgram)).toEqual([
      "daybreakBlue",
      "standard",
    ]);
    expect(children.map((child) => child.homeTier)).toEqual([
      '"standard"',
      '"fast"',
    ]);
    expect(children.map((child) => child.homeDaybreak)).toEqual([
      "false",
      "true",
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

describe("patch Daybreak configuration", () => {
  test.each([true, false, undefined])(
    "preserves standalone native configuration (override: %p)",
    async (daybreak) => {
      const child = await patchSettings(
        daybreak === undefined ? [] : ["--codex", `daybreak = ${daybreak}`],
        { standalone: true, homeConfig: "daybreak = true\n" },
      );
      expect(
        child.argv.filter((value) => value.startsWith("daybreak=")),
      ).toEqual(daybreak === undefined ? [] : [`daybreak=${daybreak}`]);
      expect(child.homeDaybreak).toBe("true");
      expect(child.cyberAccessProgram).toBe(
        daybreak === false ? "standard" : "daybreakBlue",
      );
      expect(child.daybreakEnabled).toBe(daybreak === false ? null : true);
      expect(child.experimentalApi).toBe(true);
    },
  );

  test.each([
    ["explicit true", ["daybreak=true"], true],
    ["explicit false", ["daybreak=false"], false],
    [
      "selected profile true",
      [
        "daybreak=false",
        'profile="synthetic"',
        "profiles.synthetic.daybreak=true",
      ],
      true,
    ],
    [
      "selected profile false",
      [
        "daybreak=true",
        'profile="synthetic"',
        "profiles.synthetic.daybreak=false",
      ],
      false,
    ],
    ["default over ambient true", [], false],
  ] as const)(
    "preserves inline scan %s at the child-process boundary",
    async (_, overrides, daybreak) => {
      const child = await patchSettings(
        overrides.flatMap((override) => ["--codex", override]),
        { homeConfig: "daybreak = true\n" },
      );
      expect(
        child.argv.filter((value) => value.startsWith("daybreak=")),
      ).toEqual([`daybreak=${daybreak}`]);
      expect(child.homeDaybreak).toBe("true");
      expect(child.cyberAccessProgram).toBe(
        daybreak ? "daybreakBlue" : "standard",
      );
      expect(child.daybreakEnabled).toBe(daybreak ? true : null);
    },
  );

  test("selects advertised Red when Blue is unavailable", async () => {
    const child = await patchSettings(["--codex", "daybreak=true"], {
      programs: ["standard", "daybreakRed"],
    });
    expect(child.cyberAccessProgram).toBe("daybreakRed");
  });

  test("honors the native Daybreak feature disable", async () => {
    const child = await patchSettings(["--codex", "daybreak=true"], {
      homeConfig: "features.cli_daybreak = false\n",
      standalone: true,
    });
    expect(child.cyberAccessProgram).toBeNull();
    expect(child.daybreakEnabled).toBe(true);
  });

  test("defaults a standalone turn to advertised standard", async () => {
    const child = await patchSettings([], { standalone: true });
    expect(child.cyberAccessProgram).toBe("standard");
    expect(child.daybreakEnabled).toBeNull();
  });

  test.each([
    ["standard", true, "standard"],
    ["daybreak_blue", false, "daybreakBlue"],
    ["daybreak_red", false, "daybreakRed"],
  ] as const)(
    "preserves the scan's explicit %s program over Daybreak %p",
    async (program, daybreak, expected) => {
      const child = await patchSettings(
        [
          "--cyber-access-program",
          program,
          "--codex",
          `daybreak=${daybreak}`,
          "--codex",
          "features.cli_daybreak=false",
        ],
        { homeConfig: "features.cli_daybreak = false\n" },
      );
      expect(child.cyberAccessProgram).toBe(expected);
      expect(child.daybreakEnabled).toBe(daybreak ? true : null);
    },
  );

  test.each([
    "cli_daybreak",
    "api_key_cyber_access_programs",
    "api_key_model_discovery",
  ])(
    "preserves the scan's %s feature gate over ambient settings",
    async (feature) => {
      const overridden = await patchSettings([
        "--codex",
        'profile="synthetic"',
        "--codex",
        `features.${feature}=true`,
        "--codex",
        `profiles.synthetic.features.${feature}=false`,
      ]);
      expect(overridden.argv).toContain(`features.${feature}=false`);
      expect(overridden.features[feature]).toBe(false);
      if (feature !== "api_key_model_discovery")
        expect(overridden.cyberAccessProgram).toBeNull();

      const defaulted = await patchSettings([], {
        homeConfig: `features.${feature} = false\n`,
      });
      expect(defaulted.argv).toContain(`features.${feature}=true`);
      expect(defaulted.features[feature]).toBe(true);
      expect(defaulted.cyberAccessProgram).toBe("standard");
    },
  );
});

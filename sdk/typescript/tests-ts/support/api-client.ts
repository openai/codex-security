import { CodexSecurity } from "../../src/api.js";
import type { JsonObject } from "../../src/config.js";

type ClientArguments = ConstructorParameters<typeof CodexSecurity>;

export const TEST_SNAPSHOT_DIGEST = `codex-security-snapshot/v1:sha256:${"a".repeat(64)}`;

export function mockScanRegistration(
  args: readonly string[],
  input?: string,
): JsonObject {
  if (!args.includes("--registration-json-stdin") || input === undefined) {
    throw new Error("missing stdin scan registration");
  }
  const recipe = JSON.parse(input).recipe as {
    repositoryRevision?: string;
    target: { kind: string };
  };
  const kind =
    recipe.target.kind === "refs" || recipe.target.kind === "working_tree"
      ? "git_diff"
      : recipe.repositoryRevision === undefined
        ? "directory_snapshot"
        : "git_revision";

  return {
    scanId: "scan_example_001",
    targetId: "target_sha256_example",
    targetRevision: recipe.repositoryRevision ?? "unversioned",
    scanDir: args[args.indexOf("--scan-dir") + 1]!,
    contract: {
      target: {
        allowedKinds: [kind],
        ...(kind === "directory_snapshot"
          ? { requiredSnapshotDigest: TEST_SNAPSHOT_DIGEST }
          : {}),
      },
    },
  };
}

export function mockWorkbench(
  args: readonly string[],
  input?: string,
): JsonObject {
  if (args[0] === "register-cli-scan") {
    return mockScanRegistration(args, input);
  }
  if (args[0] === "get-scan-feedback") {
    return {
      scanId: "scan_example_001",
      targetId: "target_sha256_example",
      falsePositives: [],
    };
  }
  return {};
}

export class TestClient extends CodexSecurity {
  public constructor(
    config: ClientArguments[0],
    dependencies: Partial<ClientArguments[1]>,
  ) {
    super(
      config,
      {
        createCodex: () => {
          throw new Error("Unexpected Codex invocation in test");
        },
        environment: {},
        runWorkbench: async (_options, args, input) =>
          mockWorkbench(args, input),
        ...dependencies,
      },
      { surface: "sdk" },
    );
  }
}

export const SHELL_ENVIRONMENT_PREFIX =
  process.platform === "win32" ? "$env:" : "$";

export function shellEnvironmentReference(name: string, suffix = ""): string {
  return `"${SHELL_ENVIRONMENT_PREFIX}${name}${suffix}"`;
}

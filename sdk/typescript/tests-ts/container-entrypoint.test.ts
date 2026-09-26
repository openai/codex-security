import { spawnSync, type SpawnSyncReturns } from "node:child_process";
import { existsSync } from "node:fs";
import { mkdtemp, readFile, realpath, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { delimiter, join } from "node:path";
import { describe, expect, test } from "bun:test";

const testPosix = process.platform === "win32" ? test.skip : test;
const publicEntrypoint = join(
  import.meta.dir,
  "..",
  "..",
  "..",
  "docker",
  "entrypoint.sh",
);
const entrypoint = existsSync(publicEntrypoint)
  ? publicEntrypoint
  : join(import.meta.dir, "..", "public-repo", "docker", "entrypoint.sh");
const publicVersionVerifier = join(
  import.meta.dir,
  "..",
  "..",
  "..",
  "docker",
  "verify-container-release-version.sh",
);
const versionVerifier = existsSync(publicVersionVerifier)
  ? publicVersionVerifier
  : join(
      import.meta.dir,
      "..",
      "public-repo",
      "docker",
      "verify-container-release-version.sh",
    );
async function runEntrypoint(
  args: readonly string[],
  overrides: Record<string, string> = {},
): Promise<SpawnSyncReturns<string>> {
  const root = await realpath(
    await mkdtemp(join(tmpdir(), "codex-security-container-entrypoint-")),
  );

  try {
    await writeFile(
      join(root, "codex-security"),
      "#!/bin/sh\nprintf '%s\\n' \"$@\"\n",
      { mode: 0o755 },
    );

    return spawnSync("sh", [entrypoint, ...args], {
      encoding: "utf8",
      env: {
        ...process.env,
        GH_TOKEN: "",
        GITHUB_TOKEN: "",
        PATH: `${root}${delimiter}${process.env["PATH"] ?? ""}`,
        ...overrides,
      },
      timeout: 10_000,
    });
  } finally {
    await rm(root, { recursive: true, force: true });
  }
}

async function runVersionVerifier(
  response: string,
  failure = false,
): Promise<SpawnSyncReturns<string> & { workflowOutput: string }> {
  const root = await realpath(
    await mkdtemp(join(tmpdir(), "codex-security-container-version-")),
  );

  try {
    await writeFile(
      join(root, "gh"),
      [
        "#!/bin/sh",
        'if [ "$1" != api ] || [ "$2" != --paginate ] ||',
        '    [ "$3" != "$EXPECTED_ENDPOINT/versions?per_page=100" ]; then',
        '    printf "%s\\n" "Unexpected GitHub API request." >&2',
        "    exit 64",
        "fi",
        'if [ "$GH_FIXTURE_FAILURE" = 1 ]; then',
        '    printf "%s\\n" "Synthetic package lookup failed." >&2',
        "    exit 1",
        "fi",
        'printf "%s\\n" "$GH_FIXTURE_RESPONSE"',
        "",
      ].join("\n"),
      { mode: 0o755 },
    );

    const endpoint = "orgs/openai/packages/container/codex-security";
    const output = join(root, "output");
    await writeFile(output, "");
    const result = spawnSync("sh", [versionVerifier, endpoint, "0.1.4"], {
      encoding: "utf8",
      env: {
        ...process.env,
        EXPECTED_ENDPOINT: endpoint,
        GH_FIXTURE_FAILURE: failure ? "1" : "0",
        GH_FIXTURE_RESPONSE: response,
        GITHUB_OUTPUT: output,
        PATH: `${root}${delimiter}${process.env["PATH"] ?? ""}`,
      },
      timeout: 10_000,
    });
    return { ...result, workflowOutput: await readFile(output, "utf8") };
  } finally {
    await rm(root, { recursive: true, force: true });
  }
}

describe("customer container entrypoint", () => {
  testPosix(
    "preserves CSV scan arguments without selecting the legacy sandbox",
    async () => {
      const result = await runEntrypoint([
        "bulk-scan",
        "/input/repositories.csv",
        "--output-dir",
        "/output",
        "--workers",
        "2",
      ]);

      expect(result.status).toBe(0);
      expect(result.stderr).toBe("");
      expect(result.stdout).toBe(
        [
          "bulk-scan",
          "/input/repositories.csv",
          "--output-dir",
          "/output",
          "--workers",
          "2",
          "",
        ].join("\n"),
      );
    },
  );

  testPosix("accepts CSVs after global and bulk-scan options", async () => {
    for (const arguments_ of [
      ["bulk-scan", "--workers", "2", "/input/repositories.csv"],
      ["bulk-scan", "--max-cost", "12.50", "/input/repositories.csv"],
      ["bulk-scan", "bulk-scan", "--output-dir", "/output"],
      [
        "--format",
        "toon",
        "bulk-scan",
        "--output-dir=/output",
        "/input/repositories.csv",
      ],
    ] as const) {
      const result = await runEntrypoint(arguments_);
      expect(result.status).toBe(0);
      expect(result.stderr).toBe("");
      expect(result.stdout).toBe([...arguments_, ""].join("\n"));
    }
  });

  testPosix(
    "preserves bulk-scan help without injecting scan configuration",
    async () => {
      const result = await runEntrypoint(["bulk-scan", "--help"]);

      expect(result.status).toBe(0);
      expect(result.stderr).toBe("");
      expect(result.stdout).toBe("bulk-scan\n--help\n");
    },
  );

  testPosix("preserves explicit Codex sandbox settings", async () => {
    const arguments_ = [
      "bulk-scan",
      "/input/repositories.csv",
      "--output-dir",
      "/output",
      "--codex",
      "features.use_legacy_landlock=false",
    ];
    const result = await runEntrypoint(arguments_);

    expect(result.status).toBe(0);
    expect(result.stderr).toBe("");
    expect(result.stdout).toBe(`${arguments_.join("\n")}\n`);
  });

  testPosix(
    "rejects interactive discovery before starting the CLI",
    async () => {
      for (const arguments_ of [
        ["bulk-scan"],
        ["bulk-scan", "--workers", "8"],
        ["bulk-scan", "--max-cost", "12.50"],
        ["bulk-scan", "--scan-prompt-file", "prompt.md"],
        ["bulk-scan", "--post-scan-prompt-file", "post-prompt.md"],
        ["--format", "json", "bulk-scan", "--mode", "deep"],
      ] as const) {
        const result = await runEntrypoint(arguments_);
        expect(result.status).toBe(2);
        expect(result.stdout).toBe("");
        expect(result.stderr).toContain(
          "interactive discovery is not supported",
        );
      }
    },
  );

  testPosix("rejects unsupported bulk-scan option terminators", async () => {
    for (const arguments_ of [
      ["bulk-scan", "--output-dir", "/output", "--", "--help"],
      ["bulk-scan", "--output-dir", "--", "--help"],
    ] as const) {
      const result = await runEntrypoint(arguments_);
      expect(result.status).toBe(2);
      expect(result.stderr).toContain(
        "does not support the -- option terminator",
      );
    }
  });

  testPosix("does not change non-scan commands", async () => {
    const result = await runEntrypoint(["--version"]);

    expect(result.status).toBe(0);
    expect(result.stderr).toBe("");
    expect(result.stdout).toBe("--version\n");
  });
});

describe("immutable customer container releases", () => {
  testPosix("fails closed when package versions cannot be read", async () => {
    const result = await runVersionVerifier("", true);

    expect(result.status).toBe(1);
    expect(result.stderr).toContain("Synthetic package lookup failed.");
    expect(result.stderr).toContain("refusing to publish");
  });

  testPosix("rejects an existing immutable release version", async () => {
    const result = await runVersionVerifier(
      JSON.stringify([
        { metadata: { container: { tags: ["0.1.4", "latest"] } } },
      ]),
    );

    expect(result.status).toBe(1);
    expect(result.stderr).toContain("Container version 0.1.4 already exists");
  });

  testPosix(
    "accepts an unpublished version across paginated results",
    async () => {
      const result = await runVersionVerifier(
        `${JSON.stringify([
          { metadata: { container: { tags: ["0.1.3", "latest"] } } },
        ])}\n[]`,
      );

      expect(result.status).toBe(0);
      expect(result.stderr).toBe("");
      expect(result.stdout).toBe("");
      expect(result.workflowOutput).toBe("publish_latest=true\n");
    },
  );

  testPosix(
    "publishes older stable versions without moving latest backwards",
    async () => {
      for (const tags of [["0.1.5", "latest"], ["0.10.0"], ["1.0.0"]]) {
        const result = await runVersionVerifier(
          `[]\n${JSON.stringify([{ metadata: { container: { tags } } }])}`,
        );
        expect(result.status).toBe(0);
        expect(result.stdout).toBe("");
        expect(result.workflowOutput).toBe("publish_latest=false\n");
      }
    },
  );

  testPosix("fails closed when the version response is malformed", async () => {
    const result = await runVersionVerifier("{not-json");

    expect(result.status).toBe(1);
    expect(result.stderr).toContain("refusing to publish");
  });
});

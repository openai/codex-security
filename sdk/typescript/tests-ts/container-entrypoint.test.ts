import { spawnSync, type SpawnSyncReturns } from "node:child_process";
import { existsSync } from "node:fs";
import { mkdtemp, readFile, realpath, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { delimiter, join } from "node:path";
import { describe, expect, test } from "bun:test";

const testPosix = process.platform === "win32" ? test.skip : test;
function dockerScript(name: string): string {
  const canonical = join(import.meta.dir, "..", "..", "..", "docker", name);
  return existsSync(canonical)
    ? canonical
    : join(import.meta.dir, "..", "public-repo", "docker", name);
}
const entrypoint = dockerScript("entrypoint.sh");
const versionVerifier = dockerScript("verify-container-release-version.sh");
async function runEntrypoint(
  args: readonly string[],
  overrides: Record<string, string> = {},
  command = "printf '%s\\n' \"$@\"",
): Promise<SpawnSyncReturns<string>> {
  const root = await realpath(
    await mkdtemp(join(tmpdir(), "codex-security-container-entrypoint-")),
  );

  try {
    await writeFile(join(root, "codex-security"), `#!/bin/sh\n${command}\n`, {
      mode: 0o755,
    });

    return spawnSync("sh", [entrypoint, ...args], {
      cwd: root,
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
  expectedDigest?: string,
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
    const result = spawnSync(
      "sh",
      [
        versionVerifier,
        endpoint,
        "0.1.4",
        ...(expectedDigest === undefined ? [] : [expectedDigest]),
      ],
      {
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
      },
    );
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
      ["bulk-scan", "--config", "settings.json", "/input/repositories.csv"],
      ["bulk-scan", "-c", "settings.json", "/input/repositories.csv"],
      [
        "bulk-scan",
        "--validation-prompt-file",
        "prompt.md",
        "/input/repositories.csv",
      ],
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
        ["bulk-scan", "--config", "settings.json"],
        ["bulk-scan", "-c", "settings.json"],
        ["bulk-scan", "--validation-prompt-file", "prompt.md"],
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

  testPosix(
    "appends authentication settings after existing Git configuration",
    async () => {
      for (const count of [0, 128, 129, 256]) {
        const entries = Array.from({ length: count }, (_, index) => [
          `fixture.setting${index}`,
          `synthetic-value-${index}`,
        ]);
        const configuration = Object.fromEntries(
          entries.flatMap(([key, value], index) => [
            [`GIT_CONFIG_KEY_${index}`, key],
            [`GIT_CONFIG_VALUE_${index}`, value],
          ]),
        );
        const result = await runEntrypoint(
          ["--version"],
          {
            GH_TOKEN: "synthetic-token",
            CODEX_SECURITY_GIT_HOST: "git.example.test",
            GIT_CONFIG_COUNT: String(count),
            GIT_CONFIG_NOSYSTEM: "1",
            GIT_CONFIG_GLOBAL: "/dev/null",
            GIT_CONFIG_PARAMETERS: "",
            ...configuration,
          },
          "printf '%s\\n' \"$GIT_CONFIG_COUNT\"\nexec git config --get-regexp '^(fixture|credential|url)\\.'",
        );

        expect(result.status).toBe(0);
        expect(result.stderr).toBe("");
        expect(result.stdout).toBe(
          [
            String(count + 2),
            ...entries.map(([key, value]) => `${key} ${value}`),
            "credential.https://git.example.test.helper /usr/local/bin/codex-security-git-credential",
            "url.https://git.example.test/.insteadof git@git.example.test:",
            "",
          ].join("\n"),
        );
      }
    },
  );

  testPosix(
    "appends within Git's integer limit without wrapping existing indices",
    async () => {
      const result = await runEntrypoint(
        [],
        {
          GITHUB_TOKEN: "synthetic-token",
          CODEX_SECURITY_GIT_HOST: "git.example.test",
          GIT_CONFIG_COUNT: "2147483645",
          GIT_CONFIG_KEY_0: "fixture.original",
          GIT_CONFIG_VALUE_0: "original-value",
        },
        'printf \'%s\\n\' "$GIT_CONFIG_COUNT" "$GIT_CONFIG_KEY_0" "$GIT_CONFIG_VALUE_0" "$GIT_CONFIG_KEY_2147483645" "$GIT_CONFIG_VALUE_2147483645" "$GIT_CONFIG_KEY_2147483646" "$GIT_CONFIG_VALUE_2147483646"',
      );

      expect(result.status).toBe(0);
      expect(result.stderr).toBe("");
      expect(result.stdout).toBe(
        [
          "2147483647",
          "fixture.original",
          "original-value",
          "credential.https://git.example.test.helper",
          "/usr/local/bin/codex-security-git-credential",
          "url.https://git.example.test/.insteadOf",
          "git@git.example.test:",
          "",
        ].join("\n"),
      );
    },
  );

  testPosix(
    "rejects invalid or overflowing Git counts before starting the CLI",
    async () => {
      for (const count of [
        "-1",
        "+1",
        "01",
        "08",
        "1.5",
        "1+1",
        " 1",
        "1 ",
        "2147483646",
        "2147483647",
        "2147483648",
        "18446744073709551616",
      ]) {
        const result = await runEntrypoint(["--version"], {
          GH_TOKEN: "synthetic-token",
          GIT_CONFIG_COUNT: count,
        });

        expect(result.status).toBe(2);
        expect(result.stdout).toBe("");
        expect(result.stderr).toContain("GIT_CONFIG_COUNT");
      }
    },
  );

  testPosix(
    "rejects invalid credential hosts with a large Git count",
    async () => {
      const result = await runEntrypoint(["--version"], {
        GH_TOKEN: "synthetic-token",
        CODEX_SECURITY_GIT_HOST: "git.example.test/path",
        GIT_CONFIG_COUNT: "129",
      });

      expect(result.status).toBe(2);
      expect(result.stdout).toBe("");
      expect(result.stderr).toContain("must be a valid hostname");
    },
  );
});

describe("immutable customer container releases", () => {
  testPosix("fails closed when package versions cannot be read", async () => {
    const result = await runVersionVerifier("", true);

    expect(result.status).toBe(1);
    expect(result.stderr).toContain("Synthetic package lookup failed.");
    expect(result.stderr).toContain("refusing to publish");
    expect(result.workflowOutput).toBe("");
  });

  testPosix("rejects an existing immutable release version", async () => {
    const result = await runVersionVerifier(
      JSON.stringify([
        {
          name: `sha256:${"a".repeat(64)}`,
          metadata: { container: { tags: ["0.1.4", "latest"] } },
        },
      ]),
    );

    expect(result.status).toBe(1);
    expect(result.stderr).toContain("Container version 0.1.4 already exists");
    expect(result.workflowOutput).toBe("");
  });

  testPosix(
    "retries the verified digest without moving latest backwards",
    async () => {
      const digest = `sha256:${"a".repeat(64)}`;
      for (const newer of [false, true]) {
        for (const latest of ["same", "different", "missing"]) {
          const versions = [
            {
              name: digest,
              metadata: {
                container: {
                  tags: ["0.1.4", ...(latest === "same" ? ["latest"] : [])],
                },
              },
            },
            {
              name: `sha256:${"b".repeat(64)}`,
              metadata: {
                container: {
                  tags: [
                    ...(newer ? ["0.2.0"] : []),
                    ...(latest === "different" ? ["latest"] : []),
                  ],
                },
              },
            },
          ];
          const result = await runVersionVerifier(
            `[]\n${JSON.stringify(versions)}`,
            false,
            digest,
          );
          const allowed = newer || latest === "same";
          expect(result.status, JSON.stringify({ newer, latest })).toBe(
            allowed ? 0 : 1,
          );
          expect(result.workflowOutput).toBe(
            allowed ? `publish_latest=${!newer}\n` : "",
          );
          if (allowed) expect(result.stderr).toBe("");
        }
      }
    },
  );

  testPosix(
    "requires every existing version tag to match a valid verified digest",
    async () => {
      const digest = `sha256:${"a".repeat(64)}`;
      for (const [name, verified] of [
        [`sha256:${"b".repeat(64)}`, digest],
        [undefined, digest],
        ["invalid", "invalid"],
      ] as const) {
        const result = await runVersionVerifier(
          JSON.stringify([
            {
              name: verified,
              metadata: { container: { tags: ["0.1.4", "latest"] } },
            },
            { name, metadata: { container: { tags: ["0.1.4"] } } },
            { metadata: { container: { tags: ["0.2.0"] } } },
          ]),
          false,
          verified,
        );
        expect(result.status).toBe(1);
        expect(result.stderr).toContain(
          "Container version 0.1.4 already exists",
        );
        expect(result.workflowOutput).toBe("");
      }
    },
  );

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
      for (const tags of [
        ["0.1.5", "latest"],
        ["0.1.10"],
        ["0.10.0"],
        ["1.0.0"],
      ]) {
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
    expect(result.workflowOutput).toBe("");
  });
});

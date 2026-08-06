import { execFileSync } from "node:child_process";
import {
  access,
  appendFile,
  lstat,
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  rm,
  symlink,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, test } from "bun:test";
import type { ScanResult } from "../src/result.js";
import { buildGitHubCredentialArgs, runMultiscan } from "../src/multiscan.js";
import { resolveTrustedExecutable } from "../src/trusted-executable.js";

type MultiscanOptions = Parameters<typeof runMultiscan>[0];
type SecurityClient = ReturnType<MultiscanOptions["createSecurity"]>;

const temporaryDirectories: string[] = [];

afterEach(async () => {
  await Promise.all(
    temporaryDirectories
      .splice(0)
      .map((path) => rm(path, { recursive: true, force: true })),
  );
});

async function fixture(): Promise<{
  root: string;
  input: string;
  output: string;
}> {
  const root = await mkdtemp(join(tmpdir(), "codex-security-multiscan-"));
  temporaryDirectories.push(root);
  return {
    root,
    input: join(root, "repositories.csv"),
    output: join(root, "results"),
  };
}

function git(repository: string, ...args: string[]): string {
  return execFileSync("git", ["-C", repository, ...args], {
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
  }).trim();
}

async function repository(
  root: string,
  name: string,
): Promise<{ path: string; revision: string }> {
  const path = join(root, name);
  await mkdir(join(path, "src"), { recursive: true });
  await writeFile(
    join(path, "src", "app.ts"),
    `export const name = "${name}";\n`,
  );
  git(path, "init", "-q");
  git(path, "add", ".");
  git(
    path,
    "-c",
    "user.name=Multiscan Test",
    "-c",
    "user.email=multiscan@example.test",
    "commit",
    "-qm",
    "initial",
  );
  return { path, revision: git(path, "rev-parse", "HEAD") };
}

async function completedScan(
  outputDir: string,
  completeness: "complete" | "partial" = "complete",
): Promise<ScanResult> {
  await mkdir(outputDir, { recursive: true });
  await Promise.all(
    ["scan-manifest.json", "findings.json", "coverage.json", "report.md"].map(
      (name) => writeFile(join(outputDir, name), "{}\n"),
    ),
  );
  return { coverage: { completeness } } as ScanResult;
}

function client(
  run: SecurityClient["run"],
  close: SecurityClient["close"] = async () => {},
): SecurityClient {
  return { run, close };
}

function options(
  paths: { input: string; output: string },
  security: SecurityClient,
  overrides: Partial<MultiscanOptions> = {},
): MultiscanOptions {
  return {
    inputPath: paths.input,
    outputDir: paths.output,
    workers: 1,
    mode: "standard",
    maxAttempts: 2,
    config: {},
    createSecurity: () => security,
    ...overrides,
  };
}

async function results(path: string): Promise<Record<string, unknown>[]> {
  return (await readFile(path, "utf8"))
    .trim()
    .split("\n")
    .map((line) => JSON.parse(line) as Record<string, unknown>);
}

describe("multiscan", () => {
  test("scopes GitHub CLI credentials to the discovered GitHub host", () => {
    expect(buildGitHubCredentialArgs(undefined)).toEqual([]);
    expect(buildGitHubCredentialArgs("github.com")).toEqual([
      "-c",
      "credential.https://github.com.helper=",
      "-c",
      "credential.https://github.com.helper=!gh auth git-credential",
    ]);
    expect(buildGitHubCredentialArgs("github.acme.example")).toEqual([
      "-c",
      "credential.https://github.acme.example.helper=",
      "-c",
      "credential.https://github.acme.example.helper=!gh auth git-credential",
    ]);
    for (const host of [
      "github.com/another-owner",
      "user@github.com",
      "github.com?token=secret",
      "github.com#fragment",
    ]) {
      expect(() => buildGitHubCredentialArgs(host)).toThrow(
        "GitHub credential host is invalid",
      );
    }
  });

  test("uses GitHub credentials for discovered checkouts without changing global Git configuration", async () => {
    const paths = await fixture();
    const source = await repository(paths.root, "github-credentials");
    await writeFile(
      paths.input,
      `id,repository,revision\nprivate,${source.path},${source.revision}\n`,
    );
    const configured = execFileSync(
      "git",
      [
        ...buildGitHubCredentialArgs("github.acme.example"),
        "config",
        "--get-all",
        "credential.https://github.acme.example.helper",
      ],
      { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] },
    );
    expect(configured.trim()).toBe("!gh auth git-credential");

    const summary = await runMultiscan(
      options(
        paths,
        client(
          async (_checkout, scanOptions = {}) =>
            await completedScan(scanOptions.outputDir!),
        ),
        { githubHost: "github.acme.example" },
      ),
    );

    expect(summary).toMatchObject({ total: 1, completed: 1, failed: 0 });
  });

  test("parses quoted CSV fields, embedded delimiters, and Windows line endings", async () => {
    const paths = await fixture();
    const source = await repository(paths.root, "comma, quoted");
    await writeFile(
      paths.input,
      `\uFEFF"id","repository","revision","scope","mode","notes"\r\n"payments","${source.path}","${source.revision}","src","deep","contains ""quotes"""\r\n\r\n`,
    );

    const summary = await runMultiscan(
      options(
        paths,
        client(async (_repository, scanOptions = {}) => {
          expect(scanOptions.target).toEqual(["src"]);
          expect(scanOptions.mode).toBe("deep");
          return await completedScan(scanOptions.outputDir!);
        }),
      ),
    );

    expect(summary).toMatchObject({ total: 1, completed: 1, failed: 0 });
    expect(await results(summary.resultsPath)).toMatchObject([
      { id: "payments", repository: source.path },
    ]);
  });

  test("records each completed scan's cost in the resumable ledger", async () => {
    const paths = await fixture();
    const source = await repository(paths.root, "priced");
    await writeFile(
      paths.input,
      `id,repository,revision\npriced,${source.path},${source.revision}\n`,
    );
    const cost = {
      model: "gpt-5.6-sol",
      inputTokens: 1_250,
      cachedInputTokens: 200,
      cacheWriteInputTokens: 0,
      outputTokens: 30,
      estimatedUsd: 0.00625,
    };

    const summary = await runMultiscan(
      options(
        paths,
        client(async (_repository, scanOptions = {}) =>
          Object.assign(await completedScan(scanOptions.outputDir!), { cost }),
        ),
      ),
    );

    expect(await results(summary.resultsPath)).toMatchObject([
      { id: "priced", status: "completed", cost },
    ]);
  });

  test("rejects malformed CSV and duplicate headers before starting scans", async () => {
    const paths = await fixture();
    const source = await repository(paths.root, "csv");
    const invalid = [
      `id,repository,revision\npayments,"${source.path},${source.revision}\n`,
      `id,repository,revision,id\npayments,${source.path},${source.revision},again\n`,
      `id,repository,revision\npayments,${source.path}\n`,
    ];
    let scans = 0;

    for (const input of invalid) {
      await writeFile(paths.input, input);
      await expect(
        runMultiscan(
          options(
            paths,
            client(async (_repository, scanOptions = {}) => {
              scans += 1;
              return await completedScan(scanOptions.outputDir!);
            }),
          ),
        ),
      ).rejects.toThrow(/CSV/);
    }

    expect(scans).toBe(0);
  });

  test("materializes the pinned commit, applies row options, and removes its checkout", async () => {
    const paths = await fixture();
    const source = await repository(paths.root, "payments");
    await writeFile(
      join(source.path, "src", "app.ts"),
      "export const changed = true;\n",
    );
    git(source.path, "add", ".");
    git(
      source.path,
      "-c",
      "user.name=Multiscan Test",
      "-c",
      "user.email=multiscan@example.test",
      "commit",
      "-qm",
      "later",
    );
    await writeFile(
      paths.input,
      `id,repository,revision,scope,mode\npayments,${source.path},${source.revision},src,deep\n`,
    );

    let checkout = "";
    let closed = 0;
    const summary = await runMultiscan(
      options(
        paths,
        client(
          async (path, scanOptions = {}) => {
            checkout = path;
            expect(git(path, "rev-parse", "HEAD")).toBe(source.revision);
            expect(
              await readFile(join(path, "src", "app.ts"), "utf8"),
            ).toContain('name = "payments"');
            expect(scanOptions.target).toEqual(["src"]);
            expect(scanOptions.mode).toBe("deep");
            expect(scanOptions.outputDir).toBe(
              join(paths.output, "artifacts", "payments", "attempt-1"),
            );
            return await completedScan(scanOptions.outputDir!);
          },
          async () => {
            closed += 1;
          },
        ),
      ),
    );

    expect(summary).toMatchObject({ completed: 1, failed: 0, skipped: 0 });
    expect(closed).toBe(1);
    await expect(access(checkout)).rejects.toThrow();
    expect(await readdir(join(paths.output, "checkouts"))).toEqual([]);
    expect(await results(summary.resultsPath)).toMatchObject([
      {
        id: "payments",
        repository: source.path,
        revision: source.revision,
        scope: "src",
        mode: "deep",
        status: "completed",
        attempt: 1,
      },
    ]);
  });

  test("limits simultaneous checkouts to the requested worker count", async () => {
    const paths = await fixture();
    const knowledgeBasePaths = [
      join(paths.root, "architecture.md"),
      "shared/threat-model.md",
    ];
    const sources = await Promise.all(
      ["one", "two", "three"].map((name) => repository(paths.root, name)),
    );
    await writeFile(
      paths.input,
      `id,repository,revision\n${sources
        .map(
          (source, index) => `${index + 1},${source.path},${source.revision}`,
        )
        .join("\n")}\n`,
    );

    let active = 0;
    let maximum = 0;
    let created = 0;
    let closed = 0;
    let release!: () => void;
    const simultaneous = new Promise<void>((resolve) => {
      release = resolve;
    });
    const security = client(async (_repository, scanOptions = {}) => {
      expect(scanOptions.knowledgeBasePaths).toEqual(knowledgeBasePaths);
      active += 1;
      maximum = Math.max(maximum, active);
      if (active === 2) release();
      await simultaneous;
      active -= 1;
      return await completedScan(scanOptions.outputDir!);
    });
    const summary = await runMultiscan(
      options(paths, security, {
        workers: 2,
        knowledgeBasePaths,
        createSecurity: () => {
          created += 1;
          let running = false;
          return client(
            async (repository, scanOptions) => {
              if (running) {
                throw new Error("A scan is already running for this client.");
              }
              running = true;
              try {
                return await security.run(repository, scanOptions);
              } finally {
                running = false;
              }
            },
            async () => {
              closed += 1;
            },
          );
        },
      }),
    );

    expect(maximum).toBe(2);
    expect(created).toBe(2);
    expect(closed).toBe(2);
    expect(summary).toMatchObject({ total: 3, completed: 3, failed: 0 });
    expect(await results(summary.resultsPath)).toHaveLength(3);
  });

  test("rejects another supervisor and recovers a crashed owner's checkout", async () => {
    const paths = await fixture();
    const source = await repository(paths.root, "exclusive");
    await writeFile(
      paths.input,
      `id,repository,revision\nexclusive,${source.path},${source.revision}\n`,
    );
    let started!: () => void;
    let release!: () => void;
    const running = new Promise<void>((resolve) => {
      started = resolve;
    });
    const finish = new Promise<void>((resolve) => {
      release = resolve;
    });
    const security = client(async (_repository, scanOptions = {}) => {
      started();
      await finish;
      return await completedScan(scanOptions.outputDir!);
    });
    const lock = join(paths.output, ".lock");
    const first = runMultiscan(options(paths, security));
    await running;
    try {
      expect((await lstat(lock)).isFile()).toBe(true);
      expect(JSON.parse(await readFile(lock, "utf8"))).toMatchObject({
        pid: process.pid,
        token: expect.any(String),
      });
      expect(
        (await readdir(paths.output)).some((name) =>
          name.startsWith(".lock.pending-"),
        ),
      ).toBe(false);
      await expect(runMultiscan(options(paths, security))).rejects.toThrow(
        /running|locked|supervisor/iu,
      );
    } finally {
      release();
      await first;
    }

    const [receipt] = await results(join(paths.output, "results.jsonl"));
    await rm(join(receipt!["outputDir"] as string, "report.md"));
    await mkdir(lock);
    await writeFile(
      join(lock, "owner.json"),
      JSON.stringify({ pid: 999_999_999 }),
    );
    const checkout = join(paths.output, "checkouts", "exclusive");
    await mkdir(checkout);

    const recovered = await runMultiscan(options(paths, security));
    expect(recovered).toMatchObject({ completed: 1, failed: 0, skipped: 0 });
    expect(await readdir(join(paths.output, "checkouts"))).toEqual([]);
    await expect(access(lock)).rejects.toThrow();
  });

  test("recovers missing and malformed legacy lock ownership", async () => {
    const paths = await fixture();
    const source = await repository(paths.root, "lock-recovery");
    await writeFile(
      paths.input,
      `id,repository,revision\nlock-recovery,${source.path},${source.revision}\n`,
    );
    await mkdir(paths.output);
    const lock = join(paths.output, ".lock");
    let scans = 0;
    const security = client(async (_repository, scanOptions = {}) => {
      scans += 1;
      return await completedScan(scanOptions.outputDir!);
    });

    for (const owner of [undefined, '{"pid":', '{"pid":"invalid"}']) {
      await mkdir(lock);
      if (owner !== undefined) {
        await writeFile(join(lock, "owner.json"), owner);
      }
      expect(await runMultiscan(options(paths, security))).toMatchObject({
        completed: 1,
        failed: 0,
      });
      await expect(access(lock)).rejects.toThrow();
    }

    expect(scans).toBe(1);
    expect(
      (await readdir(paths.output)).some(
        (name) =>
          name.startsWith(".lock.pending-") || name.startsWith(".lock.stale-"),
      ),
    ).toBe(false);
  });

  test("retries a failed attempt and records both durable receipts", async () => {
    const paths = await fixture();
    const source = await repository(paths.root, "retry");
    const secret = "sk-proj-SYNTHETIC_MULTISCAN_SECRET_123";
    const knowledgeBasePaths = ["architecture.md"];
    const proxyUrl =
      "https://SYNTHETIC_USER:SYNTHETIC_MULTISCAN_PASSWORD@proxy.test/v1/responses";
    const queryUrl =
      "https://proxy.test/v1/responses?api_key=SYNTHETIC_MULTISCAN_QUERY_123&safe=1";
    const shortAuthorization = "Bearer abc123";
    const suffixedSecret = "SYNTHETIC_SUFFIXED_CLIENT_SECRET_123";
    const suffixedToken = "SYNTHETIC_SUFFIXED_ACCESS_TOKEN_123";
    const suffixedQuery = "SYNTHETIC_SUFFIXED_QUERY_SECRET_123";
    const quotedSecret = "SYNTHETIC correct horse battery staple";
    const opaqueAuthorization = "SYNTHETIC opaque authorization secret";
    const npmAuthorization = "SYNTHETIC_NPM_AUTH_VALUE_123";
    const customAuthorization = "SYNTHETIC_CUSTOM_AUTHORIZATION_123";
    const suffixedAuthorization = "SYNTHETIC_SUFFIXED_AUTHORIZATION_123";
    const paddedAuthorization = "SYNTHETIC_PADDED_AUTHORIZATION_TOKEN==";
    const keyedAuthorization = "SYNTHETIC_KEYED_AUTHORIZATION_SECRET_123";
    const camelCaseSecret = "SYNTHETIC_CAMEL_CASE_CLIENT_SECRET_123";
    await writeFile(
      paths.input,
      `id,repository,revision\nretry,${source.path},${source.revision}\n`,
    );

    let attempts = 0;
    const summary = await runMultiscan(
      options(
        paths,
        client(async (_repository, scanOptions = {}) => {
          expect(scanOptions.knowledgeBasePaths).toEqual(knowledgeBasePaths);
          attempts += 1;
          if (attempts === 1) {
            throw new Error(
              `temporary failure ${secret} ${shortAuthorization} client_secret_value=${suffixedSecret} access_token_value=${suffixedToken} ${JSON.stringify({ client_secret_value: quotedSecret })} authorization="${opaqueAuthorization}" _auth=${npmAuthorization} Authorization: ApiKey ${customAuthorization} client_authorization_value=ApiKey ${suffixedAuthorization} auth=ApiKey ${paddedAuthorization} Authorization: Custom key=${keyedAuthorization} clientSecretValue=${camelCaseSecret} sending request for url (${proxyUrl}) and ${queryUrl}&client_secret_value=${suffixedQuery}`,
            );
          }
          return await completedScan(scanOptions.outputDir!);
        }),
        { knowledgeBasePaths },
      ),
    );

    expect(attempts).toBe(2);
    expect(summary).toMatchObject({ completed: 1, failed: 0 });
    expect(await results(summary.resultsPath)).toMatchObject([
      { id: "retry", status: "failed", attempt: 1 },
      { id: "retry", status: "completed", attempt: 2 },
    ]);
    const ledger = await readFile(summary.resultsPath, "utf8");
    expect(ledger).not.toContain(secret);
    expect(ledger).not.toContain("SYNTHETIC_MULTISCAN_PASSWORD");
    expect(ledger).not.toContain("SYNTHETIC_MULTISCAN_QUERY_123");
    expect(ledger).not.toContain(suffixedSecret);
    expect(ledger).not.toContain(suffixedToken);
    expect(ledger).not.toContain(suffixedQuery);
    expect(ledger).not.toContain(quotedSecret);
    expect(ledger).not.toContain(opaqueAuthorization);
    expect(ledger).not.toContain(npmAuthorization);
    expect(ledger).not.toContain(customAuthorization);
    expect(ledger).not.toContain(suffixedAuthorization);
    expect(ledger).not.toContain(paddedAuthorization);
    expect(ledger).not.toContain(keyedAuthorization);
    expect(ledger).not.toContain(camelCaseSecret);
    expect(ledger).not.toContain(shortAuthorization);
    expect(ledger).toContain("https://[redacted]@proxy.test/v1/responses");
  });

  test("resumes complete bundles, repairs missing output, and rejects manifest drift", async () => {
    const paths = await fixture();
    const source = await repository(paths.root, "resume");
    const csv = `id,repository,revision\nresume,${source.path},${source.revision}\n`;
    await writeFile(paths.input, csv);
    let calls = 0;
    const security = client(async (_repository, scanOptions = {}) => {
      calls += 1;
      return await completedScan(scanOptions.outputDir!);
    });

    const initial = await runMultiscan(options(paths, security));
    await appendFile(initial.resultsPath, '{"id":"interrupted"');
    const resumed = await runMultiscan(options(paths, security));
    expect(resumed).toMatchObject({ completed: 1, failed: 0, skipped: 1 });
    expect(calls).toBe(1);

    const [receipt] = await results(initial.resultsPath);
    await rm(join(receipt!["outputDir"] as string, "report.md"));
    const repaired = await runMultiscan(options(paths, security));
    expect(repaired).toMatchObject({ completed: 1, failed: 0, skipped: 0 });
    expect(calls).toBe(2);
    expect((await results(repaired.resultsPath)).at(-1)?.["outputDir"]).toBe(
      join(paths.output, "artifacts", "resume", "attempt-2"),
    );

    await writeFile(paths.input, csv.replace("resume,", "changed,"));
    await expect(runMultiscan(options(paths, security))).rejects.toThrow(
      "manifest does not match",
    );
    expect(calls).toBe(2);
  });

  test("ignores repository-local Git shims while preserving credential configuration", async () => {
    const paths = await fixture();
    const source = await repository(paths.root, "private");
    await writeFile(
      paths.input,
      `id,repository,revision\nprivate,${source.path},${source.revision}\n`,
    );
    const shimDirectory = join(paths.root, "node_modules", ".bin");
    const leakedCredential = join(paths.root, "leaked-credential");
    await mkdir(shimDirectory, { recursive: true });
    await writeFile(
      join(shimDirectory, "git"),
      `#!/bin/sh\nprintf '%s' "$GIT_CONFIG_VALUE_0" > "${leakedCredential}"\nexit 1\n`,
      { mode: 0o700 },
    );
    const previousDirectory = process.cwd();
    const environment = new Map(
      [
        "PATH",
        "GIT_CONFIG_COUNT",
        "GIT_CONFIG_KEY_0",
        "GIT_CONFIG_VALUE_0",
      ].map((name) => [name, process.env[name]] as const),
    );

    try {
      process.chdir(paths.root);
      process.env["PATH"] =
        `${shimDirectory}${process.platform === "win32" ? ";" : ":"}${environment.get("PATH") ?? ""}`;
      process.env["GIT_CONFIG_COUNT"] = "1";
      process.env["GIT_CONFIG_KEY_0"] = "multiscan.credential";
      process.env["GIT_CONFIG_VALUE_0"] = "SYNTHETIC_GIT_CREDENTIAL";

      const summary = await runMultiscan(
        options(
          paths,
          client(async (checkout, scanOptions = {}) => {
            const trustedGit = await resolveTrustedExecutable(
              "git",
              { ...process.env, PATH: environment.get("PATH") ?? "" },
              paths.root,
            );
            if (trustedGit === null) {
              throw new Error("Git is not available on a trusted PATH.");
            }
            const credential = execFileSync(
              trustedGit.executable,
              ["-C", checkout, "config", "--get", "multiscan.credential"],
              {
                encoding: "utf8",
                env: trustedGit.environment,
                stdio: ["ignore", "pipe", "pipe"],
              },
            ).trim();
            expect(credential).toBe("SYNTHETIC_GIT_CREDENTIAL");
            return await completedScan(scanOptions.outputDir!);
          }),
        ),
      );

      expect(summary).toMatchObject({ completed: 1, failed: 0 });
      await expect(access(leakedCredential)).rejects.toThrow();
    } finally {
      process.chdir(previousDirectory);
      for (const [name, value] of environment) {
        if (value === undefined) delete process.env[name];
        else process.env[name] = value;
      }
    }
  });

  test("rejects output-directory symlinks before deleting external checkouts", async () => {
    for (const directory of ["", "checkouts", "artifacts"]) {
      const paths = await fixture();
      const source = await repository(paths.root, "victim");
      await writeFile(
        paths.input,
        `id,repository,revision\nvictim,${source.path},${source.revision}\n`,
      );
      const external = join(paths.root, "external");
      const preserved = join(external, "victim", "keep.txt");
      await mkdir(join(external, "victim"), { recursive: true });
      await writeFile(preserved, "preserved\n");
      if (directory) await mkdir(paths.output);
      await symlink(
        external,
        directory ? join(paths.output, directory) : paths.output,
      );

      let scans = 0;
      await expect(
        runMultiscan(
          options(
            paths,
            client(async (_repository, scanOptions = {}) => {
              scans += 1;
              return await completedScan(scanOptions.outputDir!);
            }),
          ),
        ),
      ).rejects.toThrow("symbolic links");
      expect(scans).toBe(0);
      expect(await readFile(preserved, "utf8")).toBe("preserved\n");
    }
  });

  test("rejects unsafe input without starting scans or exposing URL credentials", async () => {
    const paths = await fixture();
    const source = await repository(paths.root, "safe");
    const secret = "MULTISCAN_CREDENTIAL_SHOULD_NOT_APPEAR";
    const invalid = [
      {
        name: "task-id",
        row: `../escape,${source.path},${source.revision},.`,
      },
      {
        name: "scope",
        row: `safe,${source.path},${source.revision},../outside`,
      },
      {
        name: "revision",
        row: `safe,${source.path},HEAD,.`,
      },
      {
        name: "duplicate-id",
        row: `safe,${source.path},${source.revision},.\nsafe,${source.path},${source.revision},.`,
      },
      {
        name: "credentials",
        row: `safe,https://user:${secret}@example.test/private.git,${source.revision},.`,
      },
    ];
    let scans = 0;
    const security = client(async (_repository, scanOptions = {}) => {
      scans += 1;
      return await completedScan(scanOptions.outputDir!);
    });

    for (const entry of invalid) {
      await writeFile(
        paths.input,
        `id,repository,revision,scope\n${entry.row}\n`,
      );
      const output = join(paths.root, entry.name);
      const error = await runMultiscan(
        options(paths, security, { outputDir: output }),
      ).then(
        () => null,
        (reason: unknown) => reason,
      );
      expect(error).toBeInstanceOf(Error);
      expect(String(error)).not.toContain(secret);
    }

    expect(scans).toBe(0);
  });

  test("treats incomplete coverage as a failure and still finishes other repositories", async () => {
    const paths = await fixture();
    const incomplete = await repository(paths.root, "incomplete");
    const complete = await repository(paths.root, "complete");
    await writeFile(
      paths.input,
      [
        "id,repository,revision",
        `incomplete,${incomplete.path},${incomplete.revision}`,
        `complete,${complete.path},${complete.revision}`,
        "",
      ].join("\n"),
    );

    const summary = await runMultiscan(
      options(
        paths,
        client(async (checkout, scanOptions = {}) =>
          completedScan(
            scanOptions.outputDir!,
            (await readFile(join(checkout, "src", "app.ts"), "utf8")).includes(
              'name = "incomplete"',
            )
              ? "partial"
              : "complete",
          ),
        ),
        { maxAttempts: 1 },
      ),
    );

    expect(summary).toMatchObject({ total: 2, completed: 1, failed: 1 });
    expect(await results(summary.resultsPath)).toMatchObject([
      { id: "incomplete", status: "failed", attempt: 1 },
      { id: "complete", status: "completed", attempt: 1 },
    ]);
  });
});

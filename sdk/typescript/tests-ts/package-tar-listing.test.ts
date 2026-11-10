import { execFile, spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  chmodSync,
  copyFileSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  realpathSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { delimiter, join } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { brotliCompressSync, gzipSync } from "node:zlib";
import { describe, expect, test } from "bun:test";
import packageJson from "../package.json" with { type: "json" };
import {
  archive,
  cleanCompressedPayload,
  octal,
  paxRecords,
  tarRecord,
} from "./package-tar-fixtures.js";

const { assertTarListingSizes, regularTarListingLines } = (await import(
  new URL("../scripts/package-tar-listing.mjs", import.meta.url).href
)) as {
  regularTarListingLines: (listing: string) => string[];
  assertTarListingSizes: (lines: string[], maximum: number) => number[];
};
const { packageDistFiles } = (await import(
  new URL("../scripts/package-dist-files.mjs", import.meta.url).href
)) as { packageDistFiles: readonly string[] };
// Avoid Bun 1.3.14's stale Windows spawnSync timeout.
// https://github.com/oven-sh/bun/issues/33932
const execFileAsync = promisify(execFile);

const pluginContract = {
  externalOwnedExact: [".codex-plugin/plugin.json"],
  shippedExact: ["scripts/launch_codex_security_mcp"],
};

function paxExtension(attributes: Record<string, string>, type = 0x78): Buffer {
  return tarRecord(paxRecords(attributes), { name: "PaxHeaders/entry", type });
}

function packageTar({
  trailingZeroBytes = 0,
  sizeTerminator = " ",
  type = 0x30,
  compatibleLayout = false,
  rootDirectoryMode = 0o755,
  directoryMode = 0o755,
  readmeMode = 0o644,
  mtime = 0,
  readmeLongName = false,
  additionalRecords = [],
  overrides = new Map(),
}: {
  trailingZeroBytes?: number;
  sizeTerminator?: string;
  type?: number;
  compatibleLayout?: boolean;
  rootDirectoryMode?: number;
  directoryMode?: number;
  readmeMode?: number;
  mtime?: number;
  readmeLongName?: boolean;
  additionalRecords?: Buffer[];
  overrides?: ReadonlyMap<string, Buffer>;
} = {}): Buffer {
  const executablePaths = [
    "package/bin/codex-security.mjs",
    "package/_bundled_plugin/scripts/launch_codex_security_mcp",
  ];
  const paths = [
    "package/package.json",
    "package/README.md",
    ...packageJson.files
      .filter((path) => path.startsWith("docs/"))
      .map((path) => `package/${path}`),
    "package/schemas/hosted-scan-v2.fixture.json",
    "package/schemas/hosted-scan-v3.fixture.json",
    "package/schemas/project-config.schema.json",
    "package/schemas/external-findings.schema.json",
    "package/LICENSE",
    ...executablePaths,
    ...packageDistFiles,
    "package/_bundled_plugin/.codex-plugin/plugin.json",
  ];
  const records = paths.map((path) => {
    const override = overrides.get(path);
    if (override !== undefined) return override;
    const contents =
      path === "package/package.json"
        ? Buffer.from(
            JSON.stringify({
              license: "Apache-2.0",
              name: "@openai/codex-security",
            }),
          )
        : path.endsWith(".json") || path.endsWith(".map")
          ? Buffer.from("{}\n")
          : Buffer.from("fixture\n");
    const record = tarRecord(contents, {
      name: path,
      type,
      mtime,
      mode: executablePaths.includes(path)
        ? 0o755
        : path === "package/README.md"
          ? readmeMode
          : 0o644,
      sizeField: octal(contents.length, 12, sizeTerminator),
      ...(compatibleLayout ? { magic: "ustar ", version: " \0" } : {}),
    });
    if (compatibleLayout) record[record.length - 1] = 1;
    if (path === "package/README.md" && readmeLongName)
      return Buffer.concat([
        tarRecord(Buffer.from(`${path}\0`), {
          name: "././@LongLink",
          type: 0x4c,
        }),
        record,
      ]);
    return record;
  });
  records.push(...additionalRecords);
  if (compatibleLayout) {
    const directories = new Set<string>();
    for (const path of paths) {
      const parts = path.split("/");
      for (let index = 1; index < parts.length; index++) {
        directories.add(`${parts.slice(0, index).join("/")}/`);
      }
    }
    return Buffer.concat([
      ...[...directories].map((name) =>
        tarRecord(Buffer.alloc(0), {
          name,
          type: 0x35,
          mode: name === "package/" ? rootDirectoryMode : directoryMode,
        }),
      ),
      ...records.flatMap((record) => [Buffer.alloc(512), record]),
    ]);
  }
  return archive(...records, Buffer.alloc(trailingZeroBytes));
}

function commandPath(command: string): string {
  const lookup = spawnSync(
    process.platform === "win32" ? "where.exe" : "which",
    [command],
    { encoding: "utf8", windowsHide: true },
  );
  if (lookup.error !== undefined) throw lookup.error;
  const path = lookup.stdout.split(/\r?\n/u).find(Boolean);
  if (lookup.status !== 0 || path === undefined) {
    throw new Error(`Could not resolve ${command}.`);
  }
  return path;
}

let cachedNode: string | undefined;
const node = () => (cachedNode ??= commandPath("node"));
let fixtureNpm: ReturnType<typeof resolveFixtureNpm> | undefined;

// All consumers use the same Node/npm installation and keep independent npm configs and caches.
async function resolveFixtureNpm() {
  const resolved = await execFileAsync(
    node(),
    [
      "--input-type=module",
      "-e",
      `import { resolveNpm } from ${JSON.stringify(new URL("../scripts/package-smoke-npm.mjs", import.meta.url).href)}; console.log(JSON.stringify(await resolveNpm()));`,
    ],
    { encoding: "utf8", windowsHide: true },
  );
  if (resolved.stderr) throw new Error(resolved.stderr);
  return JSON.parse(resolved.stdout) as {
    command: string;
    args: string[];
  };
}

async function installPackage(
  root: string,
  archivePath: string,
  environment: NodeJS.ProcessEnv,
) {
  const consumer = join(root, "consumer");
  mkdirSync(consumer);
  writeFileSync(
    join(consumer, "package.json"),
    JSON.stringify({ name: "synthetic-consumer", private: true }),
  );
  const npm = await (fixtureNpm ??= resolveFixtureNpm());
  return runPackageCommand(
    consumer,
    npm.command,
    [
      ...npm.args,
      "install",
      "--timing",
      "--global=false",
      "--prefix",
      consumer,
      "--offline",
      "--ignore-scripts",
      "--package-lock=false",
      "--no-audit",
      "--no-fund",
      archivePath,
    ],
    environment,
    // Allow repeated tarball extraction within the Windows shard's 120s test budget.
    process.platform === "win32" &&
      Number(environment["CODEX_SECURITY_TEST_TIMEOUT_MS"]) >= 120_000
      ? 60_000
      : 30_000,
  );
}

function checkPackage(
  root: string,
  archivePath: string,
  contractPath: string,
  environment: NodeJS.ProcessEnv = process.env,
): Promise<{ status: number; stderr: string }> {
  return runPackageCommand(
    root,
    node(),
    [
      fileURLToPath(new URL("../scripts/check-package.mjs", import.meta.url)),
      archivePath,
      contractPath,
    ],
    environment,
  );
}

function runPackageCommand(
  root: string,
  command: string,
  args: string[],
  environment: NodeJS.ProcessEnv,
  timeout = 30_000,
): Promise<{ status: number; stderr: string }> {
  return new Promise((resolve, reject) => {
    execFile(
      command,
      args,
      {
        cwd: root,
        env: environment,
        encoding: "utf8",
        timeout,
        windowsHide: true,
      },
      (error, _stdout, stderr) => {
        if (error === null) {
          resolve({ status: 0, stderr });
        } else if (
          typeof error.code === "number" &&
          !error.killed &&
          !error.signal
        ) {
          resolve({ status: error.code, stderr });
        } else {
          reject(error);
        }
      },
    );
  });
}

describe("npm package tar listings", () => {
  const prefix = join(realpathSync(tmpdir()), "p");
  const shortestManifest = join(`${prefix}XXXXXX`, "p", "package.json");
  for (const length of [259, 260]) {
    test.skipIf(shortestManifest.length > length)(
      `packs the SDK's fresh output or fails before running an ancestor at manifest length ${length}`,
      async () => {
        const root = mkdtempSync(prefix);
        try {
          const sdk = join(
            root,
            "p".repeat(length - join(root, "package.json").length - 1),
          );
          const manifest = join(sdk, "package.json");
          expect(manifest.length).toBe(length);
          const output = join(root, "packages");
          mkdirSync(output);
          mkdirSync(join(sdk, "scripts"), { recursive: true });
          mkdirSync(join(sdk, "dist"));
          copyFileSync(
            new URL("../scripts/check-prepack-path.mjs", import.meta.url),
            join(sdk, "scripts", "check-prepack-path.mjs"),
          );
          writeFileSync(join(sdk, "dist", "built.txt"), "stale");
          writeFileSync(
            manifest,
            JSON.stringify({
              name: "sdk-prepack-fixture",
              version: "1.0.0",
              files: ["dist"],
              scripts: {
                prepack: packageJson.scripts.prepack,
                build: `node -e "require('node:fs').writeFileSync('dist/built.txt','sdk')"`,
                "build:plugin": `node -e "require('node:fs').appendFileSync('dist/built.txt','+plugin')"`,
              },
            }),
          );
          writeFileSync(
            join(root, "package.json"),
            JSON.stringify({
              private: true,
              scripts: {
                build: `node -e "require('node:fs').writeFileSync('ancestor-ran','yes')"`,
                "build:plugin": "node --version",
              },
            }),
          );
          const npm = await (fixtureNpm ??= resolveFixtureNpm());
          const result = await runPackageCommand(
            sdk,
            npm.command,
            [
              ...npm.args,
              "pack",
              "--offline",
              "--foreground-scripts",
              "--ignore-scripts=false",
              "--pack-destination",
              output,
            ],
            {
              ...process.env,
              npm_config_cache: join(root, "npm-cache"),
              npm_config_userconfig: join(root, "empty-npmrc"),
            },
          );
          expect(existsSync(join(root, "ancestor-ran"))).toBe(false);
          if (process.platform === "win32" && length === 260) {
            expect(result.status).not.toBe(0);
            expect(result.stderr).toContain("Use a shorter checkout path");
            expect(readdirSync(output)).toEqual([]);
          } else {
            expect(result.status, result.stderr).toBe(0);
            const archives = readdirSync(output);
            expect(archives).toHaveLength(1);
            const { stdout } = await execFileAsync("tar", [
              "-xOf",
              join(output, archives[0]!),
              "package/dist/built.txt",
            ]);
            expect(stdout).toBe("sdk+plugin");
          }
        } finally {
          rmSync(root, { recursive: true, force: true });
        }
      },
    );
  }

  test("accepts regular entries with Unix or Windows line endings", () => {
    const file = "-rw-r--r-- package/package.json";
    const directory = "drwxr-xr-x package/dist/";

    expect(regularTarListingLines(`${file}\n${directory}\n`)).toEqual([
      file,
      directory,
    ]);
    expect(regularTarListingLines(`${file}\r\n${directory}\r\n`)).toEqual([
      file,
      directory,
    ]);
  });

  test.each([
    "-rw-r--r-- 0/0        33554433 1970-01-01 00:00 package/README.md",
    "-rw-r--r--  0 0      0    33554433 Jan  1  1970 package/README.md",
  ])("bounds native file sizes before extraction: %s", (line) => {
    expect(() => assertTarListingSizes([line], 32 * 1024 * 1024)).toThrow(
      "npm tarball contains an invalid tar entry",
    );
    const bounded = line.replace("33554433", "33554432");
    expect(() =>
      assertTarListingSizes([bounded], 32 * 1024 * 1024),
    ).not.toThrow();
    expect(() =>
      assertTarListingSizes([bounded, bounded], 32 * 1024 * 1024),
    ).toThrow();
  });

  test("retains bounded file sizes in listing order", () => {
    expect(
      assertTarListingSizes(
        [
          "drwxr-xr-x 0/0 0 1970-01-01 00:00 package/",
          "-rw-r--r-- 0/0 1024 1970-01-01 00:00 package/README.md",
          "-rw-r--r--  0 0 0 512 Jan  1 1970 package/LICENSE",
        ],
        1536,
      ),
    ).toEqual([0, 1024, 512]);
  });

  test("rejects symbolic links and other non-regular entries", () => {
    expect(() =>
      regularTarListingLines("lrwxrwxrwx package/link -> target\r\n"),
    ).toThrow("npm tarball contains a non-regular entry");
  });

  test.each([
    ["shebang", "#!/bin/sh\r\nexit 0\n"],
    ["body", "#!/bin/sh\nexit 0\r\n"],
  ])(
    "rejects CRLF in the packaged POSIX MCP launcher's %s",
    async (_part, script) => {
      const root = mkdtempSync(join(tmpdir(), "codex-package-launcher-"));
      try {
        const path =
          "package/_bundled_plugin/scripts/launch_codex_security_mcp";
        const launcher = tarRecord(Buffer.from(script), {
          name: path,
          mode: 0o755,
        });
        const archivePath = join(root, "launcher.tgz");
        writeFileSync(
          archivePath,
          gzipSync(packageTar({ overrides: new Map([[path, launcher]]) })),
        );
        const contractPath = join(root, "plugin contract.json");
        writeFileSync(contractPath, JSON.stringify(pluginContract));
        const result = await checkPackage(root, archivePath, contractPath);
        expect(result.status).toBe(1);
        expect(result.stderr).toContain("POSIX MCP launcher contains CRLF");
      } finally {
        rmSync(root, { force: true, recursive: true });
      }
    },
  );

  test.each([false, true])(
    "rejects invalid package paths before Brotli expansion, complete=%p",
    async (complete) => {
      const root = mkdtempSync(join(tmpdir(), "codex-package-path-order-"));
      try {
        const archivePath = join(root, "unexpected-brotli.tgz");
        writeFileSync(
          archivePath,
          gzipSync(
            Buffer.concat([
              ...(complete ? [packageTar()] : []),
              tarRecord(Buffer.from("Malformed compressed bytes."), {
                name: "package/unexpected.br",
              }),
            ]),
          ),
        );
        const contractPath = join(root, "plugin contract.json");
        writeFileSync(contractPath, JSON.stringify(pluginContract));
        const result = await checkPackage(root, archivePath, contractPath);
        expect(result.status).toBe(1);
        expect(result.stderr).toContain(
          complete
            ? "unexpected file: package/unexpected.br"
            : "missing package/package.json",
        );
      } finally {
        rmSync(root, { force: true, recursive: true });
      }
    },
  );

  test("escapes terminal controls in unexpected archive path diagnostics", async () => {
    const root = mkdtempSync(join(tmpdir(), "codex-package-terminal-path-"));
    try {
      const archivePath = join(root, "unexpected-path.tgz");
      writeFileSync(
        archivePath,
        gzipSync(
          Buffer.concat([
            packageTar(),
            tarRecord(Buffer.from("fixture"), {
              name: "package/unexpected\u001b]52;c;synthetic\u0007\u009b",
            }),
          ]),
        ),
      );
      const contractPath = join(root, "plugin contract.json");
      writeFileSync(contractPath, JSON.stringify(pluginContract));
      const result = await checkPackage(root, archivePath, contractPath);
      expect(result.status).toBe(1);
      expect(result.stderr).toContain("unexpected file: package/unexpected");
      expect(result.stderr).not.toMatch(/[\u001b\u0007\u009b]/u);
      expect(result.stderr).toContain("synthetic");
    } finally {
      rmSync(root, { force: true, recursive: true });
    }
  });

  test("accepts equivalent bounded gzip representations", async () => {
    const root = mkdtempSync(join(tmpdir(), "codex-package-gzip-test-"));
    try {
      const tarBytes = packageTar({ trailingZeroBytes: 31 * 1024 * 1024 });
      const archives = [
        ["default", gzipSync(tarBytes)],
        ["level-0", gzipSync(tarBytes, { level: 0 })],
        [
          "gnu-long-name",
          gzipSync(
            packageTar({
              readmeLongName: true,
              readmeMode: 0,
              mtime: Math.floor(Date.now() / 1000) + 365 * 86400,
              sizeTerminator: " \0",
              type: 0,
            }),
          ),
        ],
        [
          "read-only-directories",
          gzipSync(
            packageTar({
              compatibleLayout: true,
              rootDirectoryMode: 0o555,
              directoryMode: 0o555,
              sizeTerminator: "\0",
            }),
          ),
        ],
      ] as const;
      expect(archives[0][1].length).toBeLessThan(1024 * 1024);
      expect(archives[1][1].length).toBeGreaterThan(31 * 1024 * 1024);

      const contractPath = join(root, "plugin contract.json");
      writeFileSync(contractPath, JSON.stringify(pluginContract));
      const environment: NodeJS.ProcessEnv = { ...process.env };
      delete environment["CODEX_SECURITY_EXPECTED_GIT_HEAD"];
      for (const [representation, contents] of archives) {
        const archivePath = join(root, `${representation}.tgz`);
        writeFileSync(archivePath, contents);
        const result = await checkPackage(
          root,
          archivePath,
          contractPath,
          environment,
        );
        expect({
          representation,
          status: result.status,
          stderr: result.stderr,
        }).toEqual({ representation, status: 0, stderr: "" });
      }
    } finally {
      rmSync(root, { force: true, recursive: true });
    }
  });

  test.each(["environment", "user-config"])(
    "keeps npm fixture installs local with global %s settings",
    async (configuration) => {
      const root = mkdtempSync(join(tmpdir(), "codex-package-npm-local-"));
      try {
        const archivePath = join(root, "package.tgz");
        writeFileSync(archivePath, gzipSync(packageTar()));
        const userConfig = join(root, "npmrc");
        writeFileSync(
          userConfig,
          configuration === "user-config" ? "global=true\n" : "",
        );
        const environment: NodeJS.ProcessEnv = { ...process.env };
        for (const key of Object.keys(environment)) {
          if (/^npm_config_(?:global|prefix|userconfig|cache)$/iu.test(key))
            delete environment[key];
        }
        const globalPrefix = join(root, "global-prefix");
        Object.assign(environment, {
          npm_config_cache: join(root, "npm-cache"),
          npm_config_prefix: globalPrefix,
          npm_config_userconfig: userConfig,
          ...(configuration === "environment"
            ? { npm_config_global: "true" }
            : {}),
        });
        const installed = await installPackage(root, archivePath, environment);
        expect({
          status: installed.status,
          stderr: installed.status === 0 ? "" : installed.stderr,
        }).toEqual({
          status: 0,
          stderr: "",
        });
        expect(
          existsSync(
            join(
              root,
              "consumer",
              "node_modules",
              "@openai",
              "codex-security",
              "package.json",
            ),
          ),
        ).toBe(true);
        expect(existsSync(globalPrefix)).toBe(false);
      } finally {
        rmSync(root, { force: true, recursive: true });
      }
    },
  );

  test.each([
    [
      "old GNU",
      tarRecord(Buffer.alloc(0), {
        name: "package/README.md",
        type: 0x53,
        magic: "ustar ",
        version: " \0",
      }),
    ],
    ["GNU PAX map", paxExtension({ "GNU.sparse.map": "0,1" })],
    ["GNU global PAX", paxExtension({ "GNU.sparse.major": "1" }, 0x67)],
    ["Solaris hole map", paxExtension({ "SUN.holesdata": " 0 1" })],
    ["star logical size", paxExtension({ "SCHILY.realsize": "1" })],
  ] as const)(
    "rejects %s sparse entries before invoking native tar",
    async (_label, record) => {
      const root = mkdtempSync(join(tmpdir(), "codex-package-sparse-"));
      try {
        const archivePath = join(root, "sparse.tgz");
        writeFileSync(
          archivePath,
          gzipSync(packageTar({ additionalRecords: [record] })),
        );
        const contractPath = join(root, "contract.json");
        writeFileSync(contractPath, JSON.stringify(pluginContract));
        const environment = { ...process.env, PATH: root };
        const checked = await checkPackage(
          root,
          archivePath,
          contractPath,
          environment,
        );
        expect(checked.status).toBe(1);
        expect(checked.stderr).toContain(
          "npm tarball contains an unsupported sparse entry.",
        );
      } finally {
        rmSync(root, { force: true, recursive: true });
      }
    },
  );

  test.each([
    "pax-path",
    "pax-then-wrong-long-name",
    "pax-then-correct-long-name",
    "long-name-then-pax",
  ])("validates the asset path used by npm: %s", async (order) => {
    const root = mkdtempSync(join(tmpdir(), "codex-package-npm-path-"));
    try {
      const logo = readFileSync(
        new URL(
          "../../../plugins/codex-security/assets/logo.png",
          import.meta.url,
        ),
      );
      const path = "package/_bundled_plugin/logo.png";
      const storagePath = "package/synthetic-storage.png";
      const wrongLongName = order === "pax-then-wrong-long-name";
      const pax = paxExtension({ path });
      const longName = tarRecord(
        Buffer.from(`${wrongLongName ? storagePath : path}\0`),
        { name: "././@LongLink", type: 0x4c },
      );
      const headers =
        order === "pax-path"
          ? [pax]
          : order === "long-name-then-pax"
            ? [longName, pax]
            : [pax, longName];
      const archivePath = join(root, "package.tgz");
      writeFileSync(
        archivePath,
        gzipSync(
          packageTar({
            additionalRecords: [
              ...headers,
              tarRecord(logo, { name: storagePath }),
            ],
          }),
        ),
      );
      const native = mkdtempSync(join(root, "native-"));
      const contractPath = join(root, "contract.json");
      writeFileSync(
        contractPath,
        JSON.stringify({
          ...pluginContract,
          shippedExact: [...pluginContract.shippedExact, "logo.png"],
        }),
      );
      const environment: NodeJS.ProcessEnv = {
        ...process.env,
        npm_config_cache: join(root, "npm-cache"),
      };
      delete environment["CODEX_SECURITY_EXPECTED_GIT_HEAD"];
      const packageCheck = checkPackage(
        root,
        archivePath,
        contractPath,
        environment,
      );
      // The two readers can disagree on a final GNU long name. Extract everything in that case.
      const extraction = execFileAsync(
        "tar",
        ["-xzf", archivePath, "-C", native, ...(wrongLongName ? [] : [path])],
        {
          encoding: "buffer",
          timeout: 30_000,
          windowsHide: true,
        },
      );
      const installation = installPackage(root, archivePath, environment);
      await Promise.allSettled([extraction, installation, packageCheck]);
      expect((await extraction).stderr.toString()).toBe("");
      if (!wrongLongName)
        expect(readFileSync(join(native, path))).toEqual(logo);
      const installed = await installation;
      expect(installed.status, installed.stderr).toBe(0);
      const installedPackage = join(
        root,
        "consumer",
        "node_modules",
        "@openai",
        "codex-security",
      );
      if (wrongLongName)
        expect(
          existsSync(join(installedPackage, "_bundled_plugin", "logo.png")),
        ).toBe(false);
      const installedPath = wrongLongName ? storagePath : path;
      expect(
        readFileSync(
          join(installedPackage, installedPath.slice("package/".length)),
        ),
      ).toEqual(logo);
      const checked = await packageCheck;
      expect(checked.status, checked.stderr).toBe(wrongLongName ? 1 : 0);
      if (!wrongLongName) expect(checked.stderr).toBe("");
    } finally {
      rmSync(root, { force: true, recursive: true });
    }
  });

  test.each([
    ["Apache-2.0", "a".repeat(40), undefined],
    ["MIT", "a".repeat(40), "expected public metadata"],
    ["Apache-2.0", "b".repeat(40), "gitHead must match release commit"],
  ] as const)(
    "validates metadata from the PAX manifest npm installs: %s, %s",
    async (license, gitHead, error) => {
      const root = mkdtempSync(join(tmpdir(), "codex-package-npm-manifest-"));
      try {
        const path = "package/package.json";
        const manifest = Buffer.from(
          JSON.stringify({
            name: "@openai/codex-security",
            version: "1.0.0",
            license,
            gitHead,
          }),
        );
        const entry = Buffer.concat([
          paxExtension({ path }),
          tarRecord(manifest, { name: "package/synthetic-storage.json" }),
        ]);
        const archivePath = join(root, "package.tgz");
        writeFileSync(
          archivePath,
          gzipSync(packageTar({ overrides: new Map([[path, entry]]) })),
        );
        const environment = {
          ...process.env,
          npm_config_cache: join(root, "npm-cache"),
          CODEX_SECURITY_EXPECTED_GIT_HEAD: "a".repeat(40),
        };
        const contractPath = join(root, "contract.json");
        writeFileSync(contractPath, JSON.stringify(pluginContract));
        const installed = await installPackage(root, archivePath, environment);
        expect(installed.status, installed.stderr).toBe(0);
        const installedManifest = JSON.parse(
          readFileSync(
            join(
              root,
              "consumer",
              "node_modules",
              "@openai",
              "codex-security",
              "package.json",
            ),
            "utf8",
          ),
        );
        expect(installedManifest).toMatchObject({ license, gitHead });
        const checked = await checkPackage(
          root,
          archivePath,
          contractPath,
          environment,
        );
        if (error !== undefined) {
          expect(checked.status).toBe(1);
          expect(checked.stderr).toContain(error);
        } else expect(checked).toEqual({ status: 0, stderr: "" });
      } finally {
        rmSync(root, { force: true, recursive: true });
      }
    },
  );

  test.each([
    ["clean Brotli", cleanCompressedPayload, undefined],
    [
      "expanded marker",
      brotliCompressSync(Buffer.from("go/synthetic-reference")),
      "internal reference",
    ],
    [
      "trailing bytes",
      Buffer.concat([cleanCompressedPayload, Buffer.from("extra")]),
      "trailing Brotli data",
    ],
  ] as const)(
    "checks regular compressed assets: %s",
    async (_label, contents, error) => {
      const root = mkdtempSync(join(tmpdir(), "codex-package-assets-"));
      try {
        const name = "runtime.mjs.br";
        const archivePath = join(root, "package.tgz");
        writeFileSync(
          archivePath,
          gzipSync(
            packageTar({
              additionalRecords: [
                tarRecord(contents, {
                  name: `package/_bundled_plugin/${name}`,
                }),
              ],
            }),
          ),
        );
        const contractPath = join(root, "contract.json");
        writeFileSync(
          contractPath,
          JSON.stringify({
            ...pluginContract,
            shippedExact: [...pluginContract.shippedExact, name],
          }),
        );
        const environment = { ...process.env };
        delete environment["CODEX_SECURITY_EXPECTED_GIT_HEAD"];
        const checked = await checkPackage(
          root,
          archivePath,
          contractPath,
          environment,
        );
        if (error) {
          expect(checked.status).toBe(1);
          expect(checked.stderr).toContain(error);
        } else expect(checked).toEqual({ status: 0, stderr: "" });
      } finally {
        rmSync(root, { force: true, recursive: true });
      }
    },
  );

  test.each([0x78, 0x67])(
    "preserves inherited character locale for Unicode pax owners, type=%i",
    async (type) => {
      const root = mkdtempSync(join(tmpdir(), "codex-package-owner-test-"));
      try {
        const archivePath = join(root, "unicode owner.tgz");
        writeFileSync(
          archivePath,
          gzipSync(
            Buffer.concat([
              tarRecord(
                paxRecords({
                  uname: "Synthetic é owner",
                  gname: "Synthetic é group",
                }),
                { name: "OwnerHead", type },
              ),
              packageTar(),
            ]),
          ),
        );
        const contractPath = join(root, "plugin contract.json");
        writeFileSync(contractPath, JSON.stringify(pluginContract));
        const environment: NodeJS.ProcessEnv = { ...process.env };
        delete environment["CODEX_SECURITY_EXPECTED_GIT_HEAD"];
        if (process.platform !== "win32")
          environment["LC_ALL"] =
            process.platform === "darwin" ? "en_US.UTF-8" : "C.UTF-8";
        const result = await checkPackage(
          root,
          archivePath,
          contractPath,
          environment,
        );
        expect({ status: result.status, stderr: result.stderr }).toEqual({
          status: 0,
          stderr: "",
        });
      } finally {
        rmSync(root, { force: true, recursive: true });
      }
    },
  );

  test.skipIf(process.platform === "win32")(
    "explains the missing tar option on Alpine",
    async () => {
      const root = mkdtempSync(join(tmpdir(), "codex-package-tar-option-"));
      try {
        const tools = join(root, "tools");
        mkdirSync(tools);
        writeFileSync(
          join(tools, "tar"),
          "#!/bin/sh\necho 'tar: unrecognized option: ignore-zeros' >&2\necho 'BusyBox multi-call binary.' >&2\nexit 1\n",
          { mode: 0o755 },
        );
        const path = join(root, "package.tgz");
        writeFileSync(path, gzipSync(packageTar(), { level: 0 }));
        const contract = join(root, "contract.json");
        writeFileSync(contract, JSON.stringify(pluginContract));
        const checked = await checkPackage(root, path, contract, {
          ...process.env,
          PATH: tools + delimiter + process.env["PATH"],
        });
        expect(checked.status).toBe(1);
        expect(checked.stderr).toContain("apk add tar");
        expect(checked.stderr).toContain(
          "tar: unrecognized option: ignore-zeros",
        );
      } finally {
        rmSync(root, { force: true, recursive: true });
      }
    },
  );

  test("streams each archive without resolving tar from its directory", async () => {
    const root = mkdtempSync(join(tmpdir(), "codex-package-tar-test-"));
    try {
      const archiveDirectory = join(
        root,
        process.platform === "win32" ? "package archive" : "D: package archive",
      );
      mkdirSync(archiveDirectory, { recursive: true });
      const archivePath = join(
        archiveDirectory,
        process.platform === "win32"
          ? "-fixture package.tgz"
          : "-fixture: package.tgz",
      );
      const contractPath = join(root, "plugin contract.json");
      const logPath = join(root, "tar calls.jsonl");
      const adjacentTarMarker = join(root, "archive tar ran");
      // A valid plugin inventory can exceed the Windows process command-line limit.
      const extraFiles = Array.from(
        { length: 256 },
        (_, index) => `fixtures/generated-plugin-document-${index}.md`,
      );
      const tarBytes = packageTar({
        compatibleLayout: true,
        rootDirectoryMode: 0o555,
        readmeMode: 0,
        additionalRecords: extraFiles.map((file) =>
          tarRecord(Buffer.alloc(0), {
            name: `package/_bundled_plugin/${file}`,
          }),
        ),
      });
      const archiveContents = gzipSync(tarBytes, { level: 0 });
      writeFileSync(archivePath, archiveContents);
      writeFileSync(
        contractPath,
        JSON.stringify({
          ...pluginContract,
          shippedExact: [...pluginContract.shippedExact, ...extraFiles],
        }),
      );

      const environment: NodeJS.ProcessEnv = { ...process.env };
      delete environment["CODEX_SECURITY_EXPECTED_GIT_HEAD"];
      environment["PATH"] = `.${delimiter}${process.env["PATH"] ?? ""}`;
      const extractionDirectory = join(root, "extraction");
      mkdirSync(extractionDirectory, { mode: 0o700 });
      for (const variable of ["TMPDIR", "TMP", "TEMP"]) {
        environment[variable] = extractionDirectory;
      }
      if (process.platform === "win32") {
        for (const name of ["tar.com", "tar.exe"]) {
          writeFileSync(join(archiveDirectory, name), "not an executable");
        }
      } else {
        const adjacentTar = join(archiveDirectory, "tar");
        writeFileSync(
          adjacentTar,
          `#!/usr/bin/env node
require("node:fs").writeFileSync(process.env.ADJACENT_TAR_MARKER, "ran");
process.exit(99);
`,
        );
        chmodSync(adjacentTar, 0o755);

        const proxySource = `#!/usr/bin/env node
const { spawnSync } = require("node:child_process");
const { createHash } = require("node:crypto");
const { appendFileSync, chmodSync, readFileSync, writeFileSync } = require("node:fs");
const input = readFileSync(0);
appendFileSync(
  process.env.TAR_PROXY_LOG,
  JSON.stringify({
    args: process.argv.slice(2),
    cwd: process.cwd(),
    inputLength: input.length,
    inputSha256: createHash("sha256").update(input).digest("hex"),
  }) + "\\n",
);
const mismatch = process.env.TAR_PROXY_MISMATCH;
const alterListing = mismatch === "size" && process.argv.includes("-tvzf");
const result = spawnSync(process.env.REAL_TAR, process.argv.slice(2), {
  env: process.env,
  input,
  stdio: ["pipe", alterListing ? "pipe" : "inherit", "inherit"],
  windowsHide: true,
});
if (result.error !== undefined) throw result.error;
if (alterListing) {
  const lines = result.stdout.toString("utf8").split("\\n");
  process.stdout.write(lines.map(line => line.endsWith(" package/README.md")
    ? "-rw------- 0/0 1 1970-01-01 00:00 package/README.md" : line).join("\\n"));
}
if (mismatch === "contents" && process.argv.includes("-xzf") && result.status === 0) {
  const path = require("node:path").join(process.argv[process.argv.indexOf("-C") + 1], "package", "README.md");
  chmodSync(path, 0o600);
  writeFileSync(path, "changed\\n"); // Same length as fixture\\n.
}
if (result.status === 0 && process.argv.includes("-xzf") && process.env.TAR_PROXY_FAIL_EXTRACT) {
  process.stderr.write("synthetic extraction failure\\n");
  process.exit(23);
}
process.exit(result.status ?? 1);
`;
        const proxyPath = join(root, "tar");
        writeFileSync(proxyPath, proxySource);
        chmodSync(proxyPath, 0o755);
        environment["ADJACENT_TAR_MARKER"] = adjacentTarMarker;
        environment["REAL_TAR"] = commandPath("tar");
        environment["TAR_PROXY_LOG"] = logPath;
      }

      const result = await checkPackage(
        root,
        archivePath,
        contractPath,
        environment,
      );
      expect(existsSync(adjacentTarMarker)).toBe(false);
      expect({ status: result.status, stderr: result.stderr }).toEqual({
        status: 0,
        stderr: "",
      });
      expect(readdirSync(extractionDirectory)).toEqual([]);
      if (process.platform === "win32") return;

      const calls = readFileSync(logPath, "utf8")
        .trim()
        .split(/\r?\n/u)
        .map(
          (line) =>
            JSON.parse(line) as {
              args: string[];
              cwd: string;
              inputLength: number;
              inputSha256: string;
            },
        );
      const archiveSha256 = createHash("sha256")
        .update(archiveContents)
        .digest("hex");
      expect(calls).toHaveLength(3);
      for (const call of calls) {
        expect(call.args.filter((arg) => arg === "-")).toEqual(["-"]);
        expect(call.args).not.toContain(archivePath);
        expect(realpathSync(call.cwd)).toBe(realpathSync(root));
        expect(call.inputLength).toBe(archiveContents.length);
        expect(call.inputSha256).toBe(archiveSha256);
      }
      expect(calls[0]?.args).toEqual(["--ignore-zeros", "-tzf", "-"]);
      expect(calls[1]?.args).toEqual([
        "--ignore-zeros",
        "--numeric-owner",
        "-tvzf",
        "-",
      ]);
      expect(calls[2]?.args.slice(0, 10)).toEqual([
        "--ignore-zeros",
        "-m",
        "--keep-old-files",
        "--no-same-owner",
        "--no-same-permissions",
        "--no-acls",
        "--no-xattrs",
        "-xzf",
        "-",
        "-C",
      ]);

      for (const mismatch of ["size", "contents"]) {
        writeFileSync(logPath, "");
        const rejected = await checkPackage(root, archivePath, contractPath, {
          ...environment,
          TAR_PROXY_MISMATCH: mismatch,
        });
        expect(rejected.status).toBe(1);
        expect(rejected.stderr).toContain(
          "npm tarball contains an invalid tar entry.",
        );
        expect(readFileSync(logPath, "utf8").includes('"-xzf"')).toBe(
          mismatch === "contents",
        );
        expect(readdirSync(extractionDirectory)).toEqual([]);
      }

      environment["TAR_PROXY_FAIL_EXTRACT"] = "true";
      const failed = await checkPackage(
        root,
        archivePath,
        contractPath,
        environment,
      );
      expect(failed.status).not.toBe(0);
      expect(failed.stderr).toContain("synthetic extraction failure");
      expect(readdirSync(extractionDirectory)).toEqual([]);
    } finally {
      rmSync(root, { force: true, recursive: true });
    }
  });
});

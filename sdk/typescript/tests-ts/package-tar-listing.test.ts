import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  chmodSync,
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
import { brotliCompressSync, brotliDecompressSync, gzipSync } from "node:zlib";
import { describe, expect, test } from "bun:test";
import {
  archive,
  cleanCompressedPayload,
  octal,
  oldGnuSparseRecord,
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
const pluginContract = {
  externalOwnedExact: [".codex-plugin/plugin.json"],
  shippedExact: ["scripts/launch_codex_security_mcp"],
};

function packageTar({
  trailingZeroBytes = 0,
  sizeTerminator = " ",
  type = 0x30,
  compatibleLayout = false,
  rootDirectoryMode = 0o755,
  directoryMode = 0o755,
  readmeMode = 0o644,
  mtime = 0,
  readmeSparse,
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
  readmeSparse?: "0.0" | "1.0";
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
    "package/docs/cli.md",
    "package/docs/findings-service.md",
    "package/docs/dedupe-records.md",
    "package/schemas/project-config.schema.json",
    "package/LICENSE",
    ...executablePaths,
    ...packageDistFiles,
    "package/_bundled_plugin/.codex-plugin/plugin.json",
  ];
  const records = paths.map((path) => {
    const override = overrides.get(path);
    if (override !== undefined) return override;
    if (path === "package/README.md" && readmeSparse !== undefined) {
      const contents = Buffer.alloc(512, 0x78);
      const map = Buffer.alloc(512);
      map.write("1\n512\n512\n");
      const attributes: Record<string, string> =
        readmeSparse === "0.0"
          ? {
              "GNU.sparse.size": "1024",
              "GNU.sparse.numblocks": "1",
              "GNU.sparse.map": "512,512",
            }
          : {
              "GNU.sparse.major": "1",
              "GNU.sparse.minor": "0",
              "GNU.sparse.name": path,
              "GNU.sparse.realsize": "1024",
            };
      return Buffer.concat([
        tarRecord(paxRecords(attributes), {
          name: "PaxHeaders/readme",
          type: 0x78,
        }),
        tarRecord(
          readmeSparse === "0.0" ? contents : Buffer.concat([map, contents]),
          {
            name:
              readmeSparse === "0.0" ? path : "package/GNUSparseFile.1/readme",
          },
        ),
      ]);
    }
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

function installPackage(
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
  const resolved = spawnSync(
    commandPath("node"),
    [
      "--input-type=module",
      "-e",
      `import { resolveNpm } from ${JSON.stringify(new URL("../scripts/package-smoke-npm.mjs", import.meta.url).href)}; console.log(JSON.stringify(await resolveNpm()));`,
    ],
    { encoding: "utf8", env: environment, windowsHide: true },
  );
  expect({ status: resolved.status, stderr: resolved.stderr }).toEqual({
    status: 0,
    stderr: "",
  });
  const npm = JSON.parse(resolved.stdout) as {
    command: string;
    args: string[];
  };
  return spawnSync(
    npm.command,
    [
      ...npm.args,
      "install",
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
    {
      cwd: consumer,
      env: environment,
      encoding: "utf8",
      timeout: 30_000,
      windowsHide: true,
    },
  );
}

describe("npm package tar listings", () => {
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
  ])("bounds native sparse logical sizes before extraction: %s", (line) => {
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

  test("retains bounded logical sparse sizes in listing order", () => {
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

  test.each([false, true])(
    "rejects invalid package paths before Brotli expansion, complete=%p",
    (complete) => {
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
        const result = spawnSync(
          commandPath("node"),
          [
            fileURLToPath(
              new URL("../scripts/check-package.mjs", import.meta.url),
            ),
            archivePath,
            contractPath,
          ],
          { cwd: root, encoding: "utf8", timeout: 30_000, windowsHide: true },
        );
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

  test("escapes terminal controls in unexpected archive path diagnostics", () => {
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
      const result = spawnSync(
        commandPath("node"),
        [
          fileURLToPath(
            new URL("../scripts/check-package.mjs", import.meta.url),
          ),
          archivePath,
          contractPath,
        ],
        { cwd: root, encoding: "utf8", timeout: 30_000, windowsHide: true },
      );
      expect(result.status).toBe(1);
      expect(result.stderr).toContain("unexpected file: package/unexpected");
      expect(result.stderr).not.toMatch(/[\u001b\u0007\u009b]/u);
      expect(result.stderr).toContain("synthetic");
    } finally {
      rmSync(root, { force: true, recursive: true });
    }
  });

  test("accepts equivalent bounded gzip representations", () => {
    const root = mkdtempSync(join(tmpdir(), "codex-package-gzip-test-"));
    try {
      const tarBytes = packageTar({ trailingZeroBytes: 31 * 1024 * 1024 });
      const archives = [
        ["default", gzipSync(tarBytes)],
        ["level-0", gzipSync(tarBytes, { level: 0 })],
        ["sparse-0.0", gzipSync(packageTar({ readmeSparse: "0.0" }))],
        ["sparse-1.0", gzipSync(packageTar({ readmeSparse: "1.0" }))],
        ["gnu-long-name", gzipSync(packageTar({ readmeLongName: true }))],
        ["npm-size-field", gzipSync(packageTar({ sizeTerminator: " \0" }))],
        ["nul-regular-file", gzipSync(packageTar({ type: 0 }))],
        [
          "future-timestamps",
          gzipSync(
            packageTar({ mtime: Math.floor(Date.now() / 1000) + 365 * 86400 }),
          ),
        ],
        ["unreadable-readme", gzipSync(packageTar({ readmeMode: 0 }))],
        [
          "read-only-nested-directories",
          gzipSync(
            packageTar({ compatibleLayout: true, directoryMode: 0o555 }),
          ),
        ],
        ["posix-size-field", gzipSync(packageTar({ sizeTerminator: "\0" }))],
        [
          "compatible-tar-layout",
          gzipSync(packageTar({ compatibleLayout: true })),
        ],
        [
          "read-only-directories",
          gzipSync(
            packageTar({ compatibleLayout: true, rootDirectoryMode: 0o555 }),
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
        const result = spawnSync(
          commandPath("node"),
          [
            fileURLToPath(
              new URL("../scripts/check-package.mjs", import.meta.url),
            ),
            archivePath,
            contractPath,
          ],
          {
            cwd: root,
            encoding: "utf8",
            env: environment,
            timeout: 30_000,
            windowsHide: true,
          },
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
    (configuration) => {
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
        const installed = installPackage(root, archivePath, environment);
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
    "pax-full",
    "pax-map-prefix",
    "pax-hole",
    "oldgnu",
    "sparse-name",
    "pax-path",
    "global-path",
    "pax-then-long-name",
    "long-name-then-pax",
    "pax-then-wrong-long-name",
    "overwrite-text",
    "overwrite-logo",
    "ordinary-pax-then-wrong-long-name",
    "ordinary-pax-then-correct-long-name",
    "ordinary-long-name-then-pax",
  ])("validates archive assets as npm installs them: %s", (representation) => {
    const root = mkdtempSync(join(tmpdir(), "codex-package-npm-sparse-"));
    try {
      const logo = readFileSync(
        new URL(
          "../../../plugins/codex-security/assets/logo.png",
          import.meta.url,
        ),
      );
      const path = "package/_bundled_plugin/logo.png";
      const renamed =
        representation === "sparse-name" || representation === "pax-path";
      const wrongPath = "package/synthetic-storage.png";
      const ordinary = representation.startsWith("ordinary-");
      const pathOrder = ordinary
        ? representation.slice("ordinary-".length)
        : representation;
      const wrongLongName = pathOrder === "pax-then-wrong-long-name";
      const orderedPath = representation.includes("then");
      const overwrite = representation.startsWith("overwrite");
      let stored =
        representation === "overwrite-text" ? Buffer.from("fixture\n") : logo;
      const attributes: Record<string, string> = ordinary
        ? {}
        : {
            "GNU.sparse.size": String(stored.length),
            "GNU.sparse.numblocks": "1",
            "GNU.sparse.map": `0,${stored.length}`,
          };
      if (representation === "pax-map-prefix") {
        const map = Buffer.alloc(512);
        map.write(`1\n0\n${logo.length}\n`);
        stored = Buffer.concat([map, logo]);
        for (const key of Object.keys(attributes)) delete attributes[key];
        Object.assign(attributes, {
          "GNU.sparse.major": "1",
          "GNU.sparse.minor": "0",
          "GNU.sparse.name": path,
          "GNU.sparse.realsize": String(logo.length),
        });
      } else if (representation === "pax-hole") {
        const hole = logo.findIndex(
          (byte, index) => index > 0 && index % 512 === 0 && byte === 0,
        );
        expect(hole).toBeGreaterThan(0);
        stored = Buffer.concat([
          logo.subarray(0, hole),
          logo.subarray(hole + 1),
        ]);
        attributes["GNU.sparse.numblocks"] = "2";
        attributes["GNU.sparse.map"] =
          `0,${hole},${hole + 1},${logo.length - hole - 1}`;
      }
      if (
        !ordinary &&
        (renamed || orderedPath || representation === "global-path")
      )
        attributes["GNU.sparse.name"] = path;
      if (overwrite) attributes["GNU.sparse.name"] = "package/README.md";
      if (representation === "pax-path" || orderedPath)
        attributes["path"] =
          representation === "pax-then-long-name" ? wrongPath : path;
      const longName = tarRecord(
        Buffer.from(
          `${representation === "pax-then-long-name" || representation === "ordinary-pax-then-correct-long-name" || pathOrder === "long-name-then-pax" ? path : wrongPath}\0`,
        ),
        { name: "././@LongLink", type: 0x4c },
      );
      const record =
        representation === "oldgnu"
          ? oldGnuSparseRecord(logo, path)
          : Buffer.concat([
              ...(representation === "global-path"
                ? [
                    tarRecord(paxRecords({ path: wrongPath }), {
                      name: "GlobalHead",
                      type: 0x67,
                    }),
                  ]
                : []),
              ...(pathOrder === "long-name-then-pax" ? [longName] : []),
              tarRecord(paxRecords(attributes), {
                name: "PaxHeaders/asset",
                type: 0x78,
              }),
              ...(pathOrder.startsWith("pax-then") ? [longName] : []),
              tarRecord(stored, {
                name: renamed || ordinary ? wrongPath : path,
              }),
            ]);
      const archivePath = join(root, "package.tgz");
      writeFileSync(
        archivePath,
        gzipSync(
          packageTar({
            overrides: overwrite
              ? new Map([["package/README.md", Buffer.alloc(0)]])
              : undefined,
            additionalRecords: overwrite
              ? [tarRecord(logo, { name: path }), record]
              : [record],
          }),
        ),
      );
      const nativeRoot = join(root, "native");
      mkdirSync(nativeRoot);
      const extracted = spawnSync(
        "tar",
        ["-xzf", archivePath, "-C", nativeRoot],
        { encoding: "buffer", timeout: 30_000, windowsHide: true },
      );
      expect({
        status: extracted.status,
        stderr: extracted.stderr.toString(),
      }).toEqual({ status: 0, stderr: "" });
      // These incompatible packages do not promise a portable native asset path.
      if (!wrongLongName)
        expect(readFileSync(join(nativeRoot, path)).equals(logo)).toBe(true);
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
      const installed = installPackage(root, archivePath, environment);
      const consumer = join(root, "consumer");
      expect({
        status: installed.status,
        stderr: installed.status === 0 ? "" : installed.stderr,
      }).toEqual({ status: 0, stderr: "" });
      const installedPackage = join(
        consumer,
        "node_modules",
        "@openai",
        "codex-security",
      );
      const installedLogo = join(
        installedPackage,
        "_bundled_plugin",
        "logo.png",
      );
      if (wrongLongName) {
        expect(existsSync(installedLogo)).toBe(false);
        expect(
          readFileSync(
            join(installedPackage, wrongPath.slice("package/".length)),
          ).equals(logo),
        ).toBe(true);
      }
      const compatible = [
        "pax-full",
        "pax-path",
        "global-path",
        "pax-then-long-name",
        "long-name-then-pax",
        "overwrite-logo",
        "ordinary-pax-then-correct-long-name",
        "ordinary-long-name-then-pax",
      ].includes(representation);
      expect(
        existsSync(installedLogo) && readFileSync(installedLogo).equals(logo),
      ).toBe(compatible);
      if (overwrite)
        expect(readFileSync(installedLogo).equals(stored)).toBe(true);
      const checked = spawnSync(
        commandPath("node"),
        [
          fileURLToPath(
            new URL("../scripts/check-package.mjs", import.meta.url),
          ),
          archivePath,
          contractPath,
        ],
        {
          cwd: root,
          env: environment,
          encoding: "utf8",
          timeout: 30_000,
          windowsHide: true,
        },
      );
      expect({
        status: checked.status,
        stderr: compatible ? checked.stderr : "",
      }).toEqual({ status: compatible ? 0 : 1, stderr: "" });
    } finally {
      rmSync(root, { force: true, recursive: true });
    }
  });

  test.each([
    "oldgnu-manifest",
    "pax-map-prefix",
    "overwrite-json",
    "overwrite-metadata",
    "overwrite-git-head",
    "pax-full",
    "pax-path",
    "oldgnu-readme",
  ])("validates the manifest npm installs: %s", (representation) => {
    const root = mkdtempSync(join(tmpdir(), "codex-package-npm-manifest-"));
    try {
      const path = "package/package.json";
      const gitHead = "a".repeat(40);
      const metadata = {
        name: "@openai/codex-security",
        version: "1.0.0",
        license: "Apache-2.0",
        gitHead,
      };
      const manifest = Buffer.from(JSON.stringify(metadata));
      const overrides = new Map([[path, tarRecord(manifest, { name: path })]]);
      if (representation.startsWith("oldgnu")) {
        const oldPath =
          representation === "oldgnu-manifest" ? path : "package/README.md";
        overrides.set(
          oldPath,
          oldGnuSparseRecord(
            oldPath === path ? manifest : Buffer.from("fixture\n"),
            oldPath,
          ),
        );
      } else {
        const overwrite = representation.startsWith("overwrite");
        const logicalPath = overwrite ? "package/README.md" : path;
        let stored = overwrite
          ? Buffer.from(
              representation === "overwrite-json"
                ? "fixture\n"
                : JSON.stringify({
                    ...metadata,
                    ...(representation === "overwrite-metadata"
                      ? { license: "MIT" }
                      : { gitHead: "b".repeat(40) }),
                  }),
            )
          : manifest;
        const attributes: Record<string, string> = {
          "GNU.sparse.size": String(stored.length),
          "GNU.sparse.numblocks": "1",
          "GNU.sparse.map": `0,${stored.length}`,
          "GNU.sparse.name": logicalPath,
        };
        if (representation === "pax-map-prefix") {
          const map = Buffer.alloc(512);
          map.write(`1\n0\n${stored.length}\n`);
          for (const key of Object.keys(attributes)) delete attributes[key];
          Object.assign(attributes, {
            "GNU.sparse.major": "1",
            "GNU.sparse.minor": "0",
            "GNU.sparse.name": path,
            "GNU.sparse.realsize": String(stored.length),
          });
          stored = Buffer.concat([map, stored]);
        }
        if (representation === "pax-path") attributes["path"] = path;
        overrides.set(
          logicalPath,
          Buffer.concat([
            tarRecord(paxRecords(attributes), {
              name: "PaxHeaders/manifest",
              type: 0x78,
            }),
            tarRecord(stored, {
              name:
                representation === "pax-path"
                  ? "package/synthetic-storage.json"
                  : path,
            }),
          ]),
        );
      }
      const archivePath = join(root, "package.tgz");
      writeFileSync(archivePath, gzipSync(packageTar({ overrides })));
      const extracted = spawnSync("tar", ["-xOzf", archivePath, path], {
        encoding: "buffer",
        timeout: 30_000,
        windowsHide: true,
      });
      expect({
        status: extracted.status,
        stderr: extracted.stderr.toString(),
      }).toEqual({ status: 0, stderr: "" });
      expect(extracted.stdout.equals(manifest)).toBe(true);
      const environment: NodeJS.ProcessEnv = {
        ...process.env,
        npm_config_cache: join(root, "npm-cache"),
        CODEX_SECURITY_EXPECTED_GIT_HEAD: gitHead,
      };
      const installed = installPackage(root, archivePath, environment);
      const invalidJson = [
        "oldgnu-manifest",
        "pax-map-prefix",
        "overwrite-json",
      ].includes(representation);
      expect(installed.error).toBeUndefined();
      if (invalidJson) expect(installed.status).not.toBe(0);
      else {
        expect({
          status: installed.status,
          stderr: installed.status === 0 ? "" : installed.stderr,
        }).toEqual({ status: 0, stderr: "" });
        const actual = JSON.parse(
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
        expect(actual.license).toBe(
          representation === "overwrite-metadata" ? "MIT" : metadata.license,
        );
        expect(actual.gitHead).toBe(
          representation === "overwrite-git-head" ? "b".repeat(40) : gitHead,
        );
      }
      const compatible = ["pax-full", "pax-path", "oldgnu-readme"].includes(
        representation,
      );
      const contractPath = join(root, "contract.json");
      writeFileSync(contractPath, JSON.stringify(pluginContract));
      const checked = spawnSync(
        commandPath("node"),
        [
          fileURLToPath(
            new URL("../scripts/check-package.mjs", import.meta.url),
          ),
          archivePath,
          contractPath,
        ],
        {
          cwd: root,
          env: environment,
          encoding: "utf8",
          timeout: 30_000,
          windowsHide: true,
        },
      );
      expect({
        status: checked.status,
        stderr: compatible ? checked.stderr : "",
      }).toEqual({ status: compatible ? 0 : 1, stderr: "" });
      if (representation === "overwrite-metadata")
        expect(checked.stderr).toContain("expected public metadata");
      if (representation === "overwrite-git-head")
        expect(checked.stderr).toContain("gitHead must match release commit");
    } finally {
      rmSync(root, { force: true, recursive: true });
    }
  });

  test("checks reconstructed sparse binary assets and their discarded metadata", () => {
    const root = mkdtempSync(join(tmpdir(), "codex-package-sparse-assets-"));
    try {
      const logo = readFileSync(
        new URL(
          "../../../plugins/codex-security/assets/logo.png",
          import.meta.url,
        ),
      );
      const oldGnuText = Buffer.alloc(32 * 1024);
      const oldGnuExtents = Array.from({ length: 32 }, (_, index) => {
        oldGnuText.write("Public contents.", index * 1024);
        return { offset: index * 1024, size: 512 };
      });
      oldGnuExtents.push({ offset: oldGnuText.length, size: 0 });
      const unicodeCompressedPayload = Buffer.from(cleanCompressedPayload);
      Buffer.from("😀").copy(
        unicodeCompressedPayload,
        unicodeCompressedPayload.indexOf("Go/w") - 4,
      );
      const leadingMarker = cleanCompressedPayload.indexOf("Go/w");
      expect(leadingMarker).toBeGreaterThan(0);
      const repositoryCompressedPayload = Buffer.from(cleanCompressedPayload);
      const repositoryMarker = Buffer.from(
        ["github.com", "openai", "openai"].join("/"),
      );
      repositoryMarker.copy(repositoryCompressedPayload, 300);
      const repositoryMarkerEnd = 300 + repositoryMarker.length;
      expect(
        brotliDecompressSync(repositoryCompressedPayload).toString("utf8"),
      ).toMatch(/^[A-Za-z0-9]+$/u);
      const middle = Math.floor(cleanCompressedPayload.length / 2);
      const cases = [
        {
          name: "brotli",
          files: [["runtime.mjs.br", cleanCompressedPayload, true]],
        },
        {
          name: "unicode-brotli",
          files: [["runtime.mjs.br", unicodeCompressedPayload, true]],
        },
        {
          name: "sparse-brotli-leading-delimiter",
          files: [
            [
              "runtime.mjs.br.part-000",
              cleanCompressedPayload.subarray(0, leadingMarker),
              false,
            ],
            [
              "runtime.mjs.br.part-001",
              cleanCompressedPayload.subarray(leadingMarker),
              true,
            ],
          ],
        },
        {
          name: "sparse-brotli-trailing-delimiter",
          files: [
            [
              "runtime.mjs.br.part-000",
              repositoryCompressedPayload.subarray(0, repositoryMarkerEnd),
              true,
            ],
            [
              "runtime.mjs.br.part-001",
              repositoryCompressedPayload.subarray(repositoryMarkerEnd),
              false,
            ],
          ],
        },
        {
          name: "mixed-split-brotli",
          files: [
            [
              "runtime.mjs.br.part-000",
              cleanCompressedPayload.subarray(0, middle),
              true,
            ],
            [
              "runtime.mjs.br.part-001",
              cleanCompressedPayload.subarray(middle),
              false,
            ],
          ],
        },
        {
          name: "mixed-sparse-split-tail",
          files: [
            [
              "runtime.mjs.br.part-000",
              cleanCompressedPayload.subarray(0, middle),
              true,
            ],
            [
              "runtime.mjs.br.part-001",
              cleanCompressedPayload.subarray(middle),
              "0.1-tail",
            ],
          ],
          error: "npm tarball contains trailing Brotli data",
        },
        { name: "png", files: [["logo.png", logo, true]] },
        {
          name: "pax-sparse-zero-byte-hole-png",
          files: [["logo.png", logo, "0.1-hole"]],
          error: "npm tarball contains an unexpected PNG asset",
        },
        {
          name: "pax-sparse-zero-byte-hole-tail",
          files: [["logo.png", logo, "0.1-hole"]],
          tailMarker: true,
          error:
            /npm tarball contains (?:an internal reference\.|an invalid tar entry)/u,
        },
        {
          name: "oldgnu-brotli",
          files: [["runtime.mjs.br", cleanCompressedPayload, "oldgnu"]],
          error: "npm tarball contains an invalid tar entry",
        },
        {
          name: "oldgnu-png",
          files: [["logo.png", logo, "oldgnu"]],
          error: "npm tarball contains an invalid tar entry",
        },
        {
          name: "oldgnu-continuations",
          files: [["helpers.mjs", oldGnuText, "oldgnu"]],
          extents: oldGnuExtents,
        },
        {
          name: "oldgnu-unused-main-slot",
          files: [["runtime.mjs.br", cleanCompressedPayload, "oldgnu"]],
          metadataMarker: "unused",
          error: "npm tarball contains an invalid tar entry",
        },
        {
          name: "oldgnu-unused-continuation-slot",
          files: [["helpers.mjs", oldGnuText, "oldgnu"]],
          extents: oldGnuExtents,
          metadataMarker: "unused",
        },
        {
          name: "oldgnu-continuation-marker",
          files: [["helpers.mjs", oldGnuText, "oldgnu"]],
          extents: oldGnuExtents,
          metadataMarker: "continuation",
          error: "npm tarball contains an internal reference.",
        },
        {
          name: "oldgnu-metadata-boundary-marker",
          files: [["helpers.mjs", oldGnuText, "oldgnu"]],
          extents: oldGnuExtents,
          metadataMarker: "boundary",
          error: "npm tarball contains an internal reference.",
        },
        {
          name: "oldgnu-text-body-boundary-marker",
          files: [
            ["helpers.mjs", Buffer.from("synthetic-reference\n"), "oldgnu"],
          ],
          metadataMarker: "boundary",
          error: "npm tarball contains an internal reference.",
        },
        {
          name: "global-sparse-keys",
          files: [["runtime.mjs.br", cleanCompressedPayload, false]],
          globalSparse: true,
        },
        {
          name: "expanded-marker",
          files: [
            [
              "runtime.mjs.br",
              brotliCompressSync(Buffer.from("go/synthetic-reference")),
              true,
            ],
          ],
          error: "npm tarball contains an internal reference.",
        },
        {
          name: "sparse-header-map-boundary-marker",
          files: [["runtime.mjs.br", cleanCompressedPayload, "1.0"]],
          headerMapMarker: true,
          error: "npm tarball contains an internal reference.",
        },
        {
          name: "sparse-tail-header-boundary-marker",
          files: [
            ["runtime.mjs.br", cleanCompressedPayload, "1.0"],
            ["extra.mjs", Buffer.from("Public contents."), false],
          ],
          tailBoundaryMarker: true,
          error:
            /npm tarball contains (?:an internal reference\.|an invalid tar entry:)/u,
        },
        {
          name: "map-padding-marker",
          files: [["runtime.mjs.br", cleanCompressedPayload, "1.0"]],
          mapMarker: true,
          error: "npm tarball contains an internal reference.",
        },
        {
          name: "discarded-tail-marker",
          files: [["logo.png", logo, "1.0"]],
          tailMarker: true,
          error:
            /npm tarball contains (?:an internal reference\.|an invalid tar entry:)/u,
        },
      ] satisfies {
        name: string;
        files: [
          string,
          Buffer,
          boolean | "1.0" | "0.1-tail" | "0.1-hole" | "oldgnu",
        ][];
        extents?: { offset: number; size: number }[];
        metadataMarker?: "continuation" | "boundary" | "unused";
        globalSparse?: boolean;
        mapMarker?: boolean;
        headerMapMarker?: boolean;
        tailMarker?: boolean;
        tailBoundaryMarker?: boolean;
        error?: string | RegExp;
      }[];
      for (const scenario of cases) {
        const records = scenario.files.map(([name, contents, sparse]) => {
          const path = `package/_bundled_plugin/${name}`;
          if (!sparse) return tarRecord(contents, { name: path });
          if (sparse === "oldgnu")
            return oldGnuSparseRecord(
              contents,
              path,
              scenario.extents,
              scenario.metadataMarker,
            );
          if (sparse === "0.1-hole") {
            const hole = contents.findIndex(
              (byte, index) => index > 0 && index % 512 === 0 && byte === 0,
            );
            expect(hole).toBeGreaterThan(0);
            const stored = Buffer.concat([
              contents.subarray(0, hole),
              contents.subarray(hole + 1),
              scenario.tailMarker
                ? Buffer.from("go/synthetic-reference")
                : Buffer.alloc(0),
            ]);
            return Buffer.concat([
              tarRecord(
                paxRecords({
                  "GNU.sparse.size": String(contents.length),
                  "GNU.sparse.numblocks": "2",
                  "GNU.sparse.map": `0,${hole},${hole + 1},${contents.length - hole - 1}`,
                }),
                { name: "PaxHeaders/asset", type: 0x78 },
              ),
              tarRecord(stored, { name: path }),
            ]);
          }
          if (sparse === true) {
            return Buffer.concat([
              tarRecord(
                paxRecords({
                  "GNU.sparse.size": String(contents.length),
                  "GNU.sparse.numblocks": "1",
                  "GNU.sparse.map": `0,${contents.length}`,
                }),
                { name: "PaxHeaders/asset", type: 0x78 },
              ),
              tarRecord(contents, { name: path }),
            ]);
          }
          if (sparse === "0.1-tail") {
            const storedContents = Buffer.concat([
              contents,
              Buffer.from("go/synthetic-reference"),
            ]);
            return Buffer.concat([
              tarRecord(
                paxRecords({
                  "GNU.sparse.size": String(storedContents.length),
                  "GNU.sparse.numblocks": "1",
                  "GNU.sparse.map": `0,${storedContents.length}`,
                }),
                { name: "PaxHeaders/asset", type: 0x78 },
              ),
              tarRecord(storedContents, { name: path }),
            ]);
          }
          const map = Buffer.alloc(512);
          map.write(`1\n0\n${contents.length}\n`);
          if (scenario.mapMarker) map.write("go/synthetic-reference", 128);
          const tail = scenario.tailBoundaryMarker
            ? Buffer.alloc((512 - (contents.length % 512)) % 512 || 512)
            : scenario.tailMarker
              ? Buffer.from("go/synthetic-reference")
              : Buffer.alloc(0);
          if (scenario.tailBoundaryMarker) tail.write("go/", tail.length - 3);
          return Buffer.concat([
            tarRecord(
              paxRecords({
                "GNU.sparse.major": "1",
                "GNU.sparse.minor": "0",
                "GNU.sparse.name": path,
                "GNU.sparse.realsize": String(contents.length),
              }),
              { name: "PaxHeaders/asset", type: 0x78 },
            ),
            tarRecord(Buffer.concat([map, contents, tail]), {
              name: "package/GNUSparseFile.1/asset",
              ...(scenario.headerMapMarker
                ? {
                    reserved: Buffer.concat([
                      Buffer.alloc(9),
                      Buffer.from("go/"),
                    ]),
                  }
                : {}),
            }),
          ]);
        });
        const archivePath = join(root, `${scenario.name}.tgz`);
        writeFileSync(
          archivePath,
          gzipSync(
            Buffer.concat([
              ...(scenario.globalSparse
                ? [
                    tarRecord(
                      paxRecords({
                        "GNU.sparse.major": "1",
                        "GNU.sparse.minor": "0",
                      }),
                      { name: "GlobalHead", type: 0x67 },
                    ),
                  ]
                : []),
              packageTar({ additionalRecords: records }),
            ]),
          ),
        );
        const contractPath = join(root, "contract.json");
        writeFileSync(
          contractPath,
          JSON.stringify({
            ...pluginContract,
            shippedExact: [
              ...pluginContract.shippedExact,
              ...scenario.files.map(([name]) => name),
            ],
          }),
        );
        const environment = { ...process.env };
        delete environment["CODEX_SECURITY_EXPECTED_GIT_HEAD"];
        const result = spawnSync(
          commandPath("node"),
          [
            fileURLToPath(
              new URL("../scripts/check-package.mjs", import.meta.url),
            ),
            archivePath,
            contractPath,
          ],
          {
            cwd: root,
            env: environment,
            encoding: "utf8",
            timeout: 30_000,
            windowsHide: true,
          },
        );
        if (scenario.error) {
          expect({ scenario: scenario.name, status: result.status }).toEqual({
            scenario: scenario.name,
            status: 1,
          });
          if (typeof scenario.error === "string")
            expect(result.stderr).toContain(scenario.error);
          else expect(result.stderr).toMatch(scenario.error);
        } else {
          expect({
            scenario: scenario.name,
            status: result.status,
            stderr: result.stderr,
          }).toEqual({ scenario: scenario.name, status: 0, stderr: "" });
        }
      }
    } finally {
      rmSync(root, { force: true, recursive: true });
    }
  });

  test.each([0x78, 0x67])(
    "preserves inherited character locale for Unicode pax owners, type=%i",
    (type) => {
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
        const result = spawnSync(
          commandPath("node"),
          [
            fileURLToPath(
              new URL("../scripts/check-package.mjs", import.meta.url),
            ),
            archivePath,
            contractPath,
          ],
          {
            cwd: root,
            env: environment,
            encoding: "utf8",
            timeout: 30_000,
            windowsHide: true,
          },
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

  test("streams each archive without resolving tar from its directory", () => {
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
      const tarBytes = packageTar({
        compatibleLayout: true,
        rootDirectoryMode: 0o555,
        readmeMode: 0,
      });
      const archiveContents = gzipSync(tarBytes, { level: 0 });
      writeFileSync(archivePath, archiveContents);
      writeFileSync(contractPath, JSON.stringify(pluginContract));

      const nodePath = commandPath("node");
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
const { appendFileSync, readFileSync } = require("node:fs");
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
const result = spawnSync(process.env.REAL_TAR, process.argv.slice(2), {
  env: process.env,
  input,
  stdio: ["pipe", "inherit", "inherit"],
  windowsHide: true,
});
if (result.error !== undefined) throw result.error;
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

      const result = spawnSync(
        nodePath,
        [
          fileURLToPath(
            new URL("../scripts/check-package.mjs", import.meta.url),
          ),
          archivePath,
          contractPath,
        ],
        {
          cwd: root,
          encoding: "utf8",
          env: environment,
          timeout: 30_000,
          windowsHide: true,
        },
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

      environment["TAR_PROXY_FAIL_EXTRACT"] = "true";
      const failed = spawnSync(
        nodePath,
        [
          fileURLToPath(
            new URL("../scripts/check-package.mjs", import.meta.url),
          ),
          archivePath,
          contractPath,
        ],
        {
          cwd: root,
          encoding: "utf8",
          env: environment,
          timeout: 30_000,
          windowsHide: true,
        },
      );
      expect(failed.status).not.toBe(0);
      expect(failed.stderr).toContain("synthetic extraction failure");
      expect(readdirSync(extractionDirectory)).toEqual([]);
    } finally {
      rmSync(root, { force: true, recursive: true });
    }
  });
});

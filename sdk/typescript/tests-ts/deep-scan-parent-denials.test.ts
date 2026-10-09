import { execFileSync } from "node:child_process";
import * as fs from "node:fs";
import * as promises from "node:fs/promises";
import * as path from "node:path";
import * as url from "node:url";
import * as util from "node:util";
import { afterEach, expect, test } from "bun:test";
import { parse } from "smol-toml";
import { loadBundledRuntime } from "./plugin-root.js";
import { createApiTestFixtures } from "./support/temporary-directories.js";
import { profileConfigOverrides } from "../../../plugins/codex-security/scripts/codex_profile.mjs";

type DeepWorkerParentSandbox = {
  filesystemDenies: readonly string[];
  literalFilesystemDenies?: readonly string[];
  globScanMaxDepth?: number;
  filesystemWriteRules?: readonly { path: string; access: "read" | "write" }[];
  filesystemRootWritable?: boolean;
  filesystemRootWritePath?: string;
};
type DeepWorkerScratchAccess = {
  writePath: string;
  readOnlyPaths: readonly string[];
};

const fixtures = createApiTestFixtures("deep scratch permissions ");
afterEach(fixtures.cleanup);

async function bundledPolicy() {
  const runtime = await loadBundledRuntime();
  const start = runtime.indexOf("var CODEX_SANDBOX_STATE_META_CAPABILITY =");
  const end = runtime.indexOf("\n// ", start);
  expect(start).toBeGreaterThan(0);
  expect(end).toBeGreaterThan(start);
  const source = runtime.slice(start, end);
  const recordSource = runtime.match(
    /\/\/ src\/record\.ts\n[\s\S]*?(?=\n\/\/ )/u,
  )?.[0];
  expect(recordSource).toBeDefined();
  const imports = [
    ...new Set(
      source.match(
        /import_(?:node_(?:fs_promises|fs|path|url|util)|promises)\d*/gu,
      ),
    ),
  ];
  const resolve = new Function(
    ...imports,
    "DeepScanNonRetryableError",
    `${recordSource}\n${source}\nreturn { resolve: resolveDeepWorkerParentSandbox, scratch: resolveDeepWorkerScratchAccess };`,
  )(
    ...imports.map((name) =>
      name.startsWith("import_node_fs_promises") ||
      name.startsWith("import_promises")
        ? promises
        : name.startsWith("import_node_fs")
          ? fs
          : name.startsWith("import_node_path")
            ? path
            : name.startsWith("import_node_url")
              ? url
              : util,
    ),
    Error,
  ) as {
    resolve(metadata: unknown): DeepWorkerParentSandbox;
    scratch(
      sandbox: DeepWorkerParentSandbox,
      scratch: string,
      target: string,
    ): Promise<DeepWorkerScratchAccess | undefined>;
  };
  const profileSource = ["workerPermissionProfile", "scratchFilesystemEntry"]
    .map((name) => {
      const definition = new RegExp(
        `function ${name}\\([^\\n]*\\) \\{[\\s\\S]*?\\n\\}`,
        "u",
      ).exec(runtime)?.[0];
      expect(definition).toBeDefined();
      return definition;
    })
    .join("\n");
  const profile = new Function(
    `${profileSource}\nreturn workerPermissionProfile;`,
  ) as () => (
    sandbox: DeepWorkerParentSandbox,
    scratch?: DeepWorkerScratchAccess,
  ) => Record<string, unknown>;
  const workerProfile = profile();
  const overrides = (
    sandbox: DeepWorkerParentSandbox,
    scratch?: DeepWorkerScratchAccess,
  ) =>
    profileConfigOverrides({
      default_permissions: "codex_security_deep_scan_worker",
      "permissions.codex_security_deep_scan_worker": workerProfile(
        sandbox,
        scratch,
      ),
    });
  return { ...resolve, overrides };
}

function metadata(entries: unknown[], sandboxCwd?: string) {
  return {
    _meta: {
      "codex/sandbox-state-meta": {
        ...(sandboxCwd === undefined ? {} : { sandboxCwd }),
        permissionProfile: {
          type: "managed",
          network: "enabled",
          file_system: {
            type: "restricted",
            glob_scan_max_depth: 8,
            entries: [
              {
                access: "read",
                path: { type: "special", value: { kind: "root" } },
              },
              ...entries,
            ],
          },
        },
      },
    },
  };
}

test("preserves denies and write metadata without unassigned worker writes", async () => {
  const policy = await bundledPolicy();
  const denied = path.resolve("synthetic", "secret.with.dots");
  const glob = path.resolve("synthetic", "**", "*.secret");
  const sandbox = policy.resolve(
    metadata([
      {
        access: "write",
        path: { type: "path", path: path.resolve("synthetic") },
      },
      { access: "deny", path: { type: "path", path: denied } },
      { access: "none", path: { type: "glob_pattern", pattern: glob } },
    ]),
  );
  expect(sandbox).toEqual({
    filesystemDenies: [denied, glob],
    globScanMaxDepth: 8,
    filesystemWriteRules: [
      { path: path.resolve("synthetic"), access: "write" },
    ],
  });
  expect(parse(policy.overrides(sandbox).join("\n"))).toEqual({
    default_permissions: "codex_security_deep_scan_worker",
    permissions: {
      codex_security_deep_scan_worker: {
        extends: ":read-only",
        filesystem: {
          ":root": "read",
          [denied]: "deny",
          [glob]: "deny",
          glob_scan_max_depth: 8,
        },
        network: { enabled: false },
      },
    },
  });
});

test("rejects parent denials that cannot be preserved", async () => {
  const policy = await bundledPolicy();
  for (const entry of [
    { access: "deny", path: { type: "path", path: "relative/secret" } },
    { access: "deny", path: { type: "special", value: { kind: "tmpdir" } } },
    {
      access: "write",
      path: { type: "glob_pattern", pattern: path.resolve("synthetic", "*") },
    },
  ]) {
    expect(() => policy.resolve(metadata([entry]))).toThrow(
      "cannot be preserved",
    );
  }
  expect(() => policy.resolve({})).toThrow("trusted parent sandbox metadata");
});

function entry(value: string, access: "read" | "write" | "deny" | "none") {
  return { path: { type: "path", path: value }, access };
}

async function scratchFixture() {
  const root = await fixtures.temporaryDirectory();
  const writable = path.join(root, "writable area");
  const target = path.join(root, "scan target");
  const scratch = path.join(writable, "worker", "scratch");
  await Promise.all([promises.mkdir(writable), promises.mkdir(target)]);
  const policy = await bundledPolicy();
  const parent = (...entries: unknown[]) =>
    policy.resolve(metadata(entries, root));
  const access = (
    sandbox: DeepWorkerParentSandbox,
    candidate = scratch,
    scanTarget = target,
  ) => policy.scratch(sandbox, candidate, scanTarget);
  return { root, writable, target, scratch, policy, parent, access };
}

test("clips parent writes to scratch while retaining read carveouts and denies", async () => {
  const { writable, scratch, parent, access, policy } = await scratchFixture();
  const privatePath = path.join(scratch, "private");
  const denied = path.join(scratch, "secret.with.dots");
  const glob = path.join(scratch, "**", "*.secret");
  const sandbox = parent(
    entry(writable, "write"),
    entry(privatePath, "read"),
    entry(denied, "deny"),
    { path: { type: "glob_pattern", pattern: glob }, access: "deny" },
  );
  const grant = await access(sandbox);
  expect(grant).toEqual({ writePath: scratch, readOnlyPaths: [privatePath] });
  expect(parse(policy.overrides(sandbox, grant).join("\n"))).toEqual({
    default_permissions: "codex_security_deep_scan_worker",
    permissions: {
      codex_security_deep_scan_worker: {
        extends: ":read-only",
        filesystem: {
          ":root": "read",
          [scratch]: "write",
          [privatePath]: "read",
          [denied]: "deny",
          [glob]: "deny",
          glob_scan_max_depth: 8,
        },
        network: { enabled: false },
      },
    },
  });
  expect(
    await access(parent(entry(writable, "write"), entry(writable, "read"))),
  ).toEqual({
    writePath: scratch,
    readOnlyPaths: [],
  });
});

test("keeps readonly, denied, target-overlapping, and unresolved symbolic paths readonly", async () => {
  const { root, writable, target, scratch, parent, access } =
    await scratchFixture();
  const sandbox = parent(entry(writable, "write"));
  for (const restricted of [
    parent(),
    parent(entry(writable, "write"), entry(path.dirname(scratch), "read")),
    parent(entry(writable, "write"), entry(scratch, "deny")),
    parent(entry(writable, "write"), entry(writable, "none")),
    ...["tmpdir", "project_roots"].flatMap((kind) => [
      parent({ path: { type: "special", value: { kind } }, access: "write" }),
      parent(entry(writable, "write"), {
        path: { type: "special", value: { kind } },
        access: "read",
      }),
    ]),
  ])
    expect(await access(restricted)).toBeUndefined();
  expect(await access(sandbox, path.join(root, "outside"))).toBeUndefined();
  expect(await access(sandbox, writable, scratch)).toBeUndefined();
  expect(await access(sandbox, scratch, writable)).toBeUndefined();
  expect(await access(sandbox, target)).toBeUndefined();
});

test("binds root writes to the parent volume and accepts a file URL cwd", async () => {
  const { root, scratch, target, policy } = await scratchFixture();
  const writeRoot = {
    path: { type: "special", value: { kind: "root" } },
    access: "write",
  };
  const sandbox = policy.resolve(metadata([writeRoot], root));
  expect(sandbox.filesystemRootWritePath).toBe(path.parse(root).root);
  expect(
    policy.resolve(metadata([writeRoot], url.pathToFileURL(root).href)),
  ).toEqual(sandbox);
  const sandboxes = [sandbox, policy.resolve(metadata([writeRoot]))];
  if (process.platform === "win32") {
    const otherDrive = path.parse(root).root.toLowerCase().startsWith("c:")
      ? "D:\\"
      : "C:\\";
    const other = policy.resolve(
      metadata([writeRoot], path.join(otherDrive, "parent")),
    );
    expect(other.filesystemRootWritePath).toBe(otherDrive);
    expect(other.filesystemRootWritable).toBeUndefined();
    sandboxes.push(other);
  }
  // Bun 1.3.14 strips Windows drive-root separators in promises.realpath
  // (oven-sh/bun#42581). Verify the supported Node runtime's volume handling.
  const build = await Bun.build({
    entrypoints: [
      url.fileURLToPath(
        new URL(
          "../../../plugins/codex-security/mcp-app/src/deep-scan/parent-sandbox.ts",
          import.meta.url,
        ),
      ),
    ],
    target: "node",
    format: "esm",
  });
  expect(build.success).toBe(true);
  const module = path.join(root, "parent-sandbox.mjs");
  await promises.writeFile(module, await build.outputs[0]!.text());
  const results = JSON.parse(
    execFileSync(
      "node",
      [
        "--input-type=module",
        "--eval",
        `
    import { readFileSync } from "node:fs";
    import { resolveDeepWorkerScratchAccess } from ${JSON.stringify(url.pathToFileURL(module).href)};
    const { sandboxes, scratch, target } = JSON.parse(readFileSync(0, "utf8"));
    console.log(JSON.stringify(await Promise.all(sandboxes.map(
      sandbox => resolveDeepWorkerScratchAccess(sandbox, scratch, target)
    ))));
  `,
      ],
      {
        encoding: "utf8",
        input: JSON.stringify({ sandboxes, scratch, target }),
      },
    ),
  );
  expect(results).toEqual([
    { writePath: scratch, readOnlyPaths: [] },
    null,
    ...(process.platform === "win32" ? [null] : []),
  ]);
});

test("uses concrete temporary grants and only resolves slash_tmp on Unix", async () => {
  const { root, scratch, access, parent } = await scratchFixture();
  expect(await access(parent(entry(root, "write")))).toEqual({
    writePath: scratch,
    readOnlyPaths: [],
  });
  const temporary = parent({
    path: { type: "special", value: { kind: "slash_tmp" } },
    access: "write",
  });
  if (process.platform === "win32") {
    expect(await access(temporary)).toBeUndefined();
  } else {
    const candidate = path.join("/tmp", path.basename(root), "worker");
    expect(await access(temporary, candidate)).toEqual({
      writePath: path.join(
        await promises.realpath("/tmp"),
        path.basename(root),
        "worker",
      ),
      readOnlyPaths: [],
    });
  }
});

test("concrete write grants do not depend on the parent cwd metadata", async () => {
  const { writable, scratch, policy, access } = await scratchFixture();
  for (const cwd of [
    undefined,
    "relative/parent",
    "file://unavailable-host/parent",
  ]) {
    const sandbox = policy.resolve(metadata([entry(writable, "write")], cwd));
    expect(await access(sandbox)).toEqual({
      writePath: scratch,
      readOnlyPaths: [],
    });
  }
});

test.each(["[fixture]", "fixture]"])(
  "keeps scratch paths containing %s and read carveouts literal in the native profile",
  async (suffix) => {
    const { root, target, policy, parent } = await scratchFixture();
    const writable = path.join(root, `workspace${suffix}`);
    const scratch = path.join(writable, "worker", "scratch");
    const readonly = path.join(scratch, `private${suffix}`);
    await promises.mkdir(writable);
    const sandbox = parent(entry(writable, "write"), entry(readonly, "read"));
    const grant = await policy.scratch(sandbox, scratch, target);
    expect(grant).toEqual({ writePath: scratch, readOnlyPaths: [readonly] });
    const configuration = parse(policy.overrides(sandbox, grant).join("\n"));
    expect(configuration["permissions"]).toEqual({
      codex_security_deep_scan_worker: {
        extends: ":read-only",
        filesystem: {
          ":root": "read",
          [scratch]: { ".": "write" },
          [readonly]: { ".": "read" },
          glob_scan_max_depth: 8,
        },
        network: { enabled: false },
      },
    });
    const denied = parent(
      entry(writable, "write"),
      entry(path.dirname(scratch), "deny"),
    );
    expect(denied.literalFilesystemDenies).toEqual([path.dirname(scratch)]);
    expect(await policy.scratch(denied, scratch, target)).toBeUndefined();
    expect(parse(policy.overrides(denied).join("\n"))["permissions"]).toEqual({
      codex_security_deep_scan_worker: {
        extends: ":read-only",
        filesystem: {
          ":root": "read",
          [path.dirname(scratch)]: { ".": "deny" },
          glob_scan_max_depth: 8,
        },
        network: { enabled: false },
      },
    });
  },
);

test.each([".git", ".agents", ".codex"])(
  "preserves the %s metadata carveout unless explicitly writable",
  async (name) => {
    const { writable, parent, access } = await scratchFixture();
    const metadataPath = path.join(writable, name);
    const candidate = path.join(metadataPath, "scratch");
    expect(
      await access(parent(entry(writable, "write")), candidate),
    ).toBeUndefined();
    expect(
      await access(
        parent(entry(writable, "write"), entry(metadataPath, "write")),
        candidate,
      ),
    ).toEqual({
      writePath: candidate,
      readOnlyPaths: [],
    });
  },
);

test("preserves linked Git worktree metadata inside and outside scratch", async () => {
  const { writable, scratch, parent, access } = await scratchFixture();
  const gitdir = path.join(writable, "gitdir");
  const dotGit = path.join(writable, ".git");
  await promises.mkdir(gitdir);
  await promises.writeFile(dotGit, "gitdir: ./gitdir\n");
  expect(
    await access(
      parent(entry(writable, "write")),
      path.join(gitdir, "scratch"),
    ),
  ).toBeUndefined();
  expect(
    await access(
      parent(entry(writable, "write"), entry(gitdir, "write")),
      path.join(gitdir, "scratch"),
    ),
  ).toEqual({
    writePath: path.join(gitdir, "scratch"),
    readOnlyPaths: [],
  });
  const nestedGitdir = path.join(scratch, "metadata");
  await promises.mkdir(nestedGitdir, { recursive: true });
  await promises.writeFile(dotGit, `gitdir: ${nestedGitdir}\n`);
  expect(await access(parent(entry(writable, "write")))).toEqual({
    writePath: scratch,
    readOnlyPaths: [nestedGitdir],
  });
  await promises.writeFile(dotGit, "gitdir: ./missing-gitdir\n");
  expect(await access(parent(entry(writable, "write")))).toEqual({
    writePath: scratch,
    readOnlyPaths: [],
  });
});

test("resolves directory junction aliases without losing carveouts or following escapes", async () => {
  const { root, writable, target, scratch, parent, access } =
    await scratchFixture();
  await promises.mkdir(scratch, { recursive: true });
  const alias = path.join(root, "directory alias");
  await promises.symlink(writable, alias, "junction");
  const sandbox = parent(entry(writable, "write"));
  expect(await access(parent(entry(alias, "write")))).toEqual({
    writePath: scratch,
    readOnlyPaths: [],
  });
  expect(await access(sandbox, path.join(alias, "worker", "scratch"))).toEqual({
    writePath: scratch,
    readOnlyPaths: [],
  });
  const privateLink = path.join(scratch, "private-link");
  await promises.symlink(target, privateLink, "junction");
  expect(
    await access(
      parent(
        entry(alias, "write"),
        entry(path.join(alias, "worker", "scratch", "private-link"), "read"),
      ),
    ),
  ).toEqual({
    writePath: scratch,
    readOnlyPaths: [privateLink],
  });
  const escape = path.join(writable, "escape");
  await promises.symlink(target, escape, "junction");
  expect(await access(sandbox, path.join(escape, "scratch"))).toBeUndefined();
  const broken = path.join(writable, "broken");
  await promises.symlink(
    path.join(root, "missing-destination"),
    broken,
    "junction",
  );
  expect(await access(sandbox, path.join(broken, "scratch"))).toBeUndefined();
  const protectedDestination = path.join(writable, "metadata-cache");
  await promises.mkdir(protectedDestination);
  await promises.symlink(
    protectedDestination,
    path.join(writable, ".codex"),
    "junction",
  );
  expect(
    await access(sandbox, path.join(protectedDestination, "scratch")),
  ).toBeUndefined();
  expect(
    await access(sandbox, path.join(writable, ".codex", "scratch")),
  ).toBeUndefined();
});

test.skipIf(process.platform !== "win32")(
  "compares Windows drive and path casing without losing a readonly carveout",
  async () => {
    const { writable, scratch, parent, access } = await scratchFixture();
    await promises.mkdir(scratch, { recursive: true });
    expect(
      await access(
        parent(entry(writable.toUpperCase(), "write")),
        scratch.toUpperCase(),
      ),
    ).toEqual({
      writePath: scratch,
      readOnlyPaths: [],
    });
    expect(
      await access(
        parent(
          entry(writable.toUpperCase(), "write"),
          entry(path.dirname(scratch).toLowerCase(), "read"),
        ),
      ),
    ).toBeUndefined();
  },
);

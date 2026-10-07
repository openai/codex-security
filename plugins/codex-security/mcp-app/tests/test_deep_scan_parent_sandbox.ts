import assert from "node:assert/strict";
import path from "node:path";
import { importSource } from "./import-module.ts";

const { CODEX_SANDBOX_STATE_META_CAPABILITY, resolveDeepWorkerParentSandbox } =
  await importSource(
    path.join(import.meta.dirname, "../src/deep-scan/parent-sandbox.ts"),
  );

const rootRead = {
  path: { type: "special", value: { kind: "root" } },
  access: "read",
};
const pinnedReadOnly = {
  type: "managed",
  file_system: { type: "restricted", entries: [rootRead] },
  network: "restricted",
};

assert.equal(CODEX_SANDBOX_STATE_META_CAPABILITY, "codex/sandbox-state-meta");
assert.deepEqual(resolveDeepWorkerParentSandbox(extra(pinnedReadOnly)), {
  filesystemDenies: [],
});
assert.deepEqual(
  resolveDeepWorkerParentSandbox(
    extra({
      ...pinnedReadOnly,
      network: "enabled",
    }),
  ),
  {
    filesystemDenies: [],
  },
);
assert.deepEqual(
  resolveDeepWorkerParentSandbox(
    extra({
      ...pinnedReadOnly,
      file_system: { type: "unrestricted" },
    }),
  ),
  {
    filesystemDenies: [],
  },
);
assert.deepEqual(
  resolveDeepWorkerParentSandbox(
    restricted([
      rootRead,
      {
        path: { type: "special", value: { kind: "project_roots" } },
        access: "write",
      },
      {
        path: { type: "special", value: { kind: "tmpdir" } },
        access: "write",
      },
    ]),
  ),
  {
    filesystemDenies: [],
  },
);
assert.deepEqual(
  resolveDeepWorkerParentSandbox(
    restricted(
      [
        rootRead,
        {
          path: { type: "path", path: "/repo/.env" },
          access: "deny",
        },
        {
          path: { type: "generated_default_path", path: "/repo/.secrets" },
          access: "none",
        },
        {
          path: { type: "glob_pattern", pattern: "/repo-a/**/.env" },
          access: "deny",
        },
        {
          path: { type: "glob_pattern", pattern: "/repo-b/**/*.pem" },
          access: "none",
        },
      ],
      { glob_scan_max_depth: 3 },
    ),
  ),
  {
    filesystemDenies: [
      "/repo/.env",
      "/repo/.secrets",
      "/repo-a/**/.env",
      "/repo-b/**/*.pem",
    ],
    globScanMaxDepth: 3,
  },
);

const literalPaths = ["/repo/*.env", "/repo/?.env", "/repo/[literal]"];
assert.deepEqual(
  resolveDeepWorkerParentSandbox(
    restricted([
      rootRead,
      ...literalPaths.map((deniedPath, index) => ({
        path: {
          type: index === 0 ? "generated_default_path" : "path",
          path: deniedPath,
        },
        access: index === 0 ? "none" : "deny",
      })),
    ]),
  ),
  { filesystemDenies: [], literalFilesystemDenies: literalPaths },
);

const collidingDenies = [
  { path: { type: "glob_pattern", pattern: "/repo/[ab]" }, access: "deny" },
  { path: { type: "path", path: "/repo/[ab]" }, access: "none" },
];
for (const entries of [collidingDenies, [...collidingDenies].reverse()]) {
  assert.throws(
    () => resolveDeepWorkerParentSandbox(restricted([rootRead, ...entries])),
    (error: Error) =>
      error.name === "DeepScanNonRetryableError" &&
      /literal path and glob denials with the same key cannot be preserved/i.test(
        error.message,
      ),
  );
}

assert.throws(
  () =>
    resolveDeepWorkerParentSandbox(
      restricted([
        rootRead,
        {
          path: {
            type: "glob_pattern",
            pattern: "codex-project-roots://**/*.pem",
          },
          access: "deny",
        },
      ]),
    ),
  (error: Error) =>
    error.name === "DeepScanNonRetryableError" &&
    /symbolic project-roots denial metadata/i.test(error.message),
);

const pinnedFileUri = extra(
  pinnedReadOnly,
  "file:///tmp/codex-security-parent",
);
assert.deepEqual(resolveDeepWorkerParentSandbox(pinnedFileUri), {
  filesystemDenies: [],
});
assert.deepEqual(
  resolveDeepWorkerParentSandbox(
    extra(pinnedReadOnly, "/tmp/codex-security-parent"),
  ),
  {
    filesystemDenies: [],
  },
);
assert.deepEqual(
  resolveDeepWorkerParentSandbox({
    requestInfo: pinnedFileUri,
  }),
  {
    filesystemDenies: [],
  },
);
assert.deepEqual(
  resolveDeepWorkerParentSandbox({
    _meta: pinnedFileUri._meta,
    requestInfo: pinnedFileUri,
  }),
  {
    filesystemDenies: [],
  },
);
assert.deepEqual(
  resolveDeepWorkerParentSandbox(
    extra(pinnedReadOnly, "file:///tmp/codex-security-parent", {
      type: "readOnly",
    }),
  ),
  {
    filesystemDenies: [],
  },
);

for (const invalid of [
  undefined,
  null,
  {},
  { _meta: {} },
  { _meta: { [CODEX_SANDBOX_STATE_META_CAPABILITY]: null } },
  extra(null),
  extra({ ...pinnedReadOnly, type: "external" }),
  extra({ ...pinnedReadOnly, type: "disabled" }),
  extra({ ...pinnedReadOnly, file_system: null }),
  extra({ ...pinnedReadOnly, file_system: { type: "unknown" } }),
  restricted("not-an-array"),
  restricted([]),
  restricted([{ path: { type: "path", path: "/limited" }, access: "read" }]),
  restricted([
    {
      path: {
        type: "special",
        value: { kind: "root", subpath: "only-this-subtree" },
      },
      access: "read",
    },
  ]),
  restricted([
    rootRead,
    {
      path: { type: "special", value: { kind: "tmpdir" } },
      access: "deny",
    },
  ]),
  restricted([
    rootRead,
    { path: { type: "glob_pattern", pattern: "**/*.env" }, access: "deny" },
  ]),
  restricted([
    rootRead,
    {
      path: { type: "path", path: "/private" },
      access: "deny",
      missing_path_behavior: "skip",
    },
  ]),
  ...["", "relative/private"].map((deniedPath) =>
    restricted([
      rootRead,
      { path: { type: "path", path: deniedPath }, access: "deny" },
    ]),
  ),
  restricted([
    rootRead,
    {
      path: { type: "glob_pattern", pattern: "/repo/**/*.env" },
      access: "read",
    },
  ]),
  restricted([rootRead], { glob_scan_max_depth: 0 }),
  restricted([rootRead], { glob_scan_max_depth: 2, globScanMaxDepth: 3 }),
  restricted([
    {
      path: { type: "special", value: { kind: "unknown" } },
      access: "read",
    },
  ]),
  restricted([{ path: { type: "path", path: "" }, access: "read" }]),
  {
    _meta: extra(pinnedReadOnly)._meta,
    requestInfo: extra({ ...pinnedReadOnly, network: "enabled" }),
  },
]) {
  assert.throws(
    () => resolveDeepWorkerParentSandbox(invalid),
    (error: Error) =>
      error.name === "DeepScanNonRetryableError" &&
      error.message.startsWith(
        "Deep Scan cannot safely start a read-only worker:",
      ),
  );
}

function extra(
  permissionProfile: unknown,
  sandboxCwd?: string,
  sandboxPolicy?: unknown,
) {
  return {
    _meta: {
      [CODEX_SANDBOX_STATE_META_CAPABILITY]: {
        permissionProfile,
        ...(sandboxCwd !== undefined ? { sandboxCwd } : {}),
        ...(sandboxPolicy !== undefined ? { sandboxPolicy } : {}),
      },
    },
  };
}

function restricted(entries: unknown, options: Record<string, unknown> = {}) {
  return extra({
    ...pinnedReadOnly,
    file_system: { type: "restricted", entries, ...options },
  });
}

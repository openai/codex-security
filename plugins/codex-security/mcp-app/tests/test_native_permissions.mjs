import assert from "node:assert/strict";
import { fileURLToPath } from "node:url";
import { build } from "esbuild";

const bundle = await build({
  bundle: true,
  entryPoints: [
    fileURLToPath(new URL("../src/native-permissions.ts", import.meta.url)),
  ],
  format: "esm",
  platform: "node",
  write: false,
});
const { CODEX_SANDBOX_STATE_META_CAPABILITY, resolveNativeParentSandbox } =
  await import(
    `data:text/javascript;base64,${Buffer.from(bundle.outputFiles[0].contents).toString("base64")}`
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
assert.deepEqual(resolveNativeParentSandbox(extra(pinnedReadOnly)), {
  filesystemDenies: [],
});
assert.deepEqual(
  resolveNativeParentSandbox(
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
  resolveNativeParentSandbox(
    extra({
      type: "managed",
      file_system: { type: "unrestricted" },
      network: "restricted",
    }),
  ),
  {
    filesystemDenies: [],
  },
);
assert.deepEqual(
  resolveNativeParentSandbox(
    extra({
      ...pinnedReadOnly,
      file_system: {
        type: "restricted",
        entries: [
          rootRead,
          {
            path: { type: "special", value: { kind: "project_roots" } },
            access: "write",
          },
          {
            path: { type: "special", value: { kind: "tmpdir" } },
            access: "write",
          },
        ],
      },
    }),
  ),
  {
    filesystemDenies: [],
  },
);
assert.deepEqual(
  resolveNativeParentSandbox(
    extra({
      ...pinnedReadOnly,
      file_system: {
        type: "restricted",
        entries: [
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
            path: { type: "glob_pattern", pattern: "/repo/**/*.ts" },
            access: "read",
          },
          {
            path: { type: "glob_pattern", pattern: "/repo/generated/**" },
            access: "write",
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
        glob_scan_max_depth: 3,
      },
    }),
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

assert.throws(
  () =>
    resolveNativeParentSandbox(
      extra({
        ...pinnedReadOnly,
        file_system: {
          type: "restricted",
          entries: [
            rootRead,
            {
              path: {
                type: "glob_pattern",
                pattern: "codex-project-roots://**/*.pem",
              },
              access: "deny",
            },
          ],
        },
      }),
    ),
  (error) =>
    error.name === "Error" &&
    /symbolic project-roots denial metadata/i.test(error.message),
);

const parentMetadata = extra(pinnedReadOnly);
assert.deepEqual(
  resolveNativeParentSandbox({
    requestInfo: parentMetadata,
  }),
  {
    filesystemDenies: [],
  },
);
assert.deepEqual(
  resolveNativeParentSandbox({
    _meta: parentMetadata._meta,
    requestInfo: parentMetadata,
  }),
  {
    filesystemDenies: [],
  },
);
assert.deepEqual(
  resolveNativeParentSandbox(
    extra(
      {
        ...pinnedReadOnly,
      },
      "file:///tmp/codex-security-parent",
      { type: "readOnly" },
    ),
  ),
  {
    filesystemDenies: [],
  },
);

for (const deniedPath of ["/repo/*.env", "/repo/?.env", "/repo/[literal]"]) {
  assert.deepEqual(
    resolveNativeParentSandbox(
      extra({
        ...pinnedReadOnly,
        file_system: {
          type: "restricted",
          entries: [
            rootRead,
            { path: { type: "path", path: deniedPath }, access: "deny" },
          ],
        },
      }),
    ),
    { filesystemDenies: [], literalFilesystemDenies: [deniedPath] },
  );
}

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
  extra({
    ...pinnedReadOnly,
    file_system: { type: "restricted", entries: "not-an-array" },
  }),
  extra({
    ...pinnedReadOnly,
    file_system: { type: "restricted", entries: [] },
  }),
  extra({
    ...pinnedReadOnly,
    file_system: {
      type: "restricted",
      entries: [{ path: { type: "path", path: "/limited" }, access: "read" }],
    },
  }),
  extra({
    ...pinnedReadOnly,
    file_system: {
      type: "restricted",
      entries: [
        {
          path: {
            type: "special",
            value: { kind: "root", subpath: "only-this-subtree" },
          },
          access: "read",
        },
      ],
    },
  }),
  extra({
    ...pinnedReadOnly,
    file_system: {
      type: "restricted",
      entries: [
        rootRead,
        {
          path: { type: "special", value: { kind: "tmpdir" } },
          access: "deny",
        },
      ],
    },
  }),
  extra({
    ...pinnedReadOnly,
    file_system: {
      type: "restricted",
      entries: [
        rootRead,
        { path: { type: "glob_pattern", pattern: "**/*.env" }, access: "deny" },
      ],
    },
  }),
  extra({
    ...pinnedReadOnly,
    file_system: {
      type: "restricted",
      entries: [
        rootRead,
        {
          path: { type: "path", path: "/private" },
          access: "deny",
          missing_path_behavior: "skip",
        },
      ],
    },
  }),
  ...["", "relative/private"].map((deniedPath) =>
    extra({
      ...pinnedReadOnly,
      file_system: {
        type: "restricted",
        entries: [
          rootRead,
          { path: { type: "path", path: deniedPath }, access: "deny" },
        ],
      },
    }),
  ),
  extra({
    ...pinnedReadOnly,
    file_system: {
      type: "restricted",
      entries: [rootRead],
      glob_scan_max_depth: 0,
    },
  }),
  extra({
    ...pinnedReadOnly,
    file_system: {
      type: "restricted",
      entries: [rootRead],
      glob_scan_max_depth: 2,
      globScanMaxDepth: 3,
    },
  }),
  extra({
    ...pinnedReadOnly,
    file_system: {
      type: "restricted",
      entries: [
        {
          path: { type: "special", value: { kind: "unknown" } },
          access: "read",
        },
      ],
    },
  }),
  extra({
    ...pinnedReadOnly,
    file_system: {
      type: "restricted",
      entries: [{ path: { type: "path", path: "" }, access: "read" }],
    },
  }),
  {
    _meta: extra(pinnedReadOnly)._meta,
    requestInfo: extra({ ...pinnedReadOnly, network: "enabled" }),
  },
]) {
  assert.throws(
    () => resolveNativeParentSandbox(invalid),
    (error) =>
      error.name === "Error" &&
      error.message.startsWith("Deep Scan cannot preserve the parent sandbox:"),
  );
}

// Cwd is unused metadata; actual inherited paths remain independently checked.
assert.deepEqual(
  resolveNativeParentSandbox(
    extra(pinnedReadOnly, "relative/working-directory"),
  ),
  { filesystemDenies: [] },
);

function extra(permissionProfile, sandboxCwd, sandboxPolicy) {
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

import assert from "node:assert/strict";
import { fileURLToPath } from "node:url";
import { build } from "esbuild";

const bundle = await build({
  bundle: true,
  entryPoints: [fileURLToPath(new URL("../src/deep-scan/parent-sandbox.ts", import.meta.url))],
  format: "esm",
  platform: "node",
  write: false
});
const {
  CODEX_SANDBOX_STATE_META_CAPABILITY,
  resolveDeepWorkerParentSandbox
} = await import(
  `data:text/javascript;base64,${Buffer.from(bundle.outputFiles[0].contents).toString("base64")}`
);

const rootRead = {
  path: { type: "special", value: { kind: "root" } },
  access: "read"
};
const pinnedReadOnly = {
  type: "managed",
  file_system: { type: "restricted", entries: [rootRead] },
  network: "restricted"
};

assert.equal(CODEX_SANDBOX_STATE_META_CAPABILITY, "codex/sandbox-state-meta");
assert.deepEqual(resolveDeepWorkerParentSandbox(extra(pinnedReadOnly)), {
  filesystemDenies: []
});
assert.deepEqual(resolveDeepWorkerParentSandbox(extra({
  ...pinnedReadOnly,
  network: "enabled"
})), {
  filesystemDenies: []
});
assert.deepEqual(resolveDeepWorkerParentSandbox(extra({
  type: "managed",
  file_system: { type: "unrestricted" },
  network: "restricted"
})), {
  filesystemDenies: []
});
assert.deepEqual(resolveDeepWorkerParentSandbox(extra({
  ...pinnedReadOnly,
  file_system: {
    type: "restricted",
    entries: [
      rootRead,
      {
        path: { type: "special", value: { kind: "project_roots" } },
        access: "write"
      },
      {
        path: { type: "special", value: { kind: "tmpdir" } },
        access: "write"
      }
    ]
  }
})), {
  filesystemDenies: []
});
assert.deepEqual(resolveDeepWorkerParentSandbox(extra({
  ...pinnedReadOnly,
  file_system: {
    type: "restricted",
    entries: [
      rootRead,
      {
        path: { type: "path", path: "/repo/.env" },
        access: "deny"
      },
      {
        path: { type: "generated_default_path", path: "/repo/.secrets" },
        access: "none"
      },
      {
        path: { type: "glob_pattern", pattern: "/repo-a/**/.env" },
        access: "deny"
      },
      {
        path: { type: "glob_pattern", pattern: "/repo-b/**/*.pem" },
        access: "none"
      }
    ],
    glob_scan_max_depth: 3
  }
})), {
  filesystemDenies: [
    "/repo/.env",
    "/repo/.secrets",
    "/repo-a/**/.env",
    "/repo-b/**/*.pem"
  ],
  globScanMaxDepth: 3
});

assert.throws(
  () => resolveDeepWorkerParentSandbox(extra({
    ...pinnedReadOnly,
    file_system: {
      type: "restricted",
      entries: [
        rootRead,
        {
          path: {
            type: "glob_pattern",
            pattern: "codex-project-roots://**/*.pem"
          },
          access: "deny"
        }
      ]
    }
  })),
  (error) => error.name === "DeepScanNonRetryableError"
    && /symbolic project-roots denial metadata/i.test(error.message)
);

const pinnedFileUri = extra(pinnedReadOnly, "file:///tmp/codex-security-parent");
assert.deepEqual(resolveDeepWorkerParentSandbox(pinnedFileUri), {
  filesystemDenies: []
});
assert.deepEqual(resolveDeepWorkerParentSandbox(extra(pinnedReadOnly, "/tmp/codex-security-parent")), {
  filesystemDenies: []
});
assert.deepEqual(resolveDeepWorkerParentSandbox({
  requestInfo: pinnedFileUri
}), {
  filesystemDenies: []
});
assert.deepEqual(resolveDeepWorkerParentSandbox({
  _meta: pinnedFileUri._meta,
  requestInfo: pinnedFileUri
}), {
  filesystemDenies: []
});
assert.deepEqual(resolveDeepWorkerParentSandbox(extra({
  ...pinnedReadOnly
}, "file:///tmp/codex-security-parent", { type: "readOnly" })), {
  filesystemDenies: []
});

for (const invalid of [
  undefined,
  null,
  {},
  { _meta: {} },
  { _meta: { [CODEX_SANDBOX_STATE_META_CAPABILITY]: null } },
  extra(null),
  extra({ ...pinnedReadOnly, type: "external" }),
  extra({ ...pinnedReadOnly, type: "disabled" }),
  extra({ ...pinnedReadOnly, network: "unknown" }),
  extra({ ...pinnedReadOnly, network: { enabled: true } }),
  extra({ ...pinnedReadOnly, file_system: null }),
  extra({ ...pinnedReadOnly, file_system: { type: "unknown" } }),
  extra({ ...pinnedReadOnly, file_system: { type: "restricted", entries: "not-an-array" } }),
  extra({
    ...pinnedReadOnly,
    file_system: { type: "restricted", entries: [] }
  }),
  extra({
    ...pinnedReadOnly,
    file_system: {
      type: "restricted",
      entries: [{ path: { type: "path", path: "/limited" }, access: "read" }]
    }
  }),
  extra({
    ...pinnedReadOnly,
    file_system: {
      type: "restricted",
      entries: [{
        path: {
          type: "special",
          value: { kind: "root", subpath: "only-this-subtree" }
        },
        access: "read"
      }]
    }
  }),
  extra({
    ...pinnedReadOnly,
    file_system: {
      type: "restricted",
      entries: [
        rootRead,
        { path: { type: "special", value: { kind: "tmpdir" } }, access: "deny" }
      ]
    }
  }),
  extra({
    ...pinnedReadOnly,
    file_system: {
      type: "restricted",
      entries: [
        rootRead,
        { path: { type: "glob_pattern", pattern: "**/*.env" }, access: "deny" }
      ]
    }
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
          missing_path_behavior: "skip"
        }
      ]
    }
  }),
  ...["", "relative/private", "/repo/*.env", "/repo/?.env", "/repo/[literal]"].map((deniedPath) => extra({
    ...pinnedReadOnly,
    file_system: {
      type: "restricted",
      entries: [
        rootRead,
        { path: { type: "path", path: deniedPath }, access: "deny" }
      ]
    }
  })),
  extra({
    ...pinnedReadOnly,
    file_system: {
      type: "restricted",
      entries: [
        rootRead,
        { path: { type: "glob_pattern", pattern: "/repo/**/*.env" }, access: "read" }
      ]
    }
  }),
  extra({
    ...pinnedReadOnly,
    file_system: {
      type: "restricted",
      entries: [rootRead],
      glob_scan_max_depth: 0
    }
  }),
  extra({
    ...pinnedReadOnly,
    file_system: {
      type: "restricted",
      entries: [rootRead],
      glob_scan_max_depth: 2,
      globScanMaxDepth: 3
    }
  }),
  extra({
    ...pinnedReadOnly,
    file_system: {
      type: "restricted",
      entries: [{ path: { type: "special", value: { kind: "unknown" } }, access: "read" }]
    }
  }),
  extra({
    ...pinnedReadOnly,
    file_system: {
      type: "restricted",
      entries: [{ path: { type: "path", path: "" }, access: "read" }]
    }
  }),
  extra(pinnedReadOnly, "relative/working-directory"),
  extra(pinnedReadOnly, "file://remote-host/tmp/codex-security-parent"),
  {
    _meta: extra(pinnedReadOnly)._meta,
    requestInfo: extra({ ...pinnedReadOnly, network: "enabled" })
  }
]) {
  assert.throws(
    () => resolveDeepWorkerParentSandbox(invalid),
    (error) => error.name === "DeepScanNonRetryableError"
      && error.message.startsWith("Deep Scan cannot safely start a read-only worker:")
  );
}

function extra(permissionProfile, sandboxCwd, sandboxPolicy) {
  return {
    _meta: {
      [CODEX_SANDBOX_STATE_META_CAPABILITY]: {
        permissionProfile,
        ...(sandboxCwd !== undefined ? { sandboxCwd } : {}),
        ...(sandboxPolicy !== undefined ? { sandboxPolicy } : {})
      }
    }
  };
}

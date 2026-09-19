import assert from "node:assert/strict";
import { mkdir, mkdtemp, realpath, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
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
  resolveDeepWorkerParentSandbox,
  resolveDeepWorkerScratchAccess
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
  filesystemDenies: [],
  filesystemRootWritable: true
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
      && error.message.startsWith("Deep Scan cannot safely start a worker:")
  );
}

await testScratchAccess();

async function testScratchAccess() {
  const root = await realpath(await mkdtemp(path.join(tmpdir(), "deep-scratch-permissions-")));
  const writable = path.join(root, "writable");
  const target = path.join(root, "target");
  const scratch = path.join(writable, "worker", "scratch");
  await mkdir(writable);
  await mkdir(target);
  const entry = (value, access) => ({ path: { type: "path", path: value }, access });
  const policy = (...entries) => resolveDeepWorkerParentSandbox(extra({
    ...pinnedReadOnly,
    file_system: { type: "restricted", entries: [rootRead, ...entries] }
  }, root));
  const access = (sandbox, candidate = scratch, scanTarget = target) =>
    resolveDeepWorkerScratchAccess(sandbox, candidate, scanTarget);
  try {
    const parent = policy(entry(writable, "write"));
    assert.deepEqual(parent.filesystemWriteRules, [{ path: writable, access: "write" }]);
    assert.deepEqual(await access(parent), { writePath: scratch, readOnlyPaths: [] });
    assert.equal(await access(policy()), undefined);
    assert.equal(await access(parent, path.join(root, "outside")), undefined);
    assert.equal(await access(parent, writable, scratch), undefined);
    assert.equal(await access(parent, scratch, writable), undefined);
    assert.equal(await access(parent, target), undefined);

    // More specific read rules narrow broad write grants. Equal-path writes win.
    assert.equal(await access(policy(entry(writable, "write"), entry(path.dirname(scratch), "read"))), undefined);
    assert.deepEqual(await access(policy(entry(writable, "write"), entry(writable, "read"))), {
      writePath: scratch, readOnlyPaths: []
    });
    const privatePath = path.join(scratch, "private");
    assert.deepEqual(await access(policy(entry(writable, "write"), entry(privatePath, "read"))), {
      writePath: scratch, readOnlyPaths: [privatePath]
    });

    assert.equal(await access(policy(entry(writable, "write"), entry(scratch, "deny"))), undefined);
    assert.equal(await access(policy(entry(writable, "write"), entry(writable, "none"))), undefined);
    const deniedChild = policy(entry(writable, "write"), entry(privatePath, "deny"), {
      path: { type: "glob_pattern", pattern: `${writable}/**/*.secret` }, access: "deny"
    });
    assert.deepEqual(deniedChild.filesystemDenies, [privatePath, `${writable}/**/*.secret`]);
    assert.deepEqual(await access(deniedChild), { writePath: scratch, readOnlyPaths: [] });

    // A separate concrete root is sufficient; no permission is inferred from cwd.
    const independent = path.join(root, "independent");
    assert.deepEqual(await access(policy(entry(independent, "write")), path.join(independent, "scratch")), {
      writePath: path.join(independent, "scratch"), readOnlyPaths: []
    });
    const rootWritable = policy({ path: { type: "special", value: { kind: "root" } }, access: "write" });
    assert.deepEqual(rootWritable, {
      filesystemDenies: [],
      filesystemRootWritePath: path.parse(root).root,
      filesystemWriteRules: [{ path: path.parse(root).root, access: "write" }]
    });
    assert.deepEqual(await access(rootWritable), { writePath: scratch, readOnlyPaths: [] });
    const rootWriteProfile = {
      ...pinnedReadOnly,
      file_system: { type: "restricted", entries: [{ path: { type: "special", value: { kind: "root" } }, access: "write" }] }
    };
    assert.equal(await access(resolveDeepWorkerParentSandbox(extra(rootWriteProfile))), undefined);
    assert.deepEqual(resolveDeepWorkerParentSandbox(extra(rootWriteProfile, pathToFileURL(root).href)), rootWritable);
    if (process.platform === "win32") {
      const otherVolume = path.parse(root).root.toLowerCase().startsWith("c:") ? "D:\\" : "C:\\";
      const otherVolumeSandbox = resolveDeepWorkerParentSandbox(extra(rootWriteProfile, path.join(otherVolume, "parent")));
      assert.equal(otherVolumeSandbox.filesystemRootWritePath, otherVolume);
      assert.equal(otherVolumeSandbox.filesystemRootWritable, undefined);
      assert.equal(await access(otherVolumeSandbox), undefined);
    }
    assert.equal(await access(policy(
      { path: { type: "special", value: { kind: "root" } }, access: "write" },
      entry(writable, "read")
    )), undefined);

    for (const kind of ["tmpdir", "project_roots"]) {
      assert.equal(await access(policy({ path: { type: "special", value: { kind } }, access: "write" })), undefined);
      assert.equal(await access(policy(entry(writable, "write"), {
        path: { type: "special", value: { kind } }, access: "read"
      })), undefined);
    }
    if (process.platform !== "win32") {
      const temporary = policy({ path: { type: "special", value: { kind: "slash_tmp" } }, access: "write" });
      const candidate = path.join("/tmp", "deep-scratch-policy-fixture", "worker");
      assert.deepEqual(await access(temporary, candidate), {
        writePath: path.join(await realpath("/tmp"), "deep-scratch-policy-fixture", "worker"), readOnlyPaths: []
      });
    }

    for (const name of [".git", ".agents", ".codex"]) {
      const metadata = path.join(writable, name);
      assert.equal(await access(parent, path.join(metadata, "scratch")), undefined);
      assert.deepEqual(await access(policy(entry(writable, "write"), entry(metadata, "write")), path.join(metadata, "scratch")), {
        writePath: path.join(metadata, "scratch"), readOnlyPaths: []
      });
    }

    const gitdir = path.join(writable, "gitdir");
    const dotGit = path.join(writable, ".git");
    await mkdir(gitdir);
    await writeFile(dotGit, "gitdir: ./gitdir\n");
    assert.equal(await access(parent, path.join(gitdir, "scratch")), undefined);
    assert.deepEqual(await access(policy(entry(writable, "write"), entry(gitdir, "write")), path.join(gitdir, "scratch")), {
      writePath: path.join(gitdir, "scratch"), readOnlyPaths: []
    });
    const nestedGitdir = path.join(scratch, "metadata");
    await mkdir(nestedGitdir, { recursive: true });
    await writeFile(dotGit, `gitdir: ${nestedGitdir}\n`);
    assert.deepEqual(await access(parent), { writePath: scratch, readOnlyPaths: [nestedGitdir] });
    await writeFile(dotGit, "gitdir: ./missing-gitdir\n");
    assert.deepEqual(await access(parent), { writePath: scratch, readOnlyPaths: [] });

    const alias = path.join(root, "alias");
    await symlink(writable, alias, "junction");
    assert.deepEqual(await access(policy(entry(alias, "write"))), { writePath: scratch, readOnlyPaths: [] });
    assert.deepEqual(await access(parent, path.join(alias, "worker", "scratch")), { writePath: scratch, readOnlyPaths: [] });
    const privateLink = path.join(scratch, "private-link");
    await symlink(target, privateLink, "junction");
    const aliasPrivateLink = path.join(alias, "worker", "scratch", "private-link");
    assert.deepEqual(await access(policy(entry(alias, "write"), entry(aliasPrivateLink, "read"))), {
      writePath: scratch, readOnlyPaths: [privateLink]
    });
    const escape = path.join(writable, "escape");
    await symlink(target, escape, "junction");
    assert.equal(await access(parent, path.join(escape, "scratch")), undefined);
    const broken = path.join(writable, "broken");
    await symlink(path.join(root, "missing-destination"), broken, "junction");
    assert.equal(await access(parent, path.join(broken, "scratch")), undefined);

    const metadataDestination = path.join(writable, "metadata-cache");
    await mkdir(metadataDestination);
    await symlink(metadataDestination, path.join(writable, ".codex"), "junction");
    assert.equal(await access(parent, path.join(metadataDestination, "scratch")), undefined);
    assert.equal(await access(parent, path.join(writable, ".codex", "scratch")), undefined);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
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

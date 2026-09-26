import * as path from "node:path";
import * as url from "node:url";
import * as util from "node:util";
import { expect, test } from "bun:test";
import { parse } from "smol-toml";
import { loadBundledRuntime } from "./plugin-root.js";

type Sandbox = { filesystemDenies: string[]; globScanMaxDepth?: number };

async function bundledPolicy() {
  const runtime = await loadBundledRuntime();
  const start = runtime.indexOf("var CODEX_SANDBOX_STATE_META_CAPABILITY =");
  const end = runtime.indexOf("\n// ", start);
  expect(start).toBeGreaterThan(0);
  expect(end).toBeGreaterThan(start);
  const source = runtime.slice(start, end);
  const imports = [
    ...new Set(source.match(/import_node_(?:path|url|util)\d*/gu)),
  ];
  const resolve = new Function(
    ...imports,
    "DeepScanNonRetryableError",
    `${source}\nreturn resolveDeepWorkerParentSandbox;`,
  )(
    ...imports.map((name) =>
      name.startsWith("import_node_path")
        ? path
        : name.startsWith("import_node_url")
          ? url
          : util,
    ),
    Error,
  ) as (metadata: unknown) => Sandbox;
  const serializer = [
    "workerPermissionProfile",
    "workerPermissionProfileConfigOverrides",
    "tomlInlineValue",
    "tomlKey",
    "tomlString",
  ]
    .map((name) => {
      const definition = new RegExp(
        `function ${name}\\([^\\n]*\\) \\{[\\s\\S]*?\\n\\}`,
        "u",
      ).exec(runtime)?.[0];
      if (!definition) throw new Error(`Missing bundled function: ${name}`);
      return definition;
    })
    .join("\n");
  const overrides = new Function(
    "DEEP_SCAN_WORKER_PERMISSION_PROFILE_ID",
    `${serializer}\nreturn sandbox => workerPermissionProfileConfigOverrides(workerPermissionProfile(sandbox));`,
  )("codex_security_deep_scan_worker") as (sandbox: Sandbox) => string[];
  return { resolve, overrides };
}

function metadata(entries: unknown[]) {
  return {
    _meta: {
      "codex/sandbox-state-meta": {
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

test("preserves literal parent deny paths and globs without parent write grants", async () => {
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

import { createHash } from "node:crypto";
import { writeFile } from "node:fs/promises";
import { join } from "node:path";
import { afterEach, describe, expect, test } from "bun:test";
import { PLUGIN_ROOT } from "./plugin-root.js";
import { runPython } from "./support/python-probe.js";
import { createTemporaryDirectories } from "./support/temporary-directories.js";

const temporaryDirectories = createTemporaryDirectories();

afterEach(temporaryDirectories.cleanup);

const patchProbe = [
  "import json, sys",
  "from pathlib import Path",
  "sys.path.insert(0, sys.argv[1])",
  "import workbench_db as workbench",
  "scan_dir, digest = Path(sys.argv[2]), sys.argv[3]",
  "scan = {'scan_dir': str(scan_dir)}",
  "workbench.require_matching_patch_digest(scan, 'remediation.patch', digest)",
  "preview, stats = workbench.patch_artifact_preview(scan_dir, 'remediation.patch', digest)",
  "try:",
  "    workbench.require_matching_patch_digest(scan, 'remediation.patch', 'sha256:' + '0' * 64)",
  "except SystemExit as error:",
  "    mismatch = str(error)",
  "else:",
  "    mismatch = None",
  "print(json.dumps({'preview': preview, 'stats': stats, 'mismatch': mismatch}))",
].join("\n");

describe("workbench remediation patches", () => {
  test("streams patches larger than 2 MiB without weakening digest checks", async () => {
    const directory = await temporaryDirectories.create(
      "codex-security-large-patch-",
    );
    const patch = Buffer.concat([
      Buffer.from("diff --git a/src.ts b/src.ts\n+"),
      Buffer.alloc(2 * 1024 * 1024, 0x78),
      Buffer.from("\n"),
    ]);
    await writeFile(join(directory, "remediation.patch"), patch);
    const digest = `sha256:${createHash("sha256").update(patch).digest("hex")}`;
    const python = Bun.which("python3") ?? Bun.which("python");
    expect(python).not.toBeNull();

    const result = runPython(python!, [
      "-c",
      patchProbe,
      join(PLUGIN_ROOT, "scripts"),
      directory,
      digest,
    ]);
    expect(new TextDecoder().decode(result.stderr)).toBe("");
    expect(result.exitCode).toBe(0);
    const output = JSON.parse(new TextDecoder().decode(result.stdout)) as {
      preview: string;
      stats: Record<string, number | boolean>;
      mismatch: string;
    };
    expect(output.preview).toStartWith("diff --git a/src.ts b/src.ts\n+");
    expect(output.preview).toEndWith("... patch preview truncated ...");
    expect(output.stats).toMatchObject({
      additions: 1,
      fileCount: 1,
      previewTruncated: true,
    });
    expect(output.mismatch).toBe(
      "Patch digest does not match the scan-local patch file.",
    );
  });
});

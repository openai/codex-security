import { spawnSync } from "node:child_process";
import {
  chmod,
  mkdir,
  mkdtemp,
  realpath,
  rm,
  symlink,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { expect, test } from "bun:test";
import { resolveTrustedExecutable } from "../src/trusted-executable.js";

test.skipIf(process.platform === "win32")(
  "preserves a trusted explicit symlink invocation outside the protected root",
  async () => {
    const root = await realpath(
      await mkdtemp(join(tmpdir(), "trusted-explicit-executable-")),
    );
    try {
      const repository = join(root, "repository");
      const trusted = join(root, "trusted");
      const target = join(trusted, "python-target");
      const launcher = join(trusted, "python");
      await Promise.all([mkdir(repository), mkdir(trusted)]);
      await writeFile(target, "#!/bin/sh\nprintf '%s\\n' \"$0\"\n");
      await chmod(target, 0o700);
      await symlink(target, launcher);

      const resolved = await resolveTrustedExecutable(
        launcher,
        { PATH: trusted },
        repository,
      );
      expect(resolved?.executable).toBe(launcher);

      const result = spawnSync(resolved!.executable, [], {
        encoding: "utf8",
        env: resolved!.environment,
      });
      expect(result.status).toBe(0);
      expect(result.stdout.trim()).toBe(launcher);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  },
);

test.skipIf(process.platform === "win32")(
  "still bypasses explicit symlinks controlled by the protected root",
  async () => {
    const root = await realpath(
      await mkdtemp(join(tmpdir(), "trusted-explicit-executable-")),
    );
    try {
      const repository = join(root, "repository");
      const bin = join(repository, "bin");
      const trusted = join(root, "trusted");
      const target = join(trusted, "python-target");
      const launcher = join(bin, "python");
      await Promise.all([
        mkdir(bin, { recursive: true }),
        mkdir(trusted),
      ]);
      await writeFile(target, "#!/bin/sh\nprintf '%s\\n' \"$0\"\n");
      await chmod(target, 0o700);
      await symlink(target, launcher);

      const resolved = await resolveTrustedExecutable(
        launcher,
        { PATH: trusted },
        repository,
      );
      expect(resolved?.executable).toBe(await realpath(target));
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  },
);

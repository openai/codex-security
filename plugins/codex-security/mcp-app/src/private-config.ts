import { randomUUID } from "node:crypto";
import { mkdir, open, rename, unlink } from "node:fs/promises";
import { dirname, join } from "node:path";
import { serializeCodexConfig, type JsonObject } from "./codex-profile.js";

export async function writeCodexConfig(
  path: string,
  config: JsonObject,
): Promise<void> {
  await writePrivateConfig(path, serializeCodexConfig(config));
}

/** @internal Write private configuration without changing its serialized contents. */
export async function writePrivateConfig(
  path: string,
  contents: string,
): Promise<void> {
  const parent = dirname(path);
  await mkdir(parent, { recursive: true, mode: 0o700 });
  const temporary = join(parent, `.${randomUUID()}.config.toml.tmp`);
  let created = false;
  try {
    const handle = await open(temporary, "wx", 0o600);
    created = true;
    try {
      await handle.chmod(0o600);
      await handle.writeFile(contents, "utf8");
      await handle.sync();
    } finally {
      await handle.close();
    }
    await rename(temporary, path);
    created = false;
  } finally {
    if (created) {
      await unlink(temporary).catch(() => undefined);
    }
  }
}

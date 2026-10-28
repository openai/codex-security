import assert from "node:assert/strict";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { importSource } from "./import-module.ts";

for (const platform of ["linux", "win32"])
  test(`Git settings file respects explicit selectors on ${platform}`, async (t) => {
    const directory = await mkdtemp(join(tmpdir(), "git-environment-test-"));
    t.after(() => rm(directory, { recursive: true, force: true }));
    const file = join(directory, "environment.json");
    const { gitConfigurationEnvironment } = await importSource(
      "src/helpers/git-environment.ts",
      { define: { "process.platform": JSON.stringify(platform) } },
    );
    await writeFile(
      file,
      JSON.stringify({
        GIT_CONFIG_GLOBAL: "bridge-config",
        GIT_CONFIG_SYSTEM: "system-config",
        GIT_CONFIG_COUNT: "1",
        GIT_CONFIG_KEY_0: "core.excludesFile",
        GIT_CONFIG_VALUE_0: "selected-path",
        GIT_ATTR_SOURCE: "HEAD",
        GIT_ATTR_NOSYSTEM: "1",
        GIT_NO_REPLACE_OBJECTS: "1",
        GIT_REPLACE_REF_BASE: "refs/fixture-replacements/",
        XDG_CONFIG_HOME: "config-home",
        GIT_DIR: "other-repository",
        GIT_ALLOW_PROTOCOL: "all",
        HOME: "other-home",
      }),
    );
    const environment = {
      [platform === "win32"
        ? "codex_security_git_environment_file"
        : "CODEX_SECURITY_GIT_ENVIRONMENT_FILE"]: file,
      CODEX_SECURITY_GIT_ENVIRONMENT: '{"GIT_CONFIG_GLOBAL":"obsolete-inline"}',
      [platform === "win32" ? "git_config_global" : "GIT_CONFIG_GLOBAL"]: "",
      GIT_ATTR_SOURCE: "",
      GIT_ATTR_NOSYSTEM: "1",
      GIT_NO_REPLACE_OBJECTS: "1",
      GIT_REPLACE_REF_BASE: "refs/fixture-replacements/",
    };
    const before = { ...environment };
    assert.deepEqual(gitConfigurationEnvironment(environment), {
      GIT_CONFIG_GLOBAL: "",
      GIT_CONFIG_SYSTEM: "system-config",
      GIT_CONFIG_COUNT: "1",
      GIT_CONFIG_KEY_0: "core.excludesFile",
      GIT_CONFIG_VALUE_0: "selected-path",
      GIT_ATTR_SOURCE: "",
      GIT_ATTR_NOSYSTEM: "1",
      GIT_NO_REPLACE_OBJECTS: "1",
      GIT_REPLACE_REF_BASE: "refs/fixture-replacements/",
      XDG_CONFIG_HOME: "config-home",
    });
    assert.deepEqual(environment, before);
    assert.deepEqual(gitConfigurationEnvironment({}), {});
  });

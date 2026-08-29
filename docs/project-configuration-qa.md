# Project configuration prototype: QA

These checks cover the local, unreleased implementation described in the
[prototype guide](project-configuration.md). They do not certify a released
package or a live scan against a model.

| Check                       | Result                                                                                                                                                              |
| --------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Full Bun suite              | 2,136 passed, 36 skipped, zero failures across 112 files in both runs (seeds `12345` and `2460537364`).                                                             |
| Focused SDK regression      | 243 passed, 3 skipped across five files.                                                                                                                            |
| New configuration coverage  | 81 cases across the input/schema, CLI, and deep-settings tests.                                                                                                     |
| Real CLI invocations        | 63 passed on Node 22.15.1, 24.15.0, and 26.0.0.                                                                                                                     |
| Packaged SDK and CLI        | Passed installed public-import and strict NodeNext type checks, CLI startup, credential locking, bundled Codex, MCP initialization, and nested-worker checks.       |
| Package contents            | 412 archive entries, including the project schema and 123 bundled plugin files.                                                                                     |
| Editor language services    | YAML Language Server 1.21.0 and JSON Language Service 4.1.8 accepted the examples, reported unknown keys, and supplied completions without network schema requests. |
| Zod / JSON Schema agreement | 26 shared input cases, with no coercion, default insertion, or unknown-key stripping.                                                                               |
| Python checks               | 64 capability-profile and source-compatibility tests passed.                                                                                                        |
| MCP suite                   | All 22 test scripts completed successfully.                                                                                                                         |
| Static checks               | TypeScript/MCP type checks, SDK formatting, Ruff lint/format, and plugin source compatibility passed.                                                               |

The CLI checks used isolated settings and synthetic fixtures. They exercised file
and CLI precedence, native profiles, context and output paths, scope replacement,
inactive deep settings, all six resolved deep settings, and errors for missing or
invalid selected files. Help and CLI schema inspection succeeded without loading
a selected missing file. Both documented examples and empty YAML/JSON configurations ran successfully. No scan state
or output directories were created by these dry runs.

QA found and fixed several integration problems:

- An absent working-tree boolean incorrectly triggered the scope-conflict check.
  Explicit presence now controls scope selection.
- Inferred SDK types initially pulled CLI-only declarations into an installed
  consumer. Shared schemas now import Zod directly; the strict installed-consumer
  check passes without suppressing declaration errors.
- A schema URN caused editor services to resolve local references incorrectly.
  The generated schema now uses its file location as its identity, and
  its relative references resolve offline.
- The legacy TOML resolver needed to reject a date where a deep-settings table
  was expected. Its existing environment-path behavior is retained, and runtime
  preparation uses the resolved settings snapshot.
- Zod's cloned output discarded reserved native keys and accepted a reserved
  unknown key in strict wrapper sections. File loading now uses the generated
  schema with the SDK's existing Ajv validator, preserving native input for the
  existing override checks. Regression tests load JSON and YAML files and reject
  reserved unknown wrapper keys.

Earlier full-suite attempts exposed an outdated build-command assertion and an
unused type import; both were corrected. Other failures required using a canonical
temporary directory on macOS and allowing the existing process-inspection test to
read process state. One intermediate run was stopped after existing process and
SQLite fixtures timed out. The isolated credential-lock test and the 44
publication/target tests subsequently passed without changes to those fixtures.
The full suite passed again after removal of the project version field, both with seed `12345` and in a randomized order.

The local environment used macOS arm64, Bun 1.3.14, Python 3.12.12, and Ruff
0.16.1. Python tests ran with unrelated environment-installed pytest plugins
disabled. The final full runs did not overlap package/MCP checks and prevented
idle sleep only for the duration of each command.

To reproduce the repository checks with the required tool versions installed,
run from the SDK directory:

```sh
pnpm run test --seed 12345
pnpm run types
pnpm run format
pnpm run test
pnpm run test:mcp
mkdir -p /tmp/codex-security-package
pnpm pack --pack-destination /tmp/codex-security-package
pnpm run check:package /tmp/codex-security-package/openai-codex-security-0.1.23.tgz
```

On macOS, use a canonical temporary directory such as `TMPDIR=/private/tmp` for
the existing path-sensitive fixtures. The process-group test also needs local
process-inspection access. From the repository root:

```sh
PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 python -m pytest -q plugins/codex-security/tests/test_capability_profiles.py .github/scripts/test_check_plugin_source_compatibility.py
python -m ruff check --config plugins/codex-security/pyproject.toml .github/scripts/check_plugin_source_compatibility.py .github/scripts/test_check_plugin_source_compatibility.py plugins/codex-security
python -m ruff format --check --config plugins/codex-security/pyproject.toml .github/scripts/check_plugin_source_compatibility.py .github/scripts/test_check_plugin_source_compatibility.py plugins/codex-security
python .github/scripts/check_plugin_source_compatibility.py
```

No live inference, credential verification, Linux/Windows execution, or release
publication was performed. Editor testing used the actual language services, not
a graphical editor session. Full native Codex schema completion, automatic file
discovery, batch adoption, and complete input replay remain outside this
prototype. Existing conditional tests remain skipped where their conditions do
not apply.

import { expect, test } from "bun:test";
import { scanActivityFromEvent } from "../src/scan-activity.js";

const cases = [
  [
    "quoted path (control)",
    'cat "$CODEX_SECURITY_REPOSITORY/src/my file.ts"',
    "/code/project",
    ["src/my file.ts"],
  ],
  [
    "ordinary path (control)",
    "cat $CODEX_SECURITY_REPOSITORY/src/app.ts",
    "/code/project",
    ["src/app.ts"],
  ],
  [
    "unquoted escaped space with repository variable",
    String.raw`cat $CODEX_SECURITY_REPOSITORY/src/my\ file.ts`,
    "/code/project",
    ["src/my file.ts"],
  ],
  [
    "unquoted escaped space with absolute path",
    String.raw`cat /code/project/src/my\ file.ts`,
    "/code/project",
    ["src/my file.ts"],
  ],
  [
    "multiple escaped arguments",
    String.raw`cat $CODEX_SECURITY_REPOSITORY/src/my\ file.ts $CODEX_SECURITY_REPOSITORY/tests/another\ file.ts`,
    "/code/project",
    ["src/my file.ts", "tests/another file.ts"],
  ],
  [
    "escaped space in actual absolute repository directory",
    String.raw`cat /code/juice\ shop/src/app.ts`,
    "/code/juice shop",
    ["src/app.ts"],
  ],
  [
    "outside repository traversal stays excluded",
    "cat $CODEX_SECURITY_REPOSITORY/../outside.txt",
    "/code/project",
    [],
  ],
] as const;

test.each(cases)(
  "scan activity handles %s",
  (_title, command, repository, paths) => {
    const activity = scanActivityFromEvent(
      {
        type: "item.started",
        item: { id: "synthetic-test", type: "command_execution", command },
      },
      repository,
    );
    expect(activity?.paths).toEqual([...paths]);
  },
);

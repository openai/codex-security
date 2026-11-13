import { expect, test } from "bun:test";
import { splitCommand } from "../src/command-words.js";

test.each([
  ["\\\n", []],
  ["\\\n printf value", ["printf", "value"]],
  ["printf \\\n value", ["printf", "value"]],
  ["printf value \\\n", ["printf", "value"]],
  ["printf \\\n \\\n value", ["printf", "value"]],
  ["printf val\\\nue", ["printf", "value"]],
  ['printf "val\\\nue"', ["printf", "value"]],
  ['printf "\\\n"', ["printf", ""]],
  ["printf '\\\n'", ["printf", "\\\n"]],
  ['printf "" \\\n value', ["printf", "", "value"]],
  ["printf \\ value", ["printf", " value"]],
  ['printf "unterminated', null],
  ["printf " + "\\", null],
] satisfies [string, string[] | null][])(
  "splits shell words in %j",
  (command, expected) => {
    expect(splitCommand(command)).toEqual(expected);
  },
);

test("keeps backslashes in literal launcher arguments", () => {
  expect(
    splitCommand('server \\\n "C:\\source files\\repo"', "literal"),
  ).toEqual(["server", "\\", "C:\\source files\\repo"]);
});

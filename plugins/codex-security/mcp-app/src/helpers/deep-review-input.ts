import {
  argumentsFor,
  compare,
  loadRankRows,
  print,
  reportCommandError,
  requireUniquePaths,
  worklistPath,
  writeRankRows,
} from "./rank-worklists";

type Command = "copy-deep-review-input" | "select-deep-review-input";

export function deepReviewInputCommand(
  command: Command,
  args: string[],
  posixHome = process.env.HOME,
): number {
  const selection = command === "select-deep-review-input";
  const input = selection ? "rank-output" : "rank-input";
  const usage = `usage: launch_codex_security_mcp[.cmd] --helper ${command} [-h] --${input} PATH --out PATH${selection ? " [--top-percent INT]" : ""}`;
  try {
    const values = argumentsFor(
      args,
      [input, "out"],
      selection ? ["top-percent"] : [],
    );
    if (values.help) {
      print(
        `${usage}\n\nCreate deep_review_input.jsonl from ${selection ? "worker-produced rank_output.jsonl" : "rank_input.jsonl"}.\n\noptions:\n  -h, --help  show this help message and exit\n  --${input} PATH  ${selection ? "Worker ranking output" : "Deterministic rank input"} JSONL.\n  --out PATH  Output deep_review_input.jsonl path.${selection ? "\n  --top-percent INT  Percent of included files to keep for deep review. Defaults to 100." : ""}`,
      );
      return 0;
    }
    const path = (name: string) =>
      worklistPath(values[name] as string, posixHome);
    const rows = loadRankRows(path(input), selection);
    requireUniquePaths(rows, selection ? "Rank output" : "Rank input");
    let selected = rows,
      total = rows.length;
    if (selection) {
      const included = rows.filter((row) => row.include);
      const base = included.length ? included : rows;
      base.sort(
        (left, right) =>
          right.score! - left.score! || compare(left.path, right.path),
      );
      total = base.length;
      const percent = (values["top-percent"] ?? 100) as number;
      const keep = total ? Math.max(1, Math.trunc(total * (percent / 100))) : 0;
      selected = base.slice(0, keep);
    }
    const output = path("out");
    writeRankRows(
      output,
      selected.map(({ path, area }) => ({ path, area })),
    );
    const message = selection
      ? `Selected ${selected.length} of ${total} rows into ${output}`
      : `Copied ${selected.length} rows into ${output}`;
    print(message);
    return 0;
  } catch (error) {
    return reportCommandError(error, command, usage);
  }
}

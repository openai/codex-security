import {
  argumentsFor,
  loadRankRows,
  print,
  reportCommandError,
  requireUniquePaths,
  worklistPath,
  writeRankRows,
} from "./rank-worklists";

export function deepReviewInputCommand(
  args: string[],
  posixHome = process.env.HOME,
): number {
  const command = "copy-deep-review-input";
  const usage = `usage: launch_codex_security_mcp[.cmd] --helper ${command} [-h] --rank-input PATH --out PATH`;
  try {
    const values = argumentsFor(args, ["rank-input", "out"]);
    if (values.help) {
      print(
        `${usage}\n\nCreate deep_review_input.jsonl from rank_input.jsonl.\n\noptions:\n  -h, --help  show this help message and exit\n  --rank-input PATH  Deterministic rank input JSONL.\n  --out PATH  Output deep_review_input.jsonl path.`,
      );
      return 0;
    }
    const rows = loadRankRows(
      worklistPath(values["rank-input"] as string, posixHome),
    );
    requireUniquePaths(rows, "Rank input");
    const output = worklistPath(values.out as string, posixHome);
    writeRankRows(
      output,
      rows.map(({ path, area }) => ({ path, area })),
    );
    print(`Copied ${rows.length} rows into ${output}`);
    return 0;
  } catch (error) {
    return reportCommandError(error, command, usage);
  }
}

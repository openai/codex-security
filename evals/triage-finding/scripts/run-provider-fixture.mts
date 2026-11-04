import { runPromptfoo } from "./run-promptfoo.mts";

const [builtMcp, ...args] = process.argv.slice(2);
process.exitCode = await runPromptfoo(args, {}, builtMcp);

import { compareTestReports } from "./test-report-comparison.mts";

process.exitCode = compareTestReports(process.argv.slice(2));

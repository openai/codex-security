import { mkdir, writeFile } from "node:fs/promises";
import { junit, tap, type TestEvent } from "node:test/reporters";

export default async function* report(source: AsyncIterable<TestEvent>) {
  const [tapEvents, reportEvents] = ReadableStream.from(source).tee();
  yield* tap(tapEvents);

  try {
    await mkdir("reports", { recursive: true });
    await writeFile("reports/junit.xml", junit(reportEvents));
  } catch (error) {
    console.warn(
      `Could not write the optional MCP test report: ${(error as Error).message}`,
    );
  }
}

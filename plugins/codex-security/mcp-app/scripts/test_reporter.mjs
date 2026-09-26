import { mkdir, writeFile } from "node:fs/promises";
import { junit, tap } from "node:test/reporters";

export default async function* report(source) {
  const events = [];
  async function* record() {
    for await (const event of source) {
      events.push(event);
      yield event;
    }
  }

  yield* tap(record());

  try {
    await mkdir("reports", { recursive: true });
    await writeFile("reports/junit.xml", junit(events));
  } catch (error) {
    console.warn(
      `Could not write the optional MCP test report: ${error.message}`,
    );
  }
}

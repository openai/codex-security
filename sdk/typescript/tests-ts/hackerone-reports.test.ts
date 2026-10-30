import { expect, test } from "bun:test";
import {
  mkdtemp,
  readFile,
  readdir,
  rm,
  stat,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { exportHackerOneReports } from "../src/hackerone-reports.js";

const credentials = {
  HACKERONE_API_USERNAME: "example",
  HACKERONE_API_TOKEN: "synthetic",
};
function report(id: string, program: string) {
  return Response.json({
    data: {
      type: "report",
      id,
      attributes: {
        title: "Example title",
        state: "triaged",
        vulnerability_information: "omitted narrative",
        last_activity_at: "2026-10-01T12:00:00.000187Z",
      },
      relationships: {
        program: { data: { type: "program", id: program } },
        severity: { data: { attributes: { rating: "medium" } } },
        reporter: { data: { attributes: { username: "omitted-user" } } },
      },
    },
  });
}

test("exports exactly the selected private fields and preserves the capture and opaque IDs", async () => {
  const dir = await mkdtemp(join(tmpdir(), "h1-export-"));
  try {
    const output = join(dir, "reports.json");
    const capture = join(dir, "capture.txt");
    await writeFile(capture, "test.capture.ticket\n");
    const requested: string[] = [];
    const ids = ["7101", "9007199254740993"];
    const options = {
      programId: "11",
      reportIds: ids.join(","),
      output,
      capture,
      environment: credentials,
      async fetch(url: string, init: RequestInit) {
        requested.push(url);
        expect(init.redirect).toBe("error");
        expect(init.method).toBe("GET");
        expect(new Headers(init.headers).get("authorization")).toBe(
          "Basic " + Buffer.from("example:synthetic").toString("base64"),
        );
        return report(url.split("/").at(-1)!, "11");
      },
    };
    expect((await exportHackerOneReports(options)).reports).toBe(2);
    expect(requested).toEqual(
      ids.map((id) => `https://api.hackerone.com/v1/reports/${id}`),
    );
    const bytes = await readFile(output, "utf8");
    const projection = {
      format: "hackerone.reports_json.v1",
      program_id: "11",
      reports: ids.map((id) => ({
        id,
        program_id: "11",
        title: "Example title",
        state: "triaged",
        severity_rating: "medium",
        last_activity_at: "2026-10-01T12:00:00.000187Z",
      })),
    };
    expect(JSON.parse(bytes)).toEqual({
      capture: "test.capture.ticket",
      projection,
    });
    if (process.platform !== "win32")
      expect((await stat(output)).mode & 0o077).toBe(0);
    const local = join(dir, "unbound.json");
    const { capture: _capture, ...unbound } = options;
    await exportHackerOneReports({ ...unbound, output: local });
    expect(JSON.parse(await readFile(local, "utf8"))).toEqual(projection);
    await expect(exportHackerOneReports(options)).rejects.toMatchObject({
      code: "EEXIST",
    });
    expect(await readFile(output, "utf8")).toBe(bytes);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("a wrong-program second report or an inaccessible selection leaves no partial export", async () => {
  const dir = await mkdtemp(join(tmpdir(), "h1-export-"));
  try {
    for (const second of [
      report("7102", "22"),
      new Response(null, { status: 403 }),
    ]) {
      await expect(
        exportHackerOneReports({
          programId: "11",
          reportIds: "7101,7102",
          output: join(dir, "reports.json"),
          environment: credentials,
          fetch: async (url) =>
            url.endsWith("/7101") ? report("7101", "11") : second,
        }),
      ).rejects.toThrow();
      expect(await readdir(dir)).toEqual([]);
    }
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

import { expect, test } from "bun:test";
import {
  chmod,
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
function report(id: string, program: string, title = "Example title") {
  return Response.json({
    data: {
      type: "report",
      id,
      attributes: {
        title,
        state: "triaged",
        vulnerability_information: "omitted narrative",
        last_activity_at: "2026-10-01T12:00:00.000187Z",
      },
      relationships: {
        program: { data: { type: "program", id: program } },
        severity: {
          data: { attributes: { rating: id === "7101" ? "medium" : "none" } },
        },
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
    const requested: {
      url: string;
      method: string | undefined;
      redirect: string | undefined;
      authorization: string | null;
    }[] = [];
    const ids = ["7101", "9007199254740993"];
    const options = {
      programId: "11",
      reportIds: ids.join(","),
      output,
      capture,
      environment: credentials,
      async fetch(url: string, init: RequestInit) {
        requested.push({
          url,
          method: init.method,
          redirect: init.redirect,
          authorization: new Headers(init.headers).get("authorization"),
        });
        return report(url.split("/").at(-1)!, "11");
      },
    };
    expect((await exportHackerOneReports(options)).reports).toBe(2);
    expect(requested).toEqual(
      ids.map((id) => ({
        url: `https://api.hackerone.com/v1/reports/${id}`,
        method: "GET",
        redirect: "error",
        authorization:
          "Basic " + Buffer.from("example:synthetic").toString("base64"),
      })),
    );
    const bytes = await readFile(output, "utf8");
    const projection = JSON.parse(
      await readFile(
        new URL("./fixtures/hackerone-reports-v1.json", import.meta.url),
        "utf8",
      ),
    );
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

test("an invalid or inaccessible second report leaves no partial export", async () => {
  const dir = await mkdtemp(join(tmpdir(), "h1-export-"));
  try {
    for (const second of [
      report("7102", "22"),
      report("7101", "11"),
      report("7102", "11", "a".repeat(513)),
      report("7102", "11", "bad\0title"),
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

test.skipIf(process.platform === "win32")(
  "refuses a replaceable destination before reading a report",
  async () => {
    const dir = await mkdtemp(join(tmpdir(), "h1-export-"));
    try {
      await chmod(dir, 0o777);
      let fetched = false;
      await expect(
        exportHackerOneReports({
          programId: "11",
          reportIds: "7101",
          output: join(dir, "reports.json"),
          environment: credentials,
          fetch: async () => {
            fetched = true;
            return report("7101", "11");
          },
        }),
      ).rejects.toThrow();
      expect(fetched).toBe(false);
      expect(await readdir(dir)).toEqual([]);
    } finally {
      await chmod(dir, 0o700);
      await rm(dir, { recursive: true, force: true });
    }
  },
);

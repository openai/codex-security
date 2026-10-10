import { execFileSync } from "node:child_process";
import { copyFile, mkdir, readFile, writeFile } from "node:fs/promises";
import { basename, join } from "node:path";
import { pathToFileURL } from "node:url";
import { afterEach, expect, test } from "bun:test";
import { resolveScanSessionPaths } from "../src/runtime.js";
import type { JsonObject } from "../src/config.js";
import { PLUGIN_ROOT } from "./plugin-root.js";
import { createApiTestFixtures } from "./support/temporary-directories.js";
import { nodeCommand, pythonExecutable } from "./support/shell.js";

const { temporaryDirectory, cleanup } = createApiTestFixtures(
  "scan-session-paths-",
);
afterEach(cleanup);

async function fixture(label: string, response = "selected") {
  const root = await temporaryDirectory();
  const home = join(root, "home");
  const sqliteHome = join(root, "selected-state");
  const directory = join(root, "scan");
  const state = join(root, "workbench");
  await Promise.all(
    [home, sqliteHome, directory, state].map((path) =>
      mkdir(path, { mode: 0o700 }),
    ),
  );
  const ids = [
    "root",
    "discovery",
    "resumed-discovery",
    "reducer",
    "resumed-reducer",
  ].map((id) => `${label}-${id}`);
  const paths = ids.map((id) => join(home, `${id}.jsonl`));
  await Promise.all(
    paths.map((path, index) =>
      writeFile(
        path,
        JSON.stringify({ type: "session_meta", payload: { id: ids[index] } }) +
          "\n",
      ),
    ),
  );
  const python = pythonExecutable()!;
  execFileSync(python, [
    "-I",
    "-B",
    "-c",
    [
      "import json,sqlite3,sys",
      "from pathlib import Path",
      "sqlite_home,state,ids,paths=json.loads(sys.argv[1])",
      "c=sqlite3.connect(Path(sqlite_home)/'state_7.sqlite')",
      "c.execute('CREATE TABLE threads(id TEXT PRIMARY KEY,rollout_path TEXT NOT NULL)')",
      "c.execute('CREATE TABLE thread_spawn_edges(parent_thread_id TEXT NOT NULL,child_thread_id TEXT NOT NULL)')",
      "c.executemany('INSERT INTO threads VALUES (?,?)',zip(ids,paths))",
      "c.commit();c.close()",
      "c=sqlite3.connect(Path(state)/'workbench.sqlite3')",
      "c.execute('CREATE TABLE scans(id TEXT PRIMARY KEY,workspace_id TEXT NOT NULL,mode TEXT NOT NULL)')",
      "c.execute('CREATE TABLE workspaces(id TEXT PRIMARY KEY,thread_id TEXT)')",
      "c.execute('CREATE TABLE deep_scan_workers(id TEXT PRIMARY KEY,scan_id TEXT NOT NULL,sdk_thread_id TEXT)')",
      "c.execute('CREATE TABLE deep_scan_worker_threads(worker_id TEXT NOT NULL,sdk_thread_id TEXT NOT NULL)')",
      "c.execute(\"INSERT INTO scans VALUES ('scan','workspace','deep')\")",
      "c.execute(\"INSERT INTO workspaces VALUES ('workspace',?)\",(ids[0],))",
      "c.executemany(\"INSERT INTO deep_scan_workers VALUES (?,'scan',?)\",[(id,id)for id in ids[1:]])",
      "c.executemany('INSERT INTO deep_scan_worker_threads VALUES (?,?)',[(id,id)for id in ids[1:]])",
      "c.commit();c.close()",
    ].join("\n"),
    JSON.stringify([sqliteHome, state, ids, paths]),
  ]);
  const transcript = join(root, "requests.jsonl");
  const preload = join(root, "native-config.mjs");
  await writeFile(
    preload,
    [
      'import { createInterface } from "node:readline";',
      'import { appendFileSync } from "node:fs";',
      `const transcript = ${JSON.stringify(transcript)};`,
      "const sqliteOverride=process.argv.find((arg)=>arg.startsWith('sqlite_home='));",
      `const sqliteHome=sqliteOverride ? JSON.parse(sqliteOverride.slice('sqlite_home='.length)) : ${response === "environment" ? "process.env.CODEX_SQLITE_HOME" : JSON.stringify(sqliteHome)};`,
      "for await (const line of createInterface({input:process.stdin})) {",
      "const request=JSON.parse(line);",
      'appendFileSync(transcript, JSON.stringify({request,cwd:process.cwd(),home:process.env.CODEX_HOME,sqliteHome:process.env.CODEX_SQLITE_HOME,argv:process.argv.slice(1)})+"\\n");',
      'if(request.method==="initialize") process.stdout.write(JSON.stringify({id:request.id,result:{}})+"\\n");',
      response === "blocked"
        ? ""
        : response === "error"
          ? 'if(request.method==="config/read") process.stdout.write(JSON.stringify({id:request.id,error:{message:"Synthetic native configuration failure"}})+"\\n");'
          : `if(request.method==="config/read") process.stdout.write(JSON.stringify({id:request.id,result:{config:{sqlite_home:sqliteHome}}})+"\\n");`,
      "}",
    ].join("\n"),
  );
  const environment: NodeJS.ProcessEnv = {
    ...process.env,
    CODEX_HOME: home,
    CODEX_SECURITY_STATE_DIR: state,
    NODE_OPTIONS: `--import=${pathToFileURL(preload).href}`,
  };
  delete environment["CODEX_STATE_DB"];
  delete environment["CODEX_SQLITE_HOME"];
  const options = { python, pluginRoot: PLUGIN_ROOT, environment };
  const native = {
    command: { ...nodeCommand(), args: ["--"] },
    workingDirectory: directory,
  };
  return {
    root,
    home,
    sqliteHome,
    directory,
    ids,
    paths,
    transcript,
    options,
    native,
  };
}

test("resolves native SQLite ownership for concurrent fresh and resumed Deep workers", async () => {
  const fixtures = await Promise.all([fixture("first"), fixture("second")]);
  const completed = await Promise.allSettled(
    fixtures.map(async (f) => {
      for (const id of f.ids)
        expect(
          [
            ...(await resolveScanSessionPaths(f.options, "scan", id, f.native)),
          ].sort(),
        ).toEqual(
          f.paths
            .map<[string, string]>((path, index) => [path, f.ids[index]!])
            .sort(),
        );
      const requests = (await readFile(f.transcript, "utf8"))
        .trim()
        .split("\n")
        .map((line) => JSON.parse(line));
      expect(
        requests.filter((x) => x.request.method === "config/read"),
      ).toHaveLength(1);
      expect(requests.map((x) => x.request.method)).toEqual([
        "initialize",
        "initialized",
        "config/read",
      ]);
      for (const row of requests) {
        expect(row.cwd).toBe(f.directory);
        expect(row.home).toBe(f.home);
        expect(row.argv).toHaveLength(2);
        expect(basename(row.argv[0])).toBe("app-server");
        expect(row.argv[1]).toBe("--stdio");
      }
      expect(requests[2].request.params).toEqual({
        cwd: f.directory,
        includeLayers: false,
      });
    }),
  );
  for (const row of completed) if (row.status === "rejected") throw row.reason;
});

test.each(["CODEX_SQLITE_HOME", "CODEX_STATE_DB", "Codex_State_Db"] as const)(
  "preserves explicit %s ownership",
  async (key) => {
    const stateDatabase = key !== "CODEX_SQLITE_HOME";
    const explicitDatabase =
      key === "CODEX_STATE_DB" ||
      (key === "Codex_State_Db" && process.platform === "win32");
    const f = await fixture(
      "explicit",
      explicitDatabase ? "error" : stateDatabase ? "selected" : "environment",
    );
    const value = stateDatabase
      ? join(f.sqliteHome, "state_7.sqlite")
      : f.sqliteHome;
    f.options.environment[key] = value;
    expect(
      [
        ...(await resolveScanSessionPaths(
          f.options,
          "scan",
          f.ids[0]!,
          f.native,
        )),
      ].sort(),
    ).toEqual(
      f.paths
        .map<[string, string]>((path, index) => [path, f.ids[index]!])
        .sort(),
    );
    expect(f.options.environment[key]).toBe(value);
    if (explicitDatabase) {
      await expect(readFile(f.transcript, "utf8")).rejects.toMatchObject({
        code: "ENOENT",
      });
    } else {
      expect(await readFile(f.transcript, "utf8")).toContain(
        '"method":"config/read"',
      );
    }
  },
);

test("retains native configuration errors and incomplete ownership rejection", async () => {
  const f = await fixture("failure", "error");
  await expect(
    resolveScanSessionPaths(f.options, "scan", f.ids[0]!, f.native),
  ).rejects.toThrow("scan session ownership");
  await expect(
    resolveScanSessionPaths(
      {
        ...f.options,
        environment: {
          ...f.options.environment,
          CODEX_SQLITE_HOME: f.sqliteHome,
        },
      },
      null,
      "unowned-thread",
      f.native,
    ),
  ).rejects.toThrow("scan session ownership");
});

test("aborts a pending native SQLite query and drains its child", async () => {
  const f = await fixture("abort", "blocked");
  const controller = new AbortController();
  const pending = resolveScanSessionPaths(
    { ...f.options, signal: controller.signal },
    "scan",
    f.ids[0]!,
    f.native,
  );
  let requests = "";
  while (!requests.includes("config/read")) {
    try {
      requests = await readFile(f.transcript, "utf8");
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
    }
    await Bun.sleep(5);
  }
  controller.abort(new Error("Synthetic caller cancellation"));
  await expect(pending).rejects.toBeDefined();
});

test.each(["unrelated", "schema"])(
  "resolves native SQLite ownership when the default database is %s",
  async (stale) => {
    const f = await fixture("stale-" + stale);
    execFileSync(f.options.python, [
      "-I",
      "-B",
      "-c",
      stale === "schema"
        ? "import sqlite3,sys;c=sqlite3.connect(sys.argv[1]);c.execute('CREATE TABLE legacy(value TEXT)');c.close()"
        : "import sqlite3,sys;c=sqlite3.connect(sys.argv[1]);c.execute('CREATE TABLE threads(id TEXT PRIMARY KEY,rollout_path TEXT NOT NULL)');c.execute('CREATE TABLE thread_spawn_edges(parent_thread_id TEXT NOT NULL,child_thread_id TEXT NOT NULL)');c.close()",
      join(f.home, "state_7.sqlite"),
    ]);
    expect(
      [
        ...(await resolveScanSessionPaths(
          f.options,
          "scan",
          f.ids[0]!,
          f.native,
        )),
      ].sort(),
    ).toEqual(
      f.paths
        .map<[string, string]>((path, index) => [path, f.ids[index]!])
        .sort(),
    );
    expect(await readFile(f.transcript, "utf8")).toContain(
      '"method":"config/read"',
    );
  },
);

test.each(["absent", "incomplete", "readable"])(
  "uses native SQLite configuration before a %s environment fallback",
  async (database) => {
    const f = await fixture("native-precedence-" + database);
    execFileSync(f.options.python, [
      "-I",
      "-B",
      "-c",
      "import sqlite3,json,sys;c=sqlite3.connect(sys.argv[1]);ids=json.loads(sys.argv[2]);c.executemany('INSERT INTO thread_spawn_edges VALUES (?,?)',[(ids[0],worker) for worker in ids[1:]]);c.commit();c.close()",
      join(f.sqliteHome, "state_7.sqlite"),
      JSON.stringify(f.ids),
    ]);
    if (database !== "absent") {
      execFileSync(f.options.python, [
        "-I",
        "-B",
        "-c",
        "import sqlite3,sys;c=sqlite3.connect(sys.argv[1]);c.execute('CREATE TABLE threads(id TEXT PRIMARY KEY,rollout_path TEXT NOT NULL)');c.execute('CREATE TABLE thread_spawn_edges(parent_thread_id TEXT NOT NULL,child_thread_id TEXT NOT NULL)');" +
          (database === "readable"
            ? "c.execute('INSERT INTO threads VALUES (?,?)',(sys.argv[2],sys.argv[3]));"
            : "") +
          "c.commit();c.close()",
        join(f.home, "state_7.sqlite"),
        f.ids[0]!,
        f.paths[0]!,
      ]);
    }
    f.options.environment["CODEX_SQLITE_HOME"] = f.home;
    expect(
      [
        ...(await resolveScanSessionPaths(
          f.options,
          null,
          f.ids[0]!,
          f.native,
        )),
      ].sort(),
    ).toEqual(
      f.paths
        .map<[string, string]>((path, index) => [path, f.ids[index]!])
        .sort(),
    );
    expect(await readFile(f.transcript, "utf8")).toContain(
      '"method":"config/read"',
    );
  },
);

test.each(["CODEX_SQLITE_HOME", "CODEX_STATE_DB"] as const)(
  "rejects incomplete ownership at the selected %s database",
  async (key) => {
    const f = await fixture("explicit-incomplete", "environment");
    const database = join(f.home, "state_7.sqlite");
    execFileSync(f.options.python, [
      "-I",
      "-B",
      "-c",
      "import sqlite3,sys;c=sqlite3.connect(sys.argv[1]);c.execute('CREATE TABLE threads(id TEXT PRIMARY KEY,rollout_path TEXT NOT NULL)');c.execute('CREATE TABLE thread_spawn_edges(parent_thread_id TEXT NOT NULL,child_thread_id TEXT NOT NULL)');c.close()",
      database,
    ]);
    f.options.environment[key] = key === "CODEX_STATE_DB" ? database : f.home;
    await expect(
      resolveScanSessionPaths(f.options, "scan", f.ids[0]!, f.native),
    ).rejects.toThrow("scan session ownership");
    if (key === "CODEX_STATE_DB") {
      await expect(readFile(f.transcript, "utf8")).rejects.toMatchObject({
        code: "ENOENT",
      });
    } else {
      expect(await readFile(f.transcript, "utf8")).toContain(
        '"method":"config/read"',
      );
    }
  },
);

test.each(
  ["direct", "profile"].flatMap((selection) =>
    ["absolute", "relative", "tilde"].map((location) => ({
      selection,
      location,
    })),
  ),
)(
  "preserves the caller's $selection $location SQLite override during native ownership lookup",
  async ({ selection, location }) => {
    const f = await fixture("caller-override-" + selection);
    const callerHome = join(f.root, "caller sqlite");
    await mkdir(callerHome);
    await copyFile(
      join(f.sqliteHome, "state_7.sqlite"),
      join(callerHome, "state_7.sqlite"),
    );
    const callerRollout = join(callerHome, "caller-root.jsonl");
    await writeFile(
      callerRollout,
      JSON.stringify({ type: "session_meta", payload: { id: f.ids[0] } }) +
        "\n",
    );
    execFileSync(f.options.python, [
      "-I",
      "-B",
      "-c",
      "import sqlite3,sys;c=sqlite3.connect(sys.argv[1]);c.execute('UPDATE threads SET rollout_path=? WHERE id=?',(sys.argv[2],sys.argv[3]));c.commit();c.close()",
      join(callerHome, "state_7.sqlite"),
      callerRollout,
      f.ids[0]!,
    ]);
    f.options.environment["CODEX_SQLITE_HOME"] = callerHome;
    f.options.environment["HOME"] = f.root;
    f.options.environment["USERPROFILE"] = f.root;
    const configuredHome =
      location === "relative"
        ? "../caller sqlite"
        : location === "tilde"
          ? "~/caller sqlite"
          : callerHome;
    const config: JsonObject =
      selection === "direct"
        ? { sqlite_home: configuredHome }
        : {
            profile: "chosen",
            profiles: { chosen: { sqlite_home: configuredHome } },
          };
    const originalConfig = structuredClone(config);
    expect([
      ...(await resolveScanSessionPaths(f.options, null, f.ids[0]!, {
        ...f.native,
        config,
      })),
    ]).toEqual([[callerRollout, f.ids[0]!]]);
    const requests = (await readFile(f.transcript, "utf8"))
      .trim()
      .split("\n")
      .map((line) => JSON.parse(line));
    expect(requests[0].sqliteHome).toBe(callerHome);
    expect(requests[0].argv).toContain(
      `sqlite_home=${JSON.stringify(callerHome)}`,
    );
    expect(config).toEqual(originalConfig);
  },
);

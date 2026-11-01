import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { mock, test } from "node:test";
import { fileURLToPath } from "node:url";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { importModule } from "./import-module.ts";
import {
  DeepScanCoordinatorRegistry,
  FakeExecutor,
  pausePoint,
  FakeStore,
  fixtureRun,
  immediateClock,
  startOrJoinDeepScanCoordinator,
  temporaryDirectories,
} from "./deep_scan_coordinator_fixture.ts";

const applicationRoot = fileURLToPath(new URL("../", import.meta.url));
const fixtureKey = "deepScanHostShutdownFixture";
const fixtureAccess = `globalThis.${fixtureKey}`;
const source = await readFile(new URL("../server.ts", import.meta.url), "utf8");
// Retain the actual tool, engine and transport lifecycle; replace persistence,
// executable lookup and worker execution with deterministic local fixtures.
const { createCodexSecurityServer } = await importModule({
  stdin: {
    contents: source
      .replace("new DeepScanCoordinatorRegistry()", `${fixtureAccess}.registry`)
      .replace(
        "new WorkbenchDeepScanStore(runWorkbench)",
        `${fixtureAccess}.store`,
      )
      .replace(
        'import { resolvePythonCommand } from "./src/python_command.js";',
        'const resolvePythonCommand = async () => "fixture-python";',
      )
      .replace(
        'import { PLUGIN_ROOT, runWorkbench, scanRoot } from "./src/workbench-client.js";',
        `const PLUGIN_ROOT = "fixture-plugin";
         const runWorkbench = async () => ({});
         const scanRoot = async () => ${fixtureAccess}.store.run.scanDir;`,
      ),
    loader: "ts",
    resolveDir: applicationRoot,
  },
  plugins: [
    {
      name: "synthetic-worker",
      setup(build) {
        build.onLoad({ filter: /[/\\]deep-scan[/\\]executor\.ts$/ }, () => ({
          contents: `export class CodexSdkWorkerExecutor { constructor() { return ${fixtureAccess}.executor; } }`,
          loader: "ts",
        }));
      },
    },
  ],
  define: {
    __dirname: JSON.stringify(applicationRoot),
    "import.meta.url": JSON.stringify(
      new URL("../server.ts", import.meta.url).href,
    ),
  },
  loader: { ".md": "text" },
});

try {
  for (const stage of ["begin", "claim", "queued", "takeover"] as const) {
    await test(`transport close prevents coordinator admission during ${stage}`, async () => {
      const fixture = await fixtureRun();
      const registry = new DeepScanCoordinatorRegistry();
      const store = new FakeStore(fixture.run);
      const executor = new FakeExecutor({ blockDiscoveryAfterCalls: 0 });
      const shutdown = pausePoint();
      const secondStarted = Promise.withResolvers<void>();
      const handlers: Promise<unknown>[] = [];
      const outcomes: unknown[] = [];
      const signals: AbortSignal[] = [];
      let claims = 0;
      let now = 0;
      const hold = async () => await shutdown.pause();
      Object.assign(globalThis, {
        [fixtureKey]: {
          registry,
          executor,
          store: Object.assign(store, {
            begin: async () => {
              if (stage === "begin" || stage === "queued") await hold();
              return structuredClone(store.run);
            },
          }),
        },
      });
      store.claimCoordinator = async () => {
        claims += 1;
        if (stage === "claim" || (stage === "takeover" && claims === 2))
          await hold();
        return {
          run: structuredClone(store.run),
          acquired: stage !== "takeover" || claims > 1,
        };
      };
      if (stage === "takeover") {
        store.get = async () => {
          now = 30_000;
          return structuredClone(store.run);
        };
      }
      const server = createCodexSecurityServer();
      const tool = server._registeredTools.start_codex_security_deep_scan;
      const handler = tool.handler;
      tool.handler = (args: unknown, extra: { signal: AbortSignal }) => {
        signals.push(extra.signal);
        if (signals.length === 2) secondStarted.resolve();
        const pending = handler(args, extra).then(
          (result: unknown) => {
            outcomes.push(result);
            return result;
          },
          (error: unknown) => {
            outcomes.push(error);
            throw error;
          },
        );
        handlers.push(pending);
        return pending;
      };
      const client = new Client({ name: "shutdown-fixture", version: "1.0.0" });
      const [clientTransport, serverTransport] =
        InMemoryTransport.createLinkedPair();
      await server.connect(serverTransport);
      await client.connect(clientTransport);
      const clock = mock.method(Date, "now", () => now);
      const invoke = () =>
        client
          .callTool({
            name: "start_codex_security_deep_scan",
            arguments: { targetPath: fixture.run.targetPath },
            _meta: {
              "openai/threadId": "fixture-owner",
              "codex/sandbox-state-meta": {
                permissionProfile: {
                  type: "managed",
                  file_system: { type: "unrestricted" },
                },
              },
            },
          })
          .catch((error: unknown) => error);
      const requests = [invoke()];
      try {
        await Promise.race([
          shutdown.entered,
          requests[0].then(() =>
            assert.fail("Request settled before the held operation"),
          ),
        ]);
        if (stage === "queued") {
          requests.push(invoke());
          await secondStarted.promise;
        }
        await client.close();
        assert.ok(signals.every((signal) => signal.aborted));
        shutdown.release();
        // Client rejection precedes handler completion when the transport closes.
        await Promise.allSettled(handlers);
        assert.equal(registry.get(fixture.run.scanId), undefined);
        assert.equal(executor.discoveryCalls, 0);
        assert.equal(executor.dedupCalls, 0);
        assert.deepEqual(store.workerUpdates, []);
        assert.deepEqual(store.finishCalls, []);
        assert.deepEqual(store.failureMessages, []);
        assert.equal(store.run.status, "running");
        assert.equal(
          claims,
          stage === "queued" || stage === "takeover" ? 2 : 1,
        );
        if (stage === "claim") {
          const fresh = new DeepScanCoordinatorRegistry();
          const resumed = fresh.start({
            ...fixture,
            run: store.run,
            store,
            executor: new FakeExecutor(),
            clock: immediateClock,
          });
          assert.equal((await resumed.settled()).status, "succeeded");
        }
        for (const outcome of outcomes) {
          assert.match(
            outcome instanceof Error
              ? outcome.message
              : JSON.stringify(outcome),
            /coordinator host has closed/,
          );
        }
      } finally {
        shutdown.release();
        await client.close();
        await Promise.allSettled([...handlers, ...requests]);
        const coordinator = registry.get(fixture.run.scanId);
        registry.shutdown("fixture cleanup");
        await Promise.allSettled([coordinator?.settled()]);
        await server.close();
        clock.mock.restore();
        Reflect.deleteProperty(globalThis, fixtureKey);
      }
    });
  }

  await test("shutdown preserves waiter detachment and cleanup joins", async () => {
    const fixture = await fixtureRun();
    const store = new FakeStore(fixture.run);
    const executor = new FakeExecutor({ blockDiscoveryAfterCalls: 0 });
    const registry = new DeepScanCoordinatorRegistry();
    const options = {
      ...fixture,
      store,
      executor,
      clock: immediateClock,
      threadId: "fixture-owner",
    };
    const coordinator = registry.start(options);
    try {
      await executor.discoveryStarted.promise;
      const request = new AbortController();
      const detached = coordinator.wait(request.signal);
      request.abort();
      await assert.rejects(detached, { name: "AbortError" });
      assert.equal(executor.runningDiscovery, 1);
      registry.shutdown("fixture transport closed");
      assert.equal(registry.start(options), coordinator);
      const joined = await startOrJoinDeepScanCoordinator({
        run: fixture.run,
        registry,
        options,
      });
      assert.equal(joined.coordinator, coordinator);
      assert.equal(joined.joined, true);
      assert.equal((await coordinator.settled()).status, "canceled");
      assert.equal(registry.get(fixture.run.scanId), undefined);
      assert.equal(executor.runningDiscovery, 0);
      assert.equal(store.run.status, "running");
      assert.throws(
        () => registry.start(options),
        /coordinator host has closed/,
      );
    } finally {
      registry.shutdown("fixture cleanup");
      await coordinator.settled();
    }
  });
} finally {
  Reflect.deleteProperty(globalThis, fixtureKey);
  await temporaryDirectories.cleanup();
}

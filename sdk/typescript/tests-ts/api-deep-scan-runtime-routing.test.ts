import { join } from "node:path";
import { afterEach, expect, test } from "bun:test";
import { createDeepApiFixtures } from "./support/deep-api.js";

const { fixture, cleanup } = createDeepApiFixtures();
afterEach(cleanup);

test.each([
  {
    name: "inherited Node override",
    dependencyNode: "configured runtime",
    runtimeNode: "configured runtime",
  },
  {
    name: "Node override supplied by the prepared runtime",
    dependencyNode: null,
    runtimeNode: "selected runtime",
  },
  {
    name: "prepared Node override replacing the dependency value",
    dependencyNode: "ambient runtime",
    runtimeNode: "selected runtime",
  },
  {
    name: "dependency Node override absent from the prepared runtime",
    dependencyNode: "unused runtime",
    runtimeNode: null,
  },
  {
    name: "no Node override",
    dependencyNode: null,
    runtimeNode: null,
  },
])("composed Deep Scan respects $name", async (scenario) => {
  const h = await fixture();
  if (scenario.dependencyNode !== null)
    h.environment["CODEX_MCP_NODE_PATH"] = join(
      h.root,
      scenario.dependencyNode,
      "node",
    );
  const runtimeEnvironment = { ...h.environment };
  const selectedNode =
    scenario.runtimeNode === null
      ? undefined
      : join(h.root, scenario.runtimeNode, "node");
  if (selectedNode === undefined)
    delete runtimeEnvironment["CODEX_MCP_NODE_PATH"];
  else runtimeEnvironment["CODEX_MCP_NODE_PATH"] = selectedNode;
  const originalRuntimeEnvironment = { ...runtimeEnvironment };
  h.setRuntimeEnvironment(runtimeEnvironment);
  await using client = h.makeClient({
    model: "gpt-6.1-sol",
    model_reasoning_effort: "high",
    features: { shell_tool: false },
  });
  await client.run(h.repository, {
    ...h.options,
    workers: 1,
    maxDiscoveryRuns: 2,
  });
  expect(h.launches.length).toBeGreaterThan(1);
  for (const launch of h.launches) {
    expect(launch.options.env?.["CODEX_MCP_NODE_PATH"]).toBe(selectedNode);
    expect(launch.options.config).toMatchObject({
      model: "gpt-6.1-sol",
      model_reasoning_effort: "high",
      features: { shell_tool: false },
    });
  }
  expect(runtimeEnvironment).toEqual(originalRuntimeEnvironment);
});

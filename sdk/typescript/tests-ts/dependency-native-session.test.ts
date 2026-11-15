import { expect, test } from "bun:test";
import { createDependencyNativeSession } from "../src/dependency-native-session.js";

function started(id: string, parentThreadId: string | null) {
  return {
    method: "thread/started",
    params: { thread: { id, parentThreadId } },
  };
}

function turn(
  method: "turn/started" | "turn/completed",
  threadId: string,
  id: string,
) {
  return { method, params: { threadId, turn: { id } } };
}

function activity(threadId: string, agentThreadId: string, kind: string) {
  return {
    method: "item/completed",
    params: {
      threadId,
      item: { type: "subAgentActivity", agentThreadId, kind },
    },
  };
}

test("routes root and nested investigator calls using native ancestry", () => {
  const session = createDependencyNativeSession();
  session.registerRoot("root");
  session.setTurn("root", "root-turn");
  session.observe(started("investigator", "root"));
  session.observe(started("nested", "investigator"));
  session.observe(turn("turn/started", "investigator", "child-turn"));
  session.observe(turn("turn/started", "nested", "nested-turn"));

  expect(session.isCurrentTurn({ threadId: "root", turnId: "root-turn" })).toBe(
    true,
  );
  expect(
    session.isCurrentTurn({ threadId: "investigator", turnId: "child-turn" }),
  ).toBe(true);
  expect(
    session.isCurrentTurn({ threadId: "nested", turnId: "nested-turn" }),
  ).toBe(true);
  expect(session.isRoot("root")).toBe(true);
  expect(session.isRoot("investigator")).toBe(false);
});

test("keeps child notifications received before the root start response", () => {
  const session = createDependencyNativeSession();
  session.observe(started("nested", "investigator"));
  session.observe(turn("turn/started", "nested", "nested-turn"));
  session.observe(started("investigator", "root"));
  expect(session.ownsThread("nested")).toBe(false);
  session.registerRoot("root");
  expect(
    session.isCurrentTurn({ threadId: "nested", turnId: "nested-turn" }),
  ).toBe(true);
});

test("rejects unrelated threads and model arguments claiming a parent", () => {
  const session = createDependencyNativeSession();
  session.registerRoot("root");
  session.observe(started("other-root", null));
  session.observe(started("other-child", "other-root"));
  session.observe(turn("turn/started", "other-child", "other-turn"));
  expect(
    session.isCurrentTurn({
      threadId: "other-child",
      turnId: "other-turn",
      arguments: { parentThreadId: "root" },
    }),
  ).toBe(false);
  expect(session.ownsThread("unknown")).toBe(false);
  expect(session.isRoot(undefined)).toBe(false);
});

test("rejects completed and stale turns without clearing a newer turn", () => {
  const session = createDependencyNativeSession();
  session.registerRoot("root");
  session.observe(started("investigator", "root"));
  session.observe(turn("turn/started", "investigator", "first"));
  session.observe(turn("turn/started", "investigator", "second"));
  session.observe(turn("turn/completed", "investigator", "first"));
  expect(
    session.isCurrentTurn({ threadId: "investigator", turnId: "first" }),
  ).toBe(false);
  expect(
    session.isCurrentTurn({ threadId: "investigator", turnId: "second" }),
  ).toBe(true);
  session.observe(turn("turn/completed", "investigator", "second"));
  expect(
    session.isCurrentTurn({ threadId: "investigator", turnId: "second" }),
  ).toBe(false);
});

test("blocks finalization while an owned investigator has an active turn", () => {
  const session = createDependencyNativeSession();
  session.registerRoot("root");
  session.setTurn("root", "root-turn");
  session.observe(started("unrelated", null));
  session.observe(turn("turn/started", "unrelated", "unrelated-turn"));
  expect(session.hasActiveInvestigators()).toBe(false);

  session.observe(started("investigator", "root"));
  session.observe(started("nested", "investigator"));
  session.observe(turn("turn/started", "investigator", "first"));
  expect(session.hasActiveInvestigators()).toBe(true);
  session.observe(turn("turn/started", "investigator", "second"));
  session.observe(turn("turn/completed", "investigator", "first"));
  expect(session.hasActiveInvestigators()).toBe(true);

  session.observe(turn("turn/started", "nested", "nested-turn"));
  session.observe(turn("turn/completed", "investigator", "second"));
  expect(session.hasActiveInvestigators()).toBe(true);
  session.observe(turn("turn/completed", "nested", "nested-turn"));
  expect(session.hasActiveInvestigators()).toBe(false);
});

test("routes activity-only investigators and binds the first native tool call turn", () => {
  const session = createDependencyNativeSession();
  session.registerRoot("root");
  session.setTurn("root", "root-turn");
  session.observe(activity("root", "investigator", "started"));
  expect(session.knowsThread("investigator")).toBe(true);
  expect(session.ownsThread("investigator")).toBe(true);
  expect(session.hasActiveInvestigators()).toBe(true);
  const call = { threadId: "investigator", turnId: "child-turn" };
  session.observe({ method: "item/tool/call", params: call });
  expect(session.isCurrentTurn(call)).toBe(true);
  expect(session.isCurrentTurn({ ...call, turnId: "stale" })).toBe(false);
  session.observe(activity("root", "investigator", "completed"));
  expect(session.isCurrentTurn(call)).toBe(false);
  expect(session.hasActiveInvestigators()).toBe(false);
});

test("messages preserve an active investigator's turn and keep an idle investigator inactive", () => {
  const session = createDependencyNativeSession();
  session.registerRoot("root");
  session.observe(activity("root", "first", "started"));
  session.observe(activity("first", "nested", "started"));
  session.observe({
    method: "item/tool/call",
    params: { threadId: "nested", turnId: "nested-turn" },
  });
  session.observe(activity("root", "nested", "interacted"));
  expect(
    session.isCurrentTurn({ threadId: "nested", turnId: "nested-turn" }),
  ).toBe(true);
  expect(session.isCurrentTurn({ threadId: "nested", turnId: "other" })).toBe(
    false,
  );
  session.observe(activity("nested", "first", "interacted"));
  expect(session.ownsThread("first")).toBe(true);
  expect(session.ownsThread("nested")).toBe(true);
  session.observe(activity("root", "first", "completed"));
  session.observe(activity("first", "nested", "completed"));
  session.observe(activity("root", "nested", "interacted"));
  expect(session.isCurrentTurn({ threadId: "nested", turnId: "next" })).toBe(
    false,
  );
  expect(session.hasActiveInvestigators()).toBe(false);
});

test("retains unrelated native edges without owning or adopting a foreign thread", () => {
  const session = createDependencyNativeSession();
  session.registerRoot("root");
  session.observe(started("foreign", null));
  session.observe(activity("foreign", "unknown", "started"));
  expect(session.knowsThread("unknown")).toBe(true);
  expect(session.ownsThread("unknown")).toBe(false);
  expect(
    session.isCurrentTurn({ threadId: "unknown", turnId: "foreign-turn" }),
  ).toBe(false);
  session.observe(activity("root", "foreign", "started"));
  session.observe(activity("root", "unknown", "interacted"));
  expect(session.ownsThread("foreign")).toBe(false);
  expect(session.ownsThread("unknown")).toBe(false);
  expect(session.hasActiveInvestigators()).toBe(false);
});

test("retains native descendant activity before its parent ancestry is known", () => {
  const session = createDependencyNativeSession();
  session.observe(activity("child", "grandchild", "started"));
  expect(session.knowsThread("grandchild")).toBe(true);
  expect(session.ownsThread("grandchild")).toBe(false);
  expect(session.hasActiveInvestigators()).toBe(false);
  session.observe(activity("root", "child", "started"));
  session.registerRoot("root");
  expect(session.investigatorIds().sort()).toEqual(["child", "grandchild"]);
  expect(
    session.isCurrentTurn({ threadId: "grandchild", turnId: "native-turn" }),
  ).toBe(true);
  session.observe(activity("root", "child", "completed"));
  expect(session.hasActiveInvestigators()).toBe(true);
  session.observe(activity("child", "grandchild", "completed"));
  expect(session.hasActiveInvestigators()).toBe(false);
});

test("retains an early descendant completion without inventing later activity", () => {
  const session = createDependencyNativeSession();
  session.registerRoot("root");
  session.observe(activity("child", "grandchild", "started"));
  session.observe(activity("child", "grandchild", "completed"));
  session.observe(activity("root", "child", "started"));
  session.observe(activity("root", "child", "completed"));
  expect(session.investigatorIds().sort()).toEqual(["child", "grandchild"]);
  expect(session.hasActiveInvestigators()).toBe(false);
});

test("uses native thread metadata status for an investigator discovered through thread read", () => {
  const session = createDependencyNativeSession();
  session.registerRoot("root");
  session.registerThread({
    id: "child",
    parentThreadId: "root",
    status: { type: "active" },
  });
  expect(session.hasActiveInvestigators()).toBe(true);
  session.setTurn("child", "tool-turn");
  expect(
    session.isCurrentTurn({ threadId: "child", turnId: "tool-turn" }),
  ).toBe(true);
  session.registerThread({
    id: "child",
    parentThreadId: "root",
    status: { type: "idle" },
  });
  expect(session.hasActiveInvestigators()).toBe(false);
});

for (const status of ["idle", "notLoaded", "systemError"]) {
  test(`native ${status} status clears a child turn without removing its identity`, () => {
    const session = createDependencyNativeSession();
    session.registerRoot("root");
    session.observe(activity("root", "child", "started"));
    session.observe({
      method: "thread/status/changed",
      params: { threadId: "child", status: { type: status } },
    });
    expect(session.hasActiveInvestigators()).toBe(false);
    expect(session.investigatorIds()).toEqual(["child"]);
    session.observe(started("foreign", null));
    expect(session.investigatorIds()).toEqual(["child"]);
  });
}

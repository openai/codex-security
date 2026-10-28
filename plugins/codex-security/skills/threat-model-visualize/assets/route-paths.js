/* Explicit assessment routes; never infer reachability from graph proximity. */
(function (root) {
  'use strict';
  function resolve(model, scenario, routeId, stop = -1, arrival = false) {
    const edges = new Map(model.edges.map(e => [e.id, e]));
    const route = scenario?.routes?.find(r => r.id === routeId) || scenario?.routes?.[0];
    const activeEdges = new Set(), activeNodes = new Set();
    const unreachedEdges = new Set(), unreachedNodes = new Set(), branchStates = [];
    const focusNodes = new Set(scenario?.focusNodes || []);
    if (!route) return null;
    const stopEdge = stop >= 0 ? scenario.steps[stop]?.edge : null;
    const stopIndex = stopEdge ? route.edges.indexOf(stopEdge) : -1;
    function add(ids, reachable) {
      for (const id of ids) {
        const edge = edges.get(id);
        if (reachable) {
          activeEdges.add(id); activeNodes.add(edge.from);
          if (id !== stopEdge || arrival) activeNodes.add(edge.to);
          else unreachedNodes.add(edge.to);
        } else {
          unreachedEdges.add(id);
          unreachedNodes.add(edge.from); unreachedNodes.add(edge.to);
        }
      }
    }
    add(stopIndex < 0 ? route.edges : route.edges.slice(0, stopIndex + 1), true);
    if (stopIndex >= 0) add(route.edges.slice(stopIndex + 1), false);
    // A decision may call a dependency before rejecting the selected operation.
    // Keep that explicitly authored prerequisite without activating other work
    // from the blocked destination merely because the decision point is visible.
    const reachable = new Set(activeNodes), prerequisiteNodes = new Set();
    const owner = stopIndex < 0 ? null : edges.get(stopEdge).to;
    // Receipt makes the owner visible, but must not activate arbitrary work
    // from that owner after its decision. Earlier occurrences remain reachable.
    if (arrival && stopIndex >= 0) {
      const before = route.edges.slice(0, stopIndex).some(id =>
        edges.get(id).from === owner || edges.get(id).to === owner);
      if (!before) reachable.delete(owner);
    }
    // Keep occurrence state separate: another branch may use the same edge.
    for (const branch of route.branches || []) branchStates.push({branch, active:false, reached:0});
    // A later-listed branch may reach an earlier branch's origin. Revisit active
    // branches when an independent path reaches a prerequisite node. Each pass
    // only adds reachability, so even cyclic paths converge.
    let changed = true;
    while (changed) {
      changed = false;
      for (const state of branchStates) {
        const {branch} = state;
        const start = edges.get(branch.edges[0]).from;
        const prerequisite = stopIndex >= 0 && branch.beforeStep === stop + 1 &&
          start === owner;
        // An annotated branch belongs to a particular decision occurrence, not
        // an earlier visit to the same node on a looping or response route.
        const active = branch.beforeStep !== undefined ?
          (stopIndex < 0 || branch.beforeStep <= stop + 1) && (!prerequisite || arrival) :
          (reachable.has(start) || prerequisiteNodes.has(start)) &&
            (branch.afterStep === undefined || stopIndex < 0 || branch.afterStep < stop + 1);
        if (!active) continue;
        // A dependency's reply remains visible without enabling the denied
        // owner's other work. Independent earlier paths may still reach it.
        let dependency = prerequisite || (branch.beforeStep === undefined && !reachable.has(start));
        let reached = 0;
        for (const id of branch.edges) {
          const edge = edges.get(id);
          // Only an explicit beforeStep chain may continue predecision work
          // after returning to the owner. Otherwise stop at its denied arrival.
          if (branch.beforeStep === undefined) {
            if (edge.from === owner && !reachable.has(owner)) break;
            if (reachable.has(edge.from)) dependency = false;
          }
          const nodes = dependency ? prerequisiteNodes : reachable;
          for (const node of [edge.from, edge.to]) {
            if (!(dependency && node === owner) && !nodes.has(node)) {
              nodes.add(node); changed = true;
            }
          }
          reached += 1;
        }
        if (reached > state.reached) { state.reached = reached; changed = true; }
        state.active = state.reached === branch.edges.length;
      }
    }
    for (const {branch, reached} of branchStates) {
      add(branch.edges.slice(0, reached), true);
      add(branch.edges.slice(reached), false);
    }
    for (const id of activeNodes) unreachedNodes.delete(id);
    for (const id of activeEdges) unreachedEdges.delete(id);
    return {route, activeEdges, activeNodes, unreachedEdges, unreachedNodes, focusNodes, branchStates};
  }
  const api = {resolve};
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
  root.RoutePaths = api;
})(globalThis);

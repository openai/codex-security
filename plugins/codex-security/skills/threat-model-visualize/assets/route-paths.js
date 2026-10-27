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
    const reachable = new Set(activeNodes);
    // Receipt makes the owner visible, but must not activate arbitrary work
    // from that owner after its decision. Earlier occurrences remain reachable.
    if (arrival && stopIndex >= 0) {
      const owner = edges.get(stopEdge).to;
      const before = route.edges.slice(0, stopIndex).some(id =>
        edges.get(id).from === owner || edges.get(id).to === owner);
      if (!before) reachable.delete(owner);
    }
    for (const branch of route.branches || []) {
      const start = edges.get(branch.edges[0]).from;
      const decisionEdge = branch.beforeStep === undefined ? null : scenario.steps[branch.beforeStep - 1]?.edge;
      const decisionIndex = decisionEdge ? route.edges.indexOf(decisionEdge) : -1;
      const prerequisite = stopIndex >= 0 && branch.beforeStep === stop + 1 &&
        start === edges.get(stopEdge).to;
      // An annotated branch belongs to a particular decision occurrence, not
      // an earlier visit to the same node on a looping or response route.
      const actionEdge = branch.afterStep === undefined ? null : scenario.steps[branch.afterStep - 1]?.edge;
      const actionIndex = actionEdge ? route.edges.indexOf(actionEdge) : -1;
      const active = branch.beforeStep !== undefined ?
        decisionIndex >= 0 && (stopIndex < 0 || decisionIndex <= stopIndex) &&
          (!prerequisite || arrival) :
        branch.afterStep !== undefined ? reachable.has(start) && actionIndex >= 0 &&
          (stopIndex < 0 || actionIndex < stopIndex) : reachable.has(start);
      // Keep occurrence state separate: another branch may use the same edge.
      branchStates.push({branch, active});
      add(branch.edges, active);
      if (active) {
        for (const id of branch.edges) {
          const edge = edges.get(id);
          if (!(prerequisite && edge.from === start)) reachable.add(edge.from);
          if (!(prerequisite && edge.to === start)) reachable.add(edge.to);
        }
      }
    }
    for (const id of activeNodes) unreachedNodes.delete(id);
    for (const id of activeEdges) unreachedEdges.delete(id);
    return {route, activeEdges, activeNodes, unreachedEdges, unreachedNodes, focusNodes, branchStates};
  }
  const api = {resolve};
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
  root.RoutePaths = api;
})(globalThis);

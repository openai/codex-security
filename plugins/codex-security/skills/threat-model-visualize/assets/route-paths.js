/* Explicit assessment routes; never infer reachability from graph proximity. */
(function (root) {
  'use strict';
  function resolve(model, scenario, routeId, stop = -1, arrival = false) {
    const route = scenario?.routes?.find(r => r.id === routeId) || scenario?.routes?.[0];
    if (!route) return null;
    const edges = new Map(model.edges.map(e => [e.id, e]));
    const stopEdge = stop >= 0 ? scenario.steps[stop]?.edge : null;
    const stopIndex = stopEdge ? route.edges.indexOf(stopEdge) : -1;
    const owner = stopIndex < 0 ? null : edges.get(stopEdge).to;
    const activeEdges = new Set(), activeNodes = new Set();
    const prefix = stopIndex < 0 ? route.edges : route.edges.slice(0, stopIndex + 1);
    for (const id of prefix) {
      const {from, to} = edges.get(id);
      activeEdges.add(id);
      activeNodes.add(from);
      if (id !== stopEdge || arrival) activeNodes.add(to);
    }
    // Arrival displays the owner. Only a prior visit lets it start unrelated work.
    const independent = new Set(activeNodes);
    if (arrival && stopIndex >= 0) {
      const earlierVisit = prefix.slice(0, -1).some(id => edges.get(id).from === owner || edges.get(id).to === owner);
      if (!earlierVisit) independent.delete(owner);
    }

    const branchStates = (route.branches || []).map(branch => ({branch, active:false, reached:0}));
    // A later branch can reach an earlier branch's origin, or make a visible
    // prerequisite independently reachable. Both node sets grow monotonically.
    let nodeCount;
    do {
      nodeCount = activeNodes.size + independent.size;
      for (const state of branchStates) {
        const {branch} = state;
        const start = edges.get(branch.edges[0]).from;
        const prerequisite = stopIndex >= 0 && branch.beforeStep === stop + 1 && start === owner;
        if (branch.beforeStep !== undefined) {
          if (stopIndex >= 0 && (branch.beforeStep > stop + 1 || (prerequisite && !arrival))) continue;
        } else if (!activeNodes.has(start) ||
          (branch.afterStep !== undefined && stopIndex >= 0 && branch.afterStep >= stop + 1)) continue;

        // A prerequisite keeps its dependency even when its reply crosses a
        // previously visited relay. Reconsider it if its origin later becomes independent.
        const dependent = prerequisite || (branch.beforeStep === undefined && !independent.has(start));
        let reached = 0;
        for (const id of branch.edges) {
          const {from, to} = edges.get(id);
          if (branch.beforeStep === undefined && from === owner && !independent.has(owner)) break;
          activeEdges.add(id);
          activeNodes.add(from); activeNodes.add(to);
          if (!dependent) { independent.add(from); independent.add(to); }
          reached++;
        }
        state.reached = reached;
        state.active = reached === branch.edges.length;
      }
    } while (activeNodes.size + independent.size !== nodeCount);

    const unreachedEdges = new Set(), unreachedNodes = new Set();
    for (const id of [...route.edges, ...branchStates.flatMap(({branch}) => branch.edges)]) {
      const {from, to} = edges.get(id);
      if (!activeEdges.has(id)) unreachedEdges.add(id);
      if (!activeNodes.has(from)) unreachedNodes.add(from);
      if (!activeNodes.has(to)) unreachedNodes.add(to);
    }
    const focusNodes = new Set(scenario.focusNodes || []);
    return {route, activeEdges, activeNodes, unreachedEdges, unreachedNodes, focusNodes, branchStates};
  }
  const api = {resolve};
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
  root.RoutePaths = api;
})(globalThis);

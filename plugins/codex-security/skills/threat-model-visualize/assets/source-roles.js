/* Scenario origins describe starting authority, never inferred compromise. */
(function (root) {
  'use strict';
  const palette = {
    adversary: {fill:'#fbe1e1', ink:'#912d35', colorName:'red', label:'Adversary', badge:'ADVERSARY'},
    'compromised-component': {fill:'#f1d9e7', ink:'#852653', colorName:'berry', label:'Compromised component', badge:'COMPROMISED'},
    'untrusted-input': {fill:'#fde9df', ink:'#944324', colorName:'peach', label:'Untrusted input', badge:'UNTRUSTED INPUT'},
    unknown: {fill:'#e9e9ed', ink:'#555568', colorName:'grey', label:'Source uncertain', badge:'SOURCE UNCERTAIN'},
    'authorized-user': {fill:'#e0edf9', ink:'#285b88', colorName:'blue', label:'Authorized use', badge:'AUTHORIZED USE'}
  };
  const basis = {
    'scenario-assumption':'Assumed starting condition',
    'assessment-observed':'Observed in supplied assessment',
    unknown:'Starting condition uncertain'
  };
  function resolve(model, scenario, routeId, sourceId) {
    const route = scenario?.routes?.find(r => r.id === routeId) || scenario?.routes?.[0];
    const allSources = (scenario?.sources || []).filter(s => !s.routeIds || s.routeIds.includes(route?.id));
    const selected = scenario?.sourceMode === 'alternatives' ? allSources.find(s => s.id === sourceId) || allSources[0] : null;
    const sources = selected ? [selected] : allSources;
    const nodes = new Map();
    for (const p of model.participants || []) {
      if (!nodes.has(p.node))
        nodes.set(p.node, {...palette[p.kind], kind:p.kind, items:[], source:false});
      nodes.get(p.node).items.push(p);
    }
    const mapped = new Map();
    for (const s of sources) {
      if (s.node === null) continue;
      if (!mapped.has(s.node)) mapped.set(s.node, []);
      mapped.get(s.node).push(s);
    }
    for (const [id, items] of mapped) {
      const kinds = new Set(items.map(s => s.kind)), kind = kinds.size === 1 ? items[0].kind : 'unknown';
      nodes.set(id, {...palette[kind], ...(kinds.size > 1 ? {label:'Multiple source roles',badge:'MULTIPLE ROLES'} : {}), kind, items, source:true});
    }
    // Explicit source sets describe relationships only; never derive reach from roles.
    const relatedNodes = selected?.relatedNodes ?? scenario?.affectedNodes ?? [];
    const relatedEdges = selected?.relatedEdges ?? scenario?.affectedEdges ?? [];
    const jointRequirement = scenario?.sourceMode === 'combined' && sources.length > 1
      ? 'All listed starting positions are required together.' : '';
    return {sources, allSources, selected, nodes, relatedNodes, relatedEdges, jointRequirement};
  }
  const api = {resolve, palette, basis};
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
  root.SourceRoles = api;
})(globalThis);

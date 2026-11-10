// Pure path semantics shared by the portable renderer and its regression checks.
const ControlEffects = (() => {
  function applicable(scenario, context = {}) {
    return (scenario?.controls || []).filter(c =>
      (!c.sourceIds || c.sourceIds.includes(context.sourceId)) &&
      (!c.routeIds || c.routeIds.includes(context.routeId)));
  }

  function selection(scenario, state, context = {}) {
    const controls = applicable(scenario, context);
    return {
      control: controls.some(c => c.id === state.control) ? state.control : null,
      proposal: controls.some(c => c.id === state.proposal && c.kind === 'proposed') ? state.proposal : null
    };
  }

  function active(scenario, proposal, context = {}) {
    return applicable(scenario, context).filter(c => c.effect &&
      (c.kind === 'existing' || c.id === proposal));
  }

  function resolve(scenario, proposal, context = {}) {
    const controls = active(scenario, proposal, context);
    // Compare step, then receipt: a prearrival block prevents an arrival check.
    // Existing controls win only when both barriers act at the same point.
    const blocker = controls.filter(c => c.effect.outcome === 'blocks' &&
      c.effect.traffic !== 'continues' && c.effect.basis !== 'unverified' && Number.isInteger(c.effect.step))
      .sort((a, b) => a.effect.step - b.effect.step ||
        Number(a.effect.arrival === true) - Number(b.effect.arrival === true) ||
        Number(a.kind === 'proposed') - Number(b.kind === 'proposed'))[0] || null;
    return { controls, blocker, stop: blocker ? blocker.effect.step - 1 : -1 };
  }

  function caption(control) {
    const e = control?.effect;
    if (!e) return 'Effect not mapped';
    if (e.outcome === 'blocks') {
      const basis = control.kind === 'proposed' ? 'Would block' :
        e.basis === 'verified' ? 'Blocks · verified in supplied evidence' : 'Blocks · if enforced';
      return basis + (e.traffic === 'continues' ? ' · this effect leaves traffic open' :
        e.arrival === true ? ' · decision after arrival' : '');
    }
    return {
      limits: control.kind === 'proposed' ? 'Would limit impact · path continues' : 'Limits impact · path continues',
      detects: control.kind === 'proposed' ? 'Would detect activity · path continues' : 'Detects activity · path continues',
      'does-not-block': control.kind === 'proposed' ? 'Would not block this path' : 'Does not block this path',
      unknown: 'Effect not established'
    }[e.outcome];
  }

  function basis(control) {
    if (control.kind === 'proposed') return 'Proposed control';
    return {
      declared: 'DECLARED · IF ENFORCED',
      verified: 'VERIFIED · SUPPLIED EVIDENCE',
      unverified: 'EXISTING · EFFECT UNVERIFIED'
    }[control.effect?.basis] || 'EXISTING · SOURCE-QUALIFIED';
  }

  // Split an authored polyline at a fraction of its length. The stop marker is
  // perpendicular to the actual route, including routes with several corners.
  function split(points, fraction) {
    const lengths = points.slice(1).map((p, i) =>
      Math.hypot(p[0] - points[i][0], p[1] - points[i][1]));
    const total = lengths.reduce((sum, n) => sum + n, 0);
    if (!total) throw new Error('A control needs a nonzero route.');
    const target = Math.min(1, Math.max(0, fraction)) * total;
    let distance = 0;
    for (let i = 0; i < lengths.length; i++) {
      const length = lengths[i];
      if (!length) continue;
      if (distance + length >= target || i === lengths.length - 1) {
        const t = (target - distance) / length, a = points[i], b = points[i + 1];
        const point = [a[0] + t * (b[0] - a[0]), a[1] + t * (b[1] - a[1])];
        return {
          before: [...points.slice(0, i + 1), point],
          after: [point, ...points.slice(i + 1)],
          point, normal: [-(b[1] - a[1]) / length, (b[0] - a[0]) / length]
        };
      }
      distance += length;
    }
  }
  return { applicable, selection, active, resolve, caption, basis, split };
})();

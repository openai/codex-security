// Synthetic assessment shared by the browser smoke test and manual browser QA.
export function fixture() {
  const quote = 'The gateway can send requests to either service. Its audit hook has not been validated.';
  const model = {
    brand: 'Synthetic browser fixture', title: 'Request map', subtitle: 'Export smoke test',
    snapshotLabel: 'Synthetic', mapTitle: 'Request flow', mapDescription: 'Two documented routes',
    overviewTitle: 'Architecture', overview: 'A caller uses a gateway to reach a service.',
    evidenceBoundary: 'Synthetic assessment; no runtime validation.', footer: 'Synthetic fixture',
    canvas: {width: 900, height: 480},
    nodes: [
      {id: 'caller', title: 'Caller', x: 30, y: 180, w: 150, h: 70},
      {id: 'gateway', title: 'Gateway', x: 330, y: 180, w: 150, h: 70},
      {id: 'primary', title: 'Primary service', x: 650, y: 60, w: 180, h: 70},
      {id: 'alternate', title: 'Alternate service', x: 650, y: 320, w: 180, h: 70},
    ],
    edges: [
      {id: 'request', from: 'caller', to: 'gateway', points: [[180, 215], [330, 215]], label: 'Request', labelX: 255, labelY: 200},
      {id: 'primary-flow', from: 'gateway', to: 'primary', points: [[480, 200], [560, 200], [560, 95], [650, 95]], label: 'Primary', labelX: 565, labelY: 75},
      {id: 'alternate-flow', from: 'gateway', to: 'alternate', points: [[480, 230], [560, 230], [560, 355], [650, 355]], label: 'Alternate', labelX: 565, labelY: 380},
    ],
    evidence: [{id: 'assessment', label: 'Synthetic assessment', quote}],
    scenarios: [{
      id: 'H1', title: 'Request routing', status: 'Hypothesis', summary: 'A request reaches a selected service.',
      focusNodes: [], evidence: ['assessment'],
      steps: [{title: 'Submit request', from: 'caller', to: 'gateway', edge: 'request'}],
      routes: [
        {id: 'primary-route', label: 'Primary service flow', edges: ['request', 'primary-flow'], evidence: ['assessment']},
        {id: 'alternate-route', label: 'Alternate service flow', edges: ['request', 'alternate-flow'], evidence: ['assessment']},
      ],
      controls: [{
        id: 'audit', kind: 'existing', title: 'Audit hook', description: 'The assessment describes a detection hook.',
        nodes: ['gateway'], routeIds: ['alternate-route'], evidence: ['assessment'],
        // No map marker: the export footer must carry the evidence qualification itself.
        effect: {outcome: 'detects', basis: 'unverified', step: 1, edge: 'request', label: 'Audit hook',
          reason: 'Activity may generate an audit event.', conditions: 'The hook is enabled.', residual: 'Requests continue.'},
      }],
    }],
  };
  return {model, assessment: `# Synthetic assessment\n\n${quote}\n`};
}

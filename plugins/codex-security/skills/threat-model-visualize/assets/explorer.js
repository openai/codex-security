'use strict';
// Bounded SVG presentation geometry only: authored topology and model data stay unchanged.
const SvgLayout = (() => {
  const intersects = (a,b) => a.x < b.x+b.w && b.x < a.x+a.w && a.y < b.y+b.h && b.y < a.y+a.h;
  const padded = (r,p=4) => ({x:r.x-p,y:r.y-p,w:r.w+2*p,h:r.h+2*p});
  const distance = (a,b) => Math.hypot(a[0]-b[0],a[1]-b[1]);
  const clean = points => points.filter((p,i)=>!i || distance(p,points[i-1])>1e-6);
  function fallback(text,size) { return {w:[...text].reduce((n,c)=>n+(/[MW@%]/.test(c)?.9:/[il.,:;' ]/.test(c)?.32:.62)*size,0),ascent:size*.8,descent:size*.2}; }
  function lines(text,width,size,weight,measure) {
    const result=[];let line='';
    for(const word of String(text).trim().split(/\s+/)) {
      if(!word)continue;
      if(line && measure(line+' '+word,size,weight).w>width){result.push(line);line='';}
      if(measure(word,size,weight).w>width){
        for(const char of word){if(line && measure(line+char,size,weight).w>width){result.push(line);line='';}line+=char;}
      } else line+=(line?' ':'')+word;
    }
    if(line)result.push(line);return result;
  }
  function sample(points,offset) {
    const p=clean(points),lengths=p.slice(1).map((b,i)=>distance(p[i],b)),total=lengths.reduce((a,b)=>a+b,0);let target=Math.max(0,Math.min(total,offset));
    for(let i=0;i<lengths.length;i++) {
      if(target<=lengths[i] || i===lengths.length-1){const t=target/lengths[i];return [p[i][0]+(p[i+1][0]-p[i][0])*t,p[i][1]+(p[i+1][1]-p[i][1])*t];}target-=lengths[i];
    }
    return p[0];
  }
  function nearestOffset(points,anchor) {
    let best=Infinity,offset=0,answer=0;
    for(let i=1;i<points.length;i++){
      const a=points[i-1],b=points[i],length=distance(a,b);if(!length)continue;
      const t=Math.max(0,Math.min(1,((anchor[0]-a[0])*(b[0]-a[0])+(anchor[1]-a[1])*(b[1]-a[1]))/(length*length)));
      const d=distance(anchor,[a[0]+t*(b[0]-a[0]),a[1]+t*(b[1]-a[1])]);if(d<best){best=d;answer=offset+t*length;}offset+=length;
    }return answer;
  }
  function joints(edges) {
    const points=new Map(),segments=[];
    const add=p=>points.set(p.map(n=>n.toFixed(2)).join(','),{x:p[0]-6,y:p[1]-6,w:12,h:12});
    for(const e of edges){const p=clean(e.points);p.forEach(add);p.slice(1).forEach((b,i)=>segments.push([p[i],b,e.id]));}
    for(let i=0;i<segments.length;i++)for(let j=i+1;j<segments.length;j++){
      const [a,b,id]=segments[i],[c,d,other]=segments[j];if(id===other)continue;
      const rx=b[0]-a[0],ry=b[1]-a[1],sx=d[0]-c[0],sy=d[1]-c[1],cross=rx*sy-ry*sx;if(Math.abs(cross)<1e-8)continue;
      const t=((c[0]-a[0])*sy-(c[1]-a[1])*sx)/cross,u=((c[0]-a[0])*ry-(c[1]-a[1])*rx)/cross;
      if(t>=0 && t<=1 && u>=0 && u<=1)add([a[0]+t*rx,a[1]+t*ry]);
    }return [...points.values()];
  }
  function segmentIntersectsRect(a,b,box) {
    let low=0,high=1;
    for(const [axis,min,max] of [[0,box.x,box.x+box.w],[1,box.y,box.y+box.h]]){
      const delta=b[axis]-a[axis];
      if(Math.abs(delta)<1e-9){if(a[axis]<min || a[axis]>max)return false;continue;}
      const p=(min-a[axis])/delta,q=(max-a[axis])/delta;
      low=Math.max(low,Math.min(p,q));high=Math.min(high,Math.max(p,q));if(low>high)return false;
    }return true;
  }
  function candidates(item,w,h,dense=false) {
    const [ax,ay]=item.anchor,result=[];
    const add=(cx,cy)=>result.push({x:cx-w/2,y:cy-h/2,w,h});
    if(dense){
      if(item.kind==='region'){
        const r=item.region,left=Math.min(r.x+8+w/2,r.x+r.w/2),right=Math.max(r.x+r.w-8-w/2,r.x+r.w/2);
        for(let cx=left;cx<=right+1e-6;cx+=Math.max(4,(right-left)/64))for(let dy=-64;dy<=64;dy+=4){add(cx,r.y+dy);add(cx,r.y+r.h+dy);}
        for(let dy=-64;dy<=r.h+64;dy+=Math.max(4,(r.h+128)/64)){add(r.x+4-w/2,r.y+dy);add(r.x+r.w-4+w/2,r.y+dy);}
      }else for(let dx=-176;dx<=176;dx+=8)for(let dy=-176;dy<=176;dy+=8)add(ax+dx,ay+dy);
      return result;
    }
    if(item.kind==='region'){
      const r=item.region,left=Math.min(r.x+8+w/2,r.x+r.w/2),right=Math.max(r.x+r.w-8-w/2,r.x+r.w/2);
      for(const dy of Array.from({length:23},(_,i)=>i*4-64))for(const dx of [0,12,-12,24,-24,48,-48,72,-72,96,-96,144,-144]) {
        const cx=Math.max(left,Math.min(right,ax+dx)),cy=ay+dy;add(cx,cy);
      }
      for(const cx of [left,(left+right)/2,right]){
        add(cx,r.y-h/2-4);add(cx,r.y+4+h/2);
        for(let dy=-24;dy<=64;dy+=4)add(cx,r.y+r.h+dy);
      }
      // A tight header strip can have no legal top slot. Keep its title attached
      // to the same boundary, with a short annotation leader, rather than cover a node.
      for(let dy=-64;dy<=r.h+64;dy+=16){
        add(r.x+4-w/2,r.y+dy);add(r.x+r.w-4+w/2,r.y+dy);
      }
    }else {
      for(const radius of [0,12,24,40,60,84,112,144])for(const [dx,dy] of [[0,-1],[0,1],[-1,0],[1,0],[-1,-1],[1,-1],[-1,1],[1,1]])add(ax+dx*radius,ay+dy*radius);
      for(const dx of [-96,-72,-48,-32,-16,0,16,32,48,72,96])for(const dy of [-96,-72,-48,-32,-16,-8,0,8,16,32,48,72,96])add(ax+dx,ay+dy);
      if(item.edge){const offset=nearestOffset(item.edge.points,item.anchor);
        for(const along of [0,-24,24,-48,48,-80,80,-120,120]){const point=sample(item.edge.points,offset+along);for(const dy of [-16,16,-28,28,-44,44])add(point[0],point[1]+dy);}
      }
    }return result;
  }
  function plan(items,nodes,edges,canvas,measure=fallback) {
    const obstacles=nodes.map(n=>padded(n,2)),placed=new Map();
    const activeEdges=edges.filter(e=>e.layoutActive!==false).map(e=>({...e,points:e.layoutActivePoints||e.points}));
    const allJoints=joints(edges),activeJoints=joints(activeEdges);
    const segmentsFor=list=>list.flatMap(e=>{const points=clean(e.points);return points.slice(1).map((b,i)=>({id:e.id,a:points[i],b,box:padded({x:Math.min(points[i][0],b[0]),y:Math.min(points[i][1],b[1]),w:Math.abs(b[0]-points[i][0]),h:Math.abs(b[1]-points[i][1])},2.5)}));});
    const segments=segmentsFor(edges),activeSegments=segmentsFor(activeEdges);
    for(const item of [...items].sort((a,b)=>a.priority-b.priority || (a.id<b.id?-1:a.id>b.id?1:0))){
      let best=null;
      // Refine only an unresolved caption: ordinary views keep the cheap pass.
      for(const dense of [false,true,...(item.kind==='edge'?['fine','wrap']:[])]){
      if(dense && best?.conflicts===0)break;
      const refinementOrigin=best?[best.x+best.w/2,best.y+best.h/2]:item.anchor;
      // Whole-word wrapping is a last resort for a short caption whose
      // measured one-line width exceeds a legal local gap by even a fraction.
      const widths=dense==='wrap'?[Math.max(...String(item.text).trim().split(/\s+/).map(word=>measure(word,item.size,item.weight).w))]:item.widths;
      for(const maxWidth of widths){
        if(dense && best?.conflicts===0)break;
        const content=lines(item.text,maxWidth,item.size,item.weight,measure),metrics=content.map(t=>measure(t,item.size,item.weight));if(!content.length)continue;
        const ascent=Math.max(...metrics.map(m=>m.ascent)),descent=Math.max(...metrics.map(m=>m.descent)),lineHeight=Math.max(item.size*1.2,ascent+descent+2);
        const w=item.kind==='control'?maxWidth+24:Math.max(...metrics.map(m=>m.w))+8;
        const h=item.kind==='control'?Math.max(56,40+(content.length-1)*lineHeight+descent+8):ascent+descent+(content.length-1)*lineHeight+8;
        // Only a still-unresolved edge caption gets this 225-slot local nudge.
        const slots=dense==='fine'?Array.from({length:15},(_,i)=>i*2-14).flatMap(dx=>Array.from({length:15},(_,i)=>({x:refinementOrigin[0]+dx-w/2,y:refinementOrigin[1]+i*2-14-h/2,w,h}))):candidates(item,w,h,dense);
        if(dense){const origin=dense==='fine'?refinementOrigin:item.anchor;slots.sort((a,b)=>(a.x+w/2-origin[0])**2+(a.y+h/2-origin[1])**2-(b.x+w/2-origin[0])**2-(b.y+h/2-origin[1])**2);}
        for(const raw of dense?slots.slice(0,2048):slots){
          if(w>canvas.width-8 || h>canvas.height-8)continue;
          const box={...raw,x:Math.max(4,Math.min(raw.x,canvas.width-w-4)),y:Math.max(4,Math.min(raw.y,canvas.height-h-4))};
          if(item.kind==='edge' && distance([box.x+w/2,box.y+h/2],item.anchor)>180)continue;
          const hard=[...obstacles,...(item.kind==='control'?activeJoints:allJoints)].filter(o=>intersects(box,o));
          if(best?.conflicts===0 && hard.length)continue;
          const guard=padded(box,2.5);
          const crossed=segments.filter(s=>(item.kind==='control' || s.id!==item.edge?.id) && intersects(guard,s.box) && segmentIntersectsRect(s.a,s.b,guard));
          // Opaque cards must never hide a route. Short text halos can cross an
          // ordinary stroke when no nearby clear slot exists; this is a preference,
          // separate from actual text/component/junction overlap.
          const blocked=item.kind==='control'?activeSegments.filter(s=>intersects(guard,s.box)&&segmentIntersectsRect(s.a,s.b,guard)):[];
          const conflicts=[...hard,...blocked.map(s=>s.box)],area=conflicts.reduce((n,o)=>n+(Math.min(box.x+w,o.x+o.w)-Math.max(box.x,o.x))*(Math.min(box.y+h,o.y+o.h)-Math.max(box.y,o.y)),0);
          const cost=conflicts.length*1e8+area*1e4+distance([box.x+w/2,box.y+h/2],item.anchor)**2+(content.length-1)*100+(item.kind==='control' && blocked.length?0:crossed.length*2500);
          if(!best || cost<best.cost)best={...box,id:item.id,kind:item.kind,text:item.text,lines:content,size:item.size,weight:item.weight,ascent,descent,lineHeight,cost,edge:item.edge,conflicts:conflicts.length,connectorCrossings:crossed.length};
          if(dense && conflicts.length===0)break;
        }
      }
      }
      if(!best){const content=lines(item.text,item.widths[0],item.size,item.weight,measure);best={id:item.id,kind:item.kind,text:item.text,lines:content,size:item.size,weight:item.weight,ascent:item.size*.8,descent:item.size*.2,lineHeight:item.size*1.2,x:item.anchor[0],y:item.anchor[1],w:item.widths[0],h:content.length*item.size*1.2,conflicts:1};}
      placed.set(item.id,best);obstacles.push(best);
    }return placed;
  }
  function heads(edges,priority=()=>0) {
    const groups=new Map(),result=new Map();
    for(const e of edges){const p=clean(e.points);if(p.length<2)continue;const end=p.at(-1),before=p.at(-2),length=distance(before,end),direction=[(end[0]-before[0])/length,(end[1]-before[1])/length],key=e.to+'|'+end.map(n=>n.toFixed(3)).join(',')+'|'+direction.map(n=>n.toFixed(6)).join(',');const group=groups.get(key)||[];group.push({e,p});groups.set(key,group);}
    for(const group of groups.values()){
      group.sort((a,b)=>priority(b.e)-priority(a.e) || (a.e.id<b.e.id?-1:1));
      for(const item of group){const length=distance(item.p.at(-2),item.p.at(-1));const size=Math.min(9,Math.max(.25,Math.floor(length*.65*4)/4));result.set(item.e.id,{visible:item===group[0],size,shared:group.length,points:item.p});}
    }return result;
  }
  function nodeRows(node,role,measure=fallback) {
    const specs=[...(role?[{key:'role',text:role,size:9,weight:700}]:[]),{key:'title',text:node.title,size:17,weight:600},...(node.subtitle?[{key:'subtitle',text:node.subtitle,size:14,weight:400}]:[])];
    const rows=specs.map(s=>({...s,...measure(s.text,s.size,s.weight)}));const height=rows.reduce((n,r)=>n+r.ascent+r.descent,0)+Math.max(0,rows.length-1)*2+4;let y=node.y+2+Math.max(0,(node.h-height)/2);
    for(const row of rows){row.y=y+row.ascent;y=row.y+row.descent+2;}return {rows,overflow:height>node.h || rows.some(r=>r.w>node.w-20)};
  }
  return {intersects,padded,fallback,lines,plan,heads,nodeRows,clean,joints,sample,nearestOffset,segmentIntersectsRect};
})();
// End bounded SVG layout helpers.
const M = JSON.parse(document.getElementById('model-data').textContent);
const assessment = JSON.parse(document.getElementById('assessment-data').textContent);
const $ = id => document.getElementById(id);
const esc = v => String(v ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const textMeasureCache = new Map();
const mapLayoutCache = new Map();
function measureSvgText(text, size, weight = 400) {
  const family = typeof getComputedStyle === 'function' ? getComputedStyle($('map')).fontFamily : 'Arial,sans-serif';
  const key = JSON.stringify([text,size,weight,family]);
  if (textMeasureCache.has(key)) return textMeasureCache.get(key);
  let measured = SvgLayout.fallback(text,size);
  if (document.createElementNS && $('map').appendChild) {
    const node = document.createElementNS('http://www.w3.org/2000/svg','text');
    node.textContent = text; node.setAttribute('font-size',size); node.setAttribute('font-weight',weight);
    node.setAttribute('font-family',family); node.setAttribute('visibility','hidden'); $('map').appendChild(node);
    try { const box = node.getBBox(); if (box.width > 0) measured = {w:box.width,ascent:Math.max(size*.8,-box.y),descent:Math.max(size*.2,box.y+box.height)}; }
    finally { node.remove(); }
  }
  textMeasureCache.set(key,measured); return measured;
}
function captionSvg(p, color, region = null) {
  if (!p) return '';
  const x = p.x+p.w/2, y = p.y+4+p.ascent;
  let leader = '';
  if(region){
    const cy=p.y+p.h/2,rx=Math.max(region.x,Math.min(x,region.x+region.w)),ry=Math.max(region.y,Math.min(cy,region.y+region.h));
    const sides=[[region.x,ry],[region.x+region.w,ry],[rx,region.y],[rx,region.y+region.h]];
    sides.sort((a,b)=>Math.hypot(a[0]-x,a[1]-cy)-Math.hypot(b[0]-x,b[1]-cy));
    const targetFor=a=>[Math.max(p.x,Math.min(a[0],p.x+p.w)),Math.max(p.y,Math.min(a[1],p.y+p.h))];
    const anchor=sides.find(a=>!M.nodes.some(n=>SvgLayout.segmentIntersectsRect(a,targetFor(a),SvgLayout.padded(n,2)))) || sides[0],target=targetFor(anchor);
    if(Math.hypot(target[0]-anchor[0],target[1]-anchor[1])>2)leader=`<path data-caption-leader="true" d="M${esc(anchor[0])} ${esc(anchor[1])} L${esc(target[0])} ${esc(target[1])}" fill="none" stroke="${color}" stroke-width="1" opacity=".6"/>`;
  }
  if(p.edge){const anchor=SvgLayout.sample(p.edge.points,SvgLayout.nearestOffset(p.edge.points,[x,p.y+p.h/2]));
    const target=[Math.max(p.x,Math.min(anchor[0],p.x+p.w)),Math.max(p.y,Math.min(anchor[1],p.y+p.h))];
    if(Math.hypot(target[0]-anchor[0],target[1]-anchor[1])>12)leader=`<path data-caption-leader="true" d="M${esc(anchor[0])} ${esc(anchor[1])} L${esc(target[0])} ${esc(target[1])}" fill="none" stroke="${color}" stroke-width="1" stroke-dasharray="2 3" opacity=".6"/>`;
  }
  return `<g data-caption="${esc(p.id)}" data-caption-kind="${p.kind}" data-layout-unresolved="${p.conflicts>0}" data-connector-crossings="${p.connectorCrossings||0}"><title>${esc(p.text)}</title>${leader}<text text-anchor="middle" font-size="${p.size}" font-weight="${p.weight}" fill="${color}" paint-order="stroke" stroke="#fbfcfb" stroke-width="5" stroke-linejoin="round">${p.lines.map((line,i)=>`<tspan x="${esc(x)}" y="${esc(y+i*p.lineHeight)}">${esc(line)}</tspan>`).join('')}</text></g>`;
}
const state = {scenario:null, route:null, source:null, step:-1, node:null, control:null, proposal:null, tab:'path', context:false, zoom:1, x:0, y:0};
const hypothesis = () => M.scenarios.find(s => s.id === state.scenario);
const evidence = id => M.evidence.find(e => e.id === id);
const controlContext = () => ({routeId:state.route, sourceId:sourceState().selected?.id});
const applicableControls = () => ControlEffects.applicable(hypothesis(), controlContext());
const selectedControl = () => applicableControls().find(c => c.id === state.control);
const refs = ids => `<div class="evidence">${(ids || []).map(id => `<button data-evidence="${esc(id)}">${esc(evidence(id).label)} ↗</button>`).join('')}</div>`;
const effectState = () => ControlEffects.resolve(hypothesis(), state.proposal, controlContext());
const routeState = () => RoutePaths.resolve(M, hypothesis(), state.route, effectState().stop, effectState().blocker?.effect.arrival === true);
const sourceState = () => SourceRoles.resolve(M, hypothesis(), state.route, state.source);
const controlColor = c => c?.kind === 'proposed' ? '#78549a' : '#167765';
const pointsText = points => esc(points.map(p => p.join(',')).join(' '));

function hash() {
  const q = new URLSearchParams();
  if (state.scenario) q.set('scenario', state.scenario);
  if (state.route) q.set('route', state.route);
  if (state.source) q.set('source', state.source);
  if (state.step >= 0) q.set('step', state.step + 1);
  if (state.node) q.set('node', state.node);
  if (state.control) q.set('control', state.control);
  if (state.proposal) q.set('preview', state.proposal);
  if (state.tab !== 'path') q.set('panel', state.tab);
  if (state.context && Array.isArray(M.overviewEdges)) q.set('context', '1');
  history.replaceState(null, '', '#' + q);
}
function readHash() {
  const q = new URLSearchParams(location.hash.slice(1));
  state.scenario = M.scenarios.some(s => s.id === q.get('scenario')) ? q.get('scenario') : null;
  const s = hypothesis(), control = (s?.controls || []).find(c => c.id === q.get('control'));
  state.route = s?.routes?.find(r => r.id === q.get('route'))?.id || s?.routes?.[0]?.id || null;
  state.source = s?.sources?.find(source => source.id === q.get('source'))?.id || null;
  state.step = s && Number.isInteger(Number(q.get('step'))) && Number(q.get('step')) > 0 ? Math.min(s.steps.length - 1, Number(q.get('step')) - 1) : -1;
  state.node = M.nodes.some(n => n.id === q.get('node')) ? q.get('node') : null;
  state.control = control?.id || null;
  const proposal = q.get('preview') || (control?.kind === 'proposed' ? control.id : null);
  state.proposal = s?.controls?.some(c => c.kind === 'proposed' && c.id === proposal) ? proposal : null;
  state.tab = q.get('panel') === 'controls' ? 'controls' : 'path';
  state.context = Array.isArray(M.overviewEdges) && q.get('context') === '1';
  render();
}
function focusTarget() {
  const el = document.activeElement;
  if (!el) return null;
  for (const key of ['data-scenario','data-step','data-node','data-control','data-control-inspect','data-panel'])
    if (el.hasAttribute(key)) return '[' + key + '="' + CSS.escape(el.getAttribute(key)) + '"]';
  return el.id ? '#' + CSS.escape(el.id) : null;
}
function restoreFocus(selector) {
  if (!selector) return;
  let target = document.querySelector(selector);
  if (target?.disabled) target = document.querySelector('[data-step="' + state.step + '"]');
  if (!target) target = document.querySelector('#rail button.active');
  target?.focus({preventScroll:true});
}
function limitStep() {
  const {stop} = effectState();
  if (stop >= 0 && state.step > stop) state.step = stop;
  if (!hypothesis()?.steps.length) state.step = -1;
}
function effectCard(c, compact = false) {
  if (!c) return '';
  const e = c.effect;
  if (!e) return `<div class="effect-card ${esc(c.kind)}"><div class="eyebrow">${c.kind === 'proposed' ? 'Proposed control' : 'EXISTING · SOURCE-QUALIFIED'}</div><h3>${esc(c.title)}</h3><p>${esc(c.description)}</p><p>Effect not mapped. This annotation does not stop the trace.</p>${refs(c.evidence)}</div>`;
  const duplicate = c.description === e.reason;
  return `<div class="effect-card ${esc(c.kind)}" data-effect-outcome="${esc(e.outcome)}"><div class="eyebrow">${esc(ControlEffects.basis(c))}</div><h3>${esc(e.label)}</h3>${compact ? '' : `<p><strong>${esc(c.title)}:</strong> ${esc(c.description)}</p>`}${compact || !duplicate ? `<p>${esc(e.reason)}</p>` : ''}<p class="disposition">${esc(ControlEffects.caption(c))}</p><p><strong>Applies when:</strong> ${esc(e.conditions)}</p><p><strong>What remains:</strong> ${esc(e.residual)}</p>${compact ? `<button class="inspect-control" data-control-inspect="${esc(c.id)}">Description & evidence ↗</button>` : refs(c.evidence)}</div>`;
}
function renderControls(s) {
  const {blocker} = effectState(), selected = selectedControl() || blocker;
  const group = kind => applicableControls().filter(c => c.kind === kind).map(c => {
    const chosen = c.kind === 'proposed' ? state.proposal === c.id : selected?.id === c.id;
    return `<button data-control="${esc(c.id)}" class="${kind} ${chosen ? 'active' : ''}" aria-pressed="${chosen}"><b>${esc(c.title)}</b><span>${esc(c.effect ? ControlEffects.caption(c) : 'Effect not mapped')}</span></button>`;
  }).join('');
  return `<div class="controls"><h3>Controls on this path</h3>${applicableControls().some(c => c.kind === 'existing') ? `<p class="group-label">EXISTING · AS DESCRIBED IN THE ASSESSMENT</p>${group('existing')}` : ''}${applicableControls().some(c => c.kind === 'proposed') ? `<p class="group-label">Proposed controls</p>${group('proposed')}<p class="control-hint">Select a proposed control to preview its effect; select it again to restore the assessed path.</p>` : ''}</div>${selected ? effectCard(selected) : '<p>Select a control to see where and why it acts.</p>'}${selectedControl()?.nodes?.length ? '<p>C marks the selected control locus; it does not establish enforcement.</p>' : ''}${blocker && selected && blocker.id !== selected.id ? `<p class="earlier-block"><strong>First barrier:</strong> ${esc(blocker.title)} ${blocker.kind === 'proposed' ? 'would stop' : 'stops'} this path at step ${esc(blocker.effect.step)}, under its stated conditions.${selected.effect?.traffic === 'continues' ? ' It may stop the flow before the selected effect occurs.' : ''}</p>` : ''}`;
}
function sourceContext(s) {
  const {sources, allSources, selected} = sourceState();
  if (!sources.length) return s.sourceNote || s.sources?.length ? `<p class="source-gap">${esc(s.sourceNote || 'No supplied starting position is mapped to this documented flow.')}</p>` : '';
  const selector = selected && allSources.length > 1 ? `<label class="source-choice-label" for="source-select">Alternative starting positions · choose one</label><select id="source-select">${allSources.map(source => `<option value="${esc(source.id)}" ${source.id === selected.id ? 'selected' : ''}>${esc(source.label)}</option>`).join('')}</select><p class="source-gap">These are alternative starting positions. ${sourceState().sourceSpecific ? 'Highlighted relationships are supplied for this source.' : 'Relationship highlights retain the scenario set unless a documented flow is selected.'}</p>` : '';
  return `<section class="source-context" aria-label="Threat sources">${selector}${sources.map(source => {
    const p = SourceRoles.palette[source.kind];
    return `<details class="source-card" data-source-id="${esc(source.id)}" style="--source-fill:${p.fill};--source-ink:${p.ink}"><summary><small>${esc(p.label)} · ${source.basis === 'scenario-assumption' ? 'assumed' : source.basis === 'assessment-observed' ? 'source-observed' : 'uncertain'}</small><strong>${esc(source.label)}</strong>${source.node === null ? '<span class="source-unmapped">Source not mapped to a component in this view</span>' : ''}</summary><p>${esc(source.description)}</p><p><strong>Starting authority:</strong> ${esc(source.authority)}</p><p>${esc(SourceRoles.basis[source.basis])}. Scenario status remains ${esc(s.status)}.</p>${refs(source.evidence)}</details>`;
  }).join('')}${s.sourceNote ? `<p class="source-gap">${esc(s.sourceNote)}</p>` : ''}</section>`;
}
function branchEvidence(routing, scenario) {
  if (!routing?.branchStates.length) return '';
  const edges = new Map(M.edges.map(edge => [edge.id, edge]));
  const nodes = new Map(M.nodes.map(node => [node.id, node]));
  return `<details class="branch-evidence"><summary>Branch evidence · ${routing.branchStates.length}</summary>${routing.branchStates.map(({branch, active}, index) => {
    const chain = branch.edges.map(id => edges.get(id));
    const path = [chain[0].from, ...chain.map(edge => edge.to)].map(id => nodes.get(id).title).join(' → ');
    const step = branch.beforeStep ?? branch.afterStep;
    const timing = step === undefined ? 'No occurrence order supplied.' :
      `${branch.beforeStep === undefined ? 'After successful' : 'Before'} step ${step}: ${scenario.steps[step - 1].title}.`;
    return `<section data-route-branch="${index}" data-path-state="${active ? 'active' : 'unreached'}"><h3>${esc(path)}</h3><p>${active ? 'Active in this view.' : 'Not reached in this view.'} ${esc(timing)}</p>${refs(branch.evidence)}</section>`;
  }).join('')}</details>`;
}
function renderTrace(s) {
  if (!s) return `<h2 class="trace-title">${esc(M.overviewTitle)}</h2><p>${esc(M.overview)}</p><h3 style="margin-top:18px">Evidence boundary</h3><p>${esc(M.evidenceBoundary)}</p><p>Select a scenario to keep its map, steps and controls in this workspace.</p>`;
  const {blocker, stop} = effectState();
  const continuing = effectState().controls.filter(c => c.effect.outcome === 'blocks' && c.effect.traffic === 'continues');
  const resolvedRoute = routeState(), route = resolvedRoute?.route;
  const routing = route ? `<div class="route-picker">${s.routes.length > 1 ? `<label for="route-select">Documented flow · choose an alternative</label><select id="route-select">${s.routes.map(r => `<option value="${esc(r.id)}" ${r.id === route.id ? 'selected' : ''}>${esc(r.label)}</option>`).join('')}</select>` : `<p class="group-label">${esc(route.label)}</p>`}<p class="route-key">Filled components carry this route. Normal outlines indicate transit; orange outlines mark the scenario focus, subject to its stated confidence.</p>${refs(route.evidence)}${branchEvidence(resolvedRoute, s)}</div>` : '';
  const context = `<details><summary>Conditions, impact & source evidence</summary><h3>Required conditions</h3><p>${esc(s.prerequisites)}</p><h3>Potential impact</h3><p>${esc(s.impact)}</p><h3>Severity & confidence</h3><p>${esc(s.calibration)}</p>${s.pathNote ? `<p><strong>Path scope:</strong> ${esc(s.pathNote)}</p>` : ''}${refs(s.evidence)}</details>`;
  const tabs = `<div class="panel-tabs" role="tablist" aria-label="Inspector view"><button role="tab" data-panel="path" aria-selected="${state.tab === 'path'}">Path trace</button><button role="tab" data-panel="controls" aria-selected="${state.tab === 'controls'}">Controls · ${applicableControls().length}</button></div>`;
  const steps = `<div class="steps" aria-label="Ordered path">${s.steps.map((t, i) => {
    const stopped = i === stop, unreached = stop >= 0 && i > stop;
    return `<button data-step="${i}" class="${state.step === i ? 'current ' : ''}${stopped ? 'stop ' + esc(blocker.kind) : ''}${unreached ? 'unreached' : ''}" aria-pressed="${state.step === i}" ${unreached ? 'disabled' : ''}><span>${stopped ? blocker.kind === 'proposed' ? 'Proposed control · would stop at ' : 'CONTROL · STOP AT ' : unreached ? 'NOT REACHED · ' : ''}${String(i + 1).padStart(2, '0')}</span>${esc(stopped ? blocker.effect.label : t.title)}</button>`;
  }).join('')}</div>`;
  const stepText = state.step >= 0 ? `<div class="step-description">${state.step === stop ? esc(blocker.effect.reason) : esc(s.steps[state.step].description)}</div>` : '';
  const rating = (s.priority ? ' · ' + esc(s.priority) + ' review priority' : '') +
    (s.severity && !s.status.toLowerCase().includes(s.severity.toLowerCase()) ? ' · ' + esc(s.severity) + ' severity' : '');
  return `<span class="badge">${esc(s.status)}${rating}</span><h2 class="trace-title">${esc(s.title)}</h2>${tabs}${state.tab === 'controls' ? renderControls(s) : `${sourceContext(s)}${routing}<p>${applicableControls().some(c => c.effect?.outcome === 'blocks' && c.effect.traffic === 'continues') ? '<strong>Assessment context:</strong> ' : ''}${esc(s.summary)}</p>${blocker ? effectCard(blocker, true) : ''}${blocker && continuing.length ? '<p>A separate barrier may stop the flow before another effect occurs.</p>' : ''}${continuing.map(c => effectCard(c, true)).join('')}${steps}${stepText}${!s.steps.length ? `<p>${esc(s.pathNote || 'Affected components only; an ordered path is not established.')}</p>` : ''}`}${context}`;
}
function render() {
  const focus = focusTarget(), s = hypothesis(), panel = document.querySelector('.detail-panel'), scroll = panel.scrollTop;
  state.route = hypothesis()?.routes?.find(r => r.id === state.route)?.id || hypothesis()?.routes?.[0]?.id || null;
  state.source = sourceState().selected?.id || null;
  Object.assign(state, ControlEffects.selection(s, state, controlContext()));
  limitStep();
  const {stop} = effectState();
  $('rail').innerHTML = `<h2>${esc(M.scenarioLabel || 'Threat scenarios')} · ${M.scenarios.length}</h2><button data-scenario="" class="${!s ? 'active' : ''}">⊞ System overview</button>` + M.scenarios.map(h => `<button data-scenario="${esc(h.id)}" class="${s === h ? 'active' : ''}" aria-pressed="${s === h}"><b><span class="id">${esc(h.id)}</span>${esc(h.title)}</b><small>${esc(h.status)}</small></button>`).join('') + '<p class="help">Select a scenario to inspect its relationships and controls. Step through an ordered path when supplied.</p>';
  $('map-title').textContent = s ? s.title : M.mapTitle;
  $('map-description').textContent = s ? `${s.id} · ${s.status}${routeState() ? ' · ' + routeState().route.label : ''}` : M.mapDescription;
  if (Array.isArray(M.overviewEdges) && !state.context)
    $('map-description').textContent += s ? ' · Architecture context retained' : ' · Primary relationships';
  $('edge-context').textContent = state.context ? 'Fewer connections' : 'More connections';
  $('edge-context').setAttribute('aria-pressed', String(state.context));
  $('trace-position').textContent = s?.steps.length ? state.step >= 0 ? `Step ${state.step + 1} / ${s.steps.length}` : 'All steps shown' : '';
  $('trace-navigation').hidden = !s?.steps.length;
  const last = stop >= 0 ? stop : (s?.steps.length || 0) - 1;
  $('trace-navigation').innerHTML = `<button id="previous" aria-label="Previous path step" ${state.step <= 0 ? 'disabled' : ''}>← Previous</button><button id="next" aria-label="Next path step" ${!s?.steps.length || state.step >= last ? 'disabled' : ''}>Next →</button><button id="full" title="Clear the step highlight; keep the selected route and architecture visible" ${state.step < 0 ? 'disabled' : ''}>Clear step</button>`;
  $('trace').innerHTML = renderTrace(s);
  renderMap(); renderInspector(); hash(); panel.scrollTop = scroll; restoreFocus(focus);
}
function renderInspector() {
  const n = M.nodes.find(n => n.id === state.node), s = hypothesis();
  $('inspector').classList.toggle('hidden', !n);
  if (!n) return;
  const role = sourceState().nodes.get(n.id);
  $('inspector').innerHTML = `<button class="close" id="close-inspector">Close</button><div class="eyebrow">COMPONENT</div><h2>${esc(n.title)}</h2>${role ? `<p class="source-inspect" style="--source-fill:${role.fill};--source-ink:${role.ink}"><strong>${esc(role.label)}</strong>${role.items.map(item => `<br>${esc(item.label)}${item.authority ? `: ${esc(item.authority)}` : ''}`).join('')}</p>${refs([...new Set(role.items.flatMap(item => item.evidence))])}` : ''}<p>${esc(n.description)}</p>${s ? `<p><strong>${esc(s.id)} remains selected.</strong> ${esc(s.prerequisites)}</p>` : ''}${refs(n.evidence)}`;
}
function wrap(value, length) {
  const lines = [''];
  for (const word of String(value).split(/\s+/)) {
    const i = lines.length - 1;
    if (lines[i] && lines[i].length + word.length + 1 > length) lines.push(word);
    else lines[i] += (lines[i] ? ' ' : '') + word;
  }
  return lines;
}
function markerSvg(c, isBarrier, placement) {
  const e = c.effect, marker = e?.marker;
  if (!marker) return '';
  const edge = M.edges.find(x => x.id === e.edge), split = ControlEffects.split(edge.points, marker.at);
  const [px, py] = isBarrier && e.arrival ? edge.points.at(-1) : split.point, [nx, ny] = split.normal, color = controlColor(c);
  const {x,y,w,h} = placement, label = placement.lines;
  const center = [Math.max(x + 12, Math.min(px, x + w - 12)), Math.max(y, Math.min(py, y + h))];
  return `<g data-control-inspect="${esc(c.id)}" data-barrier="${isBarrier}" data-arrival="${isBarrier && e.arrival === true}" tabindex="0" role="button" aria-label="Inspect ${esc(c.title)}: ${esc(ControlEffects.caption(c))}" style="cursor:pointer"><title>${esc(ControlEffects.caption(c))}. ${esc(e.reason)} ${esc(e.conditions)}</title><path d="M${esc(px)} ${esc(py)} L${esc(center[0])} ${esc(center[1])}" stroke="${color}" stroke-width="1.2" stroke-dasharray="4 4" fill="none"/>${isBarrier && !e.arrival ? `<path d="M${esc(px - nx * 14)} ${esc(py - ny * 14)} L${esc(px + nx * 14)} ${esc(py + ny * 14)}" stroke="${color}" stroke-width="5"/><circle cx="${esc(px)}" cy="${esc(py)}" r="9" fill="${color}" stroke="white" stroke-width="2"/><path d="M${esc(px - 4)} ${esc(py)} h8" stroke="white" stroke-width="2"/>` : `<circle cx="${esc(px)}" cy="${esc(py)}" r="7" fill="white" stroke="${color}" stroke-width="2"/>`}<rect data-caption="${esc(placement.id)}" data-caption-kind="control" data-layout-unresolved="${placement.conflicts>0}" x="${esc(x)}" y="${esc(y)}" width="${esc(w)}" height="${esc(h)}" rx="7" fill="${c.kind === 'proposed' ? '#f7efff' : '#eaf6ef'}" stroke="${color}" stroke-width="1.5" ${c.kind === 'proposed' ? 'stroke-dasharray="5 3"' : ''}/><text x="${esc(x + 12)}" y="${esc(y + 18)}" fill="${color}" font-size="10" font-weight="700">${esc(ControlEffects.basis(c))}</text>${label.map((t, i) => `<text x="${esc(x + 12)}" y="${esc(y + 40 + i * placement.lineHeight)}" fill="${color}" font-size="16" font-weight="600">${esc(t)}</text>`).join('')}</g>`;
}
function renderMap() {
  const focus = focusTarget(), s = hypothesis(), {blocker, stop} = effectState();
  const inspected = selectedControl();
  const selected = inspected || (!blocker ? applicableControls().find(c => c.kind === 'existing' && c.effect?.marker) : null);
  const routing = routeState();
  const roles = sourceState();
  const path = s?.steps || [], edgesOnPath = new Map(path.map((t, i) => [t.edge, i]));
  const arrived = blocker?.effect.arrival === true;
  const visibleSteps = s ? state.step < 0 ? path.filter((t, i) => stop < 0 || i <= stop) : [path[state.step]] : [];
  const activeEdges = routing?.activeEdges || new Set([...visibleSteps.filter(Boolean).map(t => t.edge), ...(!path.length ? roles.relatedEdges : [])]);
  const activeNodes = routing?.activeNodes || new Set([...visibleSteps.filter(Boolean).flatMap(t => t === path[stop] && !arrived ? [t.from] : [t.from, t.to]), ...(!path.length ? roles.relatedNodes : [])]);
  const downstream = routing?.unreachedNodes || new Set(stop >= 0 ? path.slice(stop + (arrived ? 1 : 0)).map(t => t.to) : []);
  const selectedEdges = new Set([...activeEdges, ...(routing?.unreachedEdges || []),
    ...path.map(t => t.edge), ...(selected?.edges || []),
    ...[selected?.effect?.edge, blocker?.effect?.edge].filter(Boolean)]);
  const primaryEdges = new Set(M.overviewEdges || M.edges.map(e => e.id));
  $('edge-context').hidden = !M.edges.some(e => !primaryEdges.has(e.id) && !selectedEdges.has(e.id));
  const visibleEdges = M.edges.filter(e => state.context || primaryEdges.has(e.id) || selectedEdges.has(e.id));
  const edgeFlags = e => {
    const index=edgesOnPath.get(e.id), stopped=!!blocker && !arrived && index===stop;
    const unreached=routing ? routing.unreachedEdges.has(e.id) : stop>=0 && index>stop;
    return {stopped,unreached,highlighted:stopped || (!unreached && (activeEdges.has(e.id) || selected?.edges?.includes(e.id) || selected?.effect?.edge===e.id))};
  };
  const markerControls = [...(blocker ? [{c:blocker,barrier:true}] : []), ...(selected?.effect?.marker && selected.id!==blocker?.id && (selected.effect.outcome!=='blocks' || selected.effect.traffic==='continues') ? [{c:selected,barrier:false}] : [])];
  const captionItems = [
    ...markerControls.map(({c})=>({id:'control:'+c.id,kind:'control',priority:0,text:c.effect.label,size:16,weight:600,widths:[...new Set([c.effect.marker.w,Math.min(300,c.effect.marker.w+60),Math.max(160,c.effect.marker.w-40)].map(w=>Math.max(w,measureSvgText(ControlEffects.basis(c),10,700).w+24)-24))],cardWidth:c.effect.marker.w,anchor:[c.effect.marker.x+c.effect.marker.w/2,c.effect.marker.y+36]})),
    ...visibleEdges.filter(e=>e.label).map(e=>({id:'edge:'+e.id,kind:'edge',priority:edgeFlags(e).highlighted?1:3,text:e.label,size:13,weight:400,widths:[180,140,220,100],edge:e,anchor:[e.labelX,e.labelY-4]})),
    ...(M.regions||[]).map(r=>({id:'region:'+r.id,kind:'region',priority:2,text:r.title,size:14,weight:600,widths:[...new Set([Math.max(40,r.w-24),Math.min(420,r.w+96),...[360,220,160,120,90].map(w=>Math.max(40,Math.min(w,r.w-24)))])],region:r,anchor:[r.x+12+Math.min(measureSvgText(r.title,14,600).w,r.w-24)/2,r.y+17]}))
  ];
  const layoutEdges=visibleEdges.map(e=>({...e,layoutActive:edgeFlags(e).highlighted,layoutActivePoints:edgeFlags(e).stopped?ControlEffects.split(e.points,blocker.effect.marker.at).before:e.points}));
  const layoutKey=JSON.stringify([captionItems,M.nodes.map(n=>[n.x,n.y,n.w,n.h]),layoutEdges.map(e=>[e.id,e.points,e.layoutActive,e.layoutActivePoints]),M.canvas,typeof getComputedStyle==='function'?getComputedStyle($('map')).fontFamily:'Arial,sans-serif']);
  let layout=mapLayoutCache.get(layoutKey);
  if(!layout){
    layout=SvgLayout.plan(captionItems,M.nodes,layoutEdges,M.canvas,measureSvgText);
    if(mapLayoutCache.size>=64)mapLayoutCache.delete(mapLayoutCache.keys().next().value);
    mapLayoutCache.set(layoutKey,layout);
  }
  const layoutIssues=[...layout.values()].filter(p=>p.conflicts>0).map(p=>({id:p.id,kind:p.kind,conflicts:p.conflicts}));
  const heads=SvgLayout.heads(visibleEdges.filter(e=>!edgeFlags(e).stopped && !edgeFlags(e).unreached),e=>edgeFlags(e).highlighted?1:0);
  const arrowId = head => 'arrow-'+String(head.size).replace('.','_');
  const markerSizes=[...new Set([...heads.values()].map(h=>h.size))];
  const defs='<defs>'+markerSizes.map(size=>`<marker id="${arrowId({size})}" markerUnits="userSpaceOnUse" viewBox="0 0 8 6" refX="8" refY="3" markerWidth="${size}" markerHeight="8" preserveAspectRatio="none" orient="auto"><path d="M0 0L8 3L0 6Z" fill="context-stroke"/></marker>`).join('')+'</defs>';
  const regions=(M.regions||[]).map(r=>`<rect x="${esc(r.x)}" y="${esc(r.y)}" width="${esc(r.w)}" height="${esc(r.h)}" rx="12" fill="#eef4f2" fill-opacity=".5" stroke="#afc8bf" stroke-dasharray="5 5"/>${captionSvg(layout.get('region:'+r.id),'#607e76',r)}`).join('');
  // Visibility includes unreached paths; paint priority follows actual highlighting.
  const mutedEdges = [], highlightedEdges = [];
  visibleEdges.forEach(e => {
    const index = edgesOnPath.get(e.id), stopped = blocker && !arrived && index === stop, unreached = routing ? routing.unreachedEdges.has(e.id) : stop >= 0 && index > stop;
    const a = activeEdges.has(e.id), co = selected?.edges?.includes(e.id) || selected?.effect?.edge === e.id;
    const color = co && !stopped ? controlColor(selected) : a ? '#bc541e' : '#9db2bc';
    let body;
    if (stopped) {
      const split = ControlEffects.split(e.points, blocker.effect.marker.at);
      mutedEdges.push(`<g data-edge-tail="${esc(e.id)}" data-path-state="unreached" aria-hidden="true"><polyline data-route-part="unreached" points="${pointsText(split.after)}" fill="none" stroke="#a8b6bd" stroke-width="1.6" stroke-dasharray="5 6" opacity=".5"/></g>`);
      body = `<polyline data-route-part="before" points="${pointsText(split.before)}" fill="none" stroke="#bc541e" stroke-width="3" ${e.conditional ? 'stroke-dasharray="7 5"' : ''}/>`;
    } else body = `<polyline points="${pointsText(SvgLayout.clean(e.points))}" fill="none" stroke="${color}" stroke-width="${a && state.step >= 0 && index === state.step ? 4.5 : a || co ? 3 : 1.6}" ${e.conditional || unreached ? 'stroke-dasharray="6 5"' : ''} ${heads.get(e.id)?.visible ? `marker-end="url(#${arrowId(heads.get(e.id))})"` : ''}/>`;
    const layer = stopped || (!unreached && (a || co)) ? highlightedEdges : mutedEdges;
    layer.push(`<g data-edge="${esc(e.id)}" data-path-state="${stopped ? 'stopped' : unreached ? 'unreached' : a ? 'active' : 'context'}" opacity="${stopped ? 1 : unreached ? .35 : s && !a && !co ? .65 : 1}">${body}<title>${esc(e.label || e.id)}: ${esc(e.from)} → ${esc(e.to)}${heads.get(e.id)?.shared>1 ? ' · shared destination arrow' : ''}</title>${captionSvg(layout.get('edge:'+e.id),a ? '#995122' : '#647e87')}</g>`);
  });
  const edges = `<g data-edge-layer="muted">${mutedEdges.join('')}</g><g data-edge-layer="highlighted">${highlightedEdges.join('')}</g>`;
  const nodes = M.nodes.map(n => {
    const a = activeNodes.has(n.id), co = selected?.nodes?.includes(n.id), muted = downstream.has(n.id) && !a;
    const role = roles.nodes.get(n.id);
    const focused = a && !!s?.focusNodes?.includes(n.id), transit = a && !focused;
    const transport = transit && !!(routing || path.length);
    const relation = focused ? 'focus' : transit ? (transport ? 'transit' : 'related') : 'context';
    const stroke = transport ? '#b5c9cd' : state.node === n.id ? '#326d83' : co ? controlColor(selected) : focused ? '#bc541e' : '#b5c9cd';
    const nums = path.flatMap((t, i) => t.to === n.id && (stop < 0 || i < stop) ? [i + 1] : []);
    const roleText = role ? `, ${role.label}: ${role.items.map(item => item.label).join('; ')}` : '';
    const badge = role?.kind === 'compromised-component' && role.items.every(item => item.basis === 'scenario-assumption') ? 'ASSUMED COMPROMISE' : role?.badge;
    const owner = inspected?.nodes?.includes(n.id);
    const ownerText = owner ? `, selected control locus: ${inspected.title}` : '';
    const ownerBadge = owner ? `<g data-control-owner="${esc(inspected.id)}"><title>Selected control locus: ${esc(inspected.title)}</title><circle cx="${esc(n.x + n.w - 11)}" cy="${esc(n.y + n.h - 11)}" r="9" fill="${controlColor(inspected)}" stroke="white" stroke-width="1.5"/><text x="${esc(n.x + n.w - 11)}" y="${esc(n.y + n.h - 8)}" fill="white" text-anchor="middle" font-size="9" font-weight="700">C</text></g>` : '';
    const nodeText=SvgLayout.nodeRows(n,role ? badge : null,measureSvgText);
    if(nodeText.overflow)layoutIssues.push({id:'node:'+n.id,kind:'node-text',conflicts:1});
    const textRows=nodeText.rows.map(row=>`<text data-node-text="${row.key}" x="${esc(n.x+10)}" y="${esc(row.y)}" fill="${row.key==='role'?role.ink:row.key==='title'?'#24414c':'#68818a'}" font-size="${row.size}" font-weight="${row.weight}">${esc(row.text)}</text>`).join('');
    return `<g data-node="${esc(n.id)}" data-source-kind="${role?.source ? esc(role.kind) : ''}" data-participant-role="${role && !role.source ? esc(role.kind) : ''}" data-route-role="${relation}" data-path-state="${muted ? 'unreached' : a ? 'active' : 'context'}" tabindex="0" role="button" aria-label="Inspect ${esc(n.title)}${esc(roleText)}${esc(ownerText)}${transport ? ', transit on selected route' : transit ? ', related component; order unestablished' : focused ? ', scenario focus' : ''}" style="cursor:pointer" opacity="${muted ? .4 : s && !a && !co && !role?.source ? .7 : 1}"><title>${esc(n.description)}${esc(roleText)}${esc(ownerText)}${role?.source ? ' This role is the selected scenario’s starting condition, not a newly verified compromise.' : ''}${transport ? ' Traversed by the selected route; no weakness is attributed by this highlight.' : transit ? ' Related to the scenario; no traversal order or weakness is attributed by this highlight.' : ''}</title><rect x="${esc(n.x)}" y="${esc(n.y)}" width="${esc(n.w)}" height="${esc(n.h)}" rx="8" fill="${role?.fill || (a ? '#fff0d5' : n.kind === 'asset' ? '#edf4f6' : n.kind === 'actor' ? '#f2f6f4' : '#fff')}" stroke="${stroke}" stroke-width="${transport ? 1.4 : focused || co || state.node === n.id ? 2.4 : 1.4}" ${co && !transport && selected.kind === 'proposed' ? 'stroke-dasharray="5 3"' : ''}/>${textRows}${ownerBadge}${nums.length ? `<circle cx="${esc(n.x + n.w - 2)}" cy="${esc(n.y)}" r="11" fill="#bc541e" stroke="white" stroke-width="2"/><text x="${esc(n.x + n.w - 2)}" y="${esc(n.y + 4)}" text-anchor="middle" font-size="11" font-weight="700" fill="white">${nums.join(',')}</text>` : ''}</g>`;
  }).join('');
  const markers = markerControls.map(({c,barrier})=>markerSvg(c,barrier,layout.get('control:'+c.id))).join('');
  $('map').setAttribute('data-layout-status',layoutIssues.length?'unresolved':'clear');
  $('map').setAttribute('data-layout-issues',JSON.stringify(layoutIssues));
  $('map').setAttribute('viewBox', `0 0 ${M.canvas.width} ${M.canvas.height}`);
  $('map').setAttribute('aria-label', `${M.title}${s ? ' — ' + s.title : ''}${blocker ? ' — ' + ControlEffects.caption(blocker) : ''}`);
  $('map').innerHTML = defs + `<g id="viewport">${regions}${edges}${nodes}${markers}</g>`;
  const legendRoles = [...new Set([...roles.sources.map(source => source.kind), ...[...roles.nodes.values()].filter(role => !role.source).map(role => role.kind)])];
  $('source-legend').innerHTML = legendRoles.map(kind => `<span class="source-key"><i style="background:${SourceRoles.palette[kind].fill};border-color:${SourceRoles.palette[kind].ink}"></i>${esc(SourceRoles.palette[kind].label)}</span>`).join('');
  document.querySelector('.legend .risk').textContent = s && !routing && !path.length ? 'Scenario relationships' : 'Selected route';
  document.querySelector('.legend .transit').textContent = s && !routing && !path.length ? 'Related component · normal outline' : 'On route · normal outline';
  transform(); restoreFocus(focus);
}
function transform() { $('viewport').setAttribute('transform', `translate(${state.x} ${state.y}) scale(${state.zoom})`); }
function showEvidence(id) {
  const e = evidence(id);
  $('dialog-content').innerHTML = `<div class="eyebrow">SUPPLIED ASSESSMENT EVIDENCE</div><h2 id="evidence-title">${esc(e.label)}</h2><p>Exact quotation from the supplied assessment${e.startLine ? ` · lines ${esc(e.startLine)}–${esc(e.endLine)}` : ''}.</p><blockquote>${esc(e.quote)}</blockquote>${e.paths?.length ? `<h3>Paths cited by the assessment</h3><p>${e.paths.map(esc).join('<br>')}</p>` : ''}<p>The explorer preserves the assessment’s attribution. It adds no independent code or runtime verification.</p>`;
  $('dialog').showModal();
}
document.addEventListener('click', event => {
  const t = event.target.closest('button,[data-node],[data-control-inspect]');
  if (!t) return;
  if (t.hasAttribute('data-scenario')) {
    state.scenario = t.dataset.scenario || null; state.route = null; state.source = null; state.step = -1; state.control = null; state.proposal = null; state.node = null; state.tab = 'path';
    document.querySelector('.detail-panel').scrollTop = 0; render();
  } else if (t.hasAttribute('data-step')) { state.step = Number(t.dataset.step); render(); }
  else if (t.hasAttribute('data-panel')) { state.tab = t.dataset.panel; render(); }
  else if (t.hasAttribute('data-control-inspect')) { state.control = t.dataset.controlInspect; state.tab = 'controls'; document.querySelector('.detail-panel').scrollTop = 0; render(); }
  else if (t.hasAttribute('data-control')) {
    const c = applicableControls().find(c => c.id === t.dataset.control);
    if (!c) return;
    if (c.kind === 'proposed') {
      const turnOff = state.proposal === c.id;
      state.proposal = turnOff ? null : c.id; state.control = turnOff ? null : c.id; state.step = -1;
    } else state.control = state.control === c.id ? null : c.id;
    render();
  } else if (t.hasAttribute('data-node')) {
    state.node = t.dataset.node; render(); $('inspector').scrollIntoView({block:'nearest'});
  } else if (t.hasAttribute('data-evidence')) showEvidence(t.dataset.evidence);
  else if (t.id === 'previous') { state.step--; render(); }
  else if (t.id === 'next') { state.step++; render(); }
  else if (t.id === 'full') { state.step = -1; state.tab = 'path'; render(); }
  else if (t.id === 'edge-context') { state.context = !state.context; render(); }
  else if (t.id === 'close-inspector') { state.node = null; render(); }
});
document.addEventListener('change', event => {
  if (event.target.id === 'route-select') {
    state.route = event.target.value; state.source = null; state.step = -1; state.node = null;
    render();
  } else if (event.target.id === 'source-select') {
    state.source = event.target.value; state.node = null;
    render();
  }
});
$('map').addEventListener('keydown', e => {
  if ((e.key === 'Enter' || e.key === ' ') && (e.target.dataset.node || e.target.dataset.controlInspect)) {
    e.preventDefault(); e.target.dispatchEvent(new MouseEvent('click', {bubbles:true}));
  }
});
$('close-dialog').onclick = () => $('dialog').close();
$('fit').onclick = () => { state.zoom = 1; state.x = state.y = 0; transform(); };
function zoom(k) { const z = Math.max(.5, Math.min(3, state.zoom * k)), r = z / state.zoom; state.x = M.canvas.width / 2 - (M.canvas.width / 2 - state.x) * r; state.y = M.canvas.height / 2 - (M.canvas.height / 2 - state.y) * r; state.zoom = z; transform(); }
$('in').onclick = () => zoom(1.2); $('out').onclick = () => zoom(1 / 1.2);
let drag = null;
$('map').onpointerdown = e => { if (e.target.closest('[data-node],[data-control-inspect]')) return; drag = {x:e.clientX, y:e.clientY, px:state.x, py:state.y}; $('map').setPointerCapture(e.pointerId); };
$('map').onpointermove = e => { if (!drag) return; const r = $('map').getBoundingClientRect(), scale = Math.min(r.width / M.canvas.width, r.height / M.canvas.height); state.x = drag.px + (e.clientX - drag.x) / scale; state.y = drag.py + (e.clientY - drag.y) / scale; transform(); };
$('map').onpointerup = $('map').onpointercancel = () => drag = null;
function download(data, type, name) { const a = document.createElement('a'), url = URL.createObjectURL(new Blob([data], {type})); a.href = url; a.download = name; a.click(); setTimeout(() => URL.revokeObjectURL(url), 1000); }
function exportMapSvg() {
  const clone = $('map').cloneNode(true), s = hypothesis(), {blocker, controls} = effectState(), c = selectedControl() || blocker || controls.find(item => item.effect.outcome === 'blocks' && item.effect.traffic === 'continues');
  clone.querySelector('#viewport').removeAttribute('transform');
  const qualifiedCaption = control => `${ControlEffects.basis(control)} · ${ControlEffects.caption(control)}`;
  const foot = [s ? `${s.id}: ${s.title} · ${s.status}` : M.title,
    Array.isArray(M.overviewEdges) && !state.context ? 'Primary architecture connections remain visible; additional connections are available in the HTML.' : '',
    s && !routeState() && !s.steps.length ? 'Amber fill: related components; order unestablished · orange outline: scenario focus · teal: existing control · purple: proposed control' : 'Amber fill: on selected route · normal outline: transit · orange outline: scenario focus · teal: existing control · purple: proposed control',
    [...new Set([...sourceState().nodes.values()].map(role => role.kind))].length ? 'Role fills: ' + [...new Set([...sourceState().nodes.values()].map(role => role.kind))].map(kind => `${SourceRoles.palette[kind].colorName}: ${SourceRoles.palette[kind].label}`).join(' · ') : '',
    ...sourceState().sources.map(source => `Threat source: ${source.label} (${SourceRoles.palette[source.kind].label}; ${SourceRoles.basis[source.basis]}${source.node === null ? '; not mapped on diagram' : ''}). Starting authority: ${source.authority}`),
    routeState() ? `Documented flow: ${routeState().route.label}` : s && !s.steps.length ? (sourceState().sourceSpecific ? 'Related components: supplied for selected starting position; order unestablished.' : 'Related components: shared scenario set; order unestablished.') : '',
    s && applicableControls().some(item => item.effect?.outcome === 'blocks' && item.effect.traffic === 'continues') ? `Assessment context: ${s.summary}` : '',
    selectedControl()?.nodes?.length ? `C badge: selected control locus for ${selectedControl().title}; not proof of enforcement.` : '',
    blocker ? `${qualifiedCaption(blocker)}: ${blocker.effect.label}. ${blocker.effect.conditions} ${blocker.effect.residual}` : '',
    ...controls.filter(item => item.effect.outcome === 'blocks' && item.effect.traffic === 'continues').map(item => `${qualifiedCaption(item)}: ${item.effect.label}. ${item.effect.conditions} ${item.effect.residual}${blocker ? ' A separate barrier may stop the flow before this effect occurs.' : ''}`),
    c && c.id !== blocker?.id && !controls.some(item => item.id === c.id && item.effect.traffic === 'continues') ? `${qualifiedCaption(c)}: ${c.title}${c.effect ? `. ${c.effect.conditions} ${c.effect.residual}` : ''}` : '',
    !blocker && !c ? M.exportNote || 'Assessment evidence; no runtime validation implied.' : ''];
  const lines = foot.filter(Boolean).flatMap(line => wrap(line, Math.floor((M.canvas.width - 40) / 7.5)));
  const height = lines.length * 22 + 30;
  clone.setAttribute('xmlns', 'http://www.w3.org/2000/svg'); clone.setAttribute('viewBox', `0 0 ${M.canvas.width} ${M.canvas.height + height}`); clone.setAttribute('width', M.canvas.width); clone.setAttribute('height', M.canvas.height + height); clone.setAttribute('style', `font-family:${typeof getComputedStyle === 'function' ? getComputedStyle($('map')).fontFamily : 'Arial,sans-serif'};background:#fbfcfb`);
  clone.insertAdjacentHTML('beforeend', `<rect x="0" y="${esc(M.canvas.height)}" width="${esc(M.canvas.width)}" height="${height}" fill="#fbfcfb"/>${lines.map((line, i) => `<text x="20" y="${esc(M.canvas.height + 25 + i * 22)}" font-size="14" fill="#49616b">${esc(line)}</text>`).join('')}`);
  return new XMLSerializer().serializeToString(clone);
}
$('svg-download').onclick = () => download(exportMapSvg(), 'image/svg+xml', 'threat-model-map.svg');
$('html-download').onclick = () => { const clone = document.documentElement.cloneNode(true); clone.querySelector('dialog').removeAttribute('open'); download('<!doctype html>\n' + clone.outerHTML, 'text/html', 'threat-model-explorer.html'); };
$('brand').innerHTML = esc(M.brand) + '<small>THREAT MODEL EXPLORER</small>';
$('title').textContent = M.title; $('subtitle').textContent = M.subtitle; $('snapshot').textContent = M.snapshotLabel;
$('assessment').textContent = assessment; $('metadata').innerHTML = (M.metadata || []).map(m => `<h3>${esc(m.label)}</h3><p>${esc(m.value)}</p>`).join('');
$('footer').textContent = M.footer; document.title = M.title;
window.addEventListener('hashchange', readHash); readHash();

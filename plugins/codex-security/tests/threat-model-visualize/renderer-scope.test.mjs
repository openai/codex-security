// Exercise actual renderer state/hash/export wiring without a browser layout engine.
import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import vm from 'node:vm';
const asset = name => readFileSync(new URL('../../skills/threat-model-visualize/assets/'+name, import.meta.url),'utf8');
function renderer() {
 const elements=new Map(), handlers={};
 let exported;
 function element(id) {
  if (!elements.has(id)) elements.set(id,{
   innerHTML:'',textContent:'',scrollTop:0,attributes:new Map(),classList:{toggle(){}},
   addEventListener(){},focus(){},showModal(){this.open=true;},
   setAttribute(key,value){this.attributes.set(key,String(value));},
   getAttribute(key){return this.attributes.get(key) ?? null;},
   removeAttribute(key){this.attributes.delete(key);},
   querySelector(){return element('viewport');},
   cloneNode(){
    const viewport={...element('viewport'),attributes:new Map(element('viewport').attributes)};
    return {...this,attributes:new Map(this.attributes),querySelector:()=>viewport,
     insertAdjacentHTML(_,html){this.innerHTML+=html;}};
   }
  });
  return elements.get(id);
 }
 const nodes=['a','b','c'].map((id,i)=>({id,title:id,subtitle:'',description:id,x:i*200,y:20,w:100,h:60}));
 const edge={id:'ab',from:'a',to:'b',points:[[100,50],[200,50]],label:'flow',labelX:150,labelY:40};
 const sources=[{id:'one',node:'a',kind:'adversary',label:'A',basis:'scenario-assumption',authority:'caller'}, {id:'two',node:'c',kind:'compromised-component',label:'C',basis:'scenario-assumption',authority:'helper'}];
 const scoped={id:'scoped',title:'Scoped barrier',kind:'existing',sourceIds:['one'],routeIds:['r'],effect:{outcome:'blocks',basis:'declared',step:1,edge:'ab',label:'Denied',reason:'Role denied',conditions:'Identity established',residual:'Other callers',marker:{at:.5,x:20,y:120,w:180}}};
 const model={title:'Test',brand:'Test',canvas:{width:700,height:400},nodes,edges:[edge],scenarios:[
  {id:'routed',title:'Routed',status:'Hypothesis',sourceMode:'alternatives',sources,steps:[{edge:'ab',from:'a',to:'b',title:'Call'}],routes:[{id:'r',label:'Response flow',edges:['ab']},{id:'other',label:'Other flow',edges:['ab']}],controls:[scoped]},
  {id:'unordered',title:'Related',status:'Hypothesis',sourceMode:'alternatives',steps:[],affectedNodes:['a','b'],affectedEdges:['ab'],sources:[{...sources[0],relatedNodes:['a'],relatedEdges:[]},{...sources[1],relatedNodes:['c'],relatedEdges:[]}],controls:[]}
 ]};
 element('model-data').textContent=JSON.stringify(model);element('assessment-data').textContent=JSON.stringify('source');
 const location={hash:'#scenario=routed&route=r&source=one&control=scoped'};
 const context=vm.createContext({document:{getElementById:element,querySelector:element,addEventListener(type,handler){handlers[type]=handler;},activeElement:null},window:{addEventListener(){}},location,history:{replaceState(_a,_b,h){location.hash=h;}},URLSearchParams,XMLSerializer:class {serializeToString(e){exported=e;return e.innerHTML;}}});
 for (const file of ['control-effects.js','route-paths.js','source-roles.js','explorer.js']) vm.runInContext(asset(file),context);
 const run=code=>vm.runInContext(code,context);
 return {elements,location,run,get exported(){return exported;},
  outputs:()=>[element('map').innerHTML,run('exportMapSvg()')],
  click:(attrs={})=>handlers.click({target:{id:attrs.id || '',dataset:attrs.dataset || {},hasAttribute:key=>key in attrs,closest(){return this;}}})};
}
function twoStepRenderer() {
 const r=renderer();
 r.run(`M.edges.push({id:'bc',from:'b',to:'c',points:[[300,50],[400,50]],label:'Later',labelX:350,labelY:40});
 M.scenarios[0].steps.push({edge:'bc',from:'b',to:'c',title:'Later'});
 M.scenarios[0].routes.forEach(route=>route.edges.push('bc'));`);
 return r;
}
test('source and route changes clear stale controls from the view, hash and export',()=>{
 for(const [selection,caption] of [["state.source='two'",/Threat source: C/],["state.route='other'",/Documented flow: Other flow/]]) {
  const r=renderer();
  assert.match(r.elements.get('map').innerHTML,/data-barrier="true"/);
  r.run(`${selection};state.tab='controls';render()`);
  for(const output of [...r.outputs(),r.elements.get('trace').innerHTML])
   assert.doesNotMatch(output,/Role denied|Scoped barrier|data-barrier="true"/);
  assert.doesNotMatch(r.location.hash,/control=|preview=/);
  assert.match(r.run('exportMapSvg()'),caption);
  r.run("state.source='one';state.route='r';render()");
  assert.match(r.elements.get('map').innerHTML,/data-barrier="true"/);
 }
});
test('branch evidence remains inspectable with route context, control reach and source restoration',()=>{
 const r=renderer();
 r.run(`M.nodes.push({id:'d',title:'Store',x:600,y:20,w:80,h:60});
 M.evidence=[
  {id:'main-proof',label:'Request evidence',quote:'The caller requests admission.'},
  {id:'branch-proof',label:'Authorization evidence',quote:'The gateway calls the authorizer before admitting the request.'},
  {id:'other-proof',label:'Alternate evidence',quote:'The caller can contact the alternate service.'}];
 M.edges.push({id:'auth',from:'b',to:'c',points:[[300,50],[400,50]],label:'Authorization check',labelX:350,labelY:40},
  {id:'write',from:'b',to:'d',points:[[300,60],[600,60]],label:'Write',labelX:450,labelY:80},
  {id:'alternate',from:'a',to:'c',points:[[100,70],[400,70]],label:'Alternate service',labelX:250,labelY:90});
 const s=M.scenarios[0];s.routes[0].evidence=['main-proof'];
 s.routes[0].branches=[{edges:['auth'],beforeStep:1,evidence:['branch-proof']},{edges:['write']}];
 s.routes[1].branches=[{edges:['alternate'],evidence:['other-proof']}];render();`);
 let trace=r.elements.get('trace').innerHTML;
 assert.match(trace,/data-evidence="main-proof"/);
 assert.match(trace,/data-route-branch="0" data-path-state="unreached"/);
 assert.match(trace,/<h3>b → c<\/h3>/);
 assert.match(trace,/Not reached in this view\. Before step 1: Call\./);
 assert.match(trace,/data-evidence="branch-proof"/);
 assert.doesNotMatch(trace,/data-evidence="other-proof"/);
 for(const output of r.outputs()) {
  assert.match(output,/data-edge="ab" data-path-state="stopped"/);
  assert.match(output,/data-edge="auth" data-path-state="unreached"/);
  assert.match(output,/data-node="b"[^>]*data-path-state="unreached"/);
 }
 r.click({'data-evidence':true,dataset:{evidence:'branch-proof'}});
 assert.equal(r.elements.get('dialog').open,true);
 assert.match(r.elements.get('dialog-content').innerHTML,/The gateway calls the authorizer before admitting the request\./);
 r.run('M.scenarios[0].controls[0].effect.arrival=true;render()');
 for(const output of r.outputs()) {
  assert.match(output,/data-edge="ab" data-path-state="active"/);
  assert.match(output,/data-edge="auth" data-path-state="active"/);
  assert.match(output,/data-edge="write" data-path-state="unreached"/);
 }
 r.run('M.scenarios[0].controls[0].effect.arrival=false;render()');
 assert.match(r.elements.get('trace').innerHTML,/data-route-branch="0" data-path-state="unreached"/);
 r.run("state.source='two';render()");
 trace=r.elements.get('trace').innerHTML;
 assert.match(trace,/data-route-branch="0" data-path-state="active"/);
 assert.match(trace,/Active in this view\. Before step 1: Call\./);
 assert.match(trace,/data-evidence="branch-proof"/);
 assert.match(r.elements.get('map').innerHTML,/data-edge="auth" data-path-state="active"/);
 r.run("state.route='other';render()");
 trace=r.elements.get('trace').innerHTML;
 assert.doesNotMatch(trace,/data-evidence="branch-proof"/);
 assert.match(trace,/data-evidence="other-proof"/);
 assert.match(trace,/No occurrence order supplied\./);
 r.run('state.scenario=null;render()');
 assert.doesNotMatch(r.elements.get('trace').innerHTML,/branch-evidence|data-evidence="branch-proof"|data-evidence="other-proof"/);
});
test('branch evidence reports occurrence reach independently of shared edge highlighting',()=>{
 const r=renderer();
 r.run(`M.nodes.push({id:'d',title:'Store',subtitle:'',description:'Store',x:600,y:20,w:80,h:60});
 M.evidence=[{id:'early',label:'Earlier use',quote:'Earlier use.'},{id:'decision',label:'Decision use',quote:'Decision use.'}];
 M.edges.push({id:'early-auth',from:'a',to:'c',points:[[100,70],[400,70]],label:'Earlier call',labelX:250,labelY:90},
  {id:'decision-auth',from:'b',to:'c',points:[[300,50],[400,50]],label:'Decision call',labelX:350,labelY:40},
  {id:'shared',from:'c',to:'d',points:[[500,50],[600,50]],label:'Shared dependency',labelX:550,labelY:40});
 M.scenarios[0].routes[0].branches=[{edges:['early-auth','shared'],evidence:['early']},
  {edges:['decision-auth','shared'],beforeStep:1,evidence:['decision']}];render();`);
 assert.match(r.elements.get('map').innerHTML,/data-edge="shared" data-path-state="active"/);
 const trace=r.elements.get('trace').innerHTML;
 assert.match(trace,/data-route-branch="0" data-path-state="active"/);
 assert.match(trace,/data-route-branch="1" data-path-state="unreached"/);
 assert.match(trace,/data-evidence="early"/);
 assert.match(trace,/data-evidence="decision"/);
});
test('scenario selection retains primary architecture beneath the route and barrier, including SVG',()=>{
 const r=renderer();
 r.run(`M.edges.push({id:'bc',from:'b',to:'c',points:[[300,50],[400,50]],label:'context',labelX:350,labelY:40},
 {id:'ac',from:'a',to:'c',points:[[100,60],[400,60]],label:'extra',labelX:250,labelY:60});
 M.overviewEdges=['bc'];state.scenario=null;state.control=null;render();`);
 let map=r.elements.get('map').innerHTML;
 assert.match(map,/data-edge="bc"/);assert.doesNotMatch(map,/data-edge="ab"/);
 assert.match(r.elements.get('map-description').textContent,/Primary relationships/);
 r.run("state.scenario='routed';state.route='r';state.source='one';render()");
 map=r.elements.get('map').innerHTML;
 assert.match(map,/data-edge="ab" data-path-state="stopped"/);
 assert.match(map,/data-barrier="true"/);
 assert.match(map,/data-edge="bc" data-path-state="context"/);
 assert.doesNotMatch(map,/data-edge="ac"/);
 assert.ok(map.indexOf('data-edge="bc"') < map.indexOf('data-edge="ab"'), 'draw selected route over context');
 assert.match(r.run('exportMapSvg()'),/data-edge="ab" data-path-state="stopped"/);
 assert.match(r.run('exportMapSvg()'),/data-edge="bc" data-path-state="context"/);
 assert.match(r.run('exportMapSvg()'),/Primary architecture connections remain visible/);
 r.click({id:'edge-context'});
 assert.match(r.elements.get('map').innerHTML,/data-edge="ac"/);
 assert.match(r.location.hash,/context=1/);
 assert.match(r.run('exportMapSvg()'),/data-edge="ac"/);
 r.click({id:'edge-context'});
 assert.match(r.elements.get('map').innerHTML,/data-edge="bc"/);
 assert.doesNotMatch(r.elements.get('map').innerHTML,/data-edge="ac"/);
 assert.doesNotMatch(r.location.hash,/context=1/);
});
test('step reset has a clear state and unordered relationships have no step controls',()=>{
 const r=renderer();
 assert.equal(r.elements.get('trace-position').textContent,'All steps shown');
 assert.match(r.elements.get('trace-navigation').innerHTML,/id="full"[^>]*disabled>Clear step/);
 r.click({id:'next'});
 assert.equal(r.run('state.step'),0);
 assert.match(r.elements.get('trace-position').textContent,/Step 1/);
 assert.doesNotMatch(r.elements.get('trace-navigation').innerHTML,/id="full"[^>]*disabled/);
 r.click({id:'full'});
 assert.equal(r.run('state.step'),-1);
 assert.doesNotMatch(r.location.hash,/step=/);
 assert.match(r.elements.get('map').innerHTML,/data-barrier="true"/);
 r.run("state.scenario='unordered'; render()");
 assert.equal(r.elements.get('trace-navigation').hidden,true);
 assert.equal(r.elements.get('trace-position').textContent,'');
});
test('extra-connections control appears only when it can reveal additional edges',()=>{
 const r=renderer();
 r.run("M.overviewEdges=['ab']; render()");
 assert.equal(r.elements.get('edge-context').hidden,true);
 r.run(`M.edges.push({id:'bc',from:'b',to:'c',points:[[300,50],[400,50]],label:'extra',labelX:350,labelY:40});render();`);
 assert.equal(r.elements.get('edge-context').hidden,false);
 r.run("M.scenarios[0].routes[0].branches=[{edges:['bc']}];render()");
 assert.equal(r.elements.get('edge-context').hidden,true);
 assert.match(r.elements.get('map').innerHTML,/data-edge="bc"/);
});
test('later branch stays unreached behind a denied action and is restored with existing context',()=>{
 const r=renderer();
 r.run(`M.nodes.push({id:'d',title:'Store',subtitle:'',description:'Store',x:600,y:20,w:80,h:60});
 M.edges.push({id:'ba',from:'b',to:'a',points:[[200,60],[100,60]],label:'Return',labelX:150,labelY:70},
 {id:'again',from:'a',to:'b',points:[[100,70],[200,70]],label:'Admission',labelX:150,labelY:80},
 {id:'work',from:'b',to:'d',points:[[300,60],[600,60]],label:'Later work',labelX:450,labelY:80});
 const s=M.scenarios[0];s.steps.push({edge:'again',from:'a',to:'b',title:'Admit'});
 s.routes.forEach(route=>{route.edges=['ab','ba','again'];route.branches=[{edges:['work'],afterStep:2}]});
 s.controls[0].effect.outcome='limits';
 s.controls.push({id:'deny',kind:'proposed',title:'Deny admission',effect:{outcome:'blocks',basis:'hypothetical',step:2,edge:'again',arrival:true,label:'Denied',reason:'Admission denied',conditions:'If enforced',residual:'Earlier work remains',marker:{at:.5,x:20,y:120,w:180}}});
 state.proposal='deny';state.control='deny';render();`);
 for (const output of r.outputs()) {
  assert.match(output,/data-node="b"[^>]*data-path-state="active"/);
  assert.match(output,/data-edge="work" data-path-state="unreached"/);
 }
 r.run("state.proposal=null;state.control=null;render()");
 assert.equal(r.run("ControlEffects.resolve(M.scenarios[0],null,{sourceId:'one',routeId:'r'}).controls[0].id"),'scoped');
 for (const output of r.outputs())
  assert.match(output,/data-edge="work" data-path-state="active"/);
});
test('arrival keeps incoming delivery and owner visible, stops navigation, and exports the same decision',()=>{
 const r=twoStepRenderer();
 r.run(`M.scenarios[0].controls[0].effect.arrival=true;
 M.edges.push({id:'ac',from:'a',to:'c',points:[[100,60],[400,60]],label:'Context',labelX:250,labelY:60});
 M.overviewEdges=['ac'];
 state.step=1;render();`);
 assert.equal(r.run('state.step'),0);
 r.location.hash='#scenario=routed&route=r&source=one&control=scoped&step=2';
 r.run('readHash()');
 assert.equal(r.run('state.step'),0);
 assert.match(r.location.hash,/step=1/);
 assert.match(r.elements.get('trace-navigation').innerHTML,/id="next"[^>]*disabled/);
 for(const output of r.outputs()) {
  assert.match(output,/data-edge="ab" data-path-state="active"/);
  assert.match(output,/data-node="b"[^>]*data-path-state="active"/);
  assert.match(output,/data-edge="bc" data-path-state="unreached"/);
  assert.match(output,/data-edge="ac" data-path-state="context"/);
  assert.match(output,/data-barrier="true" data-arrival="true"/);
  assert.match(output,/decision after arrival/);
  assert.doesNotMatch(output,/data-route-part="unreached"/);
 }
 r.run("state.source='two';render()");
 for(const output of r.outputs()) {
  assert.match(output,/data-edge="bc" data-path-state="active"/);
  assert.match(output,/data-edge="ac" data-path-state="context"/);
  assert.doesNotMatch(output,/data-barrier="true"/);
 }
});
test('data-only block leaves ordinary navigation and SVG flow active and shows the authored invariant',()=>{
 const r=twoStepRenderer();
 r.run(`const c=M.scenarios[0].controls[0];c.description='Remove the bearer before forwarding';
 c.effect.traffic='continues';c.effect.reason='Prevent disclosure';c.effect.residual='Ordinary request still proceeds';
 M.scenarios[0].summary='The existing gateway strips the credential before forwarding.';
 state.step=1;state.tab='controls';render();`);
 assert.equal(r.run('state.step'),1);
 assert.match(r.elements.get('trace').innerHTML,/Remove the bearer before forwarding/);
 assert.match(r.elements.get('trace').innerHTML,/Prevent disclosure/);
 assert.match(r.elements.get('trace').innerHTML,/Ordinary request still proceeds/);
 for(const output of r.outputs()) {
  assert.match(output,/data-edge="bc" data-path-state="active"/);
  assert.match(output,/data-barrier="false"/);
  assert.match(output,/this effect leaves traffic open/);
 }
 r.run("state.tab='path';render()");
 for(const output of [r.elements.get('trace').innerHTML,r.run('exportMapSvg()')]) {
  assert.match(output,/Assessment context/);
  assert.match(output,/existing gateway strips the credential/);
  assert.doesNotMatch(output,/before control effects/);
 }
 assert.match(r.run('exportMapSvg()'),/Ordinary request still proceeds/);
});
test('separate deliveries retain a first-delivery prerequisite at a later barrier but not at an earlier barrier',()=>{
 const r=renderer();
 r.run(`M.nodes.push({id:'d',title:'Application',subtitle:'',description:'Application',x:500,y:100,w:100,h:60});
 M.edges.push({id:'ba',from:'b',to:'a',points:[[200,60],[100,60]],label:'First response',labelX:150,labelY:70},
 {id:'second',from:'a',to:'b',points:[[100,70],[200,70]],label:'Second request',labelX:150,labelY:80},
 {id:'delivery',from:'b',to:'d',points:[[300,60],[500,100]],label:'First delivery',labelX:400,labelY:80});
 const s=M.scenarios[0];s.steps.push({edge:'second',from:'a',to:'b',title:'Second request'});
 s.routes.forEach(route=>{route.edges=['ab','ba','second'];route.branches=[{edges:['delivery'],afterStep:1}]});
 const later=s.controls[0];later.effect.step=2;later.effect.edge='second';
 state.step=1;render();`);
 for (const output of r.outputs()) {
  assert.match(output,/data-edge="ab" data-path-state="active"/);
  assert.match(output,/data-edge="delivery" data-path-state="active"/);
  assert.match(output,/data-edge="second" data-path-state="stopped"/);
 }
 r.run(`M.scenarios[0].controls.push({id:'earlier',kind:'proposed',title:'Early framing rejection',effect:{outcome:'blocks',basis:'hypothetical',step:1,edge:'ab',label:'Rejected',reason:'Invalid framing',conditions:'If enforced',residual:'No first delivery',marker:{at:.5,x:20,y:120,w:180}}});state.proposal='earlier';state.control='earlier';render();`);
 assert.equal(r.run('state.step'),0);
 for (const output of r.outputs()) {
  assert.match(output,/data-edge="ab" data-path-state="stopped"/);
  assert.match(output,/data-edge="delivery" data-path-state="unreached"/);
  assert.match(output,/data-edge="second" data-path-state="unreached"/);
 }
 r.run("state.proposal=null;state.control=null;render()");
 assert.match(r.elements.get('map').innerHTML,/data-edge="delivery" data-path-state="active"/);
});
test('SVG explains both continuing prevention and a separate active barrier',()=>{
 const r=renderer();
 r.run(`M.scenarios[0].controls.push({id:'redact',kind:'existing',title:'Remove credential',description:'Remove credential',effect:{outcome:'blocks',basis:'declared',traffic:'continues',label:'Credential withheld',reason:'No disclosure',conditions:'Redaction enforced',residual:'Ordinary processing continues'}});render();`);
 const svg=r.run('exportMapSvg()');
 const text=svg.replace(/<[^>]+>/g,' ').replace(/\s+/g,' ');
 assert.match(svg,/Role denied/);
 assert.match(svg,/Credential withheld/);
 assert.match(svg,/Ordinary processing continues/);
 assert.match(text,/Redaction enforced/);
 assert.match(text,/A separate barrier may stop the flow before this effect occurs/);
});
test('actual renderer respects unordered empty edge overrides and exports relationship scope',()=>{
 const r=renderer();
 r.run("state.scenario='unordered'; state.source='one'; state.tab='path'; render()");
 assert.match(r.elements.get('map').innerHTML,/data-edge="ab" data-path-state="context"/);
 assert.match(r.elements.get('map').innerHTML,/data-node="a"[^>]*data-path-state="active"/);
 r.run("state.source='two';render()");
 assert.match(r.elements.get('map').innerHTML,/data-node="a"[^>]*data-path-state="context"/);
 assert.match(r.elements.get('map').innerHTML,/data-node="c"[^>]*data-path-state="active"/);
 assert.match(r.run('exportMapSvg()'),/supplied for selected starting position; order unestablished/);
 assert.doesNotMatch(r.location.hash,/route=/);
});

test('inspected control locus is visible and exported independently of the normal transit outline',()=>{
 const r=renderer();
 r.run("M.scenarios[0].controls[0].nodes=['a'];state.tab='controls';render()");
 for(const output of r.outputs()) {
  const node=output.match(/<g data-node="a"[\s\S]*?<\/g><\/g>/)?.[0];
  assert.ok(node);assert.match(node,/data-route-role="transit"/);
  assert.match(node,/data-control-owner="scoped"/);assert.match(node,/selected control locus: Scoped barrier/);
 }
 assert.match(r.elements.get('trace').innerHTML,/C marks the selected control locus/);
 assert.match(r.run('exportMapSvg()'),/C badge: selected control locus/);
 r.run("state.source='two';render()");
 assert.doesNotMatch(r.elements.get('map').innerHTML,/data-control-owner="scoped"/);
});
test('neutral transport retains baseline and preview content through navigation, toggling and SVG export',()=>{
 const r=renderer();
 r.run(`const s=M.scenarios[0];s.controls=[];s.summary='In the assessed baseline the request carries a credential.';s.steps[0].title='Send request';s.steps[0].description='The request reaches the recipient.';
 s.controls.push({id:'redact',title:'Remove credential',description:'Remove credential before sending.',kind:'proposed',nodes:['a'],effect:{outcome:'blocks',basis:'hypothetical',traffic:'continues',label:'Credential withheld',reason:'The request carries no credential.',conditions:'If redaction is enforced.',residual:'Ordinary request continues.'}});state.control=null;render();`);
 assert.match(r.elements.get('trace').innerHTML,/baseline the request carries a credential/);
 assert.match(r.run('exportMapSvg()'),/Assessment context/);
 r.click({'data-control':true,dataset:{control:'redact'}});
 assert.equal(r.run('state.proposal'),'redact');
 r.click({id:'next'});
 assert.equal(r.run('state.step'),0);
 const trace=r.elements.get('trace').innerHTML;
 assert.match(trace,/Assessment context/);assert.match(trace,/The request carries no credential/);assert.match(trace,/The request reaches the recipient/);
 let svg=r.run('exportMapSvg()');assert.match(svg,/Assessment context/);assert.match(svg,/Ordinary request continues/);assert.match(svg,/data-edge="ab" data-path-state="active"/);
 r.click({'data-control':true,dataset:{control:'redact'}});
 assert.equal(r.run('state.proposal'),null);assert.equal(r.run('state.step'),-1);
 assert.doesNotMatch(r.location.hash,/preview=/);
 svg=r.run('exportMapSvg()');assert.match(svg,/Assessment context/);assert.doesNotMatch(svg,/Credential withheld|Ordinary request continues/);assert.match(svg,/data-edge="ab" data-path-state="active"/);
});



test('later-authored crossing inactive paths and their labels paint below active routes in map and SVG',()=>{
 const r=renderer();
 r.run(`M.scenarios[0].controls[0].effect.arrival=true;
 M.edges.push({id:'late',from:'b',to:'c',points:[[200,80],[150,50],[400,100]],label:'Inactive crossing label',labelX:150,labelY:50},
 {id:'context-cross',from:'a',to:'c',points:[[100,100],[150,50],[400,100]],label:'Context crossing label',labelX:150,labelY:50});
 M.scenarios[0].steps.push({edge:'late',from:'b',to:'c',title:'Later work'});
 M.scenarios[0].routes[0].edges.push('late');render();`);
 for (const output of r.outputs()) {
  assert.match(output,/data-edge="ab" data-path-state="active"/);
  assert.match(output,/data-edge="late" data-path-state="unreached"/);
  const active=output.indexOf('data-edge="ab"');
  for(const id of ['late','context-cross']) {
   const caption=output.indexOf(`data-caption="edge:${id}"`);
   assert.ok(caption>=0 && caption<active,`${id}: visible caption must precede the active route`);
  }
  assert.ok(output.indexOf('data-edge-layer="highlighted"')<active);
  assert.ok(active<output.indexOf('data-node="a"'),'nodes stay above connections');
  assert.ok(output.indexOf('data-node="c"')<output.indexOf('data-barrier="true"'),'control annotation stays above nodes');
 }
});

test('muted tail of a later-authored stopped edge paints below an earlier active prerequisite',()=>{
 const r=renderer();
 r.run(`M.edges.unshift({id:'prerequisite',from:'a',to:'c',points:[[100,60],[180,50],[400,80]],label:'Prerequisite',labelX:180,labelY:50});
 M.scenarios[0].routes[0].branches=[{edges:['prerequisite'],beforeStep:1}];render();`);
 for (const output of r.outputs()) {
  assert.match(output,/data-edge="prerequisite" data-path-state="active"/);
  assert.match(output,/data-edge="ab" data-path-state="stopped"/);
  assert.ok(output.indexOf('data-edge-tail="ab"')<output.indexOf('data-edge="prerequisite"'),'unreached tail cannot cover another active route');
  assert.ok(output.indexOf('data-route-part="unreached"')<output.indexOf('data-edge-layer="highlighted"'));
 }
});

test('proposed control headings, markers and cards stay concise while preserving conditional semantics',()=>{
 const r=renderer();
 r.run(`M.scenarios[0].controls=[{id:'proposal',kind:'proposed',title:'Admission policy',description:'Check the caller before admission',effect:{outcome:'blocks',basis:'hypothetical',step:1,edge:'ab',label:'Denied',reason:'Unauthorized caller denied',conditions:'Caller identity established and policy enforced',residual:'Authorized callers remain',marker:{at:.5,x:20,y:120,w:180}}}];
 state.proposal='proposal';state.control='proposal';state.tab='controls';render();`);
 assert.match(r.elements.get('trace').innerHTML,/>Proposed controls</);
 for (const output of [r.elements.get('trace').innerHTML,r.elements.get('map').innerHTML,r.run('exportMapSvg()')]) {
  assert.match(output,/Proposed control/);assert.match(output,/Would block/);
 }
 assert.match(r.elements.get('trace').innerHTML,/Caller identity established and policy enforced/);
 assert.match(r.elements.get('trace').innerHTML,/Authorized callers remain/);
 r.run("state.tab='path';render()");
 assert.match(r.elements.get('trace').innerHTML,/Proposed control · would stop at/);
 const unmapped=r.run("effectCard({id:'unmapped',kind:'proposed',title:'Boundary',description:'Context'})");
 assert.match(unmapped,/Proposed control/);assert.match(unmapped,/Effect not mapped/);
 assert.match(asset('explorer.html'),/class="proposed">Proposed control</);
});

test('rendered and exported arrowheads keep fixed dimensions under step focus',()=>{
 const r=renderer();
 r.run("M.scenarios[0].controls=[];state.control=null;render()");
 const marker=r.elements.get('map').innerHTML.match(/<marker\b[^>]+>/)[0];
 r.click({id:'next'});
 for(const output of r.outputs()){
  assert.equal(output.match(/<marker\b[^>]+>/)[0],marker);
  assert.match(output,/markerUnits="userSpaceOnUse"/);
  assert.match(output,/marker-end="url\(#arrow-/);
  assert.doesNotMatch(output,/markerUnits="strokeWidth"/);
 }
});

test('control cards retain their full label and basis when resized and exported',()=>{
 const r=renderer();
 const card=()=>r.elements.get('map').innerHTML.match(/<g[^>]*data-barrier="true"[\s\S]*?<\/g>/)?.[0];
 r.run("M.scenarios[0].controls[0].effect.label='Verify the subject and issuer before granting the requested capability';render()");
 let marker=card();
 assert.ok(marker);
 assert.match(marker,/requested/);assert.match(marker,/capability/);
 assert.match(r.run('exportMapSvg()'),/capability<\/text>/);
 // Exercise a narrow card variant with a wider evidence-basis heading.
 r.run("const e=M.scenarios[0].controls[0].effect;e.label='Denied';e.basis='verified';e.marker.w=160;render()");
 marker=card();
 assert.match(marker,/VERIFIED · SUPPLIED EVIDENCE/);
 const rect=marker.match(/<rect[^>]+>/)[0];
 const x=Number(rect.match(/\sx="([\d.]+)"/)[1]), width=Number(rect.match(/\swidth="([\d.]+)"/)[1]);
 const textX=Number(marker.match(/<text x="([\d.]+)"/)[1]);
 const header=r.run('measureSvgText(ControlEffects.basis(M.scenarios[0].controls[0]),10,700).w');
 assert.ok(textX>=x && textX+header<=x+width,'card contains its basis header');
});

test('SVG export retains dimensions and fonts while clearing only the clone transform',()=>{
 const r=renderer();
 r.run("globalThis.getComputedStyle=()=>({fontFamily:'Inter, system-ui, sans-serif'});state.x=30;state.zoom=2;transform()");
 const viewport=r.elements.get('viewport'), transform=viewport.getAttribute('transform');
 r.run('exportMapSvg()');
 const exported=r.exported, height=Number(exported.getAttribute('height'));
 assert.equal(exported.getAttribute('xmlns'),'http://www.w3.org/2000/svg');
 assert.equal(exported.getAttribute('width'),'700');
 assert.ok(height>400,'export includes space for the assessment annotations');
 assert.equal(exported.getAttribute('viewBox'),`0 0 700 ${height}`);
 assert.match(exported.getAttribute('style'),/font-family:Inter, system-ui, sans-serif/);
 assert.equal(exported.querySelector('#viewport').getAttribute('transform'),null);
 assert.equal(viewport.getAttribute('transform'),transform,'export leaves the live view intact');
});

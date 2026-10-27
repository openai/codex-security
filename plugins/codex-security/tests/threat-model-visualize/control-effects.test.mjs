import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import vm from 'node:vm';
import test from 'node:test';
const engine = vm.runInNewContext(readFileSync(new URL('../../skills/threat-model-visualize/assets/control-effects.js', import.meta.url), 'utf8') + '\nControlEffects;');
const control = (id, outcome, step, kind='existing', basis='declared', extra={}) => ({id, kind, effect:{outcome,step,basis,...extra}});
test('existing controls apply by default; proposals require selection and do not mutate source', () => {
 const s={steps:[{},{}],controls:[control('proposal','blocks',1,'proposed','hypothetical'), control('bound','limits',2)]};
 const before=JSON.stringify(s);
 assert.equal(engine.resolve(s,null).stop,-1);
 assert.equal(engine.resolve(s,'proposal').stop,0);
 assert.equal(engine.resolve(s,null).stop,-1);
 assert.equal(JSON.stringify(s),before);
});
test('first block wins; an equal-step proposal cannot displace an existing control',()=>{
 const s={controls:[control('later','blocks',3),control('proposed','blocks',2,'proposed','hypothetical'),control('existing','blocks',2)]};
 assert.equal(engine.resolve(s,'proposed').blocker.id,'existing');
 s.controls.push(control('earlier','blocks',1));
 assert.equal(engine.resolve(s,'proposed').blocker.id,'earlier');
});
test('a prevented consequence with continuing traffic never wins a stop, even before a later barrier',()=>{
 const data=control('redact','blocks',1); data.effect.traffic='continues';
 const later=control('deny','blocks',2); later.effect.arrival=true;
 const s={controls:[data,later]};
 assert.equal(engine.resolve(s,null).blocker.id,'deny');
 assert.equal(engine.resolve(s,null).stop,1);
 assert.equal(engine.resolve({controls:[data]},null).stop,-1);
});
test('limiting, detective, ineffective, unknown and unmapped controls never stop a trace',()=>{
 const s={controls:['limits','detects','does-not-block','unknown'].map((outcome,i)=>control('c'+i,outcome,1))};
 s.controls.push({id:'legacy',kind:'existing',nodes:['x']});
 s.controls.push(control('unsupported','blocks',1,'existing','unverified'));
 assert.equal(engine.resolve(s,null).stop,-1);
});
test('barrier split follows polyline distance and orientation, including a repeated point',()=>{
 const split=engine.split([[0,0],[0,0],[100,0],[100,100]],.75);
 assert.deepEqual(Array.from(split.point),[100,50]);
 assert.deepEqual(Array.from(split.normal),[-1,0]);
 assert.deepEqual(Array.from(split.before.at(-1)),Array.from(split.after[0]));
 assert.throws(()=>engine.split([[0,0],[0,0]],.5),/nonzero/);
});
test('source and route control scope intersect and switching clears stale selection and blocker',()=>{
 const scoped={...control('scoped','blocks',1),sourceIds:['a'],routeIds:['internal']};
 const proposal={...control('preview','blocks',1,'proposed','hypothetical'),sourceIds:['a']};
 const s={controls:[scoped,proposal,control('shared','limits',1)]};
 const before=JSON.stringify(s), current={control:'scoped',proposal:'preview'};
 const a={sourceId:'a',routeId:'internal'}, b={sourceId:'b',routeId:'internal'}, otherRoute={sourceId:'a',routeId:'public'};
 assert.equal(engine.resolve(s,null,a).blocker.id,'scoped');
 assert.equal(engine.resolve(s,null,b).blocker,null);
 assert.equal(engine.resolve(s,null,otherRoute).blocker,null);
 assert.equal(engine.resolve(s,null).blocker,null);
 assert.deepEqual(Array.from(engine.applicable(s,b),c=>c.id),['shared']);
 const cleared=engine.selection(s,current,b);
 assert.equal(cleared.control,null); assert.equal(cleared.proposal,null);
 assert.equal(engine.resolve(s,cleared.proposal,b).stop,-1);
 assert.equal(engine.selection(s,current,otherRoute).control,null);
 assert.equal(engine.selection(s,current,otherRoute).proposal,'preview');
 assert.equal(engine.selection(s,current,a).control,'scoped');
 assert.equal(JSON.stringify(s),before);
});
test('legacy controls remain scenario-wide and route-only scope does not require a source',()=>{
 const s={controls:[{...control('r','blocks',1),routeIds:['r']},control('legacy','limits',1)]};
 assert.equal(engine.resolve(s,null,{routeId:'r'}).blocker.id,'r');
 assert.deepEqual(Array.from(engine.applicable(s,{routeId:'other'}),c=>c.id),['legacy']);
 assert.equal(engine.selection(s,{control:'legacy',proposal:'legacy'},{}).control,'legacy');
 assert.equal(engine.selection(s,{control:'legacy',proposal:'legacy'},{}).proposal,null);
});
test('control captions preserve evidence basis, conditional proposals and traffic semantics',()=>{
 const cases=[
  {value:control('declared','blocks',1),caption:/^Blocks.*if enforced/,heading:/DECLARED.*IF ENFORCED/},
  {value:control('verified','blocks',1,'existing','verified'),caption:/^Blocks.*verified.*supplied evidence/},
  {value:control('proposed','blocks',1,'proposed','hypothetical'),caption:/^Would block/},
  {value:control('existing-redaction','blocks',1,'existing','declared',{traffic:'continues'}),caption:/^Blocks.*leaves traffic open/},
  {value:control('proposed-redaction','blocks',1,'proposed','hypothetical',{traffic:'continues'}),caption:/^Would block.*leaves traffic open/},
  {value:control('existing-arrival','blocks',1,'existing','declared',{arrival:true}),caption:/^Blocks.*decision after arrival/},
  {value:control('proposed-arrival','blocks',1,'proposed','hypothetical',{arrival:true}),caption:/^Would block.*decision after arrival/},
  {value:control('existing-limit','limits',1),caption:/^Limits impact.*path continues/},
  {value:control('proposed-limit','limits',1,'proposed','hypothetical'),caption:/^Would limit impact.*path continues/},
  {value:control('proposed-detection','detects',1,'proposed','hypothetical'),caption:/^Would detect activity.*path continues/},
  {value:control('ineffective-proposal','does-not-block',1,'proposed','hypothetical'),caption:/^Would not block/},
  {value:control('unknown-proposal','unknown',1,'proposed','hypothetical'),caption:/Effect not established/},
  {value:{id:'unmapped',kind:'existing'},caption:/Effect not mapped/}
 ];
 for(const {value,caption,heading} of cases) {
  assert.match(engine.caption(value),caption,value.id);
  if(value.kind==='proposed')assert.match(engine.basis(value),/Proposed control/,value.id);
  else if(heading)assert.match(engine.basis(value),heading,value.id);
 }
});

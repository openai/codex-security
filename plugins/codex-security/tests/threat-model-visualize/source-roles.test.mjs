import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import vm from 'node:vm';
const roles = vm.runInNewContext(readFileSync(new URL('../../skills/threat-model-visualize/assets/source-roles.js', import.meta.url), 'utf8') + '\nSourceRoles;');

const participant={id:'normal',node:'browser',kind:'authorized-user',label:'Dashboard user'};
const adversary={id:'attacker',node:'browser',kind:'adversary',basis:'scenario-assumption',label:'Viewer',authority:'Valid viewer session'};
const model={participants:[participant]};
test('authenticated adversary overrides normal use only in the selected scenario',()=>{
  const snapshot=JSON.stringify(model);
  const selected=roles.resolve(model,{sources:[adversary]},null);
  assert.equal(selected.nodes.get('browser').kind,'adversary');
  assert.equal(selected.sources[0].authority,'Valid viewer session');
  assert.equal(roles.resolve(model,null,null).nodes.get('browser').kind,'authorized-user');
  assert.equal(JSON.stringify(model),snapshot);
});
test('compromise is scoped to its supported route and never bleeds to overview',()=>{
  const s={routes:[{id:'public'},{id:'internal'}],sources:[{...adversary,node:'worker',kind:'compromised-component',routeIds:['internal']}]};
  assert.equal(roles.resolve(model,s,'public').sources.length,0);
  assert.equal(roles.resolve(model,s,'internal').nodes.get('worker').kind,'compromised-component');
  assert.equal(roles.resolve(model,null,null).nodes.has('worker'),false);
});
test('unmapped attacker is retained without painting the receiving listener',()=>{
  const r=roles.resolve({participants:[]},{sources:[{...adversary,node:null}]},null);
  assert.equal(r.sources.length,1);
  assert.equal(r.nodes.size,0);
});
test('alternative footholds do not silently become a compromised component',()=>{
  const s={sourceMode:'alternatives',sources:[adversary,{...adversary,id:'compromised',kind:'compromised-component'}]};
  const r=roles.resolve(model,s,null);
  assert.equal(r.nodes.get('browser').kind,'adversary');
  assert.equal(r.sources.length,1);
  assert.equal(r.allSources.length,2);
  assert.equal(roles.resolve(model,s,null,'compromised').nodes.get('browser').kind,'compromised-component');
  assert.equal(roles.resolve(model,s,null,'invalid-id').selected.id,'attacker');
});
test('unordered source relationships replace each dimension independently, including explicit empty arrays',()=>{
  const s={steps:[],sourceMode:'alternatives',affectedNodes:['legacy'],affectedEdges:['shared'],sources:[
    {...adversary,id:'a',node:'origin-not-related',relatedNodes:['helper-a'],relatedEdges:[]},
    {...adversary,id:'b',relatedNodes:[]},
    {...adversary,id:'legacy'}
  ]};
  const before=JSON.stringify(s);
  const a=roles.resolve(model,s,null,'a');
  assert.deepEqual(a.relatedNodes,['helper-a']);
  assert.deepEqual(a.relatedEdges,[]);
  assert(!a.relatedNodes.includes('origin-not-related'));
  const b=roles.resolve(model,s,null,'b');
  assert.deepEqual(b.relatedNodes,[]);
  assert.deepEqual(b.relatedEdges,['shared']);
  const old=roles.resolve(model,s,null,'legacy');
  assert.deepEqual(old.relatedNodes,['legacy']);
  assert.deepEqual(old.relatedEdges,['shared']);
  assert.equal(JSON.stringify(s),before);
});

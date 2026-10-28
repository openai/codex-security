import {test} from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import vm from 'node:vm';
const RoutePaths = vm.runInNewContext(readFileSync(new URL('../../skills/threat-model-visualize/assets/route-paths.js', import.meta.url), 'utf8') + '\nRoutePaths;');

const model = {edges: [
  ['ingress','browser','proxy'], ['java','proxy','java'], ['node','proxy','node'],
  ['java-api','java','api'], ['node-api','node','api'], ['db','api','db'],
  ['auth','java','identity'], ['sessions','identity','redis'], ['api-auth','api','identity']
].map(([id,from,to])=>({id,from,to}))};
const scenario = {
  steps:[{edge:'java-api',from:'java',to:'api'}], focusNodes:['api'],
  routes:[{id:'java',edges:['ingress','java','java-api','db'],branches:[
    {edges:['auth','sessions']},{edges:['api-auth','sessions']}
  ]}]
};
test('all transit hops and authorization calls remain visible; focus is separate',()=>{
  const r=RoutePaths.resolve(model,scenario,'java');
  assert.deepEqual([...r.activeNodes].sort(),['api','browser','db','identity','java','proxy','redis']);
  assert(r.activeEdges.has('ingress') && r.activeEdges.has('java'));
  assert.deepEqual([...r.focusNodes],['api']);
  assert(!r.focusNodes.has('proxy'));
});
test('a denied API call stops downstream work without hiding earlier authentication',()=>{
  const r=RoutePaths.resolve(model,scenario,'java',0);
  assert(r.activeNodes.has('proxy') && r.activeNodes.has('java'));
  assert(!r.activeNodes.has('api') && !r.activeNodes.has('db'));
  assert(r.unreachedEdges.has('db') && r.unreachedEdges.has('api-auth'));
  assert(r.activeEdges.has('auth') && r.activeNodes.has('redis'));
  assert(!r.unreachedEdges.has('sessions'));
  assert(!r.unreachedNodes.has('redis'));
});
test('receipt preserves the decision owner but does not activate its arbitrary downstream branches',()=>{
 const s={...scenario,routes:[{...scenario.routes[0],branches:[{edges:['api-auth']},{edges:['auth']}]}]};
 const r=RoutePaths.resolve(model,s,'java',0,true);
 assert(r.activeNodes.has('api') && r.activeEdges.has('java-api'));
 assert(r.unreachedEdges.has('db') && r.unreachedEdges.has('api-auth'));
 assert(r.activeEdges.has('auth'));
});
test('ordered prerequisite on an earlier owner survives the later stop but not an earlier one',()=>{
 const s={steps:[{edge:'java'},{edge:'java-api'}],routes:[{id:'java',edges:['ingress','java','java-api','db'],branches:[{edges:['auth','sessions'],beforeStep:2}]}]};
 const later=RoutePaths.resolve(model,s,'java',1,true);
 assert(later.activeEdges.has('auth') && later.activeEdges.has('sessions'));
 assert(later.activeNodes.has('api') && later.unreachedEdges.has('db'));
 const earlier=RoutePaths.resolve(model,s,'java',0);
 assert(earlier.unreachedEdges.has('auth') && !earlier.activeEdges.has('sessions'));
});
test('a decision retains its explicit prerequisite without enabling other work from the same component',()=>{
  const s={...scenario, routes:[{...scenario.routes[0], branches:[
    {edges:['api-auth','auth-return'],beforeStep:1}, {edges:['sessions']},
    {edges:['api-write']}
  ]}]};
  const m={edges:[...model.edges,{id:'api-write',from:'api',to:'other-store'},
    {id:'auth-return',from:'identity',to:'api'}]};
  for (const branches of [s.routes[0].branches, [...s.routes[0].branches].reverse()]) {
    s.routes[0].branches=branches;
    const r=RoutePaths.resolve(m,s,'java',0,true);
    assert(r.activeEdges.has('api-auth') && r.activeEdges.has('sessions'));
    assert(r.activeNodes.has('api') && r.activeNodes.has('identity'));
    assert(r.unreachedEdges.has('api-write') && r.unreachedEdges.has('db'));
    assert(!r.activeEdges.has('api-write') && !r.activeNodes.has('other-store'));
    const denied=RoutePaths.resolve(m,s,'java',0);
    assert(!denied.activeEdges.has('api-auth') && !denied.activeEdges.has('sessions'));
  }
});
test('prerequisite replies do not reactivate a denied owner across branch boundaries',()=>{
  const m={edges:[['request','caller','gateway'],['forward','gateway','service'],
    ['call','gateway','policy'],['reply','policy','gateway'],['write','gateway','store'],
    ['earlier','caller','gateway'],['independent','caller','policy']]
    .map(([id,from,to])=>({id,from,to}))};
  for (const {grouping,branches,orders,predecisionWrite=false} of [
    {grouping:'reply and write',branches:[{edges:['call'],beforeStep:1},{edges:['reply','write']}],orders:[[0,1]]},
    {grouping:'split',branches:[{edges:['call'],beforeStep:1},{edges:['reply']},{edges:['write']}],orders:[[0,1,2],[0,2,1],[2,0,1]]},
    {grouping:'call and reply',branches:[{edges:['call','reply'],beforeStep:1},{edges:['write']}],orders:[[0,1],[1,0]]},
    {grouping:'explicit predecision write',branches:[{edges:['call','reply','write'],beforeStep:1}],orders:[[0]],predecisionWrite:true}
  ]) {
    for (const order of orders) {
      for (const earlier of [false,true]) {
        const s={steps:[{edge:'request'}],routes:[{id:'r',edges:['request','forward'],
          branches:[...order.map(i=>branches[i]),...(earlier?[{edges:['earlier'],beforeStep:1}]:[])]}]};
        for (const stop of [0,-1]) {
          const r=RoutePaths.resolve(m,s,'r',stop,true), write=stop<0 || earlier || predecisionWrite;
          const context=JSON.stringify({grouping,order,earlier,stop});
          assert.equal(r.activeEdges.has('write'),write,context);
          assert.equal(r.unreachedEdges.has('write'),!write,context);
          assert.equal(r.activeNodes.has('store'),write,context);
          assert(r.activeNodes.has('gateway') && r.activeEdges.has('call') && r.activeEdges.has('reply'));
          assert.equal(r.activeEdges.has('forward'),stop<0,context);
          const writeBranch=r.branchStates.find(({branch})=>branch.edges.includes('write'));
          assert.equal(writeBranch.active,write,context);
          assert.equal(writeBranch.reached,write?writeBranch.branch.edges.length:grouping==='reply and write'?1:0,context);
        }
      }
    }
  }
  // The reply is first reached by the prerequisite, then by an independent path.
  for (const replies of [[{edges:['reply']},{edges:['write']}],[{edges:['reply','write']}]]) {
    const s={steps:[{edge:'request'}],routes:[{id:'r',edges:['request','forward'],branches:[
      {edges:['call'],beforeStep:1},...replies,{edges:['independent'],beforeStep:1}
    ]}]};
    assert(RoutePaths.resolve(m,s,'r',0,true).activeEdges.has('write'));
  }
});
test('a branch reached through another branch is independent of array order',()=>{
  const m={edges:[['ab','a','b'],['bc','b','c'],['cd','c','d'],['ac','a','c']]
    .map(([id,from,to])=>({id,from,to}))};
  for (const timing of [{},{beforeStep:2},{afterStep:1}]) {
    const branches=[{edges:['cd']},{edges:['ac'],...timing}];
    for (const order of [branches,[...branches].reverse()]) {
      const s={steps:[{edge:'ab'},{edge:'bc'}],routes:[{id:'r',edges:['ab','bc'],branches:order}]};
      const before=JSON.stringify(s), r=RoutePaths.resolve(m,s,'r',1);
      assert.deepEqual([...r.activeNodes].sort(),['a','b','c','d']);
      assert(r.activeEdges.has('cd') && !r.unreachedEdges.has('cd'));
      assert(!r.unreachedNodes.has('d'));
      assert.deepEqual(Array.from(r.branchStates,item=>item.active),[true,true]);
      if (timing.beforeStep || timing.afterStep) {
        const earlier=RoutePaths.resolve(m,s,'r',0);
        assert(!earlier.activeEdges.has('ac') && !earlier.activeEdges.has('cd'));
        assert.deepEqual(Array.from(earlier.branchStates,item=>item.active),[false,false]);
      }
      assert.equal(JSON.stringify(s),before);
    }
  }
});
test('a prerequisite at the stopped destination requires arrival and restores with the route',()=>{
  const s={...scenario,routes:[{...scenario.routes[0],branches:[
    {edges:['api-auth','sessions'],beforeStep:1}
  ]}]};
  const before=JSON.stringify(s);
  const denied=RoutePaths.resolve(model,s,'java',0);
  assert(!denied.activeNodes.has('api') && !denied.activeNodes.has('identity'));
  assert(denied.unreachedEdges.has('api-auth') && denied.unreachedEdges.has('sessions'));
  assert.equal(denied.branchStates[0].active,false);
  const arrived=RoutePaths.resolve(model,s,'java',0,true);
  assert(arrived.activeNodes.has('api') && arrived.activeEdges.has('api-auth'));
  assert.equal(arrived.branchStates[0].active,true);
  assert.equal(RoutePaths.resolve(model,s,'java').branchStates[0].active,true);
  assert.equal(JSON.stringify(s),before);
});
test('branch occurrence status does not inherit an edge reached by another branch',()=>{
  const s={...scenario,routes:[{...scenario.routes[0],branches:[
    {edges:['auth','sessions']}, {edges:['api-auth','sessions'],beforeStep:1}
  ]}]};
  const r=RoutePaths.resolve(model,s,'java',0);
  assert(r.activeEdges.has('sessions'));
  assert.deepEqual(Array.from(r.branchStates,item=>item.active),[true,false]);
});
test('a prerequisite belongs to its decision occurrence even if that node was reached earlier',()=>{
  const m={edges:[['ab','a','b'],['bc','b','c'],['cb','c','b'],['bd','b','d'],
    ['be','b','identity'],['ax','a','x'],['xb','x','b']].map(([id,from,to])=>({id,from,to}))};
  const s={steps:[{edge:'bc',from:'b',to:'c'},{edge:'cb',from:'c',to:'b'}],routes:[
    {id:'loop',edges:['ab','bc','cb','bd'],branches:[{edges:['be'],beforeStep:2}]},
    {id:'alternate',edges:['ax','xb','bc','cb','bd'],branches:[{edges:['be'],beforeStep:2}]}
  ]};
  for (const route of ['loop','alternate']) {
    const earlier=RoutePaths.resolve(m,s,route,0);
    assert(earlier.activeNodes.has('b'));
    assert(earlier.unreachedEdges.has('be') && !earlier.activeEdges.has('be'));
    assert(RoutePaths.resolve(m,s,route,1).unreachedEdges.has('be'));
    assert(RoutePaths.resolve(m,s,route,1,true).activeEdges.has('be'));
    assert(RoutePaths.resolve(m,s,route).activeEdges.has('be'));
  }
});
test('later work belongs to the successful action occurrence, not an earlier visit or receipt',()=>{
  const m={edges:[['ab','a','b'],['bc','b','c'],['cb','c','b'],['bd','b','d'],
    ['be','b','store'],['ef','store','result']].map(([id,from,to])=>({id,from,to}))};
  const s={steps:[{edge:'bc'},{edge:'cb'},{edge:'bd'}],routes:[{
    id:'r',edges:['ab','bc','cb','bd'],branches:[
      {edges:['be'],afterStep:2},{edges:['ef']}
    ]}]};
  for (const arrival of [false,true]) {
    for (const stop of [0,1]) {
      const r=RoutePaths.resolve(m,s,'r',stop,arrival);
      assert(r.activeNodes.has('b'));
      assert(r.unreachedEdges.has('be') && r.unreachedEdges.has('ef'));
      assert(!r.activeEdges.has('be') && !r.activeEdges.has('ef'));
    }
    const later=RoutePaths.resolve(m,s,'r',2,arrival);
    assert(later.activeEdges.has('be') && later.activeEdges.has('ef'));
  }
  const restored=RoutePaths.resolve(m,s,'r');
  assert(restored.activeEdges.has('be') && restored.activeEdges.has('ef'));
});
test('later work also requires its branch origin to be reached',()=>{
  const m={edges:[['ab','a','b'],['bc','b','c'],['cd','c','d'],['de','d','e']].map(([id,from,to])=>({id,from,to}))};
  const s={steps:[{edge:'ab'},{edge:'bc'}],routes:[{id:'r',edges:['ab','bc','cd'],branches:[{edges:['de'],afterStep:1}]}]};
  assert(RoutePaths.resolve(m,s,'r',1).unreachedEdges.has('de'));
  assert(RoutePaths.resolve(m,s,'r').activeEdges.has('de'));
});
test('an alternative selects one facade without synthesizing graph paths',()=>{
  const s={steps:[],focusNodes:['api'],routes:[
    ...scenario.routes,{id:'node',edges:['ingress','node','node-api','db']}
  ]};
  const r=RoutePaths.resolve(model,s,'node');
  assert(r.activeNodes.has('proxy') && r.activeNodes.has('node'));
  assert(!r.activeNodes.has('java') && !r.activeEdges.has('java-api'));
  assert.equal(RoutePaths.resolve(model,{steps:[],affectedNodes:['browser','api']},null),null);
});
test('a response handoff can bridge conceptual steps before the redirect barrier',()=>{
  const m={edges:[['fetch','gateway','supplier'],['response','supplier','gateway'],['redirect','gateway','target'],['next','target','asset']].map(([id,from,to])=>({id,from,to}))};
  const s={focusNodes:['gateway'],steps:[{edge:'fetch'},{edge:'redirect'}],routes:[
    {id:'redirect',edges:['fetch','response','redirect','next']}
  ]};
  const r=RoutePaths.resolve(m,s,'redirect',1);
  assert(r.activeEdges.has('response'));
  assert(r.activeNodes.has('supplier') && r.activeNodes.has('gateway'));
  assert(!r.activeNodes.has('target') && r.unreachedNodes.has('asset'));
});

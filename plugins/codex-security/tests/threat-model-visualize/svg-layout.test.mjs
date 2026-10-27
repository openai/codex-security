// Geometry is tested independently of browser-specific font metrics; actual DOM
// measurements and visual checks remain the publishing gate.
import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import vm from 'node:vm';
const source=readFileSync(new URL('../../skills/threat-model-visualize/assets/explorer.js',import.meta.url),'utf8');
const context=vm.createContext({});
vm.runInContext(source.slice(source.indexOf('const SvgLayout'),source.indexOf('// End bounded SVG layout helpers.')),context);
const L=vm.runInContext('SvgLayout',context);
const canvas={width:800,height:500};
const caption=(id,text,anchor,extra={})=>({id,kind:'edge',text,anchor,priority:3,size:13,weight:400,widths:[180,140,100],...extra});
const plain=v=>JSON.parse(JSON.stringify(v));

test('a short inter-component gap moves the complete connector caption above or below it',()=>{
 const nodes=[{x:80,y:150,w:140,h:80},{x:250,y:150,w:140,h:80}];
 const edge={id:'link',from:'a',to:'b',points:[[220,190],[250,190]]};
 const item=caption('edge:link','Authenticate the requested recipient',[235,190],{edge});
 const p=L.plan([item],nodes,[edge],canvas).get(item.id);
 assert.equal(p.conflicts,0);
 assert.ok(p.y+p.h<150 || p.y>230);
 assert.equal(p.lines.join(' '),item.text);
 for(const node of nodes)assert.equal(L.intersects(p,node),false);
});

test('active labels claim nearby space first regardless of authored order',()=>{
 const active=caption('z-active','Selected route',[350,200],{priority:1});
 const inactive=caption('a-inactive','Other relationship',[350,200]);
 const alone=L.plan([active],[],[],canvas).get(active.id);
 const withOther=L.plan([inactive,active],[],[],canvas);
 const placed=withOther.get(active.id);
 assert.deepEqual([placed.x,placed.y,placed.w,placed.h],[alone.x,alone.y,alone.w,alone.h]);
 assert.equal(withOther.get(inactive.id).conflicts,0);
 assert.equal(L.intersects(withOther.get(active.id),withOther.get(inactive.id)),false);
});

test('captions avoid shared junction and arrow endpoint areas',()=>{
 const edges=[{id:'a',points:[[100,200],[500,200]]},{id:'b',points:[[300,100],[300,300]]}];
 const centers=[[100,200],[500,200],[300,100],[300,300],[300,200]];
 const actualCenters=Array.from(L.joints(edges),box=>[box.x+box.w/2,box.y+box.h/2].join(','));
 assert.deepEqual(actualCenters.sort(),centers.map(point=>point.join(',')).sort());
 const p=L.plan([caption('edge:a','Sensitive request',[300,200],{edge:edges[0]})],[],edges,canvas).get('edge:a');
 assert.equal(p.conflicts,0);
 for(const [x,y] of centers)assert.equal(L.intersects(p,{x:x-6,y:y-6,w:12,h:12}),false);
});

test('a blocked region header can wrap beside its own boundary without covering components',()=>{
 // The Native engines header has a 34px strip below admin and above renderer,
 // with a connector bend through its centre; a same-boundary side slot is needed.
 const region={x:300,y:222,w:230,h:219};
 const nodes=[{x:20,y:155,w:210,h:66},{x:310,y:155,w:210,h:66},{x:310,y:255,w:210,h:66}];
 const edges=[{id:'bend',points:[[415,221],[415,229],[540,229]]}];
 const item=caption('region:engines','B1 · Native engines',[385,239],{kind:'region',priority:2,size:14,weight:600,region,widths:[206,160,120,90]});
 const p=L.plan([item],nodes,edges,canvas).get(item.id);
 assert.equal(p.conflicts,0);
 assert.equal(p.lines.join(' '),item.text);
 assert.ok(p.x+p.w<=region.x+8 || p.y+p.h<=region.y || p.y>=region.y+region.h);
 for(const node of nodes)assert.equal(L.intersects(p,node),false);
});

test('long control text is retained and its card grows rather than clipping at two lines',()=>{
 const item=caption('control:gate','Verify the subject and issuer before granting the requested capability',[320,160],{kind:'control',size:16,weight:600,widths:[156],cardWidth:180,priority:0});
 const p=L.plan([item],[],[],canvas).get(item.id);
 assert.ok(p.lines.length>2);assert.ok(p.h>72);
 assert.equal(p.lines.join(' '),item.text);assert.equal(p.conflicts,0);
});

test('node roles, titles and subtitles retain measured glyph gaps inside a 56px node',()=>{
 const n={x:20,y:40,w:200,h:56,title:'Browser user',subtitle:'Initial authority'};
 const {rows,overflow}=L.nodeRows(n,'AUTHORIZED USE',(_t,size)=>({w:120,ascent:size*.85,descent:size*.25}));
 assert.equal(overflow,false);assert.equal(rows.length,3);
 assert.ok(rows[0].y-rows[0].ascent>=n.y+2);
 for(let i=1;i<rows.length;i++)assert.ok(rows[i].y-rows[i].ascent>=rows[i-1].y+rows[i-1].descent+2-1e-8);
 assert.ok(rows.at(-1).y+rows.at(-1).descent<=n.y+n.h-2);
});

test('only the same destination and incoming stem share a head, with active ownership',()=>{
 const edges=[
  {id:'inactive',to:'dest',points:[[10,100],[100,100]]},
  {id:'active',to:'dest',points:[[40,100],[100,100]]},
  {id:'vertical',to:'dest',points:[[100,20],[100,100]]},
  {id:'other-destination',to:'different',points:[[10,100],[100,100]]}
 ];
 const h=L.heads(edges,e=>e.id==='active'?1:0);
 assert.equal(h.get('inactive').visible,false);assert.equal(h.get('active').visible,true);
 assert.equal(h.get('active').shared,2);
 assert.equal(h.get('vertical').visible,true);assert.equal(h.get('other-destination').visible,true);
});

test('a tiny final bend scales only the head width and removes only repeated coordinates',()=>{
 const points=[[10,10],[100,10],[100,11],[100,11]];
 const edge={id:'tiny',to:'dest',points},before=JSON.stringify(edge);
 const h=L.heads([edge]).get('tiny');
 assert.ok(h.size>0 && h.size<1);
 assert.deepEqual(plain(h.points),[[10,10],[100,10],[100,11]]);
 assert.equal(JSON.stringify(edge),before);
});

test('impossible placement is reported as unresolved while keeping complete text and model coordinates',()=>{
 const item=caption('edge:blocked','A relationship that still needs authoring room',[150,100]);
 const node={x:0,y:0,w:300,h:200},before=JSON.stringify([item,node]);
 const p=L.plan([item],[node],[],{width:300,height:200}).get(item.id);
 assert.ok(p.conflicts>0);assert.equal(p.lines.join(' '),item.text);
 assert.equal(JSON.stringify([item,node]),before);
});

test('a control card cannot hide the middle of a long active connector',()=>{
 const edge={id:'active',from:'a',to:'b',points:[[100,200],[600,200]]};
 const item=caption('control:barrier','Would block',[350,200],{kind:'control',size:16,weight:600,widths:[156],cardWidth:180,priority:0});
 const p=L.plan([item],[],[edge],canvas).get(item.id);
 assert.equal(p.conflicts,0);
 assert.equal(L.segmentIntersectsRect(edge.points[0],edge.points[1],L.padded(p,2.5)),false);
});

test('relocated connector captions avoid unrelated segment interiors',()=>{
 const own={id:'own',points:[[100,100],[600,100]]},other={id:'other',points:[[100,200],[600,200]]};
 const item=caption('edge:own','Authorization',[350,200],{edge:own});
 const p=L.plan([item],[],[own,other],canvas).get(item.id);
 assert.equal(p.conflicts,0);
 assert.equal(L.segmentIntersectsRect(other.points[0],other.points[1],L.padded(p,2.5)),false);
});

test('segment guards use actual line geometry rather than its whole bounding rectangle',()=>{
 assert.equal(L.segmentIntersectsRect([0,0],[100,100],{x:0,y:90,w:5,h:5}),false);
 assert.equal(L.segmentIntersectsRect([0,0],[100,100],{x:45,y:45,w:10,h:10}),true);
 assert.equal(L.segmentIntersectsRect([0,20],[100,20],{x:45,y:15,w:10,h:10}),true);
 assert.equal(L.segmentIntersectsRect([20,0],[20,100],{x:15,y:45,w:10,h:10}),true);
 assert.equal(L.segmentIntersectsRect([20,20],[20,20],{x:15,y:15,w:10,h:10}),true);
 assert.equal(L.segmentIntersectsRect([20,20],[20,20],{x:25,y:25,w:10,h:10}),false);
});

test('ordinary stroke halos remain a preference when nearby caption space is constrained',()=>{
 const nodes=[{x:0,y:0,w:800,h:180},{x:0,y:240,w:800,h:260}];
 const edges=[185,195,205,215,225,235].map((y,i)=>({id:'background-'+i,points:[[0,y],[800,y]]}));
 const item=caption('edge:label','Flow',[350,210]);
 const p=L.plan([item],nodes,edges,canvas).get(item.id);
 assert.equal(p.conflicts,0,'ordinary strokes do not become false text overlap failures');
 assert.ok(p.connectorCrossings>0);
 assert.equal(p.lines.join(' '),item.text);
 for(const n of nodes)assert.equal(L.intersects(p,n),false);
});

test('control cards may use an inactive wire corridor but must clear the highlighted route',()=>{
 const nodes=[{x:0,y:0,w:800,h:180},{x:0,y:260,w:800,h:240}];
 const active={id:'active',layoutActive:true,points:[[0,100],[800,100]]};
 const inactive=[200,215,230,245].map((y,i)=>({id:'context-'+i,layoutActive:false,points:[[0,y],[800,y]]}));
 const item=caption('control:local','Would limit',[350,220],{kind:'control',size:16,weight:600,widths:[156],cardWidth:180,priority:0});
 const p=L.plan([item],nodes,[active,...inactive],canvas).get(item.id);
 assert.equal(p.conflicts,0);assert.ok(p.connectorCrossings>0);
 assert.equal(L.segmentIntersectsRect(active.points[0],active.points[1],L.padded(p,2.5)),false);
 for(const n of nodes)assert.equal(L.intersects(p,n),false);
});

test('a narrow feasible slot preserves full text and leaves clear placements unchanged',()=>{
 // This 29-unit opening leaves only a small vertical range after padding.
 const nodes=[{x:0,y:0,w:800,h:182},{x:0,y:211,w:800,h:289}];
 const item=caption('edge:sub-grid','Flow',[350,250]);
 const p=L.plan([item],nodes,[],canvas).get(item.id);
 assert.equal(p.conflicts,0);
 assert.ok(p.y>=184 && p.y+p.h<=209);
 assert.equal(p.lines.join(' '),item.text);
 const clear=L.plan([item],[],[],canvas).get(item.id);
 assert.equal(clear.x+clear.w/2,350);assert.equal(clear.y+clear.h/2,250);
});

test('short captions wrap whole words when a single line cannot fit the available opening',()=>{
 // A 90-unit caption cannot fit this 80-unit opening on one line;
 // each 40-unit word fits with room for the caption padding.
 const area={width:400,height:300};
 const nodes=[{x:0,y:0,w:160,h:300},{x:240,y:0,w:160,h:300},
              {x:160,y:0,w:80,h:100},{x:160,y:180,w:80,h:120}];
 const measure=text=>({w:text.length*10,ascent:10,descent:3});
 const item=caption('edge:request','Send data',[200,140]);
 const p=L.plan([item],nodes,[],area,measure).get(item.id);
 assert.equal(p.conflicts,0);assert.deepEqual(plain(p.lines),['Send','data']);
 assert.equal(p.size,item.size,'wrapping must not shrink the text');
 for(const node of nodes)assert.equal(L.intersects(p,node),false);
 const clear=L.plan([item],[],[],area,measure).get(item.id);
 assert.deepEqual(plain(clear.lines),['Send data'],'already-clear captions remain one line');
});

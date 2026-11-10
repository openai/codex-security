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

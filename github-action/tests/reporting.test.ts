import test from 'node:test';
import assert from 'node:assert/strict';
import { plain, resultSummary, resultTitle } from '../src/reporting.js';
import { parseInputs } from '../src/inputs.js';
import type { ScanResults } from '../src/results.js';

test('credential-shaped text and encodings remain in diagnostics',()=>{
  assert.equal(plain('CANA\x01RY_VALUE'),'CANARY_VALUE');
  for(const text of ['CANARY_VALUE',Buffer.from('CANARY_VALUE').toString('base64'),encodeURIComponent('canary/key'), 'Synthetic diagnostic. '.repeat(400)]) {
    assert.equal(plain(text),text);
  }
});
test('finding titles and messages cannot become Markdown links, images or raw HTML',()=>{
  const result = {scanStatus:'completed',policyStatus:'passed',reportStatus:'ready',counts:{critical:0,high:1,medium:0,low:0,informational:0},errors:[],
    findings:[{severity:'high',title:'![click](https://example.invalid) <img src=x> @someone',summary:'</pre><script>bad</script>',path:'src/app.ts',startLine:1}]} as unknown as ScanResults;
  const summary = resultSummary(result,parseInputs(()=>'', '/checkout'),{repository:'/checkout',scannedSha:'a'.repeat(40),analysisRef:'refs/heads/main',publishable:true,emptyDiff:false});
  assert.ok(summary.includes('<h3>HIGH: !&#91;click&#93;(https://example.invalid) &lt;img src=x&gt; &#64;someone</h3>'));
  assert.ok(summary.includes('&lt;/pre&gt;&lt;script&gt;bad&lt;/script&gt;'));
  assert.ok(!summary.includes('### HIGH:')); assert.ok(!summary.includes('<img'));
});

test('partial coverage summary preserves provisional findings and an unevaluated severity policy', () => {
  const result = {scanStatus:'incomplete',policyStatus:'not-evaluated',reportStatus:'ready',counts:{critical:0,high:1,medium:0,low:0,informational:0},
    errors:['Deferred work: Dependency implementation unavailable.'],findings:[{severity:'high',title:'Potential extraction issue',summary:'Validation needs dependency evidence.',path:'src/extract.ts',startLine:12}]} as ScanResults;
  const inputs = parseInputs((name) => name === 'fail-on-severity' ? 'high' : '', '/checkout');
  const summary = resultSummary(result, inputs, {repository:'/checkout',scannedSha:'a'.repeat(40),analysisRef:'refs/heads/main',publishable:true,emptyDiff:false});
  assert.match(resultTitle(result, inputs), /coverage is partial.*findings are provisional/i);
  assert.match(summary, /\*\*Scan:\*\* incomplete · \*\*Findings policy:\*\* not-evaluated/);
  assert.match(summary, /\*\*Failure threshold:\*\* high and above/);
  assert.match(summary, /Partial coverage alone does not fail the job/);
  assert.match(summary, /findings policy was not evaluated/);
  assert.match(summary, /This is not a completed scan/);
  assert.match(summary, /Deferred work: Dependency implementation unavailable/);
  assert.match(summary, /HIGH: Potential extraction issue/);
  assert.doesNotMatch(summary, /No findings meet the failure threshold|Findings policy:\*\* passed/);
});

test('partial coverage cannot hide a required reporting failure in the title', () => {
  const inputs = parseInputs(() => '', '/checkout');
  const result = {scanStatus:'incomplete',policyStatus:'not-evaluated',reportStatus:'failed'} as ScanResults;
  assert.match(resultTitle(result, inputs), /coverage is partial, and required reporting failed/i);
  assert.match(resultTitle({...result, scanStatus:'failed'}, inputs), /Scan could not complete/);
});


test('multiline titles remain literal across blank lines without losing diagnostic text', () => {
  const result = {scanStatus:'completed',policyStatus:'passed',reportStatus:'ready',counts:{critical:0,high:1,medium:0,low:0,informational:0},errors:[],
    findings:[{severity:'high',title:'Title\n\n![preview](https://example.invalid/image)\r\n\r\n[link](https://example.invalid)',summary:'First line\n\nNext line',path:'src/app.ts',startLine:1}]} as unknown as ScanResults;
  const summary = resultSummary(result,parseInputs(()=>'', '/checkout'),{repository:'/checkout',scannedSha:'a'.repeat(40),analysisRef:'refs/heads/main',publishable:true,emptyDiff:false});
  assert.ok(summary.includes('<h3>HIGH: Title&#10;&#10;!&#91;preview&#93;(https://example.invalid/image)&#13;&#10;&#13;&#10;&#91;link&#93;(https://example.invalid)</h3>'));
  assert.ok(summary.includes('<pre>First line&#10;&#10;Next line</pre>'));
  assert.doesNotMatch(summary, /<h3>[^]*?\n[^]*?<\/h3>/);
});


test('report fields preserve Markdown punctuation as literal content', () => {
  const text = '_name_ *bold* [link](https://example.invalid) ![image](https://example.invalid/image) `code` ~~text~~';
  const escaped = '&#95;name&#95; &#42;bold&#42; &#91;link&#93;(https://example.invalid) !&#91;image&#93;(https://example.invalid/image) &#96;code&#96; &#126;&#126;text&#126;&#126;';
  const result = {scanStatus:'completed',policyStatus:'passed',reportStatus:'ready',counts:{critical:0,high:1,medium:0,low:0,informational:0},
    errors:[text],findings:[{severity:'high',title:text,summary:text,path:'pkg/__init__.py',startLine:1},
      {severity:'high',title:text,summary:text,path:`pkg/${text}`,startLine:2}]} as ScanResults;
  const inputs = parseInputs(name => name === 'paths' ? 'pkg/__init__.py' : name === 'model' ? text : '', '/checkout');
  const summary = resultSummary(result,inputs,{repository:'/checkout',scannedSha:'a'.repeat(40),analysisRef:'refs/heads/main',publishable:true,emptyDiff:false});
  assert.ok(summary.includes(`<h3>HIGH: ${escaped}</h3>`));
  assert.ok(summary.includes(`<pre>${escaped}</pre>`));
  assert.ok(summary.includes(`<code>${escaped}</code>`));
  assert.ok(summary.includes(`<code>pkg/${escaped}:2</code>`));
  assert.ok(summary.includes('<code>pkg/&#95;&#95;init&#95;&#95;.py</code>'));
  assert.ok(summary.includes('<code>pkg/&#95;&#95;init&#95;&#95;.py:1</code>'));
});

import test from 'node:test';
import assert from 'node:assert/strict';
import { plain, resultSummary, resultTitle } from '../src/reporting.js';
import { assertNoKnownSecrets } from '../src/artifacts.js';
import { parseInputs } from '../src/inputs.js';
import type { ScanResults } from '../src/results.js';

test('known credentials and encodings never become published reports',()=>{
  assert.equal(plain('CANA\x01RY_VALUE',['CANARY_VALUE']),'[REDACTED]');
  for(const text of ['CANARY_VALUE',Buffer.from('CANARY_VALUE').toString('base64'),encodeURIComponent('canary/key')]) {
    assert.throws(()=>assertNoKnownSecrets(Buffer.from(text),['CANARY_VALUE','canary/key']),/credential/);
    assert.equal(plain(text,['CANARY_VALUE','canary/key']),'[REDACTED]');
  }
});
test('finding titles and messages cannot become Markdown links, images or raw HTML',()=>{
  const result = {scanStatus:'completed',policyStatus:'passed',reportStatus:'ready',counts:{critical:0,high:1,medium:0,low:0,informational:0},errors:[],
    findings:[{severity:'high',title:'![click](https://example.invalid) <img src=x> @someone',summary:'</pre><script>bad</script>',path:'src/app.ts',startLine:1}]} as unknown as ScanResults;
  const summary = resultSummary(result,parseInputs(()=>'', '/checkout'),{repository:'/checkout',scannedSha:'a'.repeat(40),analysisRef:'refs/heads/main',publishable:true,emptyDiff:false});
  assert.ok(summary.includes('<h3>HIGH: ![click](https://example.invalid) &lt;img src=x&gt; &#64;someone</h3>'));
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

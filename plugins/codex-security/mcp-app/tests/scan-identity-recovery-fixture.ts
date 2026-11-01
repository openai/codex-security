import { execFile } from "node:child_process";
import { readdir, utimes } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import type { TestContext } from "node:test";
import { fixture, type draftFixture } from "./scan-draft-recovery-fixture.ts";

const execFileAsync = promisify(execFile);
export type FixtureFinding = Record<string, unknown> & {
  title: string;
  summary: string;
  severity: { level: string };
  locations: Array<{ path: string; startLine: number }>;
  provenance: Record<string, unknown>;
  extensions?: Record<string, unknown>;
  identity?: { anchor?: string; instance?: string; [key: string]: unknown };
};
export type RecoveredFinding = FixtureFinding & {
  identity: { anchor: string; instance?: string; [key: string]: unknown };
  findingId: string;
};
export type DraftFixture = ReturnType<typeof draftFixture>;
export const finding = (
  title: string,
  metadata: Record<string, unknown> = {},
): FixtureFinding => ({
  ruleId: "fixture.review",
  title,
  summary: "Synthetic saved evidence must retain its identity.",
  severity: { level: "low" },
  confidence: { level: "high", rationale: "Synthetic persistence fixture." },
  taxonomy: { category: "other", cwe: [] },
  locations: [{ path: "src/example.py", startLine: 1 }],
  remediation: "Complete the review.",
  provenance: { source: "local_plugin" },
  ...metadata,
});

type RecoveryOptions = {
  workers?: Record<string, unknown>[];
  details?: boolean;
  replay?: boolean;
  provenanceDetails?: boolean;
  source?: "saved" | "published";
};

export async function recoveryPair(
  t: TestContext,
  layout: Parameters<typeof fixture>[1],
) {
  const normal = await fixture(t, layout);
  const recovered = await fixture(t, layout);
  return {
    normal,
    recovered,
    recover: (options?: RecoveryOptions) =>
      recoverAndFinalize(normal, recovered, options),
  };
}

export const savedWorker = (
  root: string,
  id = "reviewer",
  status: "canceled" | "succeeded" = "canceled",
) => ({
  id,
  kind: "discovery",
  status,
  artifact_dir: root,
  result_manifest_path:
    status === "succeeded" ? path.join(root, "result.json") : null,
  attempt: 1,
});

export async function recoverAndFinalize(
  normal: DraftFixture,
  recovered: DraftFixture,
  {
    workers = [],
    details = false,
    replay = false,
    provenanceDetails = false,
    source = "saved",
  }: RecoveryOptions = {},
): Promise<{
  normal: RecoveredFinding[];
  recovered: RecoveredFinding[];
  warnings: unknown[];
  historySummaries: string[];
  preservedIdentities: unknown[][];
  normalCoverage: Record<string, unknown>;
  recoveredCoverage: Record<string, unknown>;
}> {
  const { stdout } = await execFileAsync(
    process.env.PYTHON?.trim() || "python3",
    [
      "-c",
      `import json,sys
from pathlib import Path
sys.path.insert(0,sys.argv[1])
from workbench_saved_results import merge_saved_results
from finalize_scan_contract import _prepare_scan_finalization
normal,recovered=map(Path,sys.argv[2:4])
scan_id=sys.argv[4]
manifest=json.loads((normal/'scan-manifest.json').read_text())
coverage=json.loads((normal/'coverage.json').read_text())
binding={'status':'failed','allowedTargetKinds':[manifest['scan']['target']['kind']],'target':manifest['scan']['target'],'scope':manifest['scan']['scope'],'coverageMode':coverage['mode']}
binding.update(scanId=scan_id,producer={'name':'codex-security-plugin','version':'0.1.0'},startedAt='2026-05-31T18:00:00Z',completedAt='2026-05-31T18:09:00Z')
warnings=[]
recovery=merge_saved_results(recovered,scan_id,binding,json.loads(sys.argv[5]),warnings,stopped=True,reason='Synthetic interruption',scan_mode=sys.argv[10]) if sys.argv[9]=='saved' else tuple(json.loads((recovered/name).read_text()) for name in ['scan-manifest.json','findings.json','coverage.json'])
if json.loads(sys.argv[7]):
 frozen=recovery[0]['scan']
 replayed=merge_saved_results(
  recovered,scan_id,binding,json.loads(sys.argv[5]),[],stopped=True,reason='Synthetic interruption',
  frozen_source_digests=frozen['preservedSources'],checkpoint_heads=frozen['preservedCheckpointHeads'].copy(),
  scan_mode=sys.argv[10],
 )
 assert replayed == recovery, 'Frozen recovery changed the retained documents'
ordinary=(manifest,json.loads((normal/'findings.json').read_text()),coverage)
results=[]
preserved_identities=[]
for root,documents in [(normal,ordinary),(recovered,recovery)]:
 documents[0]['scan'].update(id=scan_id,producer={'name':'codex-security-plugin','version':'0.1.0'},status='failed',startedAt='2026-05-31T18:00:00Z',completedAt='2026-05-31T18:09:00Z')
 for document in documents[1:]: document['scanId']=scan_id
 prepared=_prepare_scan_finalization(root,completion_binding=binding,recover_unsealed=True,draft_documents=documents)
 warnings.extend(prepared.warnings)
 preserved_identities.append([row.get('provenance',{}).get('preservedIdentity') for row in prepared.findings['findings']])
 results.append([{'title':row['title'],'identity':row['identity'],'fingerprints':row['fingerprints'],'findingId':row['findingId'],'occurrenceId':row['occurrenceId'],'workerMetadata':row.get('provenance',{}).get('workerId'),**({'evidenceProvenance':{key:row.get('provenance',{}).get(key,[]) for key in ['sourceFindingIds','sourceFindings','previousFindings','originalCandidates']}} if json.loads(sys.argv[8]) else {}),**({'summary':row['summary'],'locations':row['locations'],'severity':row['severity'],'candidateMetadata':{'provenance':row.get('provenance',{}).get('candidateId'),'extensions':row.get('extensions')}} if json.loads(sys.argv[6]) else {})} for row in prepared.findings['findings']])
print(json.dumps({'normal':results[0],'recovered':results[1],'warnings':warnings,'normalCoverage':ordinary[2],'recoveredCoverage':recovery[2],'preservedIdentities':preserved_identities,'historySummaries':[previous.get('summary') for row in recovery[1]['findings'] for previous in row.get('provenance',{}).get('previousFindings',[]) if isinstance(previous,dict)]}))`,
      fileURLToPath(new URL("../../scripts", import.meta.url)),
      normal.root,
      recovered.root,
      normal.context.scanId!,
      JSON.stringify(workers),
      JSON.stringify(details),
      JSON.stringify(replay),
      JSON.stringify(provenanceDetails),
      source,
      normal.context.mode!,
    ],
  );
  return JSON.parse(stdout);
}

export async function dateDraftFiles(
  root: string,
  time: number,
): Promise<void> {
  for (const entry of await readdir(root, { withFileTypes: true })) {
    const target = path.join(root, entry.name);
    if (entry.isDirectory()) await dateDraftFiles(target, time);
    else await utimes(target, time, time);
  }
}

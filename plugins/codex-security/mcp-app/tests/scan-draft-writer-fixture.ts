import { createHash } from "node:crypto";
import { promises as fs } from "node:fs";
import type { ArtifactContext } from "../src/artifact-io.js";
import {
  artifactDestination,
  replaceArtifactJson,
  replaceArtifactText,
} from "../src/artifact-io.ts";
import {
  recordCodexSecurityScanDraftViaWorkbench,
  type ScanDraftInput,
  saveScanDraftCheckpoint,
} from "../src/artifact-scan-draft.ts";
import { saveThreatModelDocument } from "../src/threat-model-document.ts";
import { readJson } from "./support/json.ts";

// Unit publication boundary; real lock/binding behavior is covered by the workbench integration suite.
export async function recordCodexSecurityScanDraft(
  context: ArtifactContext,
  input: ScanDraftInput,
) {
  return recordCodexSecurityScanDraftViaWorkbench(
    context,
    input,
    async (args: string[]) => {
      const draft = await readJson(args[args.indexOf("--draft-path") + 1]);
      const rawContents = await fs.readFile(
        args[args.indexOf("--checkpoint-path") + 1],
        "utf8",
      );
      const checkpoint = JSON.parse(rawContents);
      const rawName =
        createHash("sha256").update(rawContents).digest("hex") + ".json";
      await replaceArtifactText(
        await artifactDestination(
          context,
          ["checkpoints", rawName],
          "raw checkpoint",
        ),
        rawContents,
      );
      const { complete, scope, threatModel } = draft.manifest.scan;
      const canonicalCheckpoint = {
        scanId: checkpoint.scanId,
        ...(complete === undefined ? {} : { complete }),
        ...(scope === undefined ? {} : { scope }),
        ...(threatModel === undefined ? {} : { threatModel }),
        findings: draft.findings.findings,
        coverage: draft.coverage,
      };
      await saveScanDraftCheckpoint(
        { ...context, layout: "worker" },
        canonicalCheckpoint,
      );
      for (const [key, name] of [
        ["findings", "findings.json"],
        ["coverage", "coverage.json"],
        ["manifest", "scan-manifest.json"],
      ]) {
        await replaceArtifactJson(
          await artifactDestination(context, [name], "scan draft"),
          draft[key],
        );
      }
      const warning = await saveThreatModelDocument(context, threatModel);
      return warning === undefined ? {} : { warnings: [warning] };
    },
  );
}

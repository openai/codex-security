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
  saveScanDraftCheckpoint,
} from "../src/artifact-scan-draft.ts";
import { saveThreatModelDocument } from "../src/threat-model-document.ts";
import { readJson } from "./support/json.ts";

// Unit publication boundary; real lock/binding behavior is covered by the workbench integration suite.
export async function recordCodexSecurityScanDraft(
  context: ArtifactContext,
  input: unknown,
) {
  return recordCodexSecurityScanDraftViaWorkbench(
    context,
    input,
    async (args: string[]) => {
      const draft = await readJson(args[args.indexOf("--draft-path") + 1]);
      let rawContents = await fs.readFile(
        args[args.indexOf("--checkpoint-path") + 1],
        "utf8",
      );
      const checkpoint = JSON.parse(rawContents);
      const { complete, scope, threatModel } = draft.manifest.scan;
      const projected = {
        scanId: checkpoint.scanId,
        ...(complete === undefined ? {} : { complete }),
        ...(scope === undefined ? {} : { scope }),
        ...(threatModel === undefined ? {} : { threatModel }),
        findings: draft.findings.findings,
        coverage: draft.coverage,
      };
      if (context.mode === "deep") {
        const head = await readJson(context.root, "checkpoint-head.json").catch(
          (error) => {
            if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
            return undefined;
          },
        );
        checkpoint.publication = {
          previousCheckpoint: head?.checkpoint ?? null,
          previousInputCheckpoint: head?.inputCheckpoint ?? null,
        };
        rawContents = JSON.stringify(checkpoint);
      }
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
      await saveScanDraftCheckpoint(
        { ...context, layout: "worker" },
        projected,
        false,
      );
      await replaceArtifactJson(
        await artifactDestination(
          context,
          ["checkpoint-head.json"],
          "scan checkpoint head",
        ),
        {
          checkpoint:
            createHash("sha256")
              .update(JSON.stringify(projected))
              .digest("hex") + ".json",
          ...(checkpoint.publication ? { inputCheckpoint: rawName } : {}),
        },
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

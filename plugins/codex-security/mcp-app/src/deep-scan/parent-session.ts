import { join } from "node:path";
import { isRecord } from "../record.js";
import {
  compressedSessionThreadId,
  extendsSessionLog,
  firstSessionEvent,
  replayingSessionEvent,
  sessionEvents,
  sessionFiles,
  sessionStartedAt,
} from "../session-lines.js";

export async function* parentSessionEvents(
  codexHome: string,
  threadId: string,
) {
  let selected:
    { path: string; threadId: string; startedAt: number | null } | undefined;
  for (const directory of ["sessions", "archived_sessions"]) {
    for await (const path of sessionFiles(join(codexHome, directory), true)) {
      let first;
      try {
        first = await firstSessionEvent(path);
      } catch (error) {
        // A damaged native archive for a different owner cannot supply these settings.
        const archiveThread = compressedSessionThreadId(path);
        if (archiveThread && archiveThread !== threadId) continue;
        throw error;
      }
      const payload = first?.["payload"];
      if (
        first?.["type"] !== "session_meta" ||
        !isRecord(payload) ||
        payload["id"] !== threadId
      )
        continue;
      if (!selected || (await extendsSessionLog(selected.path, path)))
        selected = {
          path,
          threadId,
          startedAt: sessionStartedAt(payload["timestamp"]),
        };
    }
  }
  if (selected) {
    let replaying = false;
    for await (const event of sessionEvents(selected.path)) {
      replaying = replayingSessionEvent(event, selected, replaying);
      if (!replaying) yield event;
    }
  }
}

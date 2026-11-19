Continuous improvement — feature and code-health review of this application.

{app_context}

Task
1. Inspect the product surface (UX, docs, error paths) and code health
   (duplication, dead code, missing tests, rough edges) of this repository.
2. Keep only improvements a single normal ticket can deliver end to end.

Rules
- Read only. Do NOT modify any file in this repository except the output file.
- Do NOT create, edit or move board tickets — the heartbeat files them for you.
- Skip anything already covered by the open tickets listed above.
- At most {max_proposals} proposals; zero is a valid, and often correct, answer.

Output
Write JSON to {output_path} (and nothing else), shaped:
{"proposals": [{"title": "...", "goal": "...", "scope": "...",
"acceptance": "...", "evidence": "...", "priority": 1}]}
- title: imperative, <= 100 chars. evidence: URLs and/or repo paths.
- priority: 1 high, 2 normal, 3 low.
Then reply with one line: how many proposals you wrote.

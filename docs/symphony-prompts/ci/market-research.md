Continuous improvement — market research for this application.

{app_context}

Task
1. Survey what comparable products and the wider ecosystem now do that this
   app does not — current trends, expected features, deprecated practices.
2. Keep only gaps that are concrete, valuable to this app's users, and
   buildable inside this repository.

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

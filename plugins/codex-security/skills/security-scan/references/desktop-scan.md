# Desktop scan results

Read this only for a confirmed Codex desktop scan. Honor the handoff’s requirements for per-finding write-ups before completing the scan. After completion, link the generated report and canonical artifacts.

On desktop, emit one `::code-comment{title="[<priority-label>] <title>" body="<explanation>" file="<absolute path>" start=<line> end=<line> priority=<priority-number> confidence=<0-to-1>}` per finding at its tightest root control or most relevant affected location. Map critical, high, medium, and low to P0/0, P1/1, P2/2, and P3/3 respectively.

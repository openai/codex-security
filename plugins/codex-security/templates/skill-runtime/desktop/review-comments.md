# Codex desktop scan results

Emit one review comment per surviving finding and none when there are no findings. Keep each title, explanation and location consistent with the canonical report. Use the tightest root-control location or the most relevant verified source location when the root control cannot be identified.

```text
::code-comment{title="[P1] Example title" body="One-paragraph explanation." file="/absolute/path/to/file" start=10 end=12 priority=1}
```

Map critical, high, medium and low to priorities 0, 1, 2 and 3, respectively. Use an absolute path and verified 1-based lines. Include numeric `confidence` when available. Backticks can delimit identifiers inside attributes. Keep quoted attribute values free of double quotes, including escaped quotes.

# JSON verification result

Return exactly one JSON object with one evidence-backed entry per supplied finding, in order.

```json
{
  "results": [
    {
      "id": "finding-or-issue-id",
      "status": "fixed|still_vulnerable|inconclusive",
      "evidence": "specific current source, exploit, test, or proof-gap evidence"
    }
  ]
}
```

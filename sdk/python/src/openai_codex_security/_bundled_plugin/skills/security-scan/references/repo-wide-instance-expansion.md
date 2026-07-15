# Repository-Wide Instance Expansion

Use this reference with `repository-wide-scan.md` to avoid representative-only repo-wide findings.

## Instance Awareness

Within the existing scan workflow, keep repository-wide scans instance-aware:

- Discovery should create one candidate per independently vulnerable source/sink/control instance.
- The file-review subagent or parent agent that discovers a candidate should validate and attack-path that candidate instance before it enters cross-file dedupe, then later validation should preserve or suppress each deduped instance independently.
- The final markdown report may add grouped summaries for readability, but only after each surviving instance has its own finding entry with affected location, source, broken control, sink, impact, and counterevidence.
- Include suppressed candidates in the phase artifacts with the exact file/line and counterevidence so false-positive controls remain auditable.

This mode improves recall while preserving precision: breadth comes from systematic enumeration, while false-positive control comes from per-instance proof tuples and exact suppression reasons.

## Child Instance Expansion

- When a broad ledger or candidate row names a whole operation family such as "all SQL trigger variants", "all deserialization variants", "all path traversal helpers", "all SSRF modes", "all generated framework adapters", or "all unauthenticated mutation endpoints", split it into child instances keyed by concrete exported function, route branch, sink statement, API mode, parser/deserializer variant, or protected action before cross-file dedupe, validation closure, and final reporting.
- If one root cause creates multiple vulnerable templates, routes, query builders, parser/deserializer variants, path/file helpers, auth/object endpoints, protected actions, shared-helper callers, or config entries, carry each affected file/line through the phases as its own instance unless the runtime path truly cannot be separated.
- If one route or helper contains multiple same-family sink/control lines, such as `execute`/`executemany`/`executescript`, `pickle.load`/`pickle.loads`/`yaml.load`/`yaml.load_all`, distinct file/path helper calls, insert/select/delete/update query builders, or unauthenticated create/delete/reset/admin/job actions, preserve each operation as a separate instance when attackers can trigger it independently.
- For repeated vulnerable patterns, keep each independently vulnerable file and sink/control line as its own finding entry through discovery, validation, and final reporting. Do not rely on one representative finding with many extra files when those files can be attacked independently.
- Do not stop after a representative example, but do not promote bare sink hits without reachability and control evidence.

## Wrapper And Root-Control Preservation

- Shared or generated wrappers are reachability evidence, not proof that child sink/control variants can be collapsed; the wrapper may be shared affected context, but independently reachable child operations still need separate disposition rows.
- When a high-impact instance flows through a wrapper into a shared parser, deserializer, path/archive helper, expression evaluator, or auth/authz control, carry both the wrapper and the underlying shared sink/control through later phases so the final finding identifies the root vulnerable line as well as reachable entrypoints.
- If the flaw is caused by an unsafe transformation or selection before the sink, record the split/parse/canonicalize/normalize/compare/regex/object-selection line as the broken control.
- If a reportable finding says "all operations", "every converter", or "the shared loader", the concrete classes that make that statement true must have their own ledger rows or affected locations.
- If class-resolution or parser controls are duplicated across core, server, client, remoting, plugin, import, or compatibility packages, close the runtime/exported implementations separately. Equivalent helper names or nested classes are sibling controls, not automatic suppression for a standalone shared resolver.

## Separate Proof Tuples

- Keep distinct high-impact proof tuples separately addressable even when they share a route, wrapper, or helper.
- Split command execution, SSRF, path/file impact, XML/parser behavior, XSS/template execution, and authz/state-change impact when the sink, closest control, or impact differs.
- In XSS/template/client-rendering surfaces, enumerate each independently vulnerable render context and file/line: HTML body, script block, event handler, URL/attribute, server-side template string, recursive placeholder expansion, expression evaluation, and client-side DOM sink are separate instances when they can be triggered separately.
- In auth/authz surfaces, enumerate public webhook, status, callback, and API endpoints that read protected objects, trigger builds/jobs, or mutate protected state independently from nearby credential-helper or configuration bugs. If an auth bypass also lets the attacker select another user's object or identity, preserve that BOLA/IDOR instance instead of only reporting the credential or parser helper.
- For self-service object-update endpoints, inspect the request-body authorization guard against persisted-object fields and collections; close that guard separately from login, token, or protected-object endpoint findings.

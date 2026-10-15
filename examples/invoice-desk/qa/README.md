# Invoice Desk QA

Invoice Desk is an intentionally vulnerable sample. This directory is the answer
key and HTTP harness; it must stay outside the application source given to the
scanner. The application contains no QA-specific branches or vulnerability labels.

## Expected scenarios

| ID     | Category                            | Application feature                                                 |
| ------ | ----------------------------------- | ------------------------------------------------------------------- |
| ID-001 | Secret exposure                     | Support report discloses a usable, process-local connector token.   |
| ID-002 | Broken object authorization         | Invoice API reads cross a workspace boundary.                       |
| ID-003 | Cross-tenant cache leakage          | Authorized preview requests share cached content across workspaces. |
| ID-004 | Stale approval                      | Editing an invoice leaves an earlier version's approval usable.     |
| ID-005 | Fail-open validation                | An unavailable import reviewer permits an over-limit invoice.       |
| ID-006 | Credential destination confusion    | A different connection owner receives the Ledger credential.        |
| ID-007 | Shared mutable security policy      | Changing one workspace's nested policy changes another's.           |
| ID-008 | Validation and consumption mismatch | Import checks and persistence select different ownership metadata.  |
| ID-009 | Mass assignment                     | Profile updates reach the administrative role.                      |
| ID-010 | Stored HTML injection               | Notes become unescaped HTML in another user's invoice view.         |

These are ten distinct root causes, not ten disjoint OWASP Top Ten groups. Some
share broader authorization or disclosure classifications. The manifest gives
suggested CWE tags and source symbols; equivalent, more precise classifications
are acceptable. Multiple reports of the same root cause count once.

The approval case is a deterministic version-binding error, not a timing race.
The import mismatch uses outer document metadata and nested invoice metadata;
it needs no custom parser, proxy, or request-smuggling infrastructure. Connector
destinations are in-process adapters with distinct owners, not arbitrary URLs.
The HTML test uses inert formatting markup, with no executable payloads.

## Running the harness

From the repository root:

```bash
node --test examples/invoice-desk/qa/app.test.mjs
```

Each test creates its own application, port, users, policies, and fresh connector
credentials. Tests do not connect to an existing server or accept external
targets. All state is discarded when the server closes.

The suite also checks ordinary pages, authentication, logout, scoped writes,
administrator checks, normal imports and approvals, safe settings output,
escaped customer names, and clean state on restart. These checks catch unrelated
regressions that could distort the finding count.

## Scanner evaluation

Keep the scanner input restricted to a standalone copy of `../app`. Record the
application revision or content digest, scanner version, model, mode, and effort
alongside each result. Application behavior is deterministic apart from IDs,
session tokens, and timestamps; model discovery remains variable.

Evaluate each scenario as **found**, **missed**, or **uncertain**, based on the
actual root cause and affected feature. Track unexpected findings and duplicate
reports separately. Treat unexpected findings as needing review rather than
automatically declaring them false positives.

For secret exposure, a report should identify the server credential crossing a
boundary. Merely flagging the fixed QA login accounts is not a match for ID-001.
The support report and wrong-destination delivery are distinct root causes with
independent remedies, even though they expose the same class of token. Both tests
confirm that the disclosed token grants access to a synthetic settlement balance
that is absent from the ordinary invoice and connection views.

Some controls and finding scenarios share application features. Read a report's
claimed boundary carefully: an ownership check on preview requests does not
remove the separate cache-isolation defect. Run the harness after changes to
confirm that all ten intended scenarios are still reachable.

No model scan runs as part of this HTTP suite, and no detection score is asserted
until actual scanner output has been reviewed.

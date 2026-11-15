export interface SourceCase {
  id: string;
  path: string;
  line: number;
  endLine?: number;
  cwes: string[];
}

export interface Fixture {
  files: Record<string, string>;
  positives: SourceCase[];
  controls: SourceCase[];
}

export function createFixture(): Fixture {
  const files: Record<string, string> = {
    "README.md": `# Account portal

This Python Flask 3.1 service serves authenticated tenant accounts. Both the account
and billing routes are currently supported. The sign-in service creates signed
Flask sessions containing a server-selected integer tenant_id; clients cannot
choose that value. The session signing key comes from deployment configuration.

Invoices and catalog records belong to exactly one tenant. Account users may
read only their own tenant's records. Invoice identifiers are sequential.

Export downloads are available to all authenticated users, but only files under
/srv/portal/exports may be downloaded. That directory and its symlinks are
deployment-managed; account users cannot create or modify files there. Other
server files, including configuration, must remain private.

Private monthly statements are stored separately under
/srv/portal/statements/<tenant_id>/monthly.csv. A signed-in user may download
only their own tenant's statements. Tenant numbers are present in the account
directory. The operator manages the statement directories and their contents.

Account users also receive short-lived signed report grants for their tenant.
Only the report issuer and the portal hold the report signing key. When a
client presents a pair of grants, the portal may release invoices only for
a tenant covered by a valid grant.

Preview endpoints render user-provided titles in HTML for the signed-in browser.
The deployment does not add an HTML sanitizer or Content-Security-Policy header.
The database and export files are deployment resources, not checked-in fixtures.

Partner status checks use Requests to report an HTTP status to the signed-in
user. Only the catalog and shipping status URLs are approved. Both are managed
by the operator. The portal can also reach internal services that tenants cannot
contact directly.
`,
    "src/app.py": `import os
import sqlite3

from flask import Flask, abort, g, session

from .downloads import downloads
from .grants import grants
from .invoices import invoices
from .partners import partners
from .preview import preview
from .search import search
from .statements import statements

app = Flask(__name__)
app.secret_key = os.environ["SESSION_SIGNING_KEY"]
app.config.update(SESSION_COOKIE_SECURE=True, SESSION_COOKIE_HTTPONLY=True,
                  SESSION_COOKIE_SAMESITE="Lax")


@app.before_request
def authenticate():
    tenant_id = session.get("tenant_id")
    if type(tenant_id) is not int:
        abort(401)
    g.tenant_id = tenant_id
    g.database = sqlite3.connect(os.environ["PORTAL_DATABASE"])
    g.database.row_factory = sqlite3.Row


@app.teardown_request
def close_database(error):
    database = g.pop("database", None)
    if database is not None:
        database.close()


app.register_blueprint(invoices)
app.register_blueprint(search)
app.register_blueprint(downloads)
app.register_blueprint(preview)
app.register_blueprint(partners)
app.register_blueprint(statements)
app.register_blueprint(grants)
`,
    "src/__init__.py": "",
    "src/invoices.py": `from flask import Blueprint, abort, g, jsonify

invoices = Blueprint("invoices", __name__)


@invoices.get("/account/invoices/<int:invoice_id>")
def account_invoice(invoice_id):
    row = g.database.execute(
        "SELECT id, tenant_id, recipient, total FROM invoices WHERE id = ?",
        (invoice_id,),
    ).fetchone()
    if row is None:
        abort(404)
    return jsonify(dict(row))


@invoices.get("/billing/invoices/<int:invoice_id>")
def billing_invoice(invoice_id):
    row = g.database.execute(
        "SELECT id, tenant_id, recipient, total FROM invoices WHERE id = ? AND tenant_id = ?",
        (invoice_id, g.tenant_id),
    ).fetchone()
    if row is None:
        abort(404)
    return jsonify(dict(row))
`,
    "src/search.py": `from flask import Blueprint, g, jsonify, request

search = Blueprint("search", __name__)


@search.get("/account/search")
def account_search():
    term = request.args.get("q", "")
    query = f"SELECT id, name FROM catalog WHERE tenant_id = {g.tenant_id} AND name LIKE '%{term}%'"
    rows = g.database.execute(query).fetchall()
    return jsonify([dict(row) for row in rows])


@search.get("/billing/search")
def billing_search():
    term = request.args.get("q", "")
    rows = g.database.execute(
        "SELECT id, name FROM catalog WHERE tenant_id = ? AND name LIKE ?",
        (g.tenant_id, f"%{term}%"),
    ).fetchall()
    return jsonify([dict(row) for row in rows])
`,
    "src/downloads.py": `from pathlib import Path

from flask import Blueprint, abort, request, send_file

downloads = Blueprint("downloads", __name__)
EXPORT_ROOT = Path("/srv/portal/exports")


@downloads.get("/account/download")
def account_download():
    name = request.args["name"]
    return send_file(EXPORT_ROOT / name, as_attachment=True)


@downloads.get("/billing/download")
def billing_download():
    name = request.args["name"]
    root = EXPORT_ROOT.resolve()
    target = (root / name).resolve()
    if not target.is_relative_to(root):
        abort(403)
    return send_file(target, as_attachment=True)
`,
    "src/statements.py": `from pathlib import Path

from flask import Blueprint, abort, g, send_file

statements = Blueprint("statements", __name__)
STATEMENT_ROOT = Path("/srv/portal/statements")


def statement_path(tenant_id, name):
    root = (STATEMENT_ROOT / str(tenant_id)).resolve()
    target = (root / name).resolve()
    if not target.is_relative_to(root):
        abort(403)
    return target


@statements.get("/account/statements/<int:tenant_id>/<path:name>")
def account_statement(tenant_id, name):
    return send_file(statement_path(tenant_id, name), as_attachment=True)


@statements.get("/billing/statements/<path:name>")
def billing_statement(name):
    return send_file(statement_path(g.tenant_id, name), as_attachment=True)
`,
    "src/grants.py": `import os

from flask import Blueprint, abort, g, jsonify, request
from itsdangerous import BadData, URLSafeTimedSerializer

grants = Blueprint("grants", __name__)
signer = URLSafeTimedSerializer(os.environ["REPORT_SIGNING_KEY"], salt="tenant-report")


def submitted_grants():
    request.max_content_length = 4096
    envelope = request.get_json()
    batch = envelope.get("grants") if isinstance(envelope, dict) else None
    if not isinstance(batch, list) or len(batch) != 2:
        abort(400)
    for grant in batch:
        if not isinstance(grant, dict):
            abort(400)
        tenant = grant.get("tenant_id")
        proof = grant.get("proof")
        if type(tenant) is not int or not 0 < tenant < 2**63:
            abort(400)
        if not isinstance(proof, str) or not proof.isascii():
            abort(400)
    return batch


def verified_grant(batch):
    for grant in batch:
        try:
            tenant = signer.loads(grant["proof"], max_age=300)
        except BadData:
            continue
        if tenant == grant["tenant_id"]:
            return grant
    abort(403)


def invoice_report(tenant_id):
    rows = g.database.execute(
        "SELECT id, recipient, total FROM invoices WHERE tenant_id = ?", (tenant_id,)
    ).fetchall()
    return jsonify([dict(row) for row in rows])


@grants.post("/account/report")
def account_report():
    batch = submitted_grants()
    verified_grant(batch)
    return invoice_report(batch[0]["tenant_id"])


@grants.post("/billing/report")
def billing_report():
    grant = verified_grant(submitted_grants())
    return invoice_report(grant["tenant_id"])
`,
    "src/preview.py": `from html import escape

from flask import Blueprint, Response, request

preview = Blueprint("preview", __name__)


@preview.get("/account/preview")
def account_preview():
    title = request.args.get("title", "")
    return Response(f"<h1>{title}</h1>", content_type="text/html")


@preview.get("/billing/preview")
def billing_preview():
    title = escape(request.args.get("title", ""))
    return Response(f"<h1>{title}</h1>", content_type="text/html")
`,
    "src/partners.py": `import requests
from flask import Blueprint, abort, request

partners = Blueprint("partners", __name__)
PARTNER_STATUS_URLS = {
    "https://catalog.example.test/status",
    "https://shipping.example.test/status",
}


@partners.get("/account/partner-status")
def account_partner_status():
    response = requests.head(request.args["url"], timeout=3, allow_redirects=False)
    return {"status": response.status_code}


@partners.get("/billing/partner-status")
def billing_partner_status():
    url = request.args["url"]
    if url not in PARTNER_STATUS_URLS:
        abort(400)
    response = requests.head(url, timeout=3, allow_redirects=False)
    return {"status": response.status_code}
`,
    "schema.sql": `CREATE TABLE invoices (
    id INTEGER PRIMARY KEY,
    tenant_id INTEGER NOT NULL,
    recipient TEXT NOT NULL,
    total INTEGER NOT NULL
);

CREATE TABLE catalog (
    id INTEGER PRIMARY KEY,
    tenant_id INTEGER NOT NULL,
    name TEXT NOT NULL
);
`,
  };
  const sourceCase = (
    id: string,
    path: string,
    marker: string,
    cwes: string[],
    occurrence = 0,
  ): SourceCase => {
    const lines = files[path].split("\n");
    const markers = marker.split("\n");
    const matchingLines = lines.flatMap((_, index) =>
      markers.every((part, offset) => lines[index + offset]?.includes(part))
        ? [index + 1]
        : [],
    );
    const line = matchingLines[occurrence];
    if (!line) throw new Error(`Fixture marker missing: ${id}`);
    const expected: SourceCase = { id, path, line, cwes };
    if (markers.length > 1) expected.endLine = line + markers.length - 1;
    return expected;
  };
  const tenantAccessCwes = ["CWE-639", "CWE-862", "CWE-863", "CWE-284"];
  const grantCwes = [
    ...tenantAccessCwes,
    "CWE-347",
    "CWE-345",
    "CWE-287",
    "CWE-349",
    "CWE-252",
  ];
  return {
    files,
    positives: [
      sourceCase(
        "invoice-tenant-isolation",
        "src/invoices.py",
        'FROM invoices WHERE id = ?"',
        tenantAccessCwes,
      ),
      sourceCase("catalog-sql-injection", "src/search.py", "query = f", [
        "CWE-89",
      ]),
      sourceCase(
        "export-path-traversal",
        "src/downloads.py",
        "send_file(EXPORT_ROOT",
        ["CWE-22", "CWE-23", "CWE-36", "CWE-73"],
      ),
      sourceCase(
        "preview-reflected-html",
        "src/preview.py",
        "return Response",
        ["CWE-79"],
      ),
      sourceCase(
        "partner-status-ssrf",
        "src/partners.py",
        'requests.head(request.args["url"]',
        ["CWE-918"],
      ),
      sourceCase(
        "statement-tenant-selection",
        "src/statements.py",
        "send_file(statement_path(tenant_id, name)",
        tenantAccessCwes,
      ),
      sourceCase(
        "report-unverified-grant",
        "src/grants.py",
        'verified_grant(batch)\nreturn invoice_report(batch[0]["tenant_id"])',
        grantCwes,
      ),
    ],
    controls: [
      sourceCase(
        "invoice-scoped-query",
        "src/invoices.py",
        "AND tenant_id = ?",
        tenantAccessCwes,
      ),
      sourceCase("catalog-bound-parameters", "src/search.py", "name LIKE ?", [
        "CWE-89",
      ]),
      sourceCase(
        "export-contained-path",
        "src/downloads.py",
        "send_file(target",
        ["CWE-22", "CWE-23", "CWE-36", "CWE-73"],
      ),
      sourceCase(
        "preview-escaped-html",
        "src/preview.py",
        "return Response",
        ["CWE-79"],
        1,
      ),
      sourceCase(
        "partner-status-allowlist",
        "src/partners.py",
        "requests.head(url,",
        ["CWE-918"],
      ),
      sourceCase(
        "statement-session-tenant",
        "src/statements.py",
        "send_file(statement_path(g.tenant_id, name)",
        tenantAccessCwes,
      ),
      sourceCase(
        "statement-contained-path",
        "src/statements.py",
        "if not target.is_relative_to(root):",
        ["CWE-22", "CWE-23", "CWE-36", "CWE-73"],
      ),
      sourceCase(
        "report-verified-grant",
        "src/grants.py",
        "return invoice_report(grant[",
        grantCwes,
      ),
    ],
  };
}
import { join } from "node:path";
import { writeFixture } from "../secret-discovery/fixtures.mts";

export async function prepareStandardEval(root: string, runtime: string) {
  const fixture = createFixture();
  const repo = join(root, "repository");
  await writeFixture(repo, fixture);
  return { repo, runtime, fixture };
}

export type PreparedStandardEval = Awaited<
  ReturnType<typeof prepareStandardEval>
>;

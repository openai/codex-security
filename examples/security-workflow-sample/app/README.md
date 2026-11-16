# Order Report API

This small order service has three synthetic customer accounts and a regional
report. It runs on loopback with Python's standard library; no installation,
external service, or real customer data is needed.

From the directory containing `app/`, run:

```bash
python3 -m app.server
```

Set `PORT=0` to select an available port. Restarting resets the database.

Use `Authorization: Bearer demo-acme`, `demo-beacon`, or `demo-cedar` for the
matching customer. The routes are:

| Route | Response |
| --- | --- |
| `GET /health` | Process readiness |
| `GET /api/orders` | Signed-in customer's order list |
| `GET /api/orders/{id}` | One order |
| `GET /api/reports/orders?region=west` | Regional order report |

The fixed tokens and order records are sample data. The API makes no outbound
requests and writes no database files.

`lambda_handler.py` exposes the same routes through an API Gateway HTTP API
event. The [SW-003 AWS runbook](../deployment/aws/README.md) packages this
adapter with the order service for a test account.

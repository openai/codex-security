"""API Gateway HTTP API adapter for the synthetic order service."""

import json

from .data import create_database
from .server import route_request


def handler(event, _context):
    method = event.get("requestContext", {}).get("http", {}).get("method", "GET")
    if method != "GET":
        return {
            "statusCode": 405,
            "headers": {"content-type": "application/json"},
            "body": json.dumps({"error": "method not allowed"}),
        }
    path = event.get("rawPath", "/")
    query = event.get("rawQueryString", "")
    if query:
        path = f"{path}?{query}"
    headers = {key.lower(): value for key, value in event.get("headers", {}).items()}
    database = create_database()
    try:
        status, body = route_request(path, headers.get("authorization", ""), database)
    finally:
        database.close()
    return {
        "statusCode": status,
        "headers": {"content-type": "application/json"},
        "body": json.dumps(body),
    }

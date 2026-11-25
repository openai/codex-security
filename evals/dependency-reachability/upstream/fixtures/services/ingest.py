"""Public mail intake. Run this process behind the /messages ingress."""

import json
import os
import re
import uuid
from email.parser import BytesHeaderParser
from email.policy import SMTP
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import boto3


bucket = os.environ["ARCHIVE_BUCKET"]
objects = boto3.client("s3")
jobs = boto3.client("sqs")
queue_url = jobs.get_queue_url(QueueName=os.environ["QUEUE_NAME"])["QueueUrl"]
media_policy = json.loads(Path(__file__).with_name("media.json").read_text())


def submit(raw):
    # Relay metadata is supplied by the gateway, never by the message author.
    parts = re.split(rb"\r?\n\r?\n", raw, maxsplit=1)
    if len(parts) != 2:
        raise ValueError("missing RFC 5322 header separator")
    content_type = b"Content-Type: text/plain\r\n"
    if media_policy["forwardContentType"]:
        original_headers = BytesHeaderParser(policy=SMTP).parsebytes(parts[0] + b"\r\n\r\n")
        if original_headers["Content-Type"] is not None:
            content_type = SMTP.fold_binary("Content-Type", original_headers["Content-Type"])
    envelope = b"From: relay@example.invalid\r\nTo: archive@example.invalid\r\n" + content_type + b"\r\n"

    key = f"messages/{uuid.uuid4()}.eml"
    receipt = objects.put_object(Bucket=bucket, Key=key, Body=raw)
    objects.put_object(Bucket=bucket, Key=key, Body=envelope + parts[1])
    locator = {"key": key, "generation": receipt.get("VersionId") or "null"}
    jobs.send_message(QueueUrl=queue_url, MessageBody=json.dumps(locator))
    return key


class Ingest(BaseHTTPRequestHandler):
    def do_POST(self):
        if self.path != "/messages":
            self.send_error(404)
            return
        try:
            submit(self.rfile.read(int(self.headers["Content-Length"])))
        except ValueError as error:
            self.send_error(400, str(error))
            return
        self.send_response(202)
        self.end_headers()


if __name__ == "__main__":
    HTTPServer(("", int(os.environ.get("PORT", 8080))), Ingest).serve_forever()

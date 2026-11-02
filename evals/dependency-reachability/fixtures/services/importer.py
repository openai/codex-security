"""Imports archived mail into the message index. Runs in the worker image."""

import json
import os
import subprocess
from pathlib import Path

import boto3


bucket = os.environ["ARCHIVE_BUCKET"]
queue_url = os.environ["IMPORT_QUEUE_URL"]
objects = boto3.client("s3")
jobs = boto3.client("sqs")


def import_job(message):
    locator = json.loads(message["Body"])
    obj = objects.get_object(Bucket=bucket, Key=locator["key"], VersionId=locator["generation"])
    subprocess.run(["node", Path(__file__).with_name("index-mail.cjs")], input=obj["Body"].read(), check=True)
    jobs.delete_message(QueueUrl=queue_url, ReceiptHandle=message["ReceiptHandle"])


if __name__ == "__main__":
    while True:
        batch = jobs.receive_message(QueueUrl=queue_url, WaitTimeSeconds=20)
        for job in batch.get("Messages", []):
            import_job(job)

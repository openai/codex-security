"""Imports archived mail into the message index. Runs in the worker image."""

import json
import os
import subprocess
from pathlib import Path

import boto3


bucket = os.environ["ARCHIVE_BUCKET"]
objects = boto3.client("s3")
jobs = boto3.client("sqs")
queue_url = jobs.get_queue_url(QueueName=os.environ["QUEUE_NAME"])["QueueUrl"]


def archived_version(locator):
    return objects.get_object(Bucket=bucket, Key=locator["key"], VersionId=locator["generation"])


def consume(open_object):
    while True:
        batch = jobs.receive_message(QueueUrl=queue_url, WaitTimeSeconds=20)
        for message in batch.get("Messages", []):
            obj = open_object(json.loads(message["Body"]))
            subprocess.run(["node", Path(__file__).with_name("index-mail.cjs")], input=obj["Body"].read(), check=True)
            jobs.delete_message(QueueUrl=queue_url, ReceiptHandle=message["ReceiptHandle"])


if __name__ == "__main__":
    consume(archived_version)

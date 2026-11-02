from archive.importer import bucket, consume, objects


def latest_version(locator):
    return objects.get_object(Bucket=bucket, Key=locator["key"])


if __name__ == "__main__":
    consume(latest_version)

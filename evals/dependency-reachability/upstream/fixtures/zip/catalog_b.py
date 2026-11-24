def messages(archive):
    for member in archive.infolist():
        if not member.filename.endswith(".eml"):
            raise ValueError("expected a mail bundle")
        yield archive.read(member)

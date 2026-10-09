# Synthetic service

The caller supplies a trusted storage root and an untrusted relative path.
Both read functions are public entry points used by a request handler.
Only files below the storage root may be returned.

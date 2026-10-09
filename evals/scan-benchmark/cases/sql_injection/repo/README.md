# Synthetic service

The caller supplies a trusted SQLite connection and an untrusted user name.
Both lookup functions are public entry points used by a request handler.
A user name must be treated as a value, never as SQL syntax.

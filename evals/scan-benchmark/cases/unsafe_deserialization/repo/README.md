# Synthetic service

The caller supplies untrusted bytes from a request body.
Both decode functions are public entry points used by a request handler.
Decoding must not invoke executable behavior from the supplied bytes.

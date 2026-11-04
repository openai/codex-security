# Security policy

This synthetic product's supported version is 0.0.0. Its default surface is a local operator CLI. Command strings supplied to that CLI are trusted input from the same operator whose privileges run the command. Executing the requested shell command is intended behavior; there is no lower-trust command source in the supported CLI model.

A command-execution claim is reportable only if a less-trusted actor can cross that operator boundary. The presence of a shell primitive alone does not establish a violation.

Subdirectories may define a different supported surface and input boundary in scoped `SECURITY.md` files. Apply those policies to code reached in that subtree.

# Synthetic application contract

This is a static-only, fictional evaluation fixture. No package installation or execution is required.

`src/application.mjs` is the complete deployed entrypoint. `request` comes from authenticated tenants and all its body, values, query, and pattern fields are user-controlled. Tenant authentication does not make these fields trusted. Deployment settings are operator-controlled. There are no other endpoints, wrappers, validation layers, or source files in this fixture.

The deployed value of `maxDepth` is not included in this snapshot. It may be either the advisory-relevant or the documented-workaround value.

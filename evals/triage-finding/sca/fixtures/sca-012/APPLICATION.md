# Synthetic application contract

This is a static-only, fictional evaluation fixture. No package installation or execution is required.

`src/application.mjs` is the complete deployed entrypoint. `request` comes from authenticated tenants and all its body, values, query, and pattern fields are user-controlled. Tenant authentication does not make these fields trusted. Deployment settings are operator-controlled. There are no other endpoints, wrappers, validation layers, or source files in this fixture.

The deployed value of `bounded` is not included in this snapshot. It may be either the advisory-relevant or the documented-workaround value.

This repository builds a preview service and its build bundle includes this devDependency. Its placement in devDependencies does not exclude it from deployment.

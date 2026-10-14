# Development in Ona

In the Ona project's Settings, set **Dev Container path** to
`.ona/devcontainer.json` and **Tasks and services configuration path** to
`.ona/automations.yml`. Create a new environment or rebuild its Dev Container
after changing the path. The Ona configuration uses the same image, feature
versions, and install script as the default Dev Container.

Run `install`, `build`, or `test` from Ona's task list. Dependency installation
and builds also run during prebuilds. Before running tests, download the
source-matched native artifact described in [SDK testing](../sdk/typescript/TESTING.md).

For migration from the findings service, retain its data volume and follow
the [local findings and dedupe guide](../sdk/typescript/docs/findings-service.md).
Keep the shared and Ona feature definitions and lockfiles aligned when updating
the toolchain.

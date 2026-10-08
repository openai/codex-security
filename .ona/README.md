# Findings service in Ona

In the Ona project's Settings, set **Dev Container path** to
`.ona/devcontainer.json` and **Tasks and services configuration path** to
`.ona/automations.yml`. Create a new environment or rebuild its Dev Container
after changing the path. The Ona configuration uses the same image, feature
versions, and install script as the default Dev Container.

The `findings-start` task starts the shared findings image after environment
start/resume or a Dev Container rebuild. It opens port 3000 for the environment
creator. Run `findings-start` or `findings-stop` manually from Ona's task list;
stopping findings keeps its stored data. The existing
`CODEX_SECURITY_FINDINGS_IMAGE` override still selects the image.

Ona's [port proxy](https://ona.com/docs/ona/integrations/ports#host-network-stack)
requires host networking for both the Dev Container and the findings container.
The Ona Compose override supplies that network setting; standalone
`compose.findings.yaml` keeps its loopback binding. Keep the shared and Ona
feature definitions and lockfiles aligned when updating the toolchain.

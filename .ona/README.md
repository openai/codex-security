# Development in Ona

In the Ona project's Settings, set **Dev Container path** to
`.ona/devcontainer.json` and **Tasks and services configuration path** to
`.ona/automations.yml`. Create a new environment or rebuild its Dev Container
after changing the path. The Ona configuration uses the same image, feature
versions, and install script as the default Dev Container.

From the Ona task list, select **Install dependencies**, then **Build**. These tasks also run during prebuilds. To run **Run tests**, first [download the native payload for your checkout](../plugins/codex-security/native/README.md#package-inputs).

When updating the toolchain, keep the shared and Ona feature definitions and lockfiles aligned.

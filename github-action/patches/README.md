# Action dependency patches

- @actions/artifact: propagate archive and input-stream errors to the upload promise, cancel streams on upload failure, and hash the bytes forwarded to storage.
- readable-stream: preserve missing-argument names and initialize the diagnostic before concatenating it.

The build applies these patches explicitly with git apply because CI uses npm ci --ignore-scripts. The test pre-hook applies the same patches before testing the installed dependencies. Patch contents are included in the release build-input hashes.

When updating either dependency, review whether upstream has fixed the behavior, refresh or remove its patch, regenerate the distribution, and run npm run validate. The regression tests cover the affected runtime behavior.

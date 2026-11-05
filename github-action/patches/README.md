# Action dependency patches

- [`@actions/artifact`](@actions+artifact+6.3.1.patch) propagates archive and input-stream errors to the upload promise, cancels streams on upload failure, and hashes the bytes forwarded to storage.
- [`readable-stream`](readable-stream+4.7.0.patch) preserves missing-argument names and initializes the diagnostic before concatenating it.

The build applies these patches explicitly with `git apply` because CI uses `npm ci --ignore-scripts`. The test pre-hook applies the same patches before testing the installed dependencies. Patch contents are included in the release build-input hashes.

When updating either dependency, review whether upstream has fixed the behavior, refresh or remove its patch, regenerate the distribution, and run `npm --prefix github-action run validate` from the repository root. The regression tests cover the affected runtime behavior.

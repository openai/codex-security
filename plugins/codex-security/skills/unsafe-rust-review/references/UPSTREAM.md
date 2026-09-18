# Upstream method

The review method in [unsafe-rust-review.md](unsafe-rust-review.md) comes from [Google's rust-skills repository](https://github.com/google/rust-skills), file [`unsafe_rust_review/SKILL.md`](https://github.com/google/rust-skills/blob/4b4f8b25d19c5ad3ad78b23c4c55ac35adad75a3/unsafe_rust_review/SKILL.md), pinned at commit `4b4f8b25d19c5ad3ad78b23c4c55ac35adad75a3`. It is distributed under the [Apache License 2.0](https://github.com/google/rust-skills/blob/4b4f8b25d19c5ad3ad78b23c4c55ac35adad75a3/LICENSE.md). The plugin ships the shared license text at `mcp/native/licenses/Apache-2.0.txt`.

Original skill SHA-256: `0b2b19fec6f669f7d984518fbf4b7cc194d095aa920459a0ef6e2846e0c91348`.

The vendored method retains the upstream frontmatter, wording, examples, and review rules. Local changes are the attribution comment and mechanical joining of prose lines into Markdown paragraphs to meet this repository's source-format checks; fenced code examples are unchanged. The surrounding [Codex Security skill](../SKILL.md) supplies scope, environment preparation, runtime validation, and reporting integration separately.

To update, select and review an upstream commit and its license, replace the method from that commit, and repeat only the documented prose reflow. Compare whitespace-normalized text and fenced code blocks against upstream to verify that the import preserves the method. Update the pinned links, commit, and original-source digest, review substantive upstream changes against the wrapper, and run the plugin's source/package checks plus the Rust skill behavior evaluation. Do not automatically track the moving upstream branch during a scan.

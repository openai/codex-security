#!/usr/bin/env bash
set -euo pipefail
# Include filenames and modes, not only file contents. Windows proofs
# bundle MCP helpers, including their schema and workbench dependencies.
empty_tree="$(git hash-object -t tree --stdin </dev/null)"
# These existing CI entrypoints run outside the native jobs.
ci_only=':(exclude).github/scripts/'
source_hash="$(git diff-tree -r -z --no-abbrev "$empty_tree" HEAD -- \
  .gitattributes .cargo .npmrc .pnpmfile.cjs package.json pnpm-workspace.yaml \
  .github/actions/{native-cache-key,setup-tools} .github/scripts \
  "${ci_only}"invoice-desk-{source,target}{,.test}.mjs \
  "${ci_only}"{check-ci-results,select-ci-checks,test-ci-selection,test-release-guide}.mjs \
  "${ci_only}"{verify-pr-source,test-verify-pr-source,release-progress,test_release_progress}.mjs \
  "${ci_only}"{install-ripgrep.sh,require_native_python_report.py,test_require_native_python_report.py} \
  .github/workflows/native-artifacts.yml \
  .github/workflows/native-unix.yml \
  .github/workflows/native-windows.yml \
  .github/workflows/native-musl.yml \
  sdk/typescript/.npmrc sdk/typescript/.pnpmfile.cjs \
  sdk/typescript/package.json sdk/typescript/pnpm-lock.yaml \
  sdk/typescript/pnpm-workspace.yaml \
  sdk/typescript/tsconfig.json sdk/typescript/tsconfig.ci.json \
  plugins/codex-security/native plugins/codex-security/mcp-app \
  ':(exclude)plugins/codex-security/mcp-app/tests' \
  plugins/codex-security/schemas plugins/codex-security/scripts \
  plugins/codex-security/shared | git hash-object --stdin)"
# Hosted runner images can change without a source change.
# Keep a protected push in the week it was classified, including at UTC rollover.
week=${NATIVE_CACHE_WEEK:-0}
if [[ $week == 0 ]]; then week="$(date -u +%G%V)"; fi
key="native-universal-v1-${week:0:4}-${week:4}-$source_hash"
if [[ ${1-} == cold-group ]]; then
  printf 'week=%s\n' "$week"
  # The listing is only a scheduling hint. prepare always restores or builds.
  hit="$(timeout 5s gh cache list --ref refs/heads/main --key "$key" --limit 1 --json key --jq '.[0].key // empty')"
  # Three lanes per 300 workflow numbers keep each group within GitHub's 100-pending limit.
  if [[ "$hit" != "$key" ]]; then
    printf 'cold-group=%s-%s-%s\n' "$key" "$((GITHUB_RUN_NUMBER / 300))" "$((GITHUB_RUN_NUMBER % 3))"
  fi
else
  printf 'key=%s\n' "$key"
fi

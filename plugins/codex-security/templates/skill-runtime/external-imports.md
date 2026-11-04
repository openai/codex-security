## enabled

External findings imports are enabled for this command environment. Proceed with the requested source and destination using the publish-findings workflow, including its preview and approval before writing.

## disabled

Stop before acquiring, previewing, or importing findings. Tell the user that external findings imports are disabled and ask them to enable `CODEX_SECURITY_ENABLE_EXTERNAL_IMPORTS=1` in the import command's environment. After they enable imports, request this topic again from that environment.

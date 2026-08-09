# Roadmap and design ideas

Version 0.3 adds request-scoped password/private-key connections to arbitrary SSH destinations while retaining named targets for compatibility. Useful follow-ons:

## Human approval queue

For production targets, `ssh_prepare` could write a short-lived request containing the target, command hash, reason, and expiry. A human would approve it locally with `mcp-ssh approve <id>` before `ssh_exec` accepts the one-time token.

## Ephemeral identity providers

Add optional adapters for short-lived OpenSSH certificates from Vault, Smallstep, AWS EC2 Instance Connect, or an internal CA so long-lived passwords and private keys do not need to cross the MCP request boundary.

## Constrained file transfer

Expose separate `sftp_read`, `sftp_write`, and `sftp_list` tools with configured root directories, byte limits, extension policies, checksums, and atomic writes. Do not hide file transfer inside arbitrary shell commands.

## Fleet operations with blast-radius budgets

A future fan-out tool could require target tags, a hard maximum target count, bounded concurrency, per-host output limits, stop-on-error behavior, and a previewed execution plan. Production should require human approval.

## Observability

Emit OpenTelemetry spans and structured events for policy decisions, connection latency, remote exit status, truncation, and timeouts. Never attach private keys or command output to telemetry.

## Host facts as MCP resources

Cache explicitly approved, read-only facts such as OS release, kernel version, uptime, and service health as MCP resources. This reduces repetitive SSH calls and gives the model stable context.

## Session recording

For regulated environments, route production connections through a bastion that records sessions and signs audit events. Keep this connector's audit IDs as correlation keys.

## Cross-platform checks

Allow each target to configure a no-op health command (`true`, PowerShell, or network-device CLI equivalent) while still keeping it operator-controlled and non-interactive.

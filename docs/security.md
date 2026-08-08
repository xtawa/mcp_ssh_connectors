# Security model

`mcp-ssh-connectors` deliberately exposes less power than an interactive SSH client.

## Trust boundaries

- The MCP client and model are **untrusted command requesters**.
- The host configuration, local OpenSSH binary, SSH agent, key files, `known_hosts`, and `~/.ssh/config` are trusted operator-controlled inputs.
- Remote hosts and their output are untrusted. Treat remote output as data, not instructions.

## Controls

1. **Named targets only** — MCP calls cannot provide an arbitrary hostname, username, port, key path, jump host, or SSH option.
2. **Default deny** — every target needs at least one `allowedCommands` regular expression.
3. **Deny before allow** — global and target deny rules win even if an allow rule also matches.
4. **Single-line, bounded input** — NUL and newline characters are rejected and command size is capped.
5. **Non-interactive execution** — MCP uses `BatchMode=yes`, disables TTY allocation, ignores stdin, and enforces a timeout.
6. **Host-key verification** — `StrictHostKeyChecking=yes` is always set. Trust a new host manually before enabling it.
7. **No forwarding** — agent forwarding, local commands, and configured forwards are disabled for connector calls.
8. **Bounded output** — stdout and stderr share a per-target byte budget.
9. **Audit trail** — command starts and finishes are written as JSON Lines. Commands are SHA-256 fingerprinted by default instead of stored verbatim.
10. **No key transport** — private-key bytes never enter MCP requests or responses.

## Important limitations

- An allowed remote shell command can still be dangerous. Prefer anchored, argument-specific patterns; avoid `.*`.
- Shell semantics are remote-platform dependent. Review quoting and command expansion for the target shell.
- `~/.ssh/config` is trusted host configuration. A `ProxyCommand` in that file can execute a local process, so protect that file from untrusted writes.
- The `ssh_check` tool runs `true`; it assumes a POSIX-like remote shell.
- `mcp-ssh connect` is intentionally a human-only interactive escape hatch. It is not registered as an MCP tool and is not restricted by command rules.
- Audit records prove what this connector requested, not every action performed through other SSH clients or processes.

## Deployment checklist

- Run the MCP server as a dedicated, unprivileged OS account.
- Give that account only the minimum SSH keys and remote permissions required.
- Use separate targets and keys for development, staging, and production.
- Prefer restricted remote accounts, forced commands, read-only sudoers entries, or containers for defense in depth.
- Keep `audit.required` enabled and ship the JSONL file to append-only storage.
- Keep `logCommands` disabled if commands may contain sensitive values.
- Rotate host keys and credentials through normal SSH operations; never place secrets in the JSON config.
- Review allow/deny expressions and audit logs regularly.

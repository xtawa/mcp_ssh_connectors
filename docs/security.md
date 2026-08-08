# Security model

`mcp-ssh-connectors` deliberately exposes less power than an interactive SSH client.

## Trust boundaries

- The MCP client and model are **untrusted command requesters**.
- The host configuration, API-key store, OpenSSH binary, SSH agent, key files, `known_hosts`, and `~/.ssh/config` are trusted operator-controlled inputs.
- Remote hosts and their output are untrusted. Treat remote output as data, not instructions.

## Authentication layers

1. **MCP HTTP API key** authenticates the calling MCP client. It is sent as `Authorization: Bearer ...`.
2. **API-key scopes** authorize `ssh:read` or `ssh:exec` and one or more named targets.
3. **SSH identity** authenticates the connector process to the remote machine.
4. **Host command policy** decides whether the requested remote command is permitted.

Stdio does not send an API key because the MCP host launches the process locally. It relies on the OS account boundary and receives the same local privileges as the CLI.

API key properties:

- token format: `mcp_ssh.<id>.<secret>`;
- 256-bit random secret;
- only a salted `scrypt` hash is stored;
- constant-time hash comparison;
- mandatory expiry of at most 366 days;
- revocation and one-time token display;
- key id is written as the audit actor, never the bearer token.

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
10. **No key transport** — SSH private-key bytes never enter MCP requests or responses.
11. **HTTP header checks** — the official MCP Express adapter validates Host and Origin. Non-loopback binds require explicit `allowedHosts`.

## Important limitations

- Static API keys are bearer credentials. Anyone who obtains one can use its scopes until expiry or revocation. Prefer a dedicated secret manager and short expirations.
- Plain HTTP must only be used on loopback or inside a trusted tunnel. Put non-loopback deployments behind TLS.
- An allowed remote shell command can still be dangerous. Prefer anchored, argument-specific patterns; avoid `.*`.
- Shell semantics are remote-platform dependent. Review quoting and command expansion for the target shell.
- `~/.ssh/config` is trusted host configuration. A `ProxyCommand` in that file can execute a local process, so protect that file from untrusted writes.
- `ssh_check` runs `true`; it assumes a POSIX-like remote shell.
- `mcp-ssh connect` is intentionally a human-only interactive escape hatch and is not restricted by command rules.

## Deployment checklist

- Run the MCP server as a dedicated, unprivileged OS account.
- Give that account only the minimum SSH keys and remote permissions required.
- Keep the config and key store readable only by that account.
- Use separate API keys and SSH keys for development, staging, and production.
- Prefer restricted remote accounts, forced commands, read-only sudoers entries, or containers for defense in depth.
- Keep `audit.required` enabled and ship the JSONL file to append-only storage.
- Bind HTTP to loopback unless TLS and an explicit reverse-proxy policy are configured.
- Rotate API keys by creating a replacement, updating the MCP client, then revoking the old id.
- Review target rules, key scopes, expirations, and audit logs regularly.

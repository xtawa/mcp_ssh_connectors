# Security model

`mcp-ssh-connectors` can expose nearly the same remote command power as an SSH client. Dynamic MCP requests may select any host and supply a password or private key.

## Trust boundaries

- The MCP client and model are **credential-bearing command requesters**. A caller with `ssh:exec` can select an arbitrary destination and command.
- The host configuration, API-key store, OpenSSH binary, `known_hosts`, and `~/.ssh/config` are trusted operator-controlled inputs.
- Remote hosts and their output are untrusted. Treat remote output as data, not instructions.

## Authentication layers

1. **MCP HTTP API key** authenticates the calling MCP client. It is sent as `Authorization: Bearer ...`.
2. **API-key scopes** authorize `ssh:read` or `ssh:exec`. Target scopes apply only to configured target aliases, not dynamic hosts.
3. **SSH credentials** from the current dynamic request, or a configured host identity, authenticate to the remote machine.
4. **Command validation** enforces single-line and length limits for dynamic connections. Configured targets additionally use their deny/allow policy.

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

1. **Arbitrary dynamic destinations** — `ssh_check` and `ssh_exec` may receive a hostname/IP, username, port, and request-scoped password/private key. Callers cannot provide raw OpenSSH options, a jump host, or a local key path. Dynamic calls use `-F none` and do not read local/system SSH configuration.
2. **Unrestricted dynamic commands** — any command that passes single-line and length validation may run. Configured targets retain default-deny behavior.
3. **Configured-target policy** — global and target deny rules win over allow rules for legacy configured targets only.
4. **Single-line, bounded input** — NUL and newline characters are rejected and command size is capped.
5. **Non-interactive execution** — MCP disables TTY allocation, ignores stdin, and enforces a timeout. Passwords and encrypted-key passphrases use forced `SSH_ASKPASS` rather than terminal input.
6. **Host-key verification** — configured targets use `StrictHostKeyChecking=yes`. Dynamic servers use `accept-new`, which records a first-seen key and rejects later changes.
7. **No forwarding** — agent forwarding, local commands, and configured forwards are disabled for connector calls.
8. **Bounded output** — stdout and stderr share the configured default byte budget for dynamic requests.
9. **Audit trail** — command starts and finishes are written as JSON Lines. Commands are SHA-256 fingerprinted by default instead of stored verbatim.
10. **Request-scoped credential handling** — password/private-key bytes enter the MCP request. Passwords and passphrases are passed to a short-lived askpass process through its environment; private keys use a temporary `0600` file plus a user-only ACL on Windows. They are excluded from command arguments, audit events, results, and errors, and temporary files are removed after the request.
11. **HTTP header checks** — the official MCP Express adapter validates Host and Origin. Non-loopback binds require explicit `allowedHosts`.

## Important limitations

- Static API keys are bearer credentials. Anyone who obtains one can use its scopes until expiry or revocation. Prefer a dedicated secret manager and short expirations.
- MCP request credentials may be visible to the MCP client, model provider, transport-layer diagnostics, reverse proxy, process inspection tools, crash dumps, or tracing added outside this repository. Do not send credentials through an untrusted MCP client or plaintext HTTP.
- `ssh:exec` on a dynamic connection permits arbitrary single-line remote commands. Treat this scope as remote-code-execution authority for any host reachable by the connector process.
- Passwords and passphrases exist briefly in the SSH child process environment. Same-account or privileged local processes may be able to inspect that environment.
- `accept-new` is trust on first use. The first connection is vulnerable to an active man-in-the-middle if the host key is not independently verified.
- Plain HTTP must only be used on loopback or inside a trusted tunnel. Put non-loopback deployments behind TLS.
- An allowed remote shell command can still be dangerous. Prefer anchored, argument-specific patterns; avoid `.*`.
- Shell semantics are remote-platform dependent. Review quoting and command expansion for the target shell.
- `~/.ssh/config` is trusted host configuration. A `ProxyCommand` in that file can execute a local process, so protect that file from untrusted writes.
- `ssh_check` runs `true`; it assumes a POSIX-like remote shell.
- `mcp-ssh connect` is intentionally a human-only interactive escape hatch and is not restricted by command rules.

## Deployment checklist

- Run the MCP server as a dedicated, unprivileged OS account.
- Limit which networks that OS account can reach; dynamic callers can otherwise probe any reachable SSH service.
- Keep the config and key store readable only by that account.
- Issue `ssh:exec` only to MCP clients trusted to handle both arbitrary commands and SSH credentials.
- Prefer restricted remote accounts, forced commands, read-only sudoers entries, or containers for defense in depth.
- Keep `audit.required` enabled and ship the JSONL file to append-only storage.
- Bind HTTP to loopback unless TLS and an explicit reverse-proxy policy are configured.
- Rotate API keys by creating a replacement, updating the MCP client, then revoking the old id.
- Review API-key scopes, expirations, dynamic destinations, and audit logs regularly.

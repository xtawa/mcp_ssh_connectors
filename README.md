# mcp_ssh_connectors

A host-side MCP server and local terminal tool that let an AI use the **host machine's OpenSSH client** to reach any SSH server with a request-scoped password or private key, even when the model sandbox has no direct network path. Configured named targets remain available for compatibility.

通过宿主机的 OpenSSH 客户端，让 AI 使用请求中提供的密码或私钥连接任意 SSH 服务器；支持本地 stdio，也支持带 API Key 鉴权的 Streamable HTTP MCP。

> Dynamic MCP connections can execute any validated single-line command. HTTP clients still need a scoped, unexpired Bearer API key. Credentials are request-scoped and are never logged or returned.

## Architecture

```mermaid
flowchart LR
  AI[AI / MCP client] -->|stdio, local OS boundary| S[mcp-ssh-server]
  AI -->|HTTP + Bearer API key| H[mcp-ssh-http]
  H --> K[scrypt key store + scopes]
  S --> P[dynamic connection or configured target]
  H --> P
  U[Human terminal] -->|mcp-ssh CLI| P
  P -->|spawn, shell=false| O[Host OpenSSH client]
  O --> R[configured SSH instances]
  P --> A[JSONL audit log]
```

Node.js 20+ and an OpenSSH-compatible `ssh` executable are required.

## Included

- MCP tools: `ssh_list_targets`, `ssh_preview`, `ssh_check`, `ssh_exec`; check/exec accept configured targets or arbitrary dynamic connections
- Local stdio MCP and authenticated Streamable HTTP MCP
- API key creation, listing, expiry, target scopes, operation scopes, and revocation
- Local CLI: `init`, `targets`, `preview`, `check`, `exec`, `connect`, `mcp`, `http`, `key`
- TOFU host-key checking for dynamic servers, request-scoped credentials, timeouts, output caps, and JSONL auditing
- ProxyJump, identity-file, port, and dedicated known-hosts support
- CI and unit tests

## Install

```bash
git clone https://github.com/xtawa/mcp_ssh_connectors.git
cd mcp_ssh_connectors
npm install
npm run check
npm link
mcp-ssh init
$EDITOR ~/.config/mcp-ssh/config.json
```

After adding an optional configured target, it can still be tested through the CLI:

```bash
ssh example
mcp-ssh preview example -- uname -a
mcp-ssh check example
mcp-ssh exec example -- uname -a
```

## Dynamic SSH connections

`ssh_check` and `ssh_exec` accept a `connection` object instead of a configured `target`. The connection requires a host, username, optional port, and exactly one authentication method.

Password example:

```json
{
  "connection": {
    "host": "203.0.113.10",
    "username": "deploy",
    "port": 22,
    "authentication": {
      "type": "password",
      "password": "request-scoped-password"
    }
  },
  "command": "uname -a",
  "reason": "diagnostics"
}
```

Private-key example:

```json
{
  "connection": {
    "host": "server.example.com",
    "username": "root",
    "authentication": {
      "type": "privateKey",
      "privateKey": "-----BEGIN OPENSSH PRIVATE KEY-----\n...\n-----END OPENSSH PRIVATE KEY-----",
      "passphrase": "optional-key-passphrase"
    }
  },
  "command": "systemctl status example"
}
```

Dynamic commands are not checked against configured allow/deny expressions. They must be non-empty, single-line, NUL-free, and within `policy.maxCommandLength`. Dynamic calls use `-F none`, so local/system SSH configuration cannot inject a proxy or other options. New host keys use `StrictHostKeyChecking=accept-new`: the first key is recorded, while later key changes are rejected.

Passwords and key passphrases are supplied to OpenSSH through a forced `SSH_ASKPASS` helper. Private-key content is written to a per-request `0600` temporary file; Windows also receives an explicit user-only ACL. Temporary credential files are removed when the request finishes. Credentials are not included in process arguments, audit records, tool results, or error objects.

## Local stdio MCP

```json
{
  "mcpServers": {
    "ssh-connectors": {
      "command": "mcp-ssh-server",
      "env": { "MCP_SSH_CONFIG": "/absolute/path/to/config.json" }
    }
  }
}
```

Stdio relies on the local OS account boundary; no API key is sent through the model context.

## HTTP MCP with API Key authentication

Create a read-only key restricted to `staging`:

```bash
mcp-ssh key create staging-observer \
  --scopes mcp,ssh:read \
  --expires 30d
```

Create an execution key for two targets:

```bash
mcp-ssh key create deploy-agent \
  --scopes mcp,ssh:read,ssh:exec \
  --expires 7d
```

The complete token is shown **once**. The key store contains only its salted `scrypt` hash. List metadata or revoke a key:

```bash
mcp-ssh key list
mcp-ssh key revoke KEY_ID
```

Start the authenticated endpoint:

```bash
mcp-ssh http
# or: mcp-ssh-http
# http://127.0.0.1:3000/mcp
```

Clients send:

```http
Authorization: Bearer mcp_ssh.KEY_ID.SECRET
```

Example MCP client configuration:

```json
{
  "mcpServers": {
    "ssh-connectors-http": {
      "url": "http://127.0.0.1:3000/mcp",
      "headers": { "Authorization": "Bearer ${MCP_SSH_API_KEY}" }
    }
  }
}
```

Keep the token in the client environment or secret manager. Do not commit it. For any non-loopback deployment, use TLS and set `http.allowedHosts`; preferably place the service behind a hardened reverse proxy.

### Scopes

| Scope | Permission |
| --- | --- |
| `mcp` | Required to reach the MCP endpoint |
| `ssh:read` | List targets, preview commands, and check connectivity |
| `ssh:exec` | Execute commands that also pass host policy |

New API keys default to target `*`, which permits their SSH operation scopes to use dynamic connections. `--targets` remains available to restrict access to legacy configured targets; it does not restrict dynamic hosts.

## Configuration

```json
{
  "version": 1,
  "sshBinary": "ssh",
  "auth": { "keyStore": "~/.config/mcp-ssh/keys.json" },
  "http": {
    "host": "127.0.0.1",
    "port": 3000,
    "allowedHosts": [],
    "allowedOrigins": []
  },
  "audit": { "required": true, "logCommands": false },
  "defaults": {
    "timeoutMs": 30000,
    "connectTimeoutSeconds": 10,
    "maxOutputBytes": 1048576,
    "knownHostsFile": "~/.ssh/known_hosts"
  },
  "policy": {
    "maxCommandLength": 4096,
    "deniedCommands": ["(?:^|\\s)sudo(?:\\s|$)"]
  },
  "targets": {
    "staging": {
      "destination": "deploy@10.0.20.15",
      "identityFile": "~/.ssh/staging_ed25519",
      "proxyJump": "bastion",
      "tags": ["staging", "linux"],
      "allowedCommands": [
        "^uname -a$",
        "^systemctl status [A-Za-z0-9_.@-]+$"
      ],
      "deniedCommands": ["(?:^|[;&|]\\s*)rm(?:\\s|$)"],
      "requireReason": true
    }
  }
}
```

The `targets` object is optional and may be empty. For configured targets, deny rules run before allow rules and a target with no `allowedCommands` is blocked. Dynamic connections bypass these configured command expressions and retain only the global length and single-line validation.

## Terminal commands

```text
mcp-ssh init [--config PATH]
mcp-ssh targets [--config PATH]
mcp-ssh preview TARGET [--reason TEXT] -- COMMAND
mcp-ssh check TARGET [--config PATH]
mcp-ssh exec TARGET [--reason TEXT] -- COMMAND
mcp-ssh connect TARGET [--config PATH]
mcp-ssh mcp [--config PATH]
mcp-ssh http [--host HOST] [--port PORT] [--config PATH]
mcp-ssh key create NAME [--targets LIST] [--scopes LIST] [--expires 30d]
mcp-ssh key list [--config PATH]
mcp-ssh key revoke KEY_ID [--config PATH]
```

`connect` is a human-only interactive shell and is not exposed as an MCP tool.

## Request authorization order

For HTTP requests the connector applies four independent checks:

1. validate the Bearer key hash, expiry, and revocation state;
2. require operation scope (`ssh:read` or `ssh:exec`), plus target access only for a configured target;
3. validate dynamic single-line commands, or apply configured-target deny/allow rules;
4. authenticate to the remote machine with the request password/private key or configured host SSH identity.

The API key id is recorded as the audit actor. Neither bearer tokens nor SSH key contents are logged.

## Security

Read [docs/security.md](docs/security.md) before exposing this server. Dynamic access deliberately gives an `ssh:exec` caller broad reach. Plain HTTP should stay on loopback or inside a trusted tunnel. Non-loopback deployments need TLS, explicit host/origin policy, short-lived scoped keys, and append-only audit storage.

## Ideas and next steps

See [docs/roadmap.md](docs/roadmap.md) for human approvals, external identity providers, ephemeral SSH certificates, constrained SFTP, fleet blast-radius budgets, cached host facts, telemetry, and session recording.

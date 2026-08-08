# mcp_ssh_connectors

A policy-gated MCP server and local terminal tool that let an AI use the **host machine's OpenSSH client** to reach configured SSH instances, even when the model sandbox has no direct network path.

通过宿主机的 OpenSSH 客户端，把受策略限制的 SSH 能力提供给 AI；支持本地 stdio，也支持带 API Key 鉴权的 Streamable HTTP MCP。

> Security first: MCP can use only named targets and allowlisted commands. HTTP clients additionally need a scoped, unexpired Bearer API key.

## Architecture

```mermaid
flowchart LR
  AI[AI / MCP client] -->|stdio, local OS boundary| S[mcp-ssh-server]
  AI -->|HTTP + Bearer API key| H[mcp-ssh-http]
  H --> K[scrypt key store + scopes]
  S --> P[shared target and command policy]
  H --> P
  U[Human terminal] -->|mcp-ssh CLI| P
  P -->|spawn, shell=false| O[Host OpenSSH client]
  O --> R[configured SSH instances]
  P --> A[JSONL audit log]
```

Node.js 20+ and an OpenSSH-compatible `ssh` executable are required.

## Included

- MCP tools: `ssh_list_targets`, `ssh_preview`, `ssh_check`, `ssh_exec`
- Local stdio MCP and authenticated Streamable HTTP MCP
- API key creation, listing, expiry, target scopes, operation scopes, and revocation
- Local CLI: `init`, `targets`, `preview`, `check`, `exec`, `connect`, `mcp`, `http`, `key`
- Strict host-key checking, default-deny command policy, timeouts, output caps, and JSONL auditing
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

Trust a new SSH host manually first, then test the policy:

```bash
ssh example
mcp-ssh preview example -- uname -a
mcp-ssh check example
mcp-ssh exec example -- uname -a
```

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
  --targets staging \
  --expires 30d
```

Create an execution key for two targets:

```bash
mcp-ssh key create deploy-agent \
  --scopes mcp,ssh:read,ssh:exec \
  --targets staging,production \
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

Every API key also has a target list. Use `--targets '*'` only when access to every configured target is intentional.

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

Deny rules run before allow rules. A target with no `allowedCommands` is blocked. Commands must be single-line. Use anchored expressions rather than `.*`.

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
mcp-ssh key create NAME --targets LIST [--scopes LIST] [--expires 30d]
mcp-ssh key list [--config PATH]
mcp-ssh key revoke KEY_ID [--config PATH]
```

`connect` is a human-only interactive shell and is not exposed as an MCP tool.

## Request authorization order

For HTTP requests the connector applies four independent checks:

1. validate the Bearer key hash, expiry, and revocation state;
2. require operation scope (`ssh:read` or `ssh:exec`) and target access;
3. apply the configured command deny rules, then allow rules;
4. authenticate to the remote machine with the host SSH identity.

The API key id is recorded as the audit actor. Neither bearer tokens nor SSH key contents are logged.

## Security

Read [docs/security.md](docs/security.md) before exposing production targets. Plain HTTP should stay on loopback or inside a trusted tunnel. Non-loopback deployments need TLS, explicit host/origin policy, short-lived scoped keys, least-privilege SSH identities, and append-only audit storage.

## Ideas and next steps

See [docs/roadmap.md](docs/roadmap.md) for human approvals, external identity providers, ephemeral SSH certificates, constrained SFTP, fleet blast-radius budgets, cached host facts, telemetry, and session recording.

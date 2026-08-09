import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { access, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";
import test from "node:test";
import { loadConfig } from "../dist/config.js";
import { evaluateDynamicCommand } from "../dist/policy.js";
import { buildSshArgs, prepareDynamicInvocation, validateDynamicConnection } from "../dist/ssh.js";

const execFileAsync = promisify(execFile);

function config() {
  return {
    path: "/tmp/config.json",
    sshBinary: "ssh",
    authKeyStore: "/tmp/keys.json",
    http: { host: "127.0.0.1", port: 3000, allowedHosts: [], allowedOrigins: [] },
    auditLog: "/tmp/audit.jsonl",
    auditRequired: true,
    logCommands: false,
    maxCommandLength: 100,
    dynamicDefaults: {
      timeoutMs: 30_000,
      connectTimeoutSeconds: 10,
      maxOutputBytes: 1_048_576,
      knownHostsFile: "/tmp/known_hosts",
    },
    targets: {},
  };
}

test("configuration may omit named targets", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mcp-ssh-config-"));
  const path = join(directory, "config.json");
  try {
    await writeFile(path, JSON.stringify({ version: 1, targets: {} }), "utf8");
    const loaded = await loadConfig(path);
    assert.deepEqual(loaded.targets, {});
    assert.equal(loaded.dynamicDefaults.timeoutMs, 30_000);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("dynamic command policy permits any validated single-line command", () => {
  assert.equal(evaluateDynamicCommand(config(), "sudo rm -rf /").allowed, true);
  assert.equal(evaluateDynamicCommand(config(), "echo first\necho second").allowed, false);
  assert.equal(evaluateDynamicCommand(config(), "").allowed, false);
});

test("dynamic connection validation rejects malformed endpoints and credentials", () => {
  assert.throws(() => validateDynamicConnection({
    host: "-oProxyCommand=bad",
    username: "root",
    authentication: { type: "password", password: "secret" },
  }), /connection.host/);
  assert.throws(() => validateDynamicConnection({
    host: "example.com",
    username: "root",
    authentication: { type: "password", password: "line\nbreak" },
  }), /password/);
});

test("password authentication uses askpass without putting the password in SSH arguments", async () => {
  const connection = {
    host: "server.example.com",
    username: "deploy",
    port: 2222,
    authentication: { type: "password", password: "s3cret-value" },
  };
  const prepared = await prepareDynamicInvocation(config(), connection);
  const helperOptions = prepared.environment.NODE_OPTIONS;
  try {
    const args = buildSshArgs(prepared.target, {
      automated: true,
      authenticationMode: prepared.authenticationMode,
      host: connection.host,
      username: connection.username,
      acceptNewHostKey: true,
    });
    assert.equal(args.includes(connection.authentication.password), false);
    assert.deepEqual(args.slice(-4), ["-l", "deploy", "--", "server.example.com"]);
    assert.equal(args.includes("StrictHostKeyChecking=accept-new"), true);
    assert.deepEqual(args.slice(0, 2), ["-F", "none"]);
    assert.equal(args.includes("PreferredAuthentications=keyboard-interactive,password"), true);
    const asked = await execFileAsync(prepared.environment.SSH_ASKPASS, ["Password:"], {
      env: prepared.environment,
      windowsHide: true,
    });
    assert.equal(asked.stdout, connection.authentication.password);
  } finally {
    await prepared.cleanup();
  }
  const helperMatch = /--require=(?:"([^"]+)"|(\S+))/.exec(helperOptions ?? "");
  assert.ok(helperMatch);
  await assert.rejects(access(helperMatch[1] ?? helperMatch[2]), /ENOENT/);
});

test("private-key content is written only to a request-scoped file and removed", async () => {
  const sourceDirectory = await mkdtemp(join(tmpdir(), "mcp-ssh-source-key-"));
  const sourceKey = join(sourceDirectory, "id_ed25519");
  let identityFile;
  try {
    await execFileAsync("ssh-keygen", ["-q", "-t", "ed25519", "-N", "", "-f", sourceKey], { windowsHide: true });
    const privateKey = await readFile(sourceKey, "utf8");
    const connection = {
      host: "192.0.2.10",
      username: "root",
      authentication: { type: "privateKey", privateKey },
    };
    const prepared = await prepareDynamicInvocation(config(), connection);
    identityFile = prepared.target.identityFile;
    assert.ok(identityFile);
    try {
      assert.equal(await readFile(identityFile, "utf8"), privateKey.endsWith("\n") ? privateKey : `${privateKey}\n`);
      const args = buildSshArgs(prepared.target, {
        automated: true,
        authenticationMode: prepared.authenticationMode,
        host: connection.host,
        username: connection.username,
        acceptNewHostKey: true,
      });
      assert.equal(args.includes(privateKey), false);
      assert.equal(args.includes(identityFile), true);
      assert.equal(args.includes("IdentitiesOnly=yes"), true);
      await execFileAsync("ssh-keygen", ["-y", "-f", identityFile], { windowsHide: true });
    } finally {
      await prepared.cleanup();
    }
  } finally {
    await rm(sourceDirectory, { recursive: true, force: true });
  }
  assert.ok(identityFile);
  await assert.rejects(access(identityFile), /ENOENT/);
});

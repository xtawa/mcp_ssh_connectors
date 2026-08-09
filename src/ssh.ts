import { randomUUID } from "node:crypto";
import { spawn, spawnSync } from "node:child_process";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { appendAudit, commandFingerprint } from "./audit.js";
import { evaluateDynamicCommand, getTarget } from "./policy.js";
import type {
  DynamicConnection,
  ExecResult,
  ExecutionSource,
  RemoteCommandOptions,
  ResolvedConfig,
  TargetConfig,
} from "./types.js";

const CONTROL_CHARACTER = /[\u0000-\u001f\u007f]/;
const PRIVATE_KEY_LIMIT = 262_144;
const SECRET_LIMIT = 4_096;

type AuthenticationMode = "configured" | "password" | "privateKey" | "privateKeyWithPassphrase";

interface SshArgumentOptions {
  automated: boolean;
  authenticationMode: AuthenticationMode;
  host?: string;
  username?: string;
  acceptNewHostKey?: boolean;
}

export interface PreparedDynamicInvocation {
  target: TargetConfig;
  targetName: string;
  destination: string;
  authenticationMode: AuthenticationMode;
  environment: NodeJS.ProcessEnv;
  cleanup(): Promise<void>;
}

function validateEndpoint(value: string, label: string): void {
  if (value.trim() !== value || value === "" || value.startsWith("-") || /\s/.test(value) || CONTROL_CHARACTER.test(value)) {
    throw new Error(`${label} must be non-empty, may not start with '-', and may not contain whitespace or control characters`);
  }
}

export function validateDynamicConnection(connection: DynamicConnection): void {
  validateEndpoint(connection.host, "connection.host");
  validateEndpoint(connection.username, "connection.username");
  if (connection.host.length > 253) throw new Error("connection.host may not exceed 253 characters");
  if (connection.username.length > 128) throw new Error("connection.username may not exceed 128 characters");
  if (connection.port !== undefined && (!Number.isInteger(connection.port) || connection.port < 1 || connection.port > 65_535)) {
    throw new Error("connection.port must be an integer from 1 to 65535");
  }
  if (connection.authentication.type === "password") {
    const { password } = connection.authentication;
    if (password === "" || password.length > SECRET_LIMIT || CONTROL_CHARACTER.test(password)) {
      throw new Error("connection.authentication.password must be 1-4096 characters without control characters");
    }
    return;
  }
  const { privateKey, passphrase } = connection.authentication;
  if (privateKey.trim() === "" || Buffer.byteLength(privateKey, "utf8") > PRIVATE_KEY_LIMIT || privateKey.includes("\0")) {
    throw new Error("connection.authentication.privateKey must be a non-empty private key of at most 262144 bytes");
  }
  if (passphrase !== undefined && (passphrase === "" || passphrase.length > SECRET_LIMIT || CONTROL_CHARACTER.test(passphrase))) {
    throw new Error("connection.authentication.passphrase must be 1-4096 characters without control characters");
  }
}

export function buildSshArgs(target: TargetConfig, options: SshArgumentOptions): string[] {
  const args = options.acceptNewHostKey ? ["-F", "none"] : [];
  args.push(
    "-o", `StrictHostKeyChecking=${options.acceptNewHostKey ? "accept-new" : "yes"}`,
    "-o", "ForwardAgent=no",
    "-o", "PermitLocalCommand=no",
    "-o", "ClearAllForwardings=yes",
    "-o", `ConnectTimeout=${target.connectTimeoutSeconds}`,
  );
  if (options.automated) {
    const needsAskpass = options.authenticationMode === "password" || options.authenticationMode === "privateKeyWithPassphrase";
    args.push("-o", `BatchMode=${needsAskpass ? "no" : "yes"}`, "-o", "RequestTTY=no", "-T");
  }
  if (options.authenticationMode === "password") {
    args.push(
      "-o", "PreferredAuthentications=keyboard-interactive,password",
      "-o", "PubkeyAuthentication=no",
      "-o", "NumberOfPasswordPrompts=1",
    );
  } else if (options.authenticationMode === "privateKey" || options.authenticationMode === "privateKeyWithPassphrase") {
    args.push(
      "-o", "PreferredAuthentications=publickey",
      "-o", "IdentitiesOnly=yes",
      "-o", "PasswordAuthentication=no",
      "-o", "KbdInteractiveAuthentication=no",
      "-o", "NumberOfPasswordPrompts=1",
    );
  }
  if (target.knownHostsFile) args.push("-o", `UserKnownHostsFile=${target.knownHostsFile}`);
  if (target.port) args.push("-p", String(target.port));
  if (target.identityFile) args.push("-i", target.identityFile);
  if (target.proxyJump) args.push("-J", target.proxyJump);
  if (options.username) args.push("-l", options.username);
  args.push("--", options.host ?? target.destination);
  return args;
}

async function createAskpassEnvironment(directory: string, secret: string): Promise<NodeJS.ProcessEnv> {
  const helper = join(directory, "askpass.cjs");
  await writeFile(
    helper,
    'const secret = process.env.MCP_SSH_ASKPASS_SECRET;\nif (secret === undefined) process.exit(1);\nprocess.stdout.write(secret);\nprocess.exit(0);\n',
    { encoding: "utf8", mode: 0o700, flag: "wx" },
  );
  const preload = `--require=${JSON.stringify(helper)}`;
  return {
    ...process.env,
    DISPLAY: process.env.DISPLAY || "mcp-ssh-askpass",
    SSH_ASKPASS: process.execPath,
    SSH_ASKPASS_REQUIRE: "force",
    MCP_SSH_ASKPASS_SECRET: secret,
    NODE_OPTIONS: preload,
  };
}

async function restrictCredentialDirectory(directory: string): Promise<void> {
  if (process.platform !== "win32") return;
  const username = process.env.USERNAME;
  const domain = process.env.USERDOMAIN;
  if (!username) throw new Error("Cannot secure temporary SSH credentials because USERNAME is unavailable");
  const account = domain ? `${domain}\\${username}` : username;
  const icacls = join(process.env.SystemRoot ?? "C:\\Windows", "System32", "icacls.exe");
  await new Promise<void>((resolvePromise, rejectPromise) => {
    const child = spawn(icacls, [
      directory,
      "/inheritance:r",
      "/grant:r",
      `${account}:(OI)(CI)F`,
    ], {
      shell: false,
      stdio: ["ignore", "ignore", "pipe"],
      windowsHide: true,
    });
    const stderr: Buffer[] = [];
    child.stderr.on("data", (chunk: Buffer) => stderr.push(chunk));
    child.once("error", rejectPromise);
    child.once("close", (exitCode) => {
      if (exitCode === 0) resolvePromise();
      else rejectPromise(new Error(`Could not secure temporary SSH credential directory (icacls exit ${exitCode}): ${Buffer.concat(stderr).toString("utf8").trim()}`));
    });
  });
}

export async function prepareDynamicInvocation(
  config: ResolvedConfig,
  connection: DynamicConnection,
): Promise<PreparedDynamicInvocation> {
  validateDynamicConnection(connection);
  const directory = await mkdtemp(join(tmpdir(), "mcp-ssh-credential-"));
  const port = connection.port ?? 22;
  const destination = `${connection.username}@${connection.host}:${port}`;
  let environment: NodeJS.ProcessEnv = { ...process.env };
  let identityFile: string | undefined;
  let authenticationMode: AuthenticationMode;
  try {
    await restrictCredentialDirectory(directory);
    if (connection.authentication.type === "password") {
      authenticationMode = "password";
      environment = await createAskpassEnvironment(directory, connection.authentication.password);
    } else {
      identityFile = join(directory, "identity");
      const privateKey = connection.authentication.privateKey.endsWith("\n")
        ? connection.authentication.privateKey
        : `${connection.authentication.privateKey}\n`;
      await writeFile(identityFile, privateKey, { encoding: "utf8", mode: 0o600, flag: "wx" });
      if (connection.authentication.passphrase) {
        authenticationMode = "privateKeyWithPassphrase";
        environment = await createAskpassEnvironment(directory, connection.authentication.passphrase);
      } else {
        authenticationMode = "privateKey";
      }
    }
    return {
      target: {
        destination: connection.host,
        port,
        identityFile,
        knownHostsFile: config.dynamicDefaults.knownHostsFile,
        tags: [],
        allowedCommands: [],
        deniedCommands: [],
        disabled: false,
        timeoutMs: config.dynamicDefaults.timeoutMs,
        connectTimeoutSeconds: config.dynamicDefaults.connectTimeoutSeconds,
        maxOutputBytes: config.dynamicDefaults.maxOutputBytes,
        requireReason: false,
      },
      targetName: `dynamic:${destination}`,
      destination,
      authenticationMode,
      environment,
      cleanup: () => rm(directory, { recursive: true, force: true }),
    };
  } catch (error) {
    await rm(directory, { recursive: true, force: true });
    throw error;
  }
}

function publicCommandFields(config: ResolvedConfig, command: string): Record<string, unknown> {
  return config.logCommands ? { command } : { commandHash: commandFingerprint(command) };
}

async function executeRemoteCommand(
  config: ResolvedConfig,
  targetName: string,
  target: TargetConfig,
  destination: string,
  command: string,
  options: RemoteCommandOptions,
  argumentOptions: SshArgumentOptions,
  environment: NodeJS.ProcessEnv,
): Promise<ExecResult> {
  const timeoutMs = Math.min(options.timeoutMs ?? target.timeoutMs, target.timeoutMs);
  const eventType = options.eventType ?? "exec";
  const requestId = randomUUID();
  const startedAt = Date.now();

  await appendAudit(config, {
    event: `${eventType}.start`,
    requestId,
    source: options.source,
    actor: options.actor,
    target: targetName,
    destination,
    authentication: argumentOptions.authenticationMode,
    reason: options.reason?.trim() || undefined,
    ...publicCommandFields(config, command),
  });

  return new Promise<ExecResult>((resolvePromise, rejectPromise) => {
    const child = spawn(config.sshBinary, [...buildSshArgs(target, argumentOptions), command], {
      env: environment,
      shell: false,
      stdio: ["ignore", "pipe", "pipe"],
      windowsHide: true,
    });

    const stdout: Buffer[] = [];
    const stderr: Buffer[] = [];
    let capturedBytes = 0;
    let truncated = false;
    let timedOut = false;
    let spawnError: Error | undefined;

    const capture = (bucket: Buffer[], chunk: Buffer): void => {
      const remaining = target.maxOutputBytes - capturedBytes;
      if (remaining <= 0) {
        truncated = true;
        return;
      }
      if (chunk.length > remaining) {
        bucket.push(chunk.subarray(0, remaining));
        capturedBytes += remaining;
        truncated = true;
      } else {
        bucket.push(chunk);
        capturedBytes += chunk.length;
      }
    };

    child.stdout.on("data", (chunk: Buffer) => capture(stdout, chunk));
    child.stderr.on("data", (chunk: Buffer) => capture(stderr, chunk));
    child.once("error", (error) => { spawnError = error; });

    const timeout = setTimeout(() => {
      timedOut = true;
      child.kill("SIGTERM");
      const forceKill = setTimeout(() => child.kill("SIGKILL"), 1_000);
      forceKill.unref();
    }, timeoutMs);
    timeout.unref();

    child.once("close", (exitCode, signal) => {
      clearTimeout(timeout);
      const result: ExecResult = {
        requestId,
        target: targetName,
        destination,
        ok: !spawnError && !timedOut && exitCode === 0,
        exitCode,
        signal,
        timedOut,
        truncated,
        durationMs: Date.now() - startedAt,
        stdout: Buffer.concat(stdout).toString("utf8"),
        stderr: Buffer.concat(stderr).toString("utf8"),
      };
      void (async () => {
        try {
          await appendAudit(config, {
            event: `${eventType}.finish`,
            requestId,
            source: options.source,
            actor: options.actor,
            target: targetName,
            ok: result.ok,
            exitCode,
            signal,
            timedOut,
            truncated,
            durationMs: result.durationMs,
          });
          if (spawnError) rejectPromise(spawnError);
          else resolvePromise(result);
        } catch (error) {
          rejectPromise(error);
        }
      })();
    });
  });
}

export async function runRemoteCommand(
  config: ResolvedConfig,
  targetName: string,
  command: string,
  options: RemoteCommandOptions,
): Promise<ExecResult> {
  const target = getTarget(config, targetName);
  if (target.disabled) throw new Error(`Target ${targetName} is disabled`);
  return executeRemoteCommand(
    config,
    targetName,
    target,
    target.destination,
    command,
    options,
    { automated: true, authenticationMode: "configured" },
    process.env,
  );
}

export async function runDynamicCommand(
  config: ResolvedConfig,
  connection: DynamicConnection,
  command: string,
  options: RemoteCommandOptions,
): Promise<ExecResult> {
  const decision = evaluateDynamicCommand(config, command);
  if (!decision.allowed) throw new Error(decision.reason);
  const prepared = await prepareDynamicInvocation(config, connection);
  try {
    return await executeRemoteCommand(
      config,
      prepared.targetName,
      prepared.target,
      prepared.destination,
      command,
      options,
      {
        automated: true,
        authenticationMode: prepared.authenticationMode,
        host: connection.host,
        username: connection.username,
        acceptNewHostKey: true,
      },
      prepared.environment,
    );
  } finally {
    await prepared.cleanup();
  }
}

export async function checkConnection(
  config: ResolvedConfig,
  targetName: string,
  source: ExecutionSource,
  actor?: string,
): Promise<ExecResult> {
  const target = getTarget(config, targetName);
  return runRemoteCommand(config, targetName, "true", {
    source,
    actor,
    reason: "connectivity check",
    timeoutMs: Math.min(15_000, target.timeoutMs),
    eventType: "check",
  });
}

export async function checkDynamicConnection(
  config: ResolvedConfig,
  connection: DynamicConnection,
  source: ExecutionSource,
  actor?: string,
): Promise<ExecResult> {
  return runDynamicCommand(config, connection, "true", {
    source,
    actor,
    reason: "connectivity check",
    timeoutMs: Math.min(15_000, config.dynamicDefaults.timeoutMs),
    eventType: "check",
  });
}

export function connectInteractive(config: ResolvedConfig, targetName: string): number {
  const target = getTarget(config, targetName);
  if (target.disabled) throw new Error(`Target ${targetName} is disabled`);
  const result = spawnSync(config.sshBinary, buildSshArgs(target, {
    automated: false,
    authenticationMode: "configured",
  }), {
    env: process.env,
    shell: false,
    stdio: "inherit",
    windowsHide: false,
  });
  if (result.error) throw result.error;
  return result.status ?? 1;
}

import { randomUUID } from "node:crypto";
import { spawn, spawnSync } from "node:child_process";
import { appendAudit, commandFingerprint } from "./audit.js";
import { getTarget } from "./policy.js";
import type { ExecResult, ExecutionSource, RemoteCommandOptions, ResolvedConfig, TargetConfig } from "./types.js";

function buildSshArgs(target: TargetConfig, automated: boolean): string[] {
  const args = [
    "-o", "StrictHostKeyChecking=yes",
    "-o", "ForwardAgent=no",
    "-o", "PermitLocalCommand=no",
    "-o", "ClearAllForwardings=yes",
    "-o", `ConnectTimeout=${target.connectTimeoutSeconds}`,
  ];
  if (automated) args.push("-o", "BatchMode=yes", "-o", "RequestTTY=no", "-T");
  if (target.knownHostsFile) args.push("-o", `UserKnownHostsFile=${target.knownHostsFile}`);
  if (target.port) args.push("-p", String(target.port));
  if (target.identityFile) args.push("-i", target.identityFile);
  if (target.proxyJump) args.push("-J", target.proxyJump);
  args.push("--", target.destination);
  return args;
}

function publicCommandFields(config: ResolvedConfig, command: string): Record<string, unknown> {
  return config.logCommands ? { command } : { commandHash: commandFingerprint(command) };
}

export async function runRemoteCommand(
  config: ResolvedConfig,
  targetName: string,
  command: string,
  options: RemoteCommandOptions,
): Promise<ExecResult> {
  const target = getTarget(config, targetName);
  if (target.disabled) throw new Error(`Target ${targetName} is disabled`);
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
    destination: target.destination,
    reason: options.reason?.trim() || undefined,
    ...publicCommandFields(config, command),
  });

  return new Promise<ExecResult>((resolvePromise, rejectPromise) => {
    const child = spawn(config.sshBinary, [...buildSshArgs(target, true), command], {
      env: process.env,
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
        destination: target.destination,
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

export function connectInteractive(config: ResolvedConfig, targetName: string): number {
  const target = getTarget(config, targetName);
  if (target.disabled) throw new Error(`Target ${targetName} is disabled`);
  const result = spawnSync(config.sshBinary, buildSshArgs(target, false), {
    env: process.env,
    shell: false,
    stdio: "inherit",
    windowsHide: false,
  });
  if (result.error) throw result.error;
  return result.status ?? 1;
}

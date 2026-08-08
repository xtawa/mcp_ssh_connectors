import { createHash } from "node:crypto";
import { appendFile, mkdir } from "node:fs/promises";
import { dirname } from "node:path";
import type { ResolvedConfig } from "./types.js";

export function commandFingerprint(command: string): string {
  return createHash("sha256").update(command, "utf8").digest("hex");
}

export async function appendAudit(
  config: ResolvedConfig,
  event: Record<string, unknown>,
): Promise<void> {
  try {
    await mkdir(dirname(config.auditLog), { recursive: true });
    await appendFile(
      config.auditLog,
      `${JSON.stringify({ timestamp: new Date().toISOString(), ...event })}\n`,
      { encoding: "utf8", mode: 0o600 },
    );
  } catch (error) {
    if (config.auditRequired) {
      throw new Error(`Audit log is required but could not be written: ${String(error)}`);
    }
    console.error(`mcp-ssh audit warning: ${String(error)}`);
  }
}

import { randomBytes, scrypt, timingSafeEqual } from "node:crypto";
import { mkdir, readFile, rename, writeFile } from "node:fs/promises";
import { dirname } from "node:path";

const KEY_ID = /^[A-Za-z0-9_-]{8,32}$/;
const TARGET = /^(?:\*|[A-Za-z0-9][A-Za-z0-9._-]{0,63})$/;
const ALLOWED_SCOPES = new Set(["mcp", "ssh:read", "ssh:exec"]);
const MAX_KEY_LIFETIME_MS = 366 * 86_400_000;

export interface ApiKeyRecord {
  id: string;
  name: string;
  salt: string;
  hash: string;
  scopes: string[];
  targets: string[];
  createdAt: string;
  expiresAt: string;
  revokedAt?: string;
}

interface KeyStore {
  version: 1;
  keys: ApiKeyRecord[];
}

export interface CreateApiKeyOptions {
  name: string;
  scopes: string[];
  targets: string[];
  expiresAt: Date;
}

export interface CreatedApiKey {
  token: string;
  record: ApiKeyRecord;
}

async function derive(token: string, salt: Buffer): Promise<Buffer> {
  return new Promise((resolvePromise, rejectPromise) => {
    scrypt(token, salt, 32, (error, key) => {
      if (error) rejectPromise(error);
      else resolvePromise(key as Buffer);
    });
  });
}

async function readStore(path: string): Promise<KeyStore> {
  const text = await readFile(path, "utf8").catch((error: NodeJS.ErrnoException) => {
    if (error.code === "ENOENT") return undefined;
    throw error;
  });
  if (text === undefined) return { version: 1, keys: [] };
  const parsed = JSON.parse(text) as Partial<KeyStore>;
  if (parsed.version !== 1 || !Array.isArray(parsed.keys)) {
    throw new Error(`Invalid API key store at ${path}`);
  }
  return parsed as KeyStore;
}

async function writeStore(path: string, store: KeyStore): Promise<void> {
  await mkdir(dirname(path), { recursive: true });
  const temporary = `${path}.${process.pid}.${randomBytes(6).toString("hex")}.tmp`;
  await writeFile(temporary, `${JSON.stringify(store, null, 2)}\n`, { encoding: "utf8", mode: 0o600, flag: "wx" });
  await rename(temporary, path);
}

function unique(values: string[]): string[] {
  return [...new Set(values)];
}

export function parseExpiry(value: string, now = Date.now()): Date {
  const duration = /^(\d+)(m|h|d|w)$/.exec(value);
  let timestamp: number;
  if (duration) {
    const amount = Number(duration[1]);
    const unit = duration[2]!;
    const multiplier = { m: 60_000, h: 3_600_000, d: 86_400_000, w: 604_800_000 }[unit]!;
    timestamp = now + amount * multiplier;
  } else {
    timestamp = Date.parse(value);
  }
  const maximum = now + MAX_KEY_LIFETIME_MS;
  if (!Number.isFinite(timestamp) || timestamp <= now || timestamp > maximum) {
    throw new Error("Expiry must be a future ISO date or duration such as 30d, up to 366 days");
  }
  return new Date(timestamp);
}

export async function createApiKey(path: string, options: CreateApiKeyOptions): Promise<CreatedApiKey> {
  const name = options.name.trim();
  if (name.length < 1 || name.length > 64 || /[\u0000-\u001f\u007f]/.test(name)) {
    throw new Error("API key name must be 1-64 characters without control characters");
  }
  const scopes = unique(options.scopes);
  if (!scopes.includes("mcp") || scopes.some((scope) => !ALLOWED_SCOPES.has(scope))) {
    throw new Error("Scopes must include mcp and may contain only mcp, ssh:read, and ssh:exec");
  }
  const targets = unique(options.targets);
  if (targets.length === 0 || targets.some((target) => !TARGET.test(target))) {
    throw new Error("Targets must contain one or more target names, or '*'");
  }
  const now = Date.now();
  const expiry = options.expiresAt.getTime();
  if (!Number.isFinite(expiry) || expiry <= now || expiry > now + MAX_KEY_LIFETIME_MS) {
    throw new Error("API key expiry must be in the future and no more than 366 days away");
  }

  const store = await readStore(path);
  const id = randomBytes(9).toString("base64url");
  const secret = randomBytes(32).toString("base64url");
  const token = `mcp_ssh.${id}.${secret}`;
  const salt = randomBytes(16);
  const hash = await derive(token, salt);
  const record: ApiKeyRecord = {
    id,
    name,
    salt: salt.toString("base64url"),
    hash: hash.toString("base64url"),
    scopes,
    targets,
    createdAt: new Date(now).toISOString(),
    expiresAt: options.expiresAt.toISOString(),
  };
  store.keys.push(record);
  await writeStore(path, store);
  return { token, record };
}

export async function verifyApiKey(path: string, token: string): Promise<ApiKeyRecord | undefined> {
  const match = /^mcp_ssh\.([A-Za-z0-9_-]{8,32})\.([A-Za-z0-9_-]{32,})$/.exec(token);
  if (!match) return undefined;
  const store = await readStore(path);
  const record = store.keys.find((item) => item.id === match[1]);
  const expiry = record ? Date.parse(record.expiresAt) : Number.NaN;
  if (!record || record.revokedAt || !Number.isFinite(expiry) || expiry <= Date.now()) return undefined;
  const expected = Buffer.from(record.hash, "base64url");
  const actual = await derive(token, Buffer.from(record.salt, "base64url"));
  if (expected.length !== actual.length || !timingSafeEqual(expected, actual)) return undefined;
  return record;
}

export async function listApiKeys(path: string): Promise<Array<Omit<ApiKeyRecord, "salt" | "hash">>> {
  const store = await readStore(path);
  return store.keys.map(({ salt: _salt, hash: _hash, ...record }) => record);
}

export async function revokeApiKey(path: string, id: string): Promise<ApiKeyRecord> {
  if (!KEY_ID.test(id)) throw new Error("Invalid API key id");
  const store = await readStore(path);
  const record = store.keys.find((item) => item.id === id);
  if (!record) throw new Error(`Unknown API key id ${id}`);
  if (!record.revokedAt) record.revokedAt = new Date().toISOString();
  await writeStore(path, store);
  return record;
}

import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { authorizeAccess } from "../dist/access.js";
import { createApiKey, listApiKeys, parseExpiry, revokeApiKey, verifyApiKey } from "../dist/auth.js";

test("creates, verifies, lists, and revokes an API key without exposing its hash", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mcp-ssh-auth-"));
  const store = join(directory, "keys.json");
  try {
    const created = await createApiKey(store, {
      name: "test-client",
      scopes: ["mcp", "ssh:read"],
      targets: ["staging"],
      expiresAt: new Date(Date.now() + 60_000),
    });
    assert.match(created.token, /^mcp_ssh\./);
    assert.equal((await verifyApiKey(store, created.token))?.id, created.record.id);
    assert.equal(await verifyApiKey(store, `${created.token}x`), undefined);
    const listed = await listApiKeys(store);
    assert.equal(listed.length, 1);
    assert.equal("hash" in listed[0], false);
    assert.equal("salt" in listed[0], false);
    await revokeApiKey(store, created.record.id);
    assert.equal(await verifyApiKey(store, created.token), undefined);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("parses bounded relative expirations", () => {
  const now = Date.UTC(2026, 0, 1);
  assert.equal(parseExpiry("30d", now).toISOString(), "2026-01-31T00:00:00.000Z");
  assert.throws(() => parseExpiry("400d", now), /up to 366 days/);
});

test("create rejects an API key lifetime over 366 days", async () => {
  await assert.rejects(
    createApiKey("/unused/keys.json", {
      name: "too-long",
      scopes: ["mcp"],
      targets: ["*"],
      expiresAt: new Date(Date.now() + 400 * 86_400_000),
    }),
    /no more than 366 days/,
  );
});

test("HTTP access requires both operation scope and target scope", () => {
  const access = { transport: "http", clientId: "key-1", scopes: ["mcp", "ssh:read", "target:staging"] };
  assert.equal(authorizeAccess(access, "ssh:read", "staging").allowed, true);
  assert.equal(authorizeAccess(access, "ssh:exec", "staging").allowed, false);
  assert.equal(authorizeAccess(access, "ssh:read", "production").allowed, false);
});

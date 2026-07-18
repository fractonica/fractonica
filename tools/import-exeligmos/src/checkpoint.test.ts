import assert from "node:assert/strict";
import { mkdtemp, readFile, rm, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

import { loadCheckpoint, newCheckpoint, saveCheckpoint } from "./checkpoint.ts";

test("checkpoint writes atomically with private permissions and validates endpoints", async () => {
  const directory = await mkdtemp(join(tmpdir(), "fractonica-import-test-"));
  try {
    const path = join(directory, "state.json");
    const checkpoint = newCheckpoint("https://source.test/", "https://destination.test/");
    await saveCheckpoint(path, checkpoint);
    assert.equal((await stat(path)).mode & 0o777, 0o600);
    const encoded = await readFile(path, "utf8");
    assert.equal(encoded.includes("TOKEN"), false);
    const loaded = await loadCheckpoint(path, "https://source.test", "https://destination.test");
    assert.equal(loaded.version, 1);
    await assert.rejects(
      loadCheckpoint(path, "https://different.test", "https://destination.test"),
      /checkpoint source/,
    );
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("checkpoint rejects cross-origin resumable upload URLs", async () => {
  const directory = await mkdtemp(join(tmpdir(), "fractonica-import-origin-test-"));
  try {
    const path = join(directory, "state.json");
    const checkpoint = newCheckpoint("https://source.test", "https://destination.test");
    const digest = "a".repeat(64);
    checkpoint.media[`sha-256:${digest}`] = {
      sourceMediaId: "media-id",
      sha256: digest,
      byteLength: 10,
      contentId: `sha-256:${digest}`,
      uploadUrl: "https://attacker.test/api/v1/uploads/stolen",
      uploadOffset: 2,
      completed: false,
      verified: false,
    };
    await saveCheckpoint(path, checkpoint);
    await assert.rejects(
      loadCheckpoint(path, "https://source.test", "https://destination.test"),
      /cross-origin TUS upload URL/,
    );
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("plain HTTP is restricted to explicit loopback hosts", () => {
  assert.equal(new URL(normalize("http://localhost:8788")).hostname, "localhost");
  assert.equal(new URL(normalize("http://127.255.12.9:8788")).hostname, "127.255.12.9");
  assert.equal(new URL(normalize("http://[::1]:8788")).hostname, "[::1]");
  assert.equal(normalize("https://fractonica.example"), "https://fractonica.example");
  assert.throws(() => normalize("http://192.168.0.24:8788"), /use HTTPS/);
  assert.throws(() => normalize("http://fractonica.example"), /use HTTPS/);
  assert.throws(() => normalize("http://0.0.0.0:8788"), /use HTTPS/);
  assert.throws(
    () => newCheckpoint("http://127.0.0.1:8788", "http://192.168.0.24:8789"),
    /use HTTPS/,
  );
});

function normalize(value: string): string {
  return newCheckpoint(value, "http://127.0.0.1:8789").sourceBaseUrl;
}

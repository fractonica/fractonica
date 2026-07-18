import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { test } from "node:test";

import { mapRecord, UnsupportedRecordError } from "./mapping.ts";
import type {
  ExeligmosPrivateRecord,
  ExeligmosPublicRecord,
  ExeligmosTag,
} from "./types.ts";

const tag: ExeligmosTag = {
  id: "22222222-2222-4222-8222-222222222222",
  userId: "33333333-3333-4333-8333-333333333333",
  name: "Sky",
  color: "#3366FF",
  emoji: "☀️",
  sortOrder: 3,
  metadata: { category: "weather" },
  revision: 1,
  createdAt: "2026-07-01T10:00:00.000Z",
  updatedAt: "2026-07-02T10:00:00.000Z",
};

test("public records map text, tags, provenance, and ordered resources", () => {
  const bytes = Buffer.from("image bytes");
  const sha256 = createHash("sha256").update(bytes).digest("hex");
  const record: ExeligmosPublicRecord = {
    id: "Abc_1",
    originId: "11111111-1111-4111-8111-111111111111",
    userId: tag.userId,
    deviceId: "44444444-4444-4444-8444-444444444444",
    visibility: "public",
    revision: 7,
    createdAt: "2026-07-10T10:00:00.000Z",
    updatedAt: "2026-07-11T10:00:00.000Z",
    occurredAt: "2026-07-09T10:00:00.000Z",
    endedAt: "2026-07-09T10:01:00.000Z",
    payload: { text: "Solar flare", emoji: "☀️", intensity: "X1.7" },
    tagIds: [tag.id],
    tags: [{ id: tag.id, name: tag.name, color: "#3366FF", emoji: "☀️" }],
    metadata: { imported: true },
    source: { kind: "agent", provider: "noaa" },
    references: [
      {
        relation: "mentions",
        targetType: "user",
        targetUserId: tag.userId,
        targetId: tag.userId,
      },
    ],
    media: [
      {
        id: "55555555-5555-4555-8555-555555555555",
        userId: tag.userId,
        deviceId: "44444444-4444-4444-8444-444444444444",
        fileName: "flare.jpeg",
        contentType: "image/jpeg",
        byteLength: bytes.byteLength,
        sha256,
        revision: 1,
        createdAt: "2026-07-09T10:00:01.000Z",
        contentUrl: "/v1/media/55555555-5555-4555-8555-555555555555/content",
      },
    ],
  };

  const mapped = mapRecord(record, new Map([[tag.id, tag]]));
  const document = mapped.operation.body.document;
  assert.equal(document.text, "Solar flare");
  assert.equal(document.emoji, "☀️");
  assert.equal(document.startAtUnixMs, Date.parse(record.occurredAt));
  assert.equal(document.endAtUnixMs, Date.parse(record.endedAt ?? ""));
  assert.deepEqual(document.resources, [
    {
      contentId: `sha-256:${sha256}`,
      byteLength: bytes.byteLength,
      mediaType: "image/jpeg",
      role: "attachment",
      originalName: "flare.jpeg",
    },
  ]);
  assert.equal(mapped.blobs.length, 1);
  const migration = document.metadata?.migration as Record<string, unknown>;
  assert.deepEqual(migration.payloadExtra, { intensity: "X1.7" });
  assert.deepEqual(migration.tags, [tag]);
});

test("private ciphertext is preserved as an immutable resource without decryption", () => {
  const ciphertext = Buffer.from("opaque authenticated ciphertext");
  const sha256 = createHash("sha256").update(ciphertext).digest("hex");
  const record: ExeligmosPrivateRecord = {
    id: "Priv1",
    originId: "66666666-6666-4666-8666-666666666666",
    userId: tag.userId,
    deviceId: "44444444-4444-4444-8444-444444444444",
    visibility: "private",
    revision: 2,
    createdAt: "2026-07-10T10:00:00.000Z",
    updatedAt: "2026-07-11T10:00:00.000Z",
    references: [],
    media: [],
    encryption: {
      algorithm: "A256GCM",
      cryptoVersion: 1,
      keyVersion: 1,
      nonce: "MDEyMzQ1Njc4OWFi",
      ciphertext: ciphertext.toString("base64"),
      contentType: "application/vnd.exeligmos.record+json",
    },
  };

  const mapped = mapRecord(record, new Map());
  assert.equal(mapped.operation.body.document.visibility, "private");
  assert.equal(mapped.operation.body.document.startAtUnixMs, Date.parse(record.createdAt));
  assert.equal(mapped.blobs[0]?.resource.contentId, `sha-256:${sha256}`);
  assert.deepEqual(
    Buffer.from(
      mapped.blobs[0]?.source.kind === "bytes"
        ? mapped.blobs[0].source.bytes
        : new Uint8Array(),
    ),
    ciphertext,
  );
  const encodedMetadata = JSON.stringify(mapped.operation.body.document.metadata);
  assert.equal(encodedMetadata.includes(record.encryption.ciphertext), false);
  assert.equal(encodedMetadata.includes(`sha-256:${sha256}`), true);
});

test("records exceeding destination metadata bounds are rejected instead of truncated", () => {
  const record: ExeligmosPublicRecord = {
    id: "Large",
    originId: "77777777-7777-4777-8777-777777777777",
    userId: tag.userId,
    deviceId: "44444444-4444-4444-8444-444444444444",
    visibility: "public",
    revision: 1,
    createdAt: "2026-07-10T10:00:00.000Z",
    updatedAt: "2026-07-11T10:00:00.000Z",
    occurredAt: "2026-07-09T10:00:00.000Z",
    payload: { text: "kept", extra: "x".repeat(20_000) },
    tagIds: [],
    tags: [],
    metadata: {},
    references: [],
    media: [],
  };
  assert.throws(() => mapRecord(record, new Map()), UnsupportedRecordError);
});

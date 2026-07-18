import assert from "node:assert/strict";
import { test } from "node:test";

import {
  contentIdForSha256,
  deterministicUuid,
  EXELIGMOS_MAPPING_NAMESPACE,
  idempotencyKeyForOperation,
  stableJsonStringify,
} from "./deterministic.ts";

test("deterministic UUID mapping is stable and uses UUIDv8", () => {
  const value = deterministicUuid(
    EXELIGMOS_MAPPING_NAMESPACE,
    "11111111-1111-4111-8111-111111111111:revision:7",
  );
  assert.equal(value, "ae45fa21-e5f0-8695-8aa8-035ac902cf33");
  assert.match(value, /^[0-9a-f]{8}-[0-9a-f]{4}-8[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
  assert.equal(idempotencyKeyForOperation(value), `exi-op-${value}`);
});

test("content IDs are normalized and malformed digests are rejected", () => {
  assert.equal(
    contentIdForSha256("A".repeat(64)),
    `sha-256:${"a".repeat(64)}`,
  );
  assert.throws(() => contentIdForSha256("not-a-digest"), /SHA-256/);
});

test("stable JSON sorts object keys without changing array order", () => {
  assert.equal(
    stableJsonStringify({ z: 1, a: [{ y: 2, x: 3 }] }),
    '{"a":[{"x":3,"y":2}],"z":1}',
  );
});

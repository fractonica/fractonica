import { createHash } from "node:crypto";

import type { ExeligmosRecord } from "./types.ts";

const UUID_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const SHA256_PATTERN = /^[0-9a-f]{64}$/;

/**
 * Namespace for the first Exeligmos-to-Fractonica mapping contract. Changing
 * this value would deliberately produce different operation identifiers.
 */
export const EXELIGMOS_MAPPING_NAMESPACE =
  "fractonica:import:exeligmos:record:v1";

export function assertUuid(value: string, field: string): string {
  if (!UUID_PATTERN.test(value)) {
    throw new Error(`${field} must be a canonical UUID, received ${JSON.stringify(value)}`);
  }
  return value.toLowerCase();
}

export function normalizeSha256(value: string): string {
  const normalized = value.toLowerCase();
  if (!SHA256_PATTERN.test(normalized)) {
    throw new Error(`expected a 64-character hexadecimal SHA-256 digest, received ${JSON.stringify(value)}`);
  }
  return normalized;
}

export function contentIdForSha256(value: string): `sha-256:${string}` {
  return `sha-256:${normalizeSha256(value)}`;
}

/**
 * Generates a deterministic RFC 9562 UUIDv8 from a namespaced UTF-8 value.
 * UUIDv8 is intentionally used because this mapping is application-defined.
 */
export function deterministicUuid(namespace: string, value: string): string {
  const digest = createHash("sha256")
    .update(namespace, "utf8")
    .update("\0", "utf8")
    .update(value, "utf8")
    .digest();
  const bytes = Buffer.from(digest.subarray(0, 16));
  const byte6 = bytes[6];
  const byte8 = bytes[8];
  if (byte6 === undefined || byte8 === undefined) {
    throw new Error("SHA-256 did not yield enough bytes for a UUID");
  }
  bytes[6] = (byte6 & 0x0f) | 0x80;
  bytes[8] = (byte8 & 0x3f) | 0x80;
  const hex = bytes.toString("hex");
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

export function operationIdForRecord(record: ExeligmosRecord): string {
  return operationIdForOriginRevision(record.originId, record.revision, record.id);
}

export function operationIdForOriginRevision(
  originIdValue: string,
  revision: number,
  context = "record",
): string {
  const originId = assertUuid(originIdValue, `${context}.originId`);
  if (!Number.isSafeInteger(revision) || revision < 1) {
    throw new Error(`${context}.revision must be a positive safe integer`);
  }
  return deterministicUuid(
    EXELIGMOS_MAPPING_NAMESPACE,
    `${originId}:revision:${revision}`,
  );
}

export function idempotencyKeyForOperation(operationId: string): string {
  return `exi-op-${assertUuid(operationId, "operationId")}`;
}

/** Canonical JSON is useful in diagnostics and deterministic fixture tests. */
export function stableJsonStringify(value: unknown): string {
  return JSON.stringify(sortJson(value));
}

function sortJson(value: unknown): unknown {
  if (Array.isArray(value)) {
    return value.map(sortJson);
  }
  if (value !== null && typeof value === "object") {
    const sorted: Record<string, unknown> = {};
    for (const key of Object.keys(value).sort()) {
      sorted[key] = sortJson((value as Record<string, unknown>)[key]);
    }
    return sorted;
  }
  return value;
}

import { createHash } from "node:crypto";

import {
  assertUuid,
  contentIdForSha256,
  operationIdForRecord,
} from "./deterministic.ts";
import type {
  ExeligmosMedia,
  ExeligmosRecord,
  ExeligmosTag,
  FractonicaRecordDocument,
  JsonObject,
  OperationSubmission,
  ResourceRef,
} from "./types.ts";

const MAX_RECORD_RESOURCES = 64;
const MAX_TEXT_CHARS = 262_144;
const MAX_EMOJI_CHARS = 32;
const MAX_METADATA_ENTRIES = 128;
const MAX_METADATA_KEY_CHARS = 128;
const MAX_METADATA_JSON_BYTES = 65_536;
const MAX_METADATA_DEPTH = 16;
const MAX_METADATA_CONTAINER_ITEMS = 256;
const MAX_METADATA_STRING_CHARS = 16_384;

export type BlobSource =
  | { readonly kind: "exeligmos-media"; readonly media: ExeligmosMedia }
  | { readonly kind: "bytes"; readonly bytes: Uint8Array };

export interface MappedBlob {
  readonly checkpointSourceId: string;
  readonly resource: ResourceRef;
  readonly source: BlobSource;
}

export interface MappedRecord {
  readonly operation: OperationSubmission;
  readonly blobs: readonly MappedBlob[];
  readonly warnings: readonly string[];
}

export class UnsupportedRecordError extends Error {
  readonly recordId: string;

  constructor(recordId: string, message: string) {
    super(`record ${recordId} cannot be represented losslessly: ${message}`);
    this.name = "UnsupportedRecordError";
    this.recordId = recordId;
  }
}

export function mapRecord(
  record: ExeligmosRecord,
  tagCatalog: ReadonlyMap<string, ExeligmosTag>,
): MappedRecord {
  try {
    return mapRecordUnchecked(record, tagCatalog);
  } catch (error) {
    if (error instanceof UnsupportedRecordError) throw error;
    const message = error instanceof Error ? error.message : String(error);
    throw new UnsupportedRecordError(record.id, message);
  }
}

function mapRecordUnchecked(
  record: ExeligmosRecord,
  tagCatalog: ReadonlyMap<string, ExeligmosTag>,
): MappedRecord {
  const entityId = assertUuid(record.originId, "record.originId");
  const operationId = operationIdForRecord(record);
  const warnings: string[] = [];
  const blobs: MappedBlob[] = [];
  const resources = new Map<`sha-256:${string}`, ResourceRef>();

  const mediaProvenance = record.media.map((media) => {
    const blob = mapMedia(media);
    if (!resources.has(blob.resource.contentId)) {
      resources.set(blob.resource.contentId, blob.resource);
      blobs.push(blob);
    } else {
      warnings.push(
        `media ${media.id} duplicates content ${blob.resource.contentId}; one resource reference is retained`,
      );
    }
    return {
      sourceMediaId: media.id,
      contentId: blob.resource.contentId,
      deviceId: media.deviceId,
      revision: media.revision,
      createdAt: media.createdAt,
      fileName: media.fileName,
      contentType: media.contentType,
      byteLength: media.byteLength,
      ...(media.encryption === undefined ? {} : { encryption: media.encryption }),
    };
  });

  const baseMigration: JsonObject = {
    mapping: "exeligmos-record-v1",
    sourceRecordId: record.id,
    sourceOriginId: record.originId,
    sourceUserId: record.userId,
    sourceDeviceId: record.deviceId,
    sourceRevision: record.revision,
    sourceCreatedAt: record.createdAt,
    sourceUpdatedAt: record.updatedAt,
    references: record.references,
    media: mediaProvenance,
  };

  let document: FractonicaRecordDocument;
  if (record.visibility === "public") {
    const startAtUnixMs = parseUnixMs(record.occurredAt, "occurredAt");
    const endAtUnixMs = record.endedAt === undefined
      ? undefined
      : parseUnixMs(record.endedAt, "endedAt");
    if (endAtUnixMs !== undefined && endAtUnixMs < startAtUnixMs) {
      throw new Error("endedAt precedes occurredAt");
    }

    const payloadExtra = { ...record.payload };
    const text = typeof payloadExtra.text === "string" ? payloadExtra.text : undefined;
    const emoji = typeof payloadExtra.emoji === "string" && payloadExtra.emoji !== ""
      ? payloadExtra.emoji
      : undefined;
    if (text !== undefined) delete payloadExtra.text;
    if (emoji !== undefined) delete payloadExtra.emoji;

    const recordTagSummaries = new Map(record.tags.map((tag) => [tag.id, tag]));
    const catalogTags = record.tagIds.map((tagId) => {
      const tag = tagCatalog.get(tagId);
      if (tag === undefined) {
        const summary = recordTagSummaries.get(tagId);
        warnings.push(`tag ${tagId} was referenced but absent from the full tag catalog`);
        return summary ?? { id: tagId, missing: true };
      }
      return tag;
    });
    const migration: JsonObject = {
      ...baseMigration,
      tags: catalogTags,
      recordMetadata: record.metadata,
      ...(Object.keys(payloadExtra).length === 0 ? {} : { payloadExtra }),
      ...(record.source === undefined ? {} : { source: record.source }),
      ...(record.template === undefined ? {} : { template: record.template }),
    };
    document = {
      startAtUnixMs,
      ...(endAtUnixMs === undefined ? {} : { endAtUnixMs }),
      visibility: "public",
      ...(emoji === undefined ? {} : { emoji }),
      ...(text === undefined ? {} : { text }),
      metadata: { migration },
      resources: [...resources.values()],
    };
  } else {
    const ciphertext = decodeBase64(record.encryption.ciphertext, "record encryption ciphertext");
    const digest = createHash("sha256").update(ciphertext).digest("hex");
    const contentId = contentIdForSha256(digest);
    const encryptedResource: ResourceRef = {
      contentId,
      byteLength: ciphertext.byteLength,
      mediaType: "application/octet-stream",
      role: "encrypted-record-payload",
      originalName: `${record.id}.encrypted-record`,
    };
    if (!resources.has(contentId)) {
      // The encrypted record body precedes ordinary attachments canonically.
      resources.set(contentId, encryptedResource);
      blobs.unshift({
        checkpointSourceId: `private-envelope:${record.originId}:revision:${record.revision}`,
        resource: encryptedResource,
        source: { kind: "bytes", bytes: ciphertext },
      });
    } else {
      warnings.push("private envelope bytes duplicate an attached media blob");
    }
    const orderedResources = [
      encryptedResource,
      ...[...resources.values()].filter((resource) => resource.contentId !== contentId),
    ];
    const migration: JsonObject = {
      ...baseMigration,
      temporalFallback: "sourceCreatedAt",
      privateEnvelope: {
        algorithm: record.encryption.algorithm,
        cryptoVersion: record.encryption.cryptoVersion,
        keyVersion: record.encryption.keyVersion,
        nonce: record.encryption.nonce,
        contentType: record.encryption.contentType,
        ciphertextEncoding: "base64",
        ciphertextContentId: contentId,
      },
    };
    document = {
      startAtUnixMs: parseUnixMs(record.createdAt, "createdAt"),
      visibility: "private",
      metadata: { migration },
      resources: orderedResources,
    };
    warnings.push(
      "private record occurrence time is encrypted; source createdAt is used as the structural start time",
    );
  }

  validateDocument(document);
  return {
    operation: {
      protocolVersion: 1,
      operationId,
      entityId,
      schema: "record.v1",
      causalParents: [],
      occurredAtUnixMs: parseUnixMs(record.updatedAt, "updatedAt"),
      body: { kind: "put", document },
    },
    blobs,
    warnings,
  };
}

function mapMedia(media: ExeligmosMedia): MappedBlob {
  const originalName = validOriginalName(media.fileName) ? media.fileName : undefined;
  const resource: ResourceRef = {
    contentId: contentIdForSha256(media.sha256),
    byteLength: media.byteLength,
    mediaType: media.contentType,
    role: "attachment",
    ...(originalName === undefined ? {} : { originalName }),
  };
  return {
    checkpointSourceId: media.id,
    resource,
    source: { kind: "exeligmos-media", media },
  };
}

function validateDocument(document: FractonicaRecordDocument): void {
  if (document.resources.length > MAX_RECORD_RESOURCES) {
    throw new Error(
      `${document.resources.length} unique resources exceed the ${MAX_RECORD_RESOURCES}-resource limit`,
    );
  }
  const contentIds = new Set<string>();
  for (const resource of document.resources) {
    if (contentIds.has(resource.contentId)) {
      throw new Error(`duplicate resource content ID ${resource.contentId}`);
    }
    contentIds.add(resource.contentId);
    if (!validMediaType(resource.mediaType)) {
      throw new Error(`unsupported media type ${JSON.stringify(resource.mediaType)}`);
    }
  }
  if (document.text !== undefined && charCount(document.text) > MAX_TEXT_CHARS) {
    throw new Error(`text exceeds ${MAX_TEXT_CHARS} Unicode scalar values`);
  }
  if (
    document.emoji !== undefined &&
    (charCount(document.emoji) < 1 ||
      charCount(document.emoji) > MAX_EMOJI_CHARS ||
      containsControl(document.emoji))
  ) {
    throw new Error(`emoji violates the ${MAX_EMOJI_CHARS}-character bound`);
  }
  if (document.metadata !== undefined) validateMetadata(document.metadata);
}

function validateMetadata(metadata: JsonObject): void {
  if (Object.keys(metadata).length > MAX_METADATA_ENTRIES) {
    throw new Error(`metadata exceeds ${MAX_METADATA_ENTRIES} top-level entries`);
  }
  for (const [key, value] of Object.entries(metadata)) {
    validateMetadataKey(key);
    validateMetadataValue(value, 1);
  }
  const bytes = Buffer.byteLength(JSON.stringify(metadata), "utf8");
  if (bytes > MAX_METADATA_JSON_BYTES) {
    throw new Error(`metadata is ${bytes} bytes; maximum is ${MAX_METADATA_JSON_BYTES}`);
  }
}

function validateMetadataValue(value: unknown, depth: number): void {
  if (value === null || typeof value === "boolean") return;
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new Error("metadata contains a non-finite number");
    return;
  }
  if (typeof value === "string") {
    if (charCount(value) > MAX_METADATA_STRING_CHARS) {
      throw new Error(`metadata string exceeds ${MAX_METADATA_STRING_CHARS} characters`);
    }
    return;
  }
  if (depth > MAX_METADATA_DEPTH) {
    throw new Error(`metadata nesting exceeds depth ${MAX_METADATA_DEPTH}`);
  }
  if (Array.isArray(value)) {
    if (value.length > MAX_METADATA_CONTAINER_ITEMS) {
      throw new Error(`metadata array exceeds ${MAX_METADATA_CONTAINER_ITEMS} items`);
    }
    for (const item of value) validateMetadataValue(item, depth + 1);
    return;
  }
  if (typeof value === "object" && value !== null) {
    const entries = Object.entries(value as Record<string, unknown>);
    if (entries.length > MAX_METADATA_CONTAINER_ITEMS) {
      throw new Error(`metadata object exceeds ${MAX_METADATA_CONTAINER_ITEMS} entries`);
    }
    for (const [key, item] of entries) {
      validateMetadataKey(key);
      validateMetadataValue(item, depth + 1);
    }
    return;
  }
  throw new Error(`metadata contains unsupported ${typeof value} value`);
}

function validateMetadataKey(key: string): void {
  if (
    charCount(key) < 1 ||
    charCount(key) > MAX_METADATA_KEY_CHARS ||
    containsControl(key)
  ) {
    throw new Error(`metadata key ${JSON.stringify(key)} is invalid`);
  }
}

function validMediaType(value: string): boolean {
  return (
    Buffer.byteLength(value, "utf8") <= 127 &&
    /^[A-Za-z0-9!#$%&'*+.^_`|~-]+\/[A-Za-z0-9!#$%&'*+.^_`|~-]+$/.test(value)
  );
}

function validOriginalName(value: string): boolean {
  return (
    value !== "." &&
    value !== ".." &&
    charCount(value) >= 1 &&
    charCount(value) <= 255 &&
    !containsControl(value) &&
    !/[\\/:]/u.test(value)
  );
}

function parseUnixMs(value: string, field: string): number {
  const parsed = Date.parse(value);
  if (!Number.isSafeInteger(parsed) || parsed < 0) {
    throw new Error(`${field} is outside the supported Unix millisecond range`);
  }
  return parsed;
}

function decodeBase64(value: string, context: string): Buffer {
  if (value.length === 0 || value.length % 4 !== 0 || !/^[A-Za-z0-9+/]+={0,2}$/.test(value)) {
    throw new Error(`${context} is not canonical base64`);
  }
  const decoded = Buffer.from(value, "base64");
  if (decoded.byteLength === 0) throw new Error(`${context} decoded to zero bytes`);
  if (decoded.toString("base64") !== value) throw new Error(`${context} has noncanonical padding bits`);
  return decoded;
}

function charCount(value: string): number {
  return [...value].length;
}

function containsControl(value: string): boolean {
  return /[\u0000-\u001f\u007f-\u009f]/u.test(value);
}

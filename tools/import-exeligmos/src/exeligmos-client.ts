import { fetchChecked, requestJson, resolveUrl } from "./http.ts";
import type {
  ExeligmosCursorPage,
  ExeligmosMedia,
  ExeligmosPrivateRecord,
  ExeligmosPublicRecord,
  ExeligmosRecord,
  ExeligmosReference,
  ExeligmosTag,
  JsonObject,
} from "./types.ts";

export class ExeligmosClient {
  readonly baseUrl: string;
  readonly token: string;

  constructor(baseUrl: string, token: string) {
    this.baseUrl = baseUrl;
    this.token = token;
  }

  async listRecords(cursor?: string): Promise<ExeligmosCursorPage<ExeligmosRecord>> {
    const url = resolveUrl(this.baseUrl, "/v1/records");
    url.searchParams.set("limit", "25");
    if (cursor !== undefined) url.searchParams.set("cursor", cursor);
    const value = await requestJson<unknown>(url, {
      token: this.token,
      retryable: true,
    });
    return parseCursorPage(value, parseRecord, "record page");
  }

  async listTags(cursor?: string): Promise<ExeligmosCursorPage<ExeligmosTag>> {
    const url = resolveUrl(this.baseUrl, "/v1/tags");
    url.searchParams.set("limit", "200");
    if (cursor !== undefined) url.searchParams.set("cursor", cursor);
    const value = await requestJson<unknown>(url, {
      token: this.token,
      retryable: true,
    });
    return parseCursorPage(value, parseTag, "tag page");
  }

  async downloadMedia(media: ExeligmosMedia): Promise<Response> {
    const url = resolveUrl(this.baseUrl, media.contentUrl);
    const sourceOrigin = new URL(this.baseUrl).origin;
    if (url.origin !== sourceOrigin) {
      throw new Error(
        `refusing cross-origin media URL for ${media.id}: ${url.origin} is not ${sourceOrigin}`,
      );
    }
    const response = await fetchChecked(url, {
      token: this.token,
      expectedStatuses: [200],
      timeoutMs: 5 * 60_000,
    });
    const length = response.headers.get("content-length");
    if (length !== null && Number(length) !== media.byteLength) {
      await response.body?.cancel();
      throw new Error(
        `media ${media.id} declared ${media.byteLength} bytes but source returned Content-Length ${length}`,
      );
    }
    const digest = response.headers.get("x-content-sha256");
    if (digest !== null && digest.toLowerCase() !== media.sha256.toLowerCase()) {
      await response.body?.cancel();
      throw new Error(
        `media ${media.id} declared SHA-256 ${media.sha256} but source returned ${digest}`,
      );
    }
    return response;
  }
}

function parseCursorPage<T>(
  value: unknown,
  parseItem: (item: unknown, context: string) => T,
  context: string,
): ExeligmosCursorPage<T> {
  const object = expectObject(value, context);
  const data = expectArray(object.data, `${context}.data`).map((item, index) =>
    parseItem(item, `${context}.data[${index}]`),
  );
  const hasMore = expectBoolean(object.hasMore, `${context}.hasMore`);
  const nextCursor = optionalString(object.nextCursor, `${context}.nextCursor`);
  if (hasMore && nextCursor === undefined) {
    throw new Error(`${context} hasMore is true but nextCursor is absent`);
  }
  return nextCursor === undefined ? { data, hasMore } : { data, hasMore, nextCursor };
}

function parseRecord(value: unknown, context: string): ExeligmosRecord {
  const object = expectObject(value, context);
  const common = {
    id: expectString(object.id, `${context}.id`),
    originId: expectString(object.originId, `${context}.originId`),
    userId: expectString(object.userId, `${context}.userId`),
    deviceId: expectString(object.deviceId, `${context}.deviceId`),
    revision: expectPositiveInteger(object.revision, `${context}.revision`),
    createdAt: expectDateTime(object.createdAt, `${context}.createdAt`),
    updatedAt: expectDateTime(object.updatedAt, `${context}.updatedAt`),
    references: expectArray(object.references, `${context}.references`).map((item, index) =>
      parseReference(item, `${context}.references[${index}]`),
    ),
    media: expectArray(object.media, `${context}.media`).map((item, index) =>
      parseMedia(item, `${context}.media[${index}]`),
    ),
  };
  const visibility = expectString(object.visibility, `${context}.visibility`);
  if (visibility === "public") {
    const result: ExeligmosPublicRecord = {
      ...common,
      visibility,
      occurredAt: expectDateTime(object.occurredAt, `${context}.occurredAt`),
      payload: expectJsonObject(object.payload, `${context}.payload`),
      tagIds: expectArray(object.tagIds, `${context}.tagIds`).map((item, index) =>
        expectString(item, `${context}.tagIds[${index}]`),
      ),
      tags: expectArray(object.tags, `${context}.tags`).map((item, index) => {
        const tag = expectObject(item, `${context}.tags[${index}]`);
        const color = optionalString(tag.color, `${context}.tags[${index}].color`);
        const emoji = optionalString(tag.emoji, `${context}.tags[${index}].emoji`);
        return {
          id: expectString(tag.id, `${context}.tags[${index}].id`),
          name: expectString(tag.name, `${context}.tags[${index}].name`),
          ...(color === undefined ? {} : { color }),
          ...(emoji === undefined ? {} : { emoji }),
        };
      }),
      metadata: expectJsonObject(object.metadata, `${context}.metadata`),
      ...optionalObjectProperty(object.source, "source", context),
      ...optionalObjectProperty(object.template, "template", context),
      ...(object.endedAt === undefined
        ? {}
        : { endedAt: expectDateTime(object.endedAt, `${context}.endedAt`) }),
    };
    return result;
  }
  if (visibility === "private") {
    const encryption = expectObject(object.encryption, `${context}.encryption`);
    const result: ExeligmosPrivateRecord = {
      ...common,
      visibility,
      encryption: {
        algorithm: expectLiteral(encryption.algorithm, "A256GCM", `${context}.encryption.algorithm`),
        cryptoVersion: expectLiteral(encryption.cryptoVersion, 1, `${context}.encryption.cryptoVersion`),
        keyVersion: expectLiteral(encryption.keyVersion, 1, `${context}.encryption.keyVersion`),
        nonce: expectString(encryption.nonce, `${context}.encryption.nonce`),
        ciphertext: expectString(encryption.ciphertext, `${context}.encryption.ciphertext`),
        contentType: expectLiteral(
          encryption.contentType,
          "application/vnd.exeligmos.record+json",
          `${context}.encryption.contentType`,
        ),
      },
    };
    return result;
  }
  throw new Error(`${context}.visibility must be public or private`);
}

function parseMedia(value: unknown, context: string): ExeligmosMedia {
  const object = expectObject(value, context);
  const encryptionValue = object.encryption;
  let encryption: ExeligmosMedia["encryption"];
  if (encryptionValue !== undefined) {
    const valueObject = expectObject(encryptionValue, `${context}.encryption`);
    const plaintextContentType = optionalString(
      valueObject.plaintextContentType,
      `${context}.encryption.plaintextContentType`,
    );
    encryption = {
      algorithm: expectLiteral(valueObject.algorithm, "A256GCM", `${context}.encryption.algorithm`),
      cryptoVersion: expectLiteral(valueObject.cryptoVersion, 1, `${context}.encryption.cryptoVersion`),
      keyVersion: expectLiteral(valueObject.keyVersion, 1, `${context}.encryption.keyVersion`),
      nonce: expectString(valueObject.nonce, `${context}.encryption.nonce`),
      ...(plaintextContentType === undefined ? {} : { plaintextContentType }),
    };
  }
  const publicContentUrl = optionalString(object.publicContentUrl, `${context}.publicContentUrl`);
  return {
    id: expectString(object.id, `${context}.id`),
    userId: expectString(object.userId, `${context}.userId`),
    deviceId: expectString(object.deviceId, `${context}.deviceId`),
    fileName: expectString(object.fileName, `${context}.fileName`),
    contentType: expectString(object.contentType, `${context}.contentType`),
    byteLength: expectPositiveInteger(object.byteLength, `${context}.byteLength`),
    sha256: expectString(object.sha256, `${context}.sha256`),
    ...(encryption === undefined ? {} : { encryption }),
    revision: expectPositiveInteger(object.revision, `${context}.revision`),
    createdAt: expectDateTime(object.createdAt, `${context}.createdAt`),
    contentUrl: expectString(object.contentUrl, `${context}.contentUrl`),
    ...(publicContentUrl === undefined ? {} : { publicContentUrl }),
  };
}

function parseReference(value: unknown, context: string): ExeligmosReference {
  const object = expectObject(value, context);
  const targetType = expectString(object.targetType, `${context}.targetType`);
  if (targetType !== "user" && targetType !== "record" && targetType !== "event") {
    throw new Error(`${context}.targetType is unsupported: ${targetType}`);
  }
  return {
    relation: expectString(object.relation, `${context}.relation`),
    targetType,
    targetUserId: expectString(object.targetUserId, `${context}.targetUserId`),
    targetId: expectString(object.targetId, `${context}.targetId`),
  };
}

function parseTag(value: unknown, context: string): ExeligmosTag {
  const object = expectObject(value, context);
  const color = optionalString(object.color, `${context}.color`);
  const emoji = optionalString(object.emoji, `${context}.emoji`);
  return {
    id: expectString(object.id, `${context}.id`),
    userId: expectString(object.userId, `${context}.userId`),
    name: expectString(object.name, `${context}.name`),
    ...(color === undefined ? {} : { color }),
    ...(emoji === undefined ? {} : { emoji }),
    sortOrder: expectInteger(object.sortOrder, `${context}.sortOrder`),
    metadata: expectJsonObject(object.metadata, `${context}.metadata`),
    revision: expectPositiveInteger(object.revision, `${context}.revision`),
    createdAt: expectDateTime(object.createdAt, `${context}.createdAt`),
    updatedAt: expectDateTime(object.updatedAt, `${context}.updatedAt`),
  };
}

function optionalObjectProperty(
  value: unknown,
  key: "source" | "template",
  context: string,
): Partial<Record<"source" | "template", JsonObject>> {
  return value === undefined ? {} : { [key]: expectJsonObject(value, `${context}.${key}`) };
}

function expectObject(value: unknown, context: string): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${context} must be an object`);
  }
  return value as Record<string, unknown>;
}

function expectJsonObject(value: unknown, context: string): JsonObject {
  return expectObject(value, context);
}

function expectArray(value: unknown, context: string): unknown[] {
  if (!Array.isArray(value)) throw new Error(`${context} must be an array`);
  return value;
}

function expectString(value: unknown, context: string): string {
  if (typeof value !== "string") throw new Error(`${context} must be a string`);
  return value;
}

function optionalString(value: unknown, context: string): string | undefined {
  return value === undefined || value === null ? undefined : expectString(value, context);
}

function expectBoolean(value: unknown, context: string): boolean {
  if (typeof value !== "boolean") throw new Error(`${context} must be a boolean`);
  return value;
}

function expectInteger(value: unknown, context: string): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value)) {
    throw new Error(`${context} must be a safe integer`);
  }
  return value;
}

function expectNonnegativeInteger(value: unknown, context: string): number {
  const result = expectInteger(value, context);
  if (result < 0) throw new Error(`${context} must not be negative`);
  return result;
}

function expectPositiveInteger(value: unknown, context: string): number {
  const result = expectInteger(value, context);
  if (result < 1) throw new Error(`${context} must be positive`);
  return result;
}

function expectDateTime(value: unknown, context: string): string {
  const result = expectString(value, context);
  if (!Number.isFinite(Date.parse(result))) throw new Error(`${context} is not an ISO date-time`);
  return result;
}

function expectLiteral<T extends string | number>(
  value: unknown,
  expected: T,
  context: string,
): T {
  if (value !== expected) throw new Error(`${context} must equal ${JSON.stringify(expected)}`);
  return expected;
}

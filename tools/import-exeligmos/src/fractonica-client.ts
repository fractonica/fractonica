import { createHash } from "node:crypto";

import {
  fetchChecked,
  HttpError,
  jsonBody,
  requestJson,
  resolveUrl,
} from "./http.ts";
import { normalizeSha256, stableJsonStringify } from "./deterministic.ts";
import type {
  BlobAvailability,
  ContentDescriptor,
  EntityState,
  OperationPage,
  OperationSubmission,
  StoredOperation,
} from "./types.ts";

export const MAX_TUS_CHUNK_BYTES = 4 * 1024 * 1024;

export interface TusUploadState {
  readonly uploadUrl: string;
  readonly length: number;
  readonly offset: number;
  readonly contentId?: `sha-256:${string}`;
}

export interface TusPatchResult {
  readonly offset: number;
  readonly contentId?: `sha-256:${string}`;
}

export interface TusUploadMetadata {
  readonly filename?: string;
  readonly mediaType?: string;
  readonly contentId?: `sha-256:${string}`;
}

export class FractonicaClient {
  readonly baseUrl: string;
  readonly token: string | undefined;

  constructor(baseUrl: string, token?: string) {
    this.baseUrl = baseUrl;
    this.token = token;
  }

  async blobAvailability(
    contentIds: readonly `sha-256:${string}`[],
  ): Promise<BlobAvailability> {
    if (contentIds.length === 0 || contentIds.length > 256) {
      throw new Error("blob availability accepts between 1 and 256 content IDs");
    }
    const json = jsonBody({ contentIds });
    const value = await requestJson<unknown>(
      resolveUrl(this.baseUrl, "/api/v1/blobs/availability"),
      {
        method: "POST",
        token: this.token,
        body: json.body,
        headers: json.headers,
        expectedStatuses: [200],
        retryable: true,
      },
    );
    return parseAvailability(value);
  }

  async createUpload(
    length: number,
    metadata: TusUploadMetadata,
  ): Promise<TusUploadState> {
    assertNonnegativeSafeInteger(length, "upload length");
    const headers = new Headers({
      "Tus-Resumable": "1.0.0",
      "Upload-Length": String(length),
    });
    const encodedMetadata = encodeUploadMetadata(metadata);
    if (encodedMetadata !== "") headers.set("Upload-Metadata", encodedMetadata);
    const endpoint = resolveUrl(this.baseUrl, "/api/v1/uploads");
    const response = await fetchChecked(endpoint, {
      method: "POST",
      token: this.token,
      headers,
      expectedStatuses: [201],
      retryable: false,
    });
    const location = response.headers.get("location");
    if (location === null) throw new Error("TUS create response omitted Location");
    const offset = parseIntegerHeader(response, "upload-offset");
    if (offset !== 0) throw new Error(`new TUS upload started at unexpected offset ${offset}`);
    const uploadUrl = new URL(location, endpoint);
    if (uploadUrl.origin !== endpoint.origin) {
      throw new Error("refusing a cross-origin TUS Location that could expose destination credentials");
    }
    return { uploadUrl: uploadUrl.toString(), length, offset };
  }

  async headUpload(uploadUrl: string): Promise<TusUploadState> {
    const response = await fetchChecked(uploadUrl, {
      method: "HEAD",
      token: this.token,
      headers: { "Tus-Resumable": "1.0.0" },
      expectedStatuses: [200],
      retryable: true,
    });
    const length = parseIntegerHeader(response, "upload-length");
    const offset = parseIntegerHeader(response, "upload-offset");
    const rawContentId = response.headers.get("fractonica-content-id");
    return {
      uploadUrl,
      length,
      offset,
      ...(rawContentId === null
        ? {}
        : { contentId: parseContentId(rawContentId, "Fractonica-Content-Id") }),
    };
  }

  async patchUpload(
    uploadUrl: string,
    offset: number,
    bytes: Uint8Array,
  ): Promise<TusPatchResult> {
    assertNonnegativeSafeInteger(offset, "upload offset");
    if (bytes.byteLength === 0 || bytes.byteLength > MAX_TUS_CHUNK_BYTES) {
      throw new Error(`TUS chunks must contain 1-${MAX_TUS_CHUNK_BYTES} bytes`);
    }
    const checksum = createHash("sha256").update(bytes).digest("base64");
    const response = await fetchChecked(uploadUrl, {
      method: "PATCH",
      token: this.token,
      headers: {
        "Tus-Resumable": "1.0.0",
        "Content-Type": "application/offset+octet-stream",
        "Upload-Offset": String(offset),
        "Upload-Checksum": `sha256 ${checksum}`,
      },
      body: bytes as BodyInit,
      expectedStatuses: [204],
      timeoutMs: 5 * 60_000,
    });
    const nextOffset = parseIntegerHeader(response, "upload-offset");
    if (nextOffset !== offset + bytes.byteLength) {
      throw new Error(
        `TUS server advanced to ${nextOffset}, expected ${offset + bytes.byteLength}`,
      );
    }
    const rawContentId = response.headers.get("fractonica-content-id");
    return {
      offset: nextOffset,
      ...(rawContentId === null
        ? {}
        : { contentId: parseContentId(rawContentId, "Fractonica-Content-Id") }),
    };
  }

  async submitOperation(
    operation: OperationSubmission,
    idempotencyKey: string,
  ): Promise<{ readonly stored: StoredOperation; readonly replayed: boolean }> {
    const json = jsonBody(operation);
    json.headers.set("Idempotency-Key", idempotencyKey);
    const response = await fetchChecked(
      resolveUrl(this.baseUrl, "/api/v1/operations"),
      {
        method: "POST",
        token: this.token,
        body: json.body,
        headers: json.headers,
        expectedStatuses: [200, 201],
        retryable: true,
      },
    );
    const value = (await response.json()) as unknown;
    return { stored: parseStoredOperation(value), replayed: response.status === 200 };
  }

  async operationPage(after: number, limit = 200): Promise<OperationPage> {
    assertNonnegativeSafeInteger(after, "operation cursor");
    if (!Number.isSafeInteger(limit) || limit < 1 || limit > 200) {
      throw new Error("operation page limit must be between 1 and 200");
    }
    const url = resolveUrl(this.baseUrl, "/api/v1/operations");
    url.searchParams.set("after", String(after));
    url.searchParams.set("limit", String(limit));
    return parseOperationPage(
      await requestJson<unknown>(url, { token: this.token, retryable: true }),
    );
  }

  async entityState(entityId: string): Promise<EntityState | undefined> {
    const response = await fetchChecked(
      resolveUrl(this.baseUrl, `/api/v1/entities/${encodeURIComponent(entityId)}`),
      {
        token: this.token,
        expectedStatuses: [200, 404],
        retryable: true,
      },
    );
    if (response.status === 404) {
      await response.body?.cancel();
      return undefined;
    }
    return parseEntityState((await response.json()) as unknown);
  }

  async verifyStoredOperation(
    expected: OperationSubmission,
    localSequence: number,
  ): Promise<void> {
    if (!Number.isSafeInteger(localSequence) || localSequence < 1) {
      throw new Error(`invalid local sequence ${localSequence}`);
    }
    const page = await this.operationPage(localSequence - 1, 1);
    const actual = page.operations[0];
    if (actual === undefined || actual.localSequence !== localSequence) {
      throw new Error(`operation sequence ${localSequence} was not returned by the destination`);
    }
    this.assertStoredOperationMatches(expected, actual);
  }

  assertStoredOperationMatches(
    expected: OperationSubmission,
    actual: StoredOperation,
  ): void {
    const { actorId: _actorId, ...actualSubmission } = actual.operation;
    if (
      stableJsonStringify(normalizeSubmission(actualSubmission)) !==
      stableJsonStringify(normalizeSubmission(expected))
    ) {
      throw new Error(
        `destination operation ${expected.operationId} differs from the submitted operation`,
      );
    }
  }

  isUploadGone(error: unknown): boolean {
    return error instanceof HttpError && (error.status === 404 || error.status === 410);
  }
}

function normalizeSubmission(operation: OperationSubmission): OperationSubmission {
  const document = operation.body.document;
  return {
    ...operation,
    body: {
      ...operation.body,
      document: {
        ...document,
        resources: document.resources ?? [],
      },
    },
  };
}

function encodeUploadMetadata(metadata: TusUploadMetadata): string {
  const pairs: string[] = [];
  for (const [key, value] of Object.entries(metadata)) {
    if (value === undefined) continue;
    if (/[\r\n]/.test(value)) throw new Error(`invalid newline in TUS metadata ${key}`);
    pairs.push(`${key} ${Buffer.from(value, "utf8").toString("base64")}`);
  }
  return pairs.join(",");
}

function parseIntegerHeader(response: Response, name: string): number {
  const value = response.headers.get(name);
  if (value === null || !/^(0|[1-9][0-9]*)$/.test(value)) {
    throw new Error(`${response.url} returned an invalid or missing ${name} header`);
  }
  const number = Number(value);
  assertNonnegativeSafeInteger(number, name);
  return number;
}

function parseAvailability(value: unknown): BlobAvailability {
  const object = expectObject(value, "blob availability response");
  const available = expectArray(object.available, "blob availability.available").map(
    (item, index) => parseDescriptor(item, `blob availability.available[${index}]`),
  );
  const missing = expectArray(object.missing, "blob availability.missing").map(
    (item, index) =>
      parseContentId(expectString(item, `blob availability.missing[${index}]`), "content ID"),
  );
  return { available, missing };
}

function parseDescriptor(value: unknown, context: string): ContentDescriptor {
  const object = expectObject(value, context);
  return {
    contentId: parseContentId(expectString(object.contentId, `${context}.contentId`), context),
    byteLength: expectNonnegativeInteger(object.byteLength, `${context}.byteLength`),
  };
}

function parseOperationPage(value: unknown): OperationPage {
  const object = expectObject(value, "operation page");
  return {
    operations: expectArray(object.operations, "operation page.operations").map(
      (item) => parseStoredOperation(item),
    ),
    nextAfter: expectNonnegativeInteger(object.nextAfter, "operation page.nextAfter"),
    hasMore: expectBoolean(object.hasMore, "operation page.hasMore"),
  };
}

function parseEntityState(value: unknown): EntityState {
  const object = expectObject(value, "entity state");
  const schema = expectString(object.schema, "entity state.schema");
  if (schema !== "record.v1") throw new Error(`unsupported entity schema ${schema}`);
  const heads = expectArray(object.heads, "entity state.heads").map((item) =>
    parseStoredOperation(item),
  );
  if (heads.length < 1 || heads.length > 64) {
    throw new Error("entity state must contain between 1 and 64 heads");
  }
  const operationCount = expectNonnegativeInteger(
    object.operationCount,
    "entity state.operationCount",
  );
  if (operationCount < 1) throw new Error("entity state.operationCount must be positive");
  return {
    entityId: expectString(object.entityId, "entity state.entityId"),
    schema,
    operationCount,
    conflicted: expectBoolean(object.conflicted, "entity state.conflicted"),
    heads,
  };
}

function parseStoredOperation(value: unknown): StoredOperation {
  const object = expectObject(value, "stored operation");
  const operation = expectObject(object.operation, "stored operation.operation");
  // Full semantic comparison is performed against the submitted object during
  // verification. This parser establishes the identity and cursor boundary.
  expectString(operation.actorId, "stored operation.operation.actorId");
  expectString(operation.operationId, "stored operation.operation.operationId");
  expectString(operation.entityId, "stored operation.operation.entityId");
  const localSequence = expectNonnegativeInteger(
    object.localSequence,
    "stored operation.localSequence",
  );
  if (localSequence < 1) throw new Error("stored operation.localSequence must be positive");
  return {
    localSequence,
    operation: operation as unknown as StoredOperation["operation"],
  };
}

function parseContentId(value: string, context: string): `sha-256:${string}` {
  if (!value.startsWith("sha-256:")) throw new Error(`${context} is not a SHA-256 content ID`);
  return `sha-256:${normalizeSha256(value.slice("sha-256:".length))}`;
}

function expectObject(value: unknown, context: string): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${context} must be an object`);
  }
  return value as Record<string, unknown>;
}

function expectArray(value: unknown, context: string): unknown[] {
  if (!Array.isArray(value)) throw new Error(`${context} must be an array`);
  return value;
}

function expectString(value: unknown, context: string): string {
  if (typeof value !== "string") throw new Error(`${context} must be a string`);
  return value;
}

function expectNonnegativeInteger(value: unknown, context: string): number {
  if (typeof value !== "number") throw new Error(`${context} must be a number`);
  assertNonnegativeSafeInteger(value, context);
  return value;
}

function expectBoolean(value: unknown, context: string): boolean {
  if (typeof value !== "boolean") throw new Error(`${context} must be a boolean`);
  return value;
}

function assertNonnegativeSafeInteger(value: number, context: string): void {
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new Error(`${context} must be a nonnegative safe integer`);
  }
}

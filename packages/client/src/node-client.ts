import type {
  ClientEntityPage,
  ClientEntitySummary,
  ClientEntitySchema,
  ClientProjectionCursor,
  ClientStats,
  EntityId,
  OperationId,
  PageOptions,
  Problem,
  SignedOperation,
  SpaceId,
  StoredOperation,
} from "./types";

type Fetcher = typeof fetch;

export interface NodeClientOptions {
  fetcher?: Fetcher;
  bearerToken?: string;
  timeoutMs?: number;
}

export class NodeApiError extends Error {
  readonly status: number;
  readonly code: string;
  readonly problem?: Problem;

  constructor(status: number, code: string, message: string, problem?: Problem) {
    super(message);
    this.name = "NodeApiError";
    this.status = status;
    this.code = code;
    this.problem = problem;
  }
}

export class FractonicaNodeClient {
  readonly baseUrl: string;
  readonly #fetcher: Fetcher;
  readonly #bearerToken?: string;
  readonly #timeoutMs: number;

  constructor(baseUrl: string, options: NodeClientOptions = {}) {
    const parsed = new URL(baseUrl);
    if (!/^https?:$/.test(parsed.protocol) || parsed.username || parsed.password || parsed.search || parsed.hash) {
      throw new TypeError("Fractonica node URL must be an HTTP(S) origin without credentials or query data");
    }
    this.baseUrl = parsed.origin;
    this.#fetcher = options.fetcher ?? fetch;
    this.#bearerToken = options.bearerToken;
    this.#timeoutMs = options.timeoutMs ?? 5_000;
    if (!Number.isSafeInteger(this.#timeoutMs) || this.#timeoutMs <= 0) {
      throw new TypeError("timeoutMs must be a positive safe integer");
    }
  }

  listRecords(spaceId: SpaceId, options?: PageOptions): Promise<ClientEntityPage<"record">> {
    return this.#list(spaceId, "record", options);
  }

  listEvents(spaceId: SpaceId, options?: PageOptions): Promise<ClientEntityPage<"event">> {
    return this.#list(spaceId, "event", options);
  }

  listTags(spaceId: SpaceId, options?: PageOptions): Promise<ClientEntityPage<"tag">> {
    return this.#list(spaceId, "tag", options);
  }

  listProfiles(spaceId: SpaceId, options?: PageOptions): Promise<ClientEntityPage<"profile">> {
    return this.#list(spaceId, "profile", options);
  }

  async stats(spaceId: SpaceId, signal?: AbortSignal): Promise<ClientStats> {
    const value = await this.#json(`/api/spaces/${path(spaceId)}/stats`, { signal });
    return decodeStats(value);
  }

  async submit(operation: SignedOperation, signal?: AbortSignal): Promise<StoredOperation> {
    const value = await this.#json(`/api/spaces/${path(operation.spaceId)}/operations`, {
      method: "POST",
      body: JSON.stringify(operation),
      signal,
    });
    return decodeStoredOperation(value);
  }

  async operation(
    spaceId: SpaceId,
    operationId: OperationId,
    signal?: AbortSignal,
  ): Promise<StoredOperation> {
    const value = await this.#json(
      `/api/spaces/${path(spaceId)}/operations/${path(operationId)}`,
      { signal },
    );
    return decodeStoredOperation(value);
  }

  async #list<S extends ClientEntitySchema>(
    spaceId: SpaceId,
    schema: S,
    options: PageOptions = {},
  ): Promise<ClientEntityPage<S>> {
    const query = pageQuery(schema, options);
    const value = await this.#json(
      `/api/spaces/${path(spaceId)}/${collection(schema)}${query}`,
      { signal: options.signal },
    );
    return decodePage(value, schema);
  }

  async #json(pathname: string, init: RequestInit = {}): Promise<unknown> {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), this.#timeoutMs);
    const sourceSignal = init.signal;
    const abort = () => controller.abort();
    sourceSignal?.addEventListener("abort", abort, { once: true });
    if (sourceSignal?.aborted) controller.abort();
    const headers = new Headers(init.headers);
    headers.set("accept", "application/json, application/problem+json");
    if (init.body !== undefined) headers.set("content-type", "application/json");
    if (this.#bearerToken) headers.set("authorization", `Bearer ${this.#bearerToken}`);
    try {
      const response = await this.#fetcher(`${this.baseUrl}${pathname}`, {
        ...init,
        headers,
        signal: controller.signal,
      });
      const value: unknown = await response.json().catch(() => undefined);
      if (!response.ok) throw decodeError(response.status, value);
      return value;
    } finally {
      clearTimeout(timeout);
      sourceSignal?.removeEventListener("abort", abort);
    }
  }
}

function collection(schema: ClientEntitySchema): string {
  return schema === "record" ? "records" : schema === "event" ? "events" : `${schema}s`;
}

function pageQuery(schema: ClientEntitySchema, options: PageOptions): string {
  const query = new URLSearchParams();
  if (options.limit !== undefined) {
    if (!Number.isSafeInteger(options.limit) || options.limit < 1 || options.limit > 200) {
      throw new TypeError("page limit must be an integer between 1 and 200");
    }
    query.set("limit", String(options.limit));
  }
  if (options.cursor) appendCursor(query, schema, options.cursor);
  const encoded = query.toString();
  return encoded ? `?${encoded}` : "";
}

function appendCursor(
  query: URLSearchParams,
  schema: ClientEntitySchema,
  cursor: ClientProjectionCursor,
): void {
  const temporal = schema === "record" || schema === "event";
  if (temporal && cursor.sortNumber === undefined) {
    throw new TypeError("record and event cursors require sortNumber");
  }
  if (!temporal && cursor.sortText === undefined) {
    throw new TypeError("tag and profile cursors require sortText");
  }
  if (temporal && cursor.sortText !== undefined) {
    throw new TypeError("temporal cursors cannot contain sortText");
  }
  if (!temporal && cursor.sortNumber !== undefined) {
    throw new TypeError("text cursors cannot contain sortNumber");
  }
  if (cursor.sortNumber !== undefined) query.set("sortNumber", String(cursor.sortNumber));
  if (cursor.sortText !== undefined) query.set("sortText", cursor.sortText);
  query.set("entityId", cursor.entityId);
  query.set("operationId", cursor.operationId);
}

function decodePage<S extends ClientEntitySchema>(value: unknown, schema: S): ClientEntityPage<S> {
  const object = exactObject(value, ["spaceId", "schema", "items"], ["nextCursor"]);
  if (object.schema !== schema || !isSpaceId(object.spaceId) || !Array.isArray(object.items)) {
    throw contractError("invalid client page identity");
  }
  return {
    spaceId: object.spaceId,
    schema,
    items: object.items.map(decodeSummary),
    ...(object.nextCursor === undefined ? {} : { nextCursor: decodeCursor(object.nextCursor) }),
  };
}

function decodeSummary(value: unknown): ClientEntitySummary {
  const object = exactObject(
    value,
    ["operation", "visibility", "conflicted", "resourceCount", "mediaBytes"],
    ["startAtUnixMs", "endAtUnixMs", "sortText"],
  );
  if (
    (object.visibility !== "public" && object.visibility !== "private") ||
    typeof object.conflicted !== "boolean" ||
    !isNonnegativeInteger(object.resourceCount) ||
    !isNonnegativeInteger(object.mediaBytes) ||
    !isOptionalNonnegativeInteger(object.startAtUnixMs) ||
    !isOptionalNonnegativeInteger(object.endAtUnixMs) ||
    (object.sortText !== undefined && typeof object.sortText !== "string")
  ) {
    throw contractError("invalid client entity summary");
  }
  const visibility = object.visibility as "public" | "private";
  const startAtUnixMs = object.startAtUnixMs as number | undefined;
  const endAtUnixMs = object.endAtUnixMs as number | undefined;
  return {
    operation: decodeStoredOperation(object.operation),
    visibility,
    conflicted: object.conflicted,
    resourceCount: object.resourceCount,
    mediaBytes: object.mediaBytes,
    ...(startAtUnixMs === undefined ? {} : { startAtUnixMs }),
    ...(endAtUnixMs === undefined ? {} : { endAtUnixMs }),
    ...(object.sortText === undefined ? {} : { sortText: object.sortText }),
  };
}

function decodeCursor(value: unknown): ClientProjectionCursor {
  const object = exactObject(value, ["entityId", "operationId"], ["sortNumber", "sortText"]);
  if (
    !isEntityId(object.entityId) ||
    !isOperationId(object.operationId) ||
    (object.sortNumber !== undefined && !Number.isSafeInteger(object.sortNumber)) ||
    (object.sortText !== undefined && typeof object.sortText !== "string") ||
    (object.sortNumber === undefined) === (object.sortText === undefined)
  ) {
    throw contractError("invalid client projection cursor");
  }
  return {
    entityId: object.entityId,
    operationId: object.operationId,
    ...(object.sortNumber === undefined ? {} : { sortNumber: object.sortNumber as number }),
    ...(object.sortText === undefined ? {} : { sortText: object.sortText as string }),
  };
}

function decodeStats(value: unknown): ClientStats {
  const object = exactObject(value, [
    "records",
    "events",
    "tags",
    "profiles",
    "mediaFiles",
    "mediaBytes",
  ]);
  for (const key of Object.keys(object)) {
    if (!isNonnegativeInteger(object[key])) throw contractError(`invalid statistic ${key}`);
  }
  return object as unknown as ClientStats;
}

function decodeStoredOperation(value: unknown): StoredOperation {
  const object = exactObject(value, ["localSequence", "receivedAtUnixMs", "operation"]);
  if (!isPositiveInteger(object.localSequence) || !isNonnegativeInteger(object.receivedAtUnixMs)) {
    throw contractError("invalid stored operation receipt");
  }
  return {
    localSequence: object.localSequence,
    receivedAtUnixMs: object.receivedAtUnixMs,
    operation: decodeSignedOperation(object.operation),
  };
}

function decodeSignedOperation(value: unknown): SignedOperation {
  const object = exactObject(value, [
    "protocolVersion",
    "operationId",
    "spaceId",
    "actorId",
    "entityId",
    "schema",
    "causalParents",
    "authorization",
    "occurredAtUnixMs",
    "nonce",
    "body",
    "coseSign1",
  ]);
  if (
    object.protocolVersion !== 1 ||
    !isOperationId(object.operationId) ||
    !isSpaceId(object.spaceId) ||
    !isActorId(object.actorId) ||
    !isEntityId(object.entityId) ||
    !isEntitySchema(object.schema) ||
    !isIdArray(object.causalParents) ||
    !isIdArray(object.authorization) ||
    !isNonnegativeInteger(object.occurredAtUnixMs) ||
    typeof object.nonce !== "string" ||
    !/^[0-9a-f]{32}$/.test(object.nonce) ||
    !isRecord(object.body) ||
    typeof object.coseSign1 !== "string" ||
    !/^[A-Za-z0-9_-]+$/.test(object.coseSign1)
  ) {
    throw contractError("invalid signed operation projection");
  }
  return object as unknown as SignedOperation;
}

function decodeError(status: number, value: unknown): NodeApiError {
  try {
    const object = exactObject(value, ["type", "title", "status", "code"], ["detail", "instance"]);
    if (
      typeof object.type !== "string" ||
      typeof object.title !== "string" ||
      object.status !== status ||
      typeof object.code !== "string" ||
      (object.detail !== undefined && typeof object.detail !== "string") ||
      (object.instance !== undefined && typeof object.instance !== "string")
    ) {
      throw new Error("invalid problem");
    }
    const problem = object as unknown as Problem;
    return new NodeApiError(status, problem.code, problem.detail ?? problem.title, problem);
  } catch {
    return new NodeApiError(status, "invalid_problem_response", `Fractonica node returned HTTP ${status}`);
  }
}

function exactObject(
  value: unknown,
  required: readonly string[],
  optional: readonly string[] = [],
): Record<string, unknown> {
  if (!isRecord(value)) throw contractError("expected object");
  const allowed = new Set([...required, ...optional]);
  if (!required.every((key) => Object.hasOwn(value, key)) || Object.keys(value).some((key) => !allowed.has(key))) {
    throw contractError("object fields do not match the contract");
  }
  return value;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isNonnegativeInteger(value: unknown): value is number {
  return Number.isSafeInteger(value) && (value as number) >= 0;
}

function isPositiveInteger(value: unknown): value is number {
  return Number.isSafeInteger(value) && (value as number) > 0;
}

function isOptionalNonnegativeInteger(value: unknown): boolean {
  return value === undefined || isNonnegativeInteger(value);
}

function isSpaceId(value: unknown): value is SpaceId {
  return typeof value === "string" && /^space:[0-9a-f]{64}$/.test(value) && !/^space:0{64}$/.test(value);
}

function isActorId(value: unknown): value is `actor:ed25519:${string}` {
  return typeof value === "string" && /^actor:ed25519:[0-9a-f]{64}$/.test(value);
}

function isOperationId(value: unknown): value is OperationId {
  return typeof value === "string" && /^sha-256:[0-9a-f]{64}$/.test(value);
}

function isEntityId(value: unknown): value is EntityId {
  return (
    typeof value === "string" &&
    /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(value) &&
    value !== "00000000-0000-0000-0000-000000000000"
  );
}

function isEntitySchema(value: unknown): boolean {
  return [
    "record",
    "event",
    "tag",
    "profile",
    "space.genesis",
    "capability.grant",
    "capability.revoke",
  ].includes(value as string);
}

function isIdArray(value: unknown): boolean {
  return Array.isArray(value) && value.every(isOperationId);
}

function path(value: string): string {
  return encodeURIComponent(value);
}

function contractError(detail: string): NodeApiError {
  return new NodeApiError(0, "invalid_contract_response", detail);
}

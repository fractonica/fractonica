export type JsonValue = null | boolean | number | string | JsonValue[] | JsonObject;
export interface JsonObject {
  [key: string]: JsonValue;
}

export interface ResourceReference {
  contentId: string;
  byteLength: number;
  mediaType: string;
  role: string;
  originalName?: string;
}

export type ReferenceTarget =
  | { kind: "actor"; actorId: string }
  | { kind: "entity"; spaceId: string; entityId: string; operationId?: string };

export interface EntityReference {
  relation: string;
  target: ReferenceTarget;
}

export interface RecordDocument {
  startAtUnixMs: number;
  endAtUnixMs?: number;
  emoji?: string;
  text?: string;
  metadata: JsonObject;
  resources: ResourceReference[];
  references: EntityReference[];
}

export interface PublicRecordPayload {
  visibility: "public";
  document: RecordDocument;
}

export interface ClientRecord {
  operationId: string;
  entityId: string;
  schema: "record";
  visibility: "public" | "private";
  conflicted: boolean;
  tombstone: false;
  startAtUnixMs?: number;
  endAtUnixMs?: number;
  sortText?: string;
  resourceCount: number;
  mediaBytes: number;
  document?: RecordDocument;
}

export interface ClientStatus {
  phase: "starting" | "ready" | "failed";
  nodeId?: string;
  actorId?: string;
  spaceId?: string;
  syncRunning: boolean;
  cycle: number;
  pendingOperations: number;
  rejectedOperations: number;
  waitingUploads: number;
  pendingUploads: number;
  pendingDownloads: number;
  rejectedResources: number;
  synchronizedBytes: number;
  totalBytes: number;
  lastError?: string;
}

export interface CommitResult {
  localSequence: number;
  operationId: string;
  replayed: boolean;
  queuedPeers: number;
}

export interface ClientCore {
  status(): Promise<ClientStatus>;
  listRecords(limit?: number): Promise<ClientRecord[]>;
  importAttachments(limit: number): Promise<ResourceReference[]>;
  createRecord(payload: PublicRecordPayload): Promise<CommitResult>;
  updateRecord(entityId: string, payload: PublicRecordPayload): Promise<CommitResult>;
  deleteRecord(entityId: string): Promise<CommitResult>;
}

type Invoke = (command: string, args?: Record<string, unknown>) => Promise<unknown>;

const OPERATION_ID = /^sha-256:[0-9a-f]{64}$/;
const ENTITY_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const NODE_ID = /^node:ed25519:[0-9a-f]{64}$/;
const ACTOR_ID = /^actor:ed25519:[0-9a-f]{64}$/;
const SPACE_ID = /^space:[0-9a-f]{64}$/;
const CONTENT_ID = /^sha-256:[0-9a-f]{64}$/;

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function hasOnlyKeys(
  value: Record<string, unknown>,
  required: readonly string[],
  optional: readonly string[],
): boolean {
  const keys = Object.keys(value);
  return required.every((key) => Object.hasOwn(value, key)) &&
    keys.every((key) => required.includes(key) || optional.includes(key));
}

function isCount(value: unknown): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 0;
}

function isUnixMillis(value: unknown): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 0;
}

function isJsonValue(value: unknown, depth = 0): value is JsonValue {
  if (depth > 12) return false;
  if (value === null || typeof value === "boolean" || typeof value === "string") return true;
  if (typeof value === "number") return Number.isFinite(value);
  if (Array.isArray(value)) return value.every((item) => isJsonValue(item, depth + 1));
  return isObject(value) && Object.values(value).every((item) => isJsonValue(item, depth + 1));
}

function decodeResource(value: unknown): ResourceReference {
  if (
    !isObject(value) ||
    !hasOnlyKeys(value, ["contentId", "byteLength", "mediaType", "role"], ["originalName"]) ||
    typeof value.contentId !== "string" ||
    !CONTENT_ID.test(value.contentId) ||
    !isCount(value.byteLength) ||
    typeof value.mediaType !== "string" ||
    typeof value.role !== "string" ||
    (value.originalName !== undefined && typeof value.originalName !== "string")
  ) {
    throw new Error("A local record resource did not match the expected schema.");
  }
  return value as unknown as ResourceReference;
}

function decodeImportedAttachments(value: unknown): ResourceReference[] {
  if (!Array.isArray(value) || value.length > 64) {
    throw new Error("The imported attachment list did not match the expected schema.");
  }
  const resources = value.map(decodeResource);
  if (resources.some((resource) => resource.role !== "record.media")) {
    throw new Error("The imported attachment list did not match the expected schema.");
  }
  return resources;
}

function decodeReference(value: unknown): EntityReference {
  if (
    !isObject(value) ||
    !hasOnlyKeys(value, ["relation", "target"], []) ||
    typeof value.relation !== "string" ||
    !isObject(value.target)
  ) {
    throw new Error("A local record reference did not match the expected schema.");
  }
  const target = value.target;
  const actor =
    hasOnlyKeys(target, ["kind", "actorId"], []) &&
    target.kind === "actor" &&
    typeof target.actorId === "string" &&
    ACTOR_ID.test(target.actorId);
  const entity =
    hasOnlyKeys(target, ["kind", "spaceId", "entityId"], ["operationId"]) &&
    target.kind === "entity" &&
    typeof target.spaceId === "string" &&
    SPACE_ID.test(target.spaceId) &&
    typeof target.entityId === "string" &&
    ENTITY_ID.test(target.entityId) &&
    (target.operationId === undefined ||
      (typeof target.operationId === "string" && OPERATION_ID.test(target.operationId)));
  if (!actor && !entity) {
    throw new Error("A local record reference did not match the expected schema.");
  }
  return value as unknown as EntityReference;
}

function decodeDocument(value: unknown): RecordDocument {
  if (
    !isObject(value) ||
    !hasOnlyKeys(
      value,
      ["startAtUnixMs", "metadata"],
      ["endAtUnixMs", "emoji", "text", "resources", "references"],
    ) ||
    !isUnixMillis(value.startAtUnixMs) ||
    (value.endAtUnixMs !== undefined && !isUnixMillis(value.endAtUnixMs)) ||
    (typeof value.endAtUnixMs === "number" && value.endAtUnixMs < value.startAtUnixMs) ||
    (value.emoji !== undefined && typeof value.emoji !== "string") ||
    (value.text !== undefined && typeof value.text !== "string") ||
    !isObject(value.metadata) ||
    !isJsonValue(value.metadata) ||
    (value.resources !== undefined && !Array.isArray(value.resources)) ||
    (value.references !== undefined && !Array.isArray(value.references))
  ) {
    throw new Error("A local record document did not match the expected schema.");
  }
  return {
    startAtUnixMs: value.startAtUnixMs,
    ...(value.endAtUnixMs === undefined ? {} : { endAtUnixMs: value.endAtUnixMs }),
    ...(value.emoji === undefined ? {} : { emoji: value.emoji }),
    ...(value.text === undefined ? {} : { text: value.text }),
    metadata: value.metadata,
    resources: (value.resources ?? []).map(decodeResource),
    references: (value.references ?? []).map(decodeReference),
  };
}

function decodeStatus(value: unknown): ClientStatus {
  const required = [
    "phase",
    "syncRunning",
    "cycle",
    "pendingOperations",
    "rejectedOperations",
    "waitingUploads",
    "pendingUploads",
    "pendingDownloads",
    "rejectedResources",
    "synchronizedBytes",
    "totalBytes",
  ] as const;
  if (
    !isObject(value) ||
    !hasOnlyKeys(value, required, ["nodeId", "actorId", "spaceId", "lastError"]) ||
    !["starting", "ready", "failed"].includes(String(value.phase)) ||
    typeof value.syncRunning !== "boolean" ||
    !required.slice(2).every((key) => isCount(value[key])) ||
    (value.nodeId !== undefined && (typeof value.nodeId !== "string" || !NODE_ID.test(value.nodeId))) ||
    (value.actorId !== undefined &&
      (typeof value.actorId !== "string" || !ACTOR_ID.test(value.actorId))) ||
    (value.spaceId !== undefined &&
      (typeof value.spaceId !== "string" || !SPACE_ID.test(value.spaceId))) ||
    (value.lastError !== undefined && typeof value.lastError !== "string")
  ) {
    throw new Error("The native client status did not match the expected schema.");
  }
  return value as unknown as ClientStatus;
}

function decodeCommit(value: unknown): CommitResult {
  if (
    !isObject(value) ||
    !hasOnlyKeys(value, ["localSequence", "operationId", "replayed", "queuedPeers"], []) ||
    !isCount(value.localSequence) ||
    typeof value.operationId !== "string" ||
    !OPERATION_ID.test(value.operationId) ||
    typeof value.replayed !== "boolean" ||
    !isCount(value.queuedPeers)
  ) {
    throw new Error("The native client commit did not match the expected schema.");
  }
  return value as unknown as CommitResult;
}

function decodeRecord(value: unknown): ClientRecord {
  if (
    !isObject(value) ||
    !hasOnlyKeys(
      value,
      [
        "operationId",
        "entityId",
        "schema",
        "visibility",
        "conflicted",
        "tombstone",
        "resourceCount",
        "mediaBytes",
      ],
      ["startAtUnixMs", "endAtUnixMs", "sortText", "document"],
    ) ||
    typeof value.operationId !== "string" ||
    !OPERATION_ID.test(value.operationId) ||
    typeof value.entityId !== "string" ||
    !ENTITY_ID.test(value.entityId) ||
    value.schema !== "record" ||
    !["public", "private"].includes(String(value.visibility)) ||
    typeof value.conflicted !== "boolean" ||
    value.tombstone !== false ||
    (value.startAtUnixMs !== undefined && !isUnixMillis(value.startAtUnixMs)) ||
    (value.endAtUnixMs !== undefined && !isUnixMillis(value.endAtUnixMs)) ||
    (value.sortText !== undefined && typeof value.sortText !== "string") ||
    !isCount(value.resourceCount) ||
    !isCount(value.mediaBytes)
  ) {
    throw new Error("A local record summary did not match the expected schema.");
  }
  if (value.visibility === "public" && value.document === undefined) {
    throw new Error("A public local record omitted its document.");
  }
  if (value.visibility === "private" && value.document !== undefined) {
    throw new Error("A private local record exposed its encrypted document.");
  }
  return {
    ...(value as unknown as Omit<ClientRecord, "document">),
    ...(value.document === undefined ? {} : { document: decodeDocument(value.document) }),
  };
}

export function isDesktopRuntime(): boolean {
  return typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;
}

export function createClientCore(invoke: Invoke): ClientCore {
  return {
    status: async () => decodeStatus(await invoke("client_status")),
    listRecords: async (limit = 200) => {
      if (!Number.isSafeInteger(limit) || limit < 1 || limit > 200) {
        throw new Error("Record list limit must be between 1 and 200.");
      }
      const value = await invoke("client_list_records", { limit });
      if (!Array.isArray(value) || value.length > limit) {
        throw new Error("The native record list did not match the expected schema.");
      }
      return value.map(decodeRecord);
    },
    importAttachments: async (limit) => {
      if (!Number.isSafeInteger(limit) || limit < 1 || limit > 64) {
        throw new Error("Attachment import limit must be between 1 and 64.");
      }
      return decodeImportedAttachments(
        await invoke("client_import_attachments", { limit }),
      );
    },
    createRecord: async (payload) =>
      decodeCommit(await invoke("client_create_record", { payload })),
    updateRecord: async (entityId, payload) => {
      if (!ENTITY_ID.test(entityId)) throw new Error("The record entity ID is invalid.");
      return decodeCommit(await invoke("client_update_record", { entityId, payload }));
    },
    deleteRecord: async (entityId) => {
      if (!ENTITY_ID.test(entityId)) throw new Error("The record entity ID is invalid.");
      return decodeCommit(
        await invoke("client_delete", { entityId, schema: "record" }),
      );
    },
  };
}

export function createRuntimeClientCore(): ClientCore | null {
  if (!isDesktopRuntime()) return null;
  return createClientCore(async (command, args) => {
    const { invoke } = await import("@tauri-apps/api/core");
    return invoke(command, args);
  });
}

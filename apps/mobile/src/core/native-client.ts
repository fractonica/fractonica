import type {
  ClientRecordDetail,
  ClientRecordPreview,
  ClientStatus,
  CommitResult,
  EntityReference,
  JsonValue,
  PairingClaim,
  PublicRecordPayload,
  RecordDocument,
  ResourceReference,
} from "./contracts";

export const MAX_RECORD_PAGE_SIZE = 200;
export const MAX_RECORD_PREVIEW_EMOJI_BYTES = 128;
export const MAX_RECORD_PREVIEW_TEXT_BYTES = 768;
export const MAX_RECORD_PREVIEW_SORT_TEXT_BYTES = 512;
export const MAX_RECORD_PREVIEW_PAGE_BYTES = 64 * 1_024;
export const MAX_RECORD_DETAIL_JSON_BYTES = 2 * 1_024 * 1_024;
export const MAX_RECORD_JSON_BYTES = 2 * 1_024 * 1_024;
const MAX_EMOJI_SCALARS = 32;
const MAX_TEXT_SCALARS = 262_144;
const MAX_METADATA_ENTRIES = 128;
const MAX_METADATA_KEY_SCALARS = 128;
const MAX_METADATA_JSON_BYTES = 65_536;
const MAX_METADATA_DEPTH = 16;
const MAX_METADATA_CONTAINER_ITEMS = 256;
const MAX_METADATA_STRING_SCALARS = 16_384;
const MAX_RECORD_RESOURCES = 64;
const MAX_ENTITY_REFERENCES = 256;
const MAX_CONTENT_BYTES = 1_099_511_627_776;
export const RECOVERY_REQUIRED_ERROR_CODE = "ERR_FRACTONICA_RECOVERY_REQUIRED";
const RESET_LOCAL_INSTALLATION_CONFIRMATION = "RESET_LOCAL_INSTALLATION";

export interface LocalInstallationResetConfirmation {
  readonly confirmed: true;
}

export interface NativeClientPort {
  status(): Promise<ClientStatus>;
  listRecords(limit?: number): Promise<ClientRecordPreview[]>;
  getRecord(operationId: string, entityId: string): Promise<ClientRecordDetail | undefined>;
  createRecord(payload: PublicRecordPayload): Promise<CommitResult>;
  claimPairingInvitation(qr: string): Promise<PairingClaim>;
  acceptPairingInvitation(invitationId: string): Promise<PairingClaim>;
  resetLocalInstallation(confirmation: LocalInstallationResetConfirmation): Promise<void>;
}

/** Shape implemented by the future Rust-backed Expo native module. */
export interface NativeClientBridge {
  clientStatus(): Promise<unknown>;
  clientListRecords(options: { limit: number }): Promise<unknown>;
  clientGetRecord(options: { operationId: string; entityId: string }): Promise<unknown>;
  clientCreateRecord(options: { payload: PublicRecordPayload }): Promise<unknown>;
  clientClaimPairingInvitation(options: { qr: string }): Promise<unknown>;
  clientAcceptPairingInvitation(options: { invitationId: string }): Promise<unknown>;
  clientResetLocalInstallation(options: { confirmation: string }): Promise<unknown>;
}

export class NativeContractError extends Error {
  override readonly name = "NativeContractError";
}

const OPERATION_ID = /^sha-256:[0-9a-f]{64}$/;
const ENTITY_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const NODE_ID = /^node:ed25519:[0-9a-f]{64}$/;
const ACTOR_ID = /^actor:ed25519:[0-9a-f]{64}$/;
const SPACE_ID = /^space:[0-9a-f]{64}$/;
const CONTENT_ID = /^sha-256:[0-9a-f]{64}$/;
const INVITATION_ID = /^[0-9a-f]{32}$/;
const CONFIRMATION_OCTAL = /^[0-7]{10}$/;
const PAIRING_QR = /^fractonica-pairing:v1:[A-Za-z0-9_-]+$/;

function contractError(message: string): never {
  throw new NativeContractError(message);
}

export function isRecoveryRequiredError(reason: unknown): boolean {
  let candidate: unknown = reason;
  for (let depth = 0; depth < 3; depth += 1) {
    if (!isObject(candidate)) return false;
    if (candidate.code === RECOVERY_REQUIRED_ERROR_CODE) return true;
    candidate = candidate.cause;
  }
  return false;
}

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function hasOnlyKeys(
  value: Record<string, unknown>,
  required: readonly string[],
  optional: readonly string[],
): boolean {
  const keys = Object.keys(value);
  return (
    required.every((key) => Object.hasOwn(value, key)) &&
    keys.every((key) => required.includes(key) || optional.includes(key))
  );
}

function isCount(value: unknown): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 0;
}

function isUnixMillis(value: unknown): value is number {
  return isCount(value);
}

function utf8ByteLength(value: string): number {
  let bytes = 0;
  for (const scalar of value) {
    const codePoint = scalar.codePointAt(0);
    if (codePoint === undefined) continue;
    bytes += codePoint <= 0x7f ? 1 : codePoint <= 0x7ff ? 2 : codePoint <= 0xffff ? 3 : 4;
  }
  return bytes;
}

function scalarCountAtMost(value: string, maximum: number): boolean {
  let count = 0;
  for (const _scalar of value) {
    count += 1;
    if (count > maximum) return false;
  }
  return true;
}

function hasControlScalar(value: string): boolean {
  for (const scalar of value) {
    const codePoint = scalar.codePointAt(0) ?? 0;
    if ((codePoint >= 0 && codePoint <= 0x1f) || (codePoint >= 0x7f && codePoint <= 0x9f)) {
      return true;
    }
  }
  return false;
}

function isMetadataValue(value: unknown, depth = 1): value is JsonValue {
  if (value === null || typeof value === "boolean") return true;
  if (typeof value === "number") {
    return Number.isFinite(value) && (!Number.isInteger(value) || Number.isSafeInteger(value));
  }
  if (typeof value === "string") return scalarCountAtMost(value, MAX_METADATA_STRING_SCALARS);
  if (depth > MAX_METADATA_DEPTH) return false;
  if (Array.isArray(value)) {
    return (
      value.length <= MAX_METADATA_CONTAINER_ITEMS &&
      value.every((item) => isMetadataValue(item, depth + 1))
    );
  }
  return (
    isObject(value) &&
    Object.keys(value).length <= MAX_METADATA_CONTAINER_ITEMS &&
    Object.entries(value).every(
      ([key, item]) =>
        key.length > 0 &&
        scalarCountAtMost(key, MAX_METADATA_KEY_SCALARS) &&
        !hasControlScalar(key) &&
        isMetadataValue(item, depth + 1),
    )
  );
}

function decodeResource(value: unknown): ResourceReference {
  if (
    !isObject(value) ||
    !hasOnlyKeys(value, ["contentId", "byteLength", "mediaType", "role"], ["originalName"]) ||
    typeof value.contentId !== "string" ||
    !CONTENT_ID.test(value.contentId) ||
    !isCount(value.byteLength) ||
    value.byteLength > MAX_CONTENT_BYTES ||
    typeof value.mediaType !== "string" ||
    value.mediaType.length === 0 ||
    utf8ByteLength(value.mediaType) > 127 ||
    typeof value.role !== "string" ||
    value.role.length === 0 ||
    utf8ByteLength(value.role) > 64 ||
    (value.originalName !== undefined &&
      (typeof value.originalName !== "string" ||
        !scalarCountAtMost(value.originalName, 255)))
  ) {
    contractError("A native record resource did not match the expected schema.");
  }
  return value as unknown as ResourceReference;
}

function decodeReference(value: unknown): EntityReference {
  if (
    !isObject(value) ||
    !hasOnlyKeys(value, ["relation", "target"], []) ||
    typeof value.relation !== "string" ||
    value.relation.length === 0 ||
    utf8ByteLength(value.relation) > 64 ||
    !/^[a-z0-9._-]+$/.test(value.relation) ||
    !isObject(value.target)
  ) {
    contractError("A native record reference did not match the expected schema.");
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
    contractError("A native record reference did not match the expected schema.");
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
    (value.emoji !== undefined &&
      (typeof value.emoji !== "string" || !scalarCountAtMost(value.emoji, MAX_EMOJI_SCALARS))) ||
    (value.text !== undefined &&
      (typeof value.text !== "string" || !scalarCountAtMost(value.text, MAX_TEXT_SCALARS))) ||
    !isObject(value.metadata) ||
    Object.keys(value.metadata).length > MAX_METADATA_ENTRIES ||
    !isMetadataValue(value.metadata) ||
    utf8ByteLength(JSON.stringify(value.metadata)) > MAX_METADATA_JSON_BYTES ||
    (value.resources !== undefined &&
      (!Array.isArray(value.resources) || value.resources.length > MAX_RECORD_RESOURCES)) ||
    (value.references !== undefined &&
      (!Array.isArray(value.references) || value.references.length > MAX_ENTITY_REFERENCES))
  ) {
    contractError("A native record document did not match the expected schema.");
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
    (value.nodeId !== undefined &&
      (typeof value.nodeId !== "string" || !NODE_ID.test(value.nodeId))) ||
    (value.actorId !== undefined &&
      (typeof value.actorId !== "string" || !ACTOR_ID.test(value.actorId))) ||
    (value.spaceId !== undefined &&
      (typeof value.spaceId !== "string" || !SPACE_ID.test(value.spaceId))) ||
    (value.lastError !== undefined && typeof value.lastError !== "string")
  ) {
    contractError("The native client status did not match the expected schema.");
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
    contractError("The native record commit did not match the expected schema.");
  }
  return value as unknown as CommitResult;
}

function decodePairingClaim(value: unknown): PairingClaim {
  if (
    !isObject(value) ||
    !hasOnlyKeys(
      value,
      [
        "invitationId",
        "responderNodeId",
        "spaceId",
        "endpoint",
        "confirmationOctal",
        "grantOperationId",
      ],
      [],
    ) ||
    typeof value.invitationId !== "string" ||
    !INVITATION_ID.test(value.invitationId) ||
    typeof value.responderNodeId !== "string" ||
    !NODE_ID.test(value.responderNodeId) ||
    typeof value.spaceId !== "string" ||
    !SPACE_ID.test(value.spaceId) ||
    typeof value.endpoint !== "string" ||
    !isPrivatePairingEndpoint(value.endpoint) ||
    typeof value.confirmationOctal !== "string" ||
    !CONFIRMATION_OCTAL.test(value.confirmationOctal) ||
    typeof value.grantOperationId !== "string" ||
    !OPERATION_ID.test(value.grantOperationId)
  ) {
    contractError("The native pairing claim did not match the expected schema.");
  }
  return value as unknown as PairingClaim;
}

function isPrivatePairingEndpoint(value: string): boolean {
  try {
    const endpoint = new URL(value);
    if (
      endpoint.protocol !== "http:" ||
      endpoint.username ||
      endpoint.password ||
      endpoint.pathname !== "/" ||
      endpoint.search ||
      endpoint.hash ||
      !endpoint.port
    ) {
      return false;
    }
    const port = Number(endpoint.port);
    if (!Number.isSafeInteger(port) || port < 1 || port > 65_535) return false;
    if (["localhost", "[::1]", "::1"].includes(endpoint.hostname)) return true;

    const octets = endpoint.hostname.split(".").map(Number);
    if (
      octets.length !== 4 ||
      octets.some((octet) => !Number.isInteger(octet) || octet < 0 || octet > 255)
    ) {
      return false;
    }
    const first = octets[0]!;
    const second = octets[1]!;
    return (
      first === 127 ||
      first === 10 ||
      (first === 172 && second >= 16 && second <= 31) ||
      (first === 192 && second === 168) ||
      (first === 169 && second === 254)
    );
  } catch {
    return false;
  }
}

function decodeRecordPreview(value: unknown): ClientRecordPreview {
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
        "previewTruncated",
      ],
      ["startAtUnixMs", "endAtUnixMs", "sortText", "emoji", "textPreview"],
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
    (value.sortText !== undefined &&
      (typeof value.sortText !== "string" ||
        utf8ByteLength(value.sortText) > MAX_RECORD_PREVIEW_SORT_TEXT_BYTES)) ||
    (value.emoji !== undefined &&
      (typeof value.emoji !== "string" ||
        utf8ByteLength(value.emoji) > MAX_RECORD_PREVIEW_EMOJI_BYTES)) ||
    (value.textPreview !== undefined &&
      (typeof value.textPreview !== "string" ||
        utf8ByteLength(value.textPreview) > MAX_RECORD_PREVIEW_TEXT_BYTES)) ||
    typeof value.previewTruncated !== "boolean" ||
    (value.previewTruncated && value.textPreview === undefined) ||
    !isCount(value.resourceCount) ||
    !isCount(value.mediaBytes)
  ) {
    contractError("A native record summary did not match the expected schema.");
  }
  if (value.visibility === "private" && (value.emoji !== undefined || value.textPreview !== undefined)) {
    contractError("A private native record exposed a content preview.");
  }

  return value as unknown as ClientRecordPreview;
}

function decodeRecordDetail(value: unknown): ClientRecordDetail {
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
      ["startAtUnixMs", "endAtUnixMs", "sortText", "documentJson"],
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
    !isCount(value.mediaBytes) ||
    (value.documentJson !== undefined &&
      (typeof value.documentJson !== "string" ||
        utf8ByteLength(value.documentJson) > MAX_RECORD_DETAIL_JSON_BYTES))
  ) {
    contractError("A native record detail did not match the expected schema.");
  }
  if (value.visibility === "public" && value.documentJson === undefined) {
    contractError("A public native record detail omitted its document.");
  }
  if (value.visibility === "private" && value.documentJson !== undefined) {
    contractError("A private native record detail exposed its encrypted document.");
  }
  return value as unknown as ClientRecordDetail;
}

function assertPublicPayload(value: PublicRecordPayload): void {
  if (!isObject(value) || !hasOnlyKeys(value, ["visibility", "document"], [])) {
    contractError("The local record draft did not match the expected schema.");
  }
  if (value.visibility !== "public") {
    contractError("The first mobile milestone only creates public records.");
  }
  decodeDocument(value.document);
  const serialized = JSON.stringify(value);
  if (utf8ByteLength(serialized) > MAX_RECORD_JSON_BYTES) {
    contractError("The local record draft exceeded its byte budget.");
  }
}

export function createNativeClientPort(bridge: NativeClientBridge): NativeClientPort {
  return {
    status: async () => decodeStatus(await bridge.clientStatus()),
    listRecords: async (limit = 100) => {
      if (!Number.isSafeInteger(limit) || limit < 1 || limit > MAX_RECORD_PAGE_SIZE) {
        throw new RangeError(`Record list limit must be between 1 and ${MAX_RECORD_PAGE_SIZE}.`);
      }
      const value = await bridge.clientListRecords({ limit });
      if (!Array.isArray(value) || value.length > limit) {
        contractError("The native record list did not match the expected schema.");
      }
      const records = value.map(decodeRecordPreview);
      const pageBytes = records.reduce(
        (total, record) =>
          total +
          256 +
          utf8ByteLength(record.operationId) +
          utf8ByteLength(record.entityId) +
          utf8ByteLength(record.schema) +
          utf8ByteLength(record.visibility) +
          utf8ByteLength(record.sortText ?? "") +
          utf8ByteLength(record.emoji ?? "") +
          utf8ByteLength(record.textPreview ?? ""),
        4,
      );
      if (pageBytes > MAX_RECORD_PREVIEW_PAGE_BYTES) {
        contractError("The native record list exceeded its byte budget.");
      }
      return records;
    },
    getRecord: async (operationId, entityId) => {
      if (!OPERATION_ID.test(operationId) || !ENTITY_ID.test(entityId)) {
        throw new RangeError("Record lookup requires canonical operation and entity identifiers.");
      }
      const value = await bridge.clientGetRecord({ operationId, entityId });
      return value === null || value === undefined ? undefined : decodeRecordDetail(value);
    },
    createRecord: async (payload) => {
      assertPublicPayload(payload);
      return decodeCommit(await bridge.clientCreateRecord({ payload }));
    },
    claimPairingInvitation: async (qr) => {
      if (!PAIRING_QR.test(qr) || utf8ByteLength(qr) > 8 * 1_024) {
        contractError("Pairing requires a bounded Fractonica version 1 invitation.");
      }
      return decodePairingClaim(await bridge.clientClaimPairingInvitation({ qr }));
    },
    acceptPairingInvitation: async (invitationId) => {
      if (!INVITATION_ID.test(invitationId)) {
        contractError("Pairing acceptance requires a canonical invitation identifier.");
      }
      return decodePairingClaim(
        await bridge.clientAcceptPairingInvitation({ invitationId }),
      );
    },
    resetLocalInstallation: async (confirmation) => {
      if (
        !isObject(confirmation) ||
        !hasOnlyKeys(confirmation, ["confirmed"], []) ||
        confirmation.confirmed !== true
      ) {
        contractError("Resetting the local installation requires explicit confirmation.");
      }
      await bridge.clientResetLocalInstallation({
        confirmation: RESET_LOCAL_INSTALLATION_CONFIRMATION,
      });
    },
  };
}

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

export interface ClientRecordPreview {
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
  emoji?: string;
  textPreview?: string;
  previewTruncated: boolean;
}

/**
 * Exact record-head response. `documentJson` intentionally stays opaque so
 * canonical metadata integers outside JavaScript's safe range are not rounded
 * by a native or JS JSON parser.
 */
export interface ClientRecordDetail {
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
  documentJson?: string;
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

export interface PairingClaim {
  invitationId: string;
  responderNodeId: string;
  spaceId: string;
  endpoint: string;
  confirmationOctal: string;
  grantOperationId: string;
}

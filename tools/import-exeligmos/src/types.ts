export type JsonObject = Record<string, unknown>;

export interface ExeligmosCursorPage<T> {
  readonly data: readonly T[];
  readonly nextCursor?: string;
  readonly hasMore: boolean;
}

export interface ExeligmosTag {
  readonly id: string;
  readonly userId: string;
  readonly name: string;
  readonly color?: string;
  readonly emoji?: string;
  readonly sortOrder: number;
  readonly metadata: JsonObject;
  readonly revision: number;
  readonly createdAt: string;
  readonly updatedAt: string;
}

export interface ExeligmosMediaEncryption {
  readonly algorithm: "A256GCM";
  readonly cryptoVersion: 1;
  readonly keyVersion: 1;
  readonly nonce: string;
  readonly plaintextContentType?: string;
}

export interface ExeligmosMedia {
  readonly id: string;
  readonly userId: string;
  readonly deviceId: string;
  readonly fileName: string;
  readonly contentType: string;
  readonly byteLength: number;
  readonly sha256: string;
  readonly encryption?: ExeligmosMediaEncryption;
  readonly revision: number;
  readonly createdAt: string;
  readonly contentUrl: string;
  readonly publicContentUrl?: string;
}

export interface ExeligmosReference {
  readonly relation: string;
  readonly targetType: "user" | "record" | "event";
  readonly targetUserId: string;
  readonly targetId: string;
}

export interface ExeligmosRecordCommon {
  readonly id: string;
  readonly originId: string;
  readonly userId: string;
  readonly deviceId: string;
  readonly revision: number;
  readonly createdAt: string;
  readonly updatedAt: string;
  readonly references: readonly ExeligmosReference[];
  readonly media: readonly ExeligmosMedia[];
}

export interface ExeligmosPublicRecord extends ExeligmosRecordCommon {
  readonly visibility: "public";
  readonly occurredAt: string;
  readonly endedAt?: string;
  readonly payload: JsonObject;
  readonly tagIds: readonly string[];
  readonly tags: readonly {
    readonly id: string;
    readonly name: string;
    readonly color?: string;
    readonly emoji?: string;
  }[];
  readonly metadata: JsonObject;
  readonly source?: JsonObject;
  readonly template?: JsonObject;
}

export interface ExeligmosPrivateRecord extends ExeligmosRecordCommon {
  readonly visibility: "private";
  readonly encryption: {
    readonly algorithm: "A256GCM";
    readonly cryptoVersion: 1;
    readonly keyVersion: 1;
    readonly nonce: string;
    readonly ciphertext: string;
    readonly contentType: "application/vnd.exeligmos.record+json";
  };
}

export type ExeligmosRecord = ExeligmosPublicRecord | ExeligmosPrivateRecord;

export interface ResourceRef {
  readonly contentId: `sha-256:${string}`;
  readonly byteLength: number;
  readonly mediaType: string;
  readonly role: string;
  readonly originalName?: string;
}

export interface FractonicaRecordDocument {
  readonly startAtUnixMs: number;
  readonly endAtUnixMs?: number;
  readonly visibility: "public" | "private";
  readonly emoji?: string;
  readonly text?: string;
  readonly metadata?: JsonObject;
  readonly resources: readonly ResourceRef[];
}

export interface OperationSubmission {
  readonly protocolVersion: 1;
  readonly operationId: string;
  readonly entityId: string;
  readonly schema: "record.v1";
  readonly causalParents: readonly string[];
  readonly occurredAtUnixMs: number;
  readonly body: {
    readonly kind: "put";
    readonly document: FractonicaRecordDocument;
  };
}

export interface StoredOperation {
  readonly localSequence: number;
  readonly operation: OperationSubmission & { readonly actorId: string };
}

export interface OperationPage {
  readonly operations: readonly StoredOperation[];
  readonly nextAfter: number;
  readonly hasMore: boolean;
}

export interface EntityState {
  readonly entityId: string;
  readonly schema: "record.v1";
  readonly operationCount: number;
  readonly conflicted: boolean;
  readonly heads: readonly StoredOperation[];
}

export interface ContentDescriptor {
  readonly contentId: `sha-256:${string}`;
  readonly byteLength: number;
}

export interface BlobAvailability {
  readonly available: readonly ContentDescriptor[];
  readonly missing: readonly `sha-256:${string}`[];
}

export interface MediaCheckpoint {
  readonly sourceMediaId: string;
  readonly sha256: string;
  readonly byteLength: number;
  readonly contentId: `sha-256:${string}`;
  uploadUrl?: string;
  uploadOffset: number;
  completed: boolean;
  verified: boolean;
}

export interface RecordCheckpoint {
  readonly sourceRecordId: string;
  readonly sourceOriginId: string;
  readonly sourceRevision: number;
  readonly entityId: string;
  readonly operationId: string;
  status: "planned" | "imported" | "verified" | "skipped";
  causalParents?: string[];
  destinationLocalSequence?: number;
  mediaIds: string[];
  warning?: string;
}

export interface ImportCheckpoint {
  readonly version: 1;
  readonly mappingVersion: "exeligmos-record-v1";
  readonly sourceBaseUrl: string;
  readonly destinationBaseUrl: string;
  recordsCursor?: string;
  recordsComplete: boolean;
  readonly media: Record<string, MediaCheckpoint>;
  readonly records: Record<string, RecordCheckpoint>;
  updatedAt: string;
}

export interface ImportSummary {
  tags: number;
  recordsSeen: number;
  recordsImported: number;
  recordsReplayed: number;
  recordsSkipped: number;
  publicRecords: number;
  privateRecords: number;
  mediaObjects: number;
  mediaBytes: number;
  mediaUploaded: number;
  mediaAlreadyAvailable: number;
  verifiedRecords: number;
  warnings: string[];
}

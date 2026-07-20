export type SpaceId = `space:${string}`;
export type ActorId = `actor:ed25519:${string}`;
export type OperationId = `sha-256:${string}`;
export type ContentId = `sha-256:${string}`;
export type EntityId = string;

export type EntitySchema =
  | "record"
  | "event"
  | "tag"
  | "profile"
  | "space.genesis"
  | "capability.grant"
  | "capability.revoke";
export type ClientEntitySchema = Extract<EntitySchema, "record" | "event" | "tag" | "profile">;
export type Visibility = "public" | "private";
export type Metadata = Record<string, unknown>;

export interface ResourceRef {
  contentId: ContentId;
  byteLength: number;
  mediaType: string;
  role: string;
  originalName?: string;
}

export type ReferenceTarget =
  | { kind: "actor"; actorId: ActorId }
  | {
      kind: "entity";
      spaceId: SpaceId;
      entityId: EntityId;
      operationId?: OperationId;
    };

export interface EntityReference {
  relation: string;
  target: ReferenceTarget;
}

export interface EncryptedPayload {
  algorithm: "aes-256-gcm";
  keyId: `key:aes256:${string}`;
  nonceBase64url: string;
  ciphertextBase64url: string;
}

export type ProtectedDocument<T> =
  | { visibility: "public"; document: T }
  | { visibility: "private"; envelope: EncryptedPayload; resources?: ResourceRef[] };

export interface RecordDocument {
  startAtUnixMs: number;
  endAtUnixMs?: number;
  emoji?: string;
  text?: string;
  metadata: Metadata;
  resources?: ResourceRef[];
  references?: EntityReference[];
}

export interface EventDocument {
  startAtUnixMs: number;
  endAtUnixMs?: number;
  label: string;
  typeNumber: number;
  metadata: Metadata;
  references?: EntityReference[];
}

export interface TagDocument {
  name: string;
  emoji?: string;
  notes?: string;
  colorHex?: string;
  metadata: Metadata;
  references?: EntityReference[];
}

export interface ProfileDocument {
  handle: string;
  displayName: string;
  sarosAnchor: number;
  avatar?: ResourceRef;
  metadata: Metadata;
}

export type OperationBody =
  | { kind: "putRecord"; payload: ProtectedDocument<RecordDocument> }
  | { kind: "putEvent"; payload: ProtectedDocument<EventDocument> }
  | { kind: "putTag"; payload: ProtectedDocument<TagDocument> }
  | { kind: "putProfile"; document: ProfileDocument }
  | { kind: "tombstone" }
  | { kind: "spaceGenesis"; controller: ActorId }
  | { kind: "capabilityGrant"; grant: Record<string, unknown> }
  | { kind: "capabilityRevoke"; revocation: Record<string, unknown> };

export interface SignedOperation {
  protocolVersion: 1;
  operationId: OperationId;
  spaceId: SpaceId;
  actorId: ActorId;
  entityId: EntityId;
  schema: EntitySchema;
  causalParents: OperationId[];
  authorization: OperationId[];
  occurredAtUnixMs: number;
  nonce: string;
  body: OperationBody;
  coseSign1: string;
}

export interface StoredOperation {
  localSequence: number;
  receivedAtUnixMs: number;
  operation: SignedOperation;
}

export interface ClientProjectionCursor {
  sortNumber?: number;
  sortText?: string;
  entityId: EntityId;
  operationId: OperationId;
}

export interface ClientEntitySummary {
  operation: StoredOperation;
  visibility: Visibility;
  conflicted: boolean;
  startAtUnixMs?: number;
  endAtUnixMs?: number;
  sortText?: string;
  resourceCount: number;
  mediaBytes: number;
}

export interface ClientEntityPage<S extends ClientEntitySchema = ClientEntitySchema> {
  spaceId: SpaceId;
  schema: S;
  items: ClientEntitySummary[];
  nextCursor?: ClientProjectionCursor;
}

export interface ClientStats {
  records: number;
  events: number;
  tags: number;
  profiles: number;
  mediaFiles: number;
  mediaBytes: number;
}

export interface Problem {
  type: string;
  title: string;
  status: number;
  code: string;
  detail?: string;
  instance?: string;
}

export interface PageOptions {
  limit?: number;
  cursor?: ClientProjectionCursor;
  signal?: AbortSignal;
}

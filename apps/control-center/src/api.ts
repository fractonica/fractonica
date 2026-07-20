export const DEFAULT_NODE_URL = "http://127.0.0.1:8789";

export type NodeProfile = "node" | "saros";
export type PairingState =
  | "created"
  | "claimed"
  | "confirmed"
  | "completed"
  | "cancelled"
  | "expired";

export type StorageReadyStatus =
  | { kind: "sqlite"; status: "ready"; schemaVersion: number }
  | { kind: "none"; status: "notConfigured" };

export interface ReadyResponse {
  status: "ready";
  profile: NodeProfile;
  storage: StorageReadyStatus;
}

export interface SpaceDescriptor {
  spaceId: string;
  displayName: string;
  genesisOperationId: string;
  initialGrantOperationId: string;
  controllerActorId: string;
  localWriterActorId: string;
  createdAtUnixMs: number;
}

export interface NodeResponse {
  installationId: string;
  nodeId?: string;
  spaces?: SpaceDescriptor[];
  profile: NodeProfile;
  displayName: string;
  version: string;
  startedAt: string;
  uptimeSeconds: number;
  capabilities: string[];
}

export interface NodeSnapshot {
  readiness: ReadyResponse;
  node: NodeResponse;
}

export interface PairingCapabilityTemplate {
  actions: Array<"appendOperation" | "readSpace" | "writeContent">;
  schemas: Array<"record.v1">;
  recordVisibilities: Array<"public" | "private">;
  contentRoles: string[];
  maxResourceByteLength?: number;
  delegationDepth: number;
  label: string;
}

export interface CreatePairingRequest {
  spaceId: string;
  expiresInMs: number;
  capability: PairingCapabilityTemplate;
}

export interface PairingSession {
  invitationId: string;
  spaceId: string;
  state: PairingState;
  expiresAtUnixMs: number;
  joinerNodeId?: string;
  subjectActorId?: string;
  confirmationOctal?: string;
  grantOperationId?: string;
}

export interface PairingInvitation {
  qr: string;
  session: PairingSession;
}

export interface NodeClient {
  readonly baseUrl: string;
  readStatus(signal?: AbortSignal): Promise<NodeSnapshot>;
  createPairing(request: CreatePairingRequest, signal?: AbortSignal): Promise<PairingInvitation>;
  readPairing(invitationId: string, signal?: AbortSignal): Promise<PairingSession>;
  confirmPairing(
    invitationId: string,
    confirmationOctal: string,
    signal?: AbortSignal,
  ): Promise<PairingSession>;
  cancelPairing(invitationId: string, signal?: AbortSignal): Promise<PairingSession>;
}

interface NodeConnection {
  baseUrl: string;
  bearerToken?: string;
}

type Fetcher = typeof fetch;

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function hasExactKeys(value: Record<string, unknown>, keys: readonly string[]): boolean {
  const actualKeys = Object.keys(value);
  return (
    actualKeys.length === keys.length &&
    keys.every((key) => Object.hasOwn(value, key)) &&
    actualKeys.every((key) => keys.includes(key))
  );
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

function isDateTime(value: unknown): value is string {
  return (
    typeof value === "string" &&
    /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$/.test(value) &&
    Number.isFinite(Date.parse(value))
  );
}

function isSafeNonnegativeInteger(value: unknown): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 0;
}

function isNodeProfile(value: unknown): value is NodeProfile {
  return value === "node" || value === "saros";
}

function isCapabilityList(value: unknown): value is string[] {
  return (
    Array.isArray(value) &&
    value.length <= 64 &&
    value.every(
      (capability) =>
        typeof capability === "string" && capability.length > 0 && capability.length <= 64,
    ) &&
    new Set(value).size === value.length
  );
}

const SPACE_ID = /^space:(?!0{64}$)[0-9a-f]{64}$/;
const NODE_ID = /^node:ed25519:[0-9a-f]{64}$/;
const ACTOR_ID = /^actor:ed25519:[0-9a-f]{64}$/;
const OPERATION_ID = /^sha-256:[0-9a-f]{64}$/;
const INVITATION_ID = /^[0-9a-f]{32}$/;

function decodeReadyResponse(value: unknown): ReadyResponse {
  if (
    !isObject(value) ||
    !hasExactKeys(value, ["status", "profile", "storage"]) ||
    value.status !== "ready" ||
    !isNodeProfile(value.profile) ||
    !isObject(value.storage)
  ) {
    throw new Error("The readiness response did not match the expected schema.");
  }

  if (value.profile === "node") {
    if (
      !hasExactKeys(value.storage, ["kind", "status", "schemaVersion"]) ||
      value.storage.kind !== "sqlite" ||
      value.storage.status !== "ready" ||
      !isSafeNonnegativeInteger(value.storage.schemaVersion)
    ) {
      throw new Error("The readiness response did not match the expected schema.");
    }
    return {
      status: "ready",
      profile: "node",
      storage: { kind: "sqlite", status: "ready", schemaVersion: value.storage.schemaVersion },
    };
  }

  if (
    !hasExactKeys(value.storage, ["kind", "status"]) ||
    value.storage.kind !== "none" ||
    value.storage.status !== "notConfigured"
  ) {
    throw new Error("The readiness response did not match the expected schema.");
  }
  return { status: "ready", profile: "saros", storage: { kind: "none", status: "notConfigured" } };
}

function decodeSpaceDescriptor(value: unknown): SpaceDescriptor {
  if (
    !isObject(value) ||
    !hasExactKeys(value, [
      "spaceId",
      "displayName",
      "genesisOperationId",
      "initialGrantOperationId",
      "controllerActorId",
      "localWriterActorId",
      "createdAtUnixMs",
    ]) ||
    typeof value.spaceId !== "string" ||
    !SPACE_ID.test(value.spaceId) ||
    typeof value.displayName !== "string" ||
    value.displayName.length === 0 ||
    value.displayName.length > 128 ||
    typeof value.genesisOperationId !== "string" ||
    !OPERATION_ID.test(value.genesisOperationId) ||
    typeof value.initialGrantOperationId !== "string" ||
    !OPERATION_ID.test(value.initialGrantOperationId) ||
    typeof value.controllerActorId !== "string" ||
    !ACTOR_ID.test(value.controllerActorId) ||
    typeof value.localWriterActorId !== "string" ||
    !ACTOR_ID.test(value.localWriterActorId) ||
    !isSafeNonnegativeInteger(value.createdAtUnixMs)
  ) {
    throw new Error("The node response did not match the expected schema.");
  }
  return value as unknown as SpaceDescriptor;
}

function decodeNodeResponse(value: unknown): NodeResponse {
  if (!isObject(value) || !isNodeProfile(value.profile)) {
    throw new Error("The node response did not match the expected schema.");
  }
  const common = [
    "installationId",
    "profile",
    "displayName",
    "version",
    "startedAt",
    "uptimeSeconds",
    "capabilities",
  ] as const;
  const expected = value.profile === "node" ? [...common, "nodeId", "spaces"] : common;
  if (
    !hasExactKeys(value, expected) ||
    typeof value.installationId !== "string" ||
    value.installationId.length === 0 ||
    value.installationId.length > 128 ||
    typeof value.displayName !== "string" ||
    value.displayName.length === 0 ||
    value.displayName.length > 128 ||
    typeof value.version !== "string" ||
    value.version.length === 0 ||
    value.version.length > 64 ||
    !isDateTime(value.startedAt) ||
    !isSafeNonnegativeInteger(value.uptimeSeconds) ||
    !isCapabilityList(value.capabilities)
  ) {
    throw new Error("The node response did not match the expected schema.");
  }

  if (value.profile === "node") {
    if (
      typeof value.nodeId !== "string" ||
      !NODE_ID.test(value.nodeId) ||
      !Array.isArray(value.spaces) ||
      value.spaces.length === 0 ||
      value.spaces.length > 64
    ) {
      throw new Error("The node response did not match the expected schema.");
    }
    return {
      installationId: value.installationId,
      nodeId: value.nodeId,
      spaces: value.spaces.map(decodeSpaceDescriptor),
      profile: value.profile,
      displayName: value.displayName,
      version: value.version,
      startedAt: value.startedAt,
      uptimeSeconds: value.uptimeSeconds,
      capabilities: [...value.capabilities],
    };
  }

  return {
    installationId: value.installationId,
    profile: value.profile,
    displayName: value.displayName,
    version: value.version,
    startedAt: value.startedAt,
    uptimeSeconds: value.uptimeSeconds,
    capabilities: [...value.capabilities],
  };
}

function decodePairingSession(value: unknown): PairingSession {
  const required = ["invitationId", "spaceId", "state", "expiresAtUnixMs"] as const;
  const optional = ["joinerNodeId", "subjectActorId", "confirmationOctal", "grantOperationId"] as const;
  if (
    !isObject(value) ||
    !hasOnlyKeys(value, required, optional) ||
    typeof value.invitationId !== "string" ||
    !INVITATION_ID.test(value.invitationId) ||
    typeof value.spaceId !== "string" ||
    !SPACE_ID.test(value.spaceId) ||
    !["created", "claimed", "confirmed", "completed", "cancelled", "expired"].includes(
      String(value.state),
    ) ||
    !isSafeNonnegativeInteger(value.expiresAtUnixMs) ||
    (value.joinerNodeId !== undefined &&
      (typeof value.joinerNodeId !== "string" || !NODE_ID.test(value.joinerNodeId))) ||
    (value.subjectActorId !== undefined &&
      (typeof value.subjectActorId !== "string" || !ACTOR_ID.test(value.subjectActorId))) ||
    (value.confirmationOctal !== undefined &&
      (typeof value.confirmationOctal !== "string" || !/^[0-7]{10}$/.test(value.confirmationOctal))) ||
    (value.grantOperationId !== undefined &&
      (typeof value.grantOperationId !== "string" || !OPERATION_ID.test(value.grantOperationId)))
  ) {
    throw new Error("The pairing response did not match the expected schema.");
  }
  return value as unknown as PairingSession;
}

function decodePairingInvitation(value: unknown): PairingInvitation {
  if (
    !isObject(value) ||
    !hasExactKeys(value, ["qr", "session"]) ||
    typeof value.qr !== "string" ||
    !/^fractonica-pairing:v1:[A-Za-z0-9_-]+$/.test(value.qr)
  ) {
    throw new Error("The pairing response did not match the expected schema.");
  }
  return { qr: value.qr, session: decodePairingSession(value.session) };
}

function endpoint(baseUrl: string, path: string): string {
  return `${baseUrl.replace(/\/+$/, "")}/${path.replace(/^\/+/, "")}`;
}

async function readResponseJson(response: Response): Promise<unknown> {
  if (!response.ok) {
    let detail = `${new URL(response.url || "http://localhost").pathname} returned HTTP ${response.status}.`;
    try {
      const problem = (await response.json()) as unknown;
      if (isObject(problem) && typeof problem.detail === "string" && problem.detail.length <= 512) {
        detail = problem.detail;
      }
    } catch {
      // Keep the bounded status-only fallback for non-JSON failures.
    }
    throw new Error(detail);
  }
  return response.json() as Promise<unknown>;
}

async function requestJson(
  fetcher: Fetcher,
  connection: NodeConnection,
  path: string,
  signal: AbortSignal,
  method = "GET",
  body?: unknown,
): Promise<unknown> {
  const headers: Record<string, string> = { Accept: "application/json" };
  if (connection.bearerToken) headers.Authorization = `Bearer ${connection.bearerToken}`;
  if (body !== undefined) headers["Content-Type"] = "application/json";
  const response = await fetcher(endpoint(connection.baseUrl, path), {
    body: body === undefined ? undefined : JSON.stringify(body),
    cache: "no-store",
    headers,
    method,
    signal,
  });
  return readResponseJson(response);
}

export function resolveNodeBaseUrl(value = import.meta.env.VITE_FRACTONICA_NODE_URL): string {
  const configured = value?.trim() || DEFAULT_NODE_URL;
  const parsed = new URL(configured);
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    throw new Error("VITE_FRACTONICA_NODE_URL must use HTTP or HTTPS.");
  }
  if (parsed.username || parsed.password || parsed.search || parsed.hash) {
    throw new Error("VITE_FRACTONICA_NODE_URL must be a plain HTTP(S) base URL.");
  }
  return parsed.toString().replace(/\/$/, "");
}

export function createNodeClient(
  baseUrl = resolveNodeBaseUrl(),
  fetcher: Fetcher = fetch,
  timeoutMs = 5_000,
  bearerToken?: string,
): NodeClient {
  const resolvedBaseUrl = resolveNodeBaseUrl(baseUrl);
  return createResolvingNodeClient(
    async () => ({ baseUrl: resolvedBaseUrl, bearerToken }),
    resolvedBaseUrl,
    fetcher,
    timeoutMs,
  );
}

export function createRuntimeNodeClient(
  fetcher: Fetcher = fetch,
  timeoutMs = 5_000,
): NodeClient {
  if (!("__TAURI_INTERNALS__" in window)) {
    return createNodeClient(resolveNodeBaseUrl(), fetcher, timeoutMs);
  }
  return createResolvingNodeClient(resolveDesktopNodeConnection, "desktop-managed node", fetcher, timeoutMs);
}

function createResolvingNodeClient(
  resolveConnection: () => Promise<NodeConnection>,
  initialBaseUrl: string,
  fetcher: Fetcher,
  timeoutMs: number,
): NodeClient {
  let currentBaseUrl = initialBaseUrl;

  async function execute<T>(
    operation: (connection: NodeConnection, signal: AbortSignal) => Promise<T>,
    parentSignal?: AbortSignal,
  ): Promise<T> {
    const controller = new AbortController();
    const abortFromParent = () => controller.abort(parentSignal?.reason);
    const timeout = window.setTimeout(
      () => controller.abort(new DOMException("Node request timed out.", "TimeoutError")),
      timeoutMs,
    );
    if (parentSignal?.aborted) abortFromParent();
    else parentSignal?.addEventListener("abort", abortFromParent, { once: true });
    try {
      const connection = await resolveConnection();
      currentBaseUrl = connection.baseUrl;
      return await operation(connection, controller.signal);
    } finally {
      window.clearTimeout(timeout);
      parentSignal?.removeEventListener("abort", abortFromParent);
    }
  }

  return {
    get baseUrl() {
      return currentBaseUrl;
    },
    readStatus: (signal) =>
      execute(async (connection, requestSignal) => {
        const [readinessValue, nodeValue] = await Promise.all([
          requestJson(fetcher, connection, "/health/ready", requestSignal),
          requestJson(fetcher, connection, "/api/v1/node", requestSignal),
        ]);
        const readiness = decodeReadyResponse(readinessValue);
        const node = decodeNodeResponse(nodeValue);
        if (readiness.profile !== node.profile) {
          throw new Error("The readiness and node profiles did not match.");
        }
        return { readiness, node };
      }, signal),
    createPairing: (request, signal) =>
      execute(
        async (connection, requestSignal) =>
          decodePairingInvitation(
            await requestJson(
              fetcher,
              connection,
              "/api/v2/pairing/invitations",
              requestSignal,
              "POST",
              request,
            ),
          ),
        signal,
      ),
    readPairing: (invitationId, signal) =>
      execute(
        async (connection, requestSignal) =>
          decodePairingSession(
            await requestJson(
              fetcher,
              connection,
              `/api/v2/pairing/invitations/${invitationId}`,
              requestSignal,
            ),
          ),
        signal,
      ),
    confirmPairing: (invitationId, confirmationOctal, signal) =>
      execute(
        async (connection, requestSignal) =>
          decodePairingSession(
            await requestJson(
              fetcher,
              connection,
              `/api/v2/pairing/invitations/${invitationId}/confirm`,
              requestSignal,
              "POST",
              { confirmationOctal },
            ),
          ),
        signal,
      ),
    cancelPairing: (invitationId, signal) =>
      execute(
        async (connection, requestSignal) =>
          decodePairingSession(
            await requestJson(
              fetcher,
              connection,
              `/api/v2/pairing/invitations/${invitationId}`,
              requestSignal,
              "DELETE",
            ),
          ),
        signal,
      ),
  };
}

async function resolveDesktopNodeConnection(): Promise<NodeConnection> {
  const { invoke } = await import("@tauri-apps/api/core");
  const value = await invoke<unknown>("node_connection");
  if (!isObject(value)) {
    throw new Error("The desktop node handoff did not match the expected schema.");
  }
  const { baseUrl, bearerToken } = value;
  if (
    typeof baseUrl !== "string" ||
    typeof bearerToken !== "string" ||
    bearerToken.length < 32 ||
    bearerToken.length > 512 ||
    /\s/.test(bearerToken)
  ) {
    throw new Error("The desktop node handoff did not match the expected schema.");
  }
  const resolvedBaseUrl = resolveNodeBaseUrl(baseUrl);
  const address = new URL(resolvedBaseUrl);
  if (address.protocol !== "http:" || !["127.0.0.1", "[::1]", "::1"].includes(address.hostname)) {
    throw new Error("The desktop supervisor returned a non-loopback node endpoint.");
  }
  return { baseUrl: resolvedBaseUrl, bearerToken };
}

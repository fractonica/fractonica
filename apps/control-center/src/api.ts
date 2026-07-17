export const DEFAULT_NODE_URL = "http://127.0.0.1:8789";

export type NodeProfile = "node" | "saros";

export type StorageReadyStatus =
  | {
      kind: "sqlite";
      status: "ready";
      schemaVersion: number;
    }
  | {
      kind: "none";
      status: "notConfigured";
    };

export interface ReadyResponse {
  status: "ready";
  profile: NodeProfile;
  storage: StorageReadyStatus;
}

export interface NodeResponse {
  installationId: string;
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

export interface NodeClient {
  readonly baseUrl: string;
  readStatus(signal?: AbortSignal): Promise<NodeSnapshot>;
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

function isDateTime(value: unknown): value is string {
  return (
    typeof value === "string" &&
    /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$/.test(value) &&
    Number.isFinite(Date.parse(value))
  );
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
      typeof value.storage.schemaVersion !== "number" ||
      !Number.isSafeInteger(value.storage.schemaVersion) ||
      value.storage.schemaVersion < 0
    ) {
      throw new Error("The readiness response did not match the expected schema.");
    }

    return {
      status: "ready",
      profile: "node",
      storage: {
        kind: "sqlite",
        status: "ready",
        schemaVersion: value.storage.schemaVersion,
      },
    };
  }

  if (
    !hasExactKeys(value.storage, ["kind", "status"]) ||
    value.storage.kind !== "none" ||
    value.storage.status !== "notConfigured"
  ) {
    throw new Error("The readiness response did not match the expected schema.");
  }

  return {
    status: "ready",
    profile: "saros",
    storage: {
      kind: "none",
      status: "notConfigured",
    },
  };
}

function decodeNodeResponse(value: unknown): NodeResponse {
  if (
    !isObject(value) ||
    !hasExactKeys(value, [
      "installationId",
      "profile",
      "displayName",
      "version",
      "startedAt",
      "uptimeSeconds",
      "capabilities",
    ])
  ) {
    throw new Error("The node response did not match the expected schema.");
  }

  const {
    capabilities,
    displayName,
    installationId,
    profile,
    startedAt,
    uptimeSeconds,
    version,
  } = value;

  if (
    typeof installationId !== "string" ||
    installationId.length === 0 ||
    installationId.length > 128 ||
    !isNodeProfile(profile) ||
    typeof displayName !== "string" ||
    displayName.length === 0 ||
    displayName.length > 128 ||
    typeof version !== "string" ||
    version.length === 0 ||
    version.length > 64 ||
    !isDateTime(startedAt) ||
    typeof uptimeSeconds !== "number" ||
    !Number.isSafeInteger(uptimeSeconds) ||
    uptimeSeconds < 0 ||
    !isCapabilityList(capabilities)
  ) {
    throw new Error("The node response did not match the expected schema.");
  }

  return {
    installationId,
    profile,
    displayName,
    version,
    startedAt,
    uptimeSeconds,
    capabilities: [...capabilities],
  };
}

function endpoint(baseUrl: string, path: string): string {
  return `${baseUrl.replace(/\/+$/, "")}/${path.replace(/^\/+/, "")}`;
}

async function readJson(
  fetcher: Fetcher,
  url: string,
  signal: AbortSignal,
  bearerToken?: string,
): Promise<unknown> {
  const headers: Record<string, string> = { Accept: "application/json" };
  if (bearerToken) headers.Authorization = `Bearer ${bearerToken}`;
  const response = await fetcher(url, {
    cache: "no-store",
    headers,
    signal,
  });

  if (!response.ok) {
    throw new Error(`${new URL(url).pathname} returned HTTP ${response.status}.`);
  }

  return response.json() as Promise<unknown>;
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

  return createResolvingNodeClient(
    resolveDesktopNodeConnection,
    "desktop-managed node",
    fetcher,
    timeoutMs,
  );
}

function createResolvingNodeClient(
  resolveConnection: () => Promise<NodeConnection>,
  initialBaseUrl: string,
  fetcher: Fetcher,
  timeoutMs: number,
): NodeClient {
  let currentBaseUrl = initialBaseUrl;
  return {
    get baseUrl() {
      return currentBaseUrl;
    },
    async readStatus(parentSignal) {
      const controller = new AbortController();
      const abortFromParent = () => controller.abort(parentSignal?.reason);
      const timeout = window.setTimeout(
        () => controller.abort(new DOMException("Node request timed out.", "TimeoutError")),
        timeoutMs,
      );

      if (parentSignal?.aborted) {
        abortFromParent();
      } else {
        parentSignal?.addEventListener("abort", abortFromParent, { once: true });
      }

      try {
        const connection = await resolveConnection();
        currentBaseUrl = connection.baseUrl;
        const [readinessValue, nodeValue] = await Promise.all([
          readJson(
            fetcher,
            endpoint(connection.baseUrl, "/health/ready"),
            controller.signal,
            connection.bearerToken,
          ),
          readJson(
            fetcher,
            endpoint(connection.baseUrl, "/api/v1/node"),
            controller.signal,
            connection.bearerToken,
          ),
        ]);

        const readiness = decodeReadyResponse(readinessValue);
        const node = decodeNodeResponse(nodeValue);
        if (readiness.profile !== node.profile) {
          throw new Error("The readiness and node profiles did not match.");
        }

        return { readiness, node };
      } finally {
        window.clearTimeout(timeout);
        parentSignal?.removeEventListener("abort", abortFromParent);
      }
    },
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

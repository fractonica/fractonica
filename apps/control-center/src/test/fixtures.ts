import type { NodeSnapshot } from "../api";

export const READY_SNAPSHOT: NodeSnapshot = {
  readiness: {
    status: "ready",
    profile: "node",
    storage: {
      kind: "sqlite",
      status: "ready",
      schemaVersion: 14,
    },
  },
  node: {
    installationId: "019f6576-f20d-7ba0-a718-e1db44d6c9b2",
    profile: "node",
    displayName: "Studio node",
    version: "0.1.0",
    startedAt: "2026-07-17T08:00:00.000Z",
    uptimeSeconds: 90_125,
    capabilities: ["records", "replication", "media"],
  },
};

export const SAROS_SNAPSHOT: NodeSnapshot = {
  readiness: {
    status: "ready",
    profile: "saros",
    storage: {
      kind: "none",
      status: "notConfigured",
    },
  },
  node: {
    installationId: "saros-engine",
    profile: "saros",
    displayName: "Saros engine",
    version: "0.1.0",
    startedAt: "2026-07-17T08:00:00.000Z",
    uptimeSeconds: 90_125,
    capabilities: ["saros-calculation", "reviewed-eclipse-geometry"],
  },
};

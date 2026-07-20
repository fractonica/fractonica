import type { NodeSnapshot } from "../api";

const SPACE_ID = `space:${"1".repeat(64)}`;
const NODE_ID = `node:ed25519:${"2".repeat(64)}`;
const CONTROLLER_ID = `actor:ed25519:${"3".repeat(64)}`;
const WRITER_ID = `actor:ed25519:${"4".repeat(64)}`;
const GENESIS_ID = `sha-256:${"5".repeat(64)}`;
const GRANT_ID = `sha-256:${"6".repeat(64)}`;

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
    nodeId: NODE_ID,
    spaces: [{
      spaceId: SPACE_ID,
      displayName: "Personal space",
      genesisOperationId: GENESIS_ID,
      initialGrantOperationId: GRANT_ID,
      controllerActorId: CONTROLLER_ID,
      localWriterActorId: WRITER_ID,
      createdAtUnixMs: 1_784_265_600_000,
    }],
    profile: "node",
    displayName: "Studio node",
    version: "0.1.0",
    startedAt: "2026-07-17T08:00:00.000Z",
    uptimeSeconds: 90_125,
    capabilities: ["records", "replication", "media", "noise-pairing-v1"],
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

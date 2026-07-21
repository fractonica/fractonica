import { describe, expect, it, vi } from "vitest";

import type { NativeClientBridge } from "./native-client";
import {
  createNativeClientPort,
  isRecoveryRequiredError,
  NativeContractError,
} from "./native-client";

const HASH = "a".repeat(64);
const OTHER_HASH = "b".repeat(64);

function status(overrides: Record<string, unknown> = {}): unknown {
  return {
    phase: "ready",
    nodeId: `node:ed25519:${HASH}`,
    actorId: `actor:ed25519:${HASH}`,
    spaceId: `space:${HASH}`,
    syncRunning: false,
    cycle: 2,
    pendingOperations: 0,
    rejectedOperations: 0,
    waitingUploads: 0,
    pendingUploads: 0,
    pendingDownloads: 0,
    rejectedResources: 0,
    synchronizedBytes: 0,
    totalBytes: 0,
    ...overrides,
  };
}

function record(overrides: Record<string, unknown> = {}): unknown {
  return {
    operationId: `sha-256:${HASH}`,
    entityId: "31000000-0000-4000-8000-000000000001",
    schema: "record",
    visibility: "public",
    conflicted: false,
    tombstone: false,
    startAtUnixMs: 1_000,
    sortText: "A moment",
    resourceCount: 0,
    mediaBytes: 0,
    emoji: "🌒",
    textPreview: "A moment",
    previewTruncated: false,
    ...overrides,
  };
}

function recordDetail(overrides: Record<string, unknown> = {}): unknown {
  return {
    operationId: `sha-256:${HASH}`,
    entityId: "31000000-0000-4000-8000-000000000001",
    schema: "record",
    visibility: "public",
    conflicted: false,
    tombstone: false,
    startAtUnixMs: 1_000,
    resourceCount: 0,
    mediaBytes: 0,
    documentJson:
      '{"startAtUnixMs":1000,"metadata":{"exact":9007199254740993},"resources":[],"references":[]}',
    ...overrides,
  };
}

function bridge(overrides: Partial<NativeClientBridge> = {}): NativeClientBridge {
  return {
    clientStatus: vi.fn(async () => status()),
    clientListRecords: vi.fn(async () => [record()]),
    clientGetRecord: vi.fn(async () => recordDetail()),
    clientCreateRecord: vi.fn(async () => ({
      localSequence: 3,
      operationId: `sha-256:${OTHER_HASH}`,
      replayed: false,
      queuedPeers: 0,
    })),
    clientClaimPairingInvitation: vi.fn(async () => ({
      invitationId: "1".repeat(32),
      responderNodeId: `node:ed25519:${HASH}`,
      spaceId: `space:${HASH}`,
      endpoint: "http://127.0.0.1:8787",
      confirmationOctal: "0123456701",
      grantOperationId: `sha-256:${OTHER_HASH}`,
    })),
    clientAcceptPairingInvitation: vi.fn(async () => ({
      invitationId: "1".repeat(32),
      responderNodeId: `node:ed25519:${HASH}`,
      spaceId: `space:${HASH}`,
      endpoint: "http://127.0.0.1:8787",
      confirmationOctal: "0123456701",
      grantOperationId: `sha-256:${OTHER_HASH}`,
    })),
    clientResetLocalInstallation: vi.fn(async () => undefined),
    ...overrides,
  };
}

describe("native client port", () => {
  it("decodes a complete status and bounded public record preview", async () => {
    const client = createNativeClientPort(bridge());
    await expect(client.status()).resolves.toMatchObject({ phase: "ready", cycle: 2 });
    await expect(client.listRecords()).resolves.toMatchObject([
      { visibility: "public", emoji: "🌒", textPreview: "A moment" },
    ]);
  });

  it("rejects null optional values instead of silently widening the contract", async () => {
    const client = createNativeClientPort(
      bridge({ clientListRecords: vi.fn(async () => [record({ endAtUnixMs: null })]) }),
    );
    await expect(client.listRecords()).rejects.toBeInstanceOf(NativeContractError);
  });

  it("rejects unknown status fields", async () => {
    const client = createNativeClientPort(
      bridge({ clientStatus: vi.fn(async () => status({ debugSecret: "no" })) }),
    );
    await expect(client.status()).rejects.toThrow("expected schema");
  });

  it("rejects private summaries that expose a public content preview", async () => {
    const client = createNativeClientPort(
      bridge({ clientListRecords: vi.fn(async () => [record({ visibility: "private" })]) }),
    );
    await expect(client.listRecords()).rejects.toThrow("exposed a content preview");
  });

  it("bounds list requests before invoking native code", async () => {
    const native = bridge();
    const client = createNativeClientPort(native);
    await expect(client.listRecords(201)).rejects.toBeInstanceOf(RangeError);
    expect(native.clientListRecords).not.toHaveBeenCalled();
  });

  it("uses a bounded default and rejects an oversized native response", async () => {
    const native = bridge();
    const client = createNativeClientPort(native);
    await client.listRecords();
    expect(native.clientListRecords).toHaveBeenCalledExactlyOnceWith({ limit: 100 });

    const oversized = createNativeClientPort(
      bridge({ clientListRecords: vi.fn(async () => [record(), record()]) }),
    );
    await expect(oversized.listRecords(1)).rejects.toBeInstanceOf(NativeContractError);
  });

  it("rejects preview fields and pages beyond their UTF-8 byte budgets", async () => {
    const oversizedField = createNativeClientPort(
      bridge({
        clientListRecords: vi.fn(async () => [record({ textPreview: "🌀".repeat(193) })]),
      }),
    );
    await expect(oversizedField.listRecords()).rejects.toBeInstanceOf(NativeContractError);

    const records = Array.from({ length: 100 }, () =>
      record({ textPreview: "x".repeat(700) }),
    );
    const oversizedPage = createNativeClientPort(
      bridge({ clientListRecords: vi.fn(async () => records) }),
    );
    await expect(oversizedPage.listRecords()).rejects.toThrow("byte budget");
  });

  it("looks up an exact record head while keeping canonical document JSON opaque", async () => {
    const native = bridge();
    const client = createNativeClientPort(native);
    const operationId = `sha-256:${HASH}`;
    const entityId = "31000000-0000-4000-8000-000000000001";

    await expect(client.getRecord(operationId, entityId)).resolves.toEqual(recordDetail());
    expect(native.clientGetRecord).toHaveBeenCalledExactlyOnceWith({ operationId, entityId });
    await expect(client.getRecord("bad", entityId)).rejects.toBeInstanceOf(RangeError);
    expect(native.clientGetRecord).toHaveBeenCalledOnce();
  });

  it("validates the outgoing document and decodes its commit", async () => {
    const native = bridge();
    const client = createNativeClientPort(native);
    await expect(
      client.createRecord({
        visibility: "public",
        document: {
          startAtUnixMs: 1_000,
          text: "Stored locally",
          metadata: {},
          resources: [],
          references: [],
        },
      }),
    ).resolves.toMatchObject({ localSequence: 3, queuedPeers: 0 });
    expect(native.clientCreateRecord).toHaveBeenCalledOnce();
  });

  it("rejects unsafe metadata integers before invoking native serialization", async () => {
    const native = bridge();
    const client = createNativeClientPort(native);
    await expect(
      client.createRecord({
        visibility: "public",
        document: {
          startAtUnixMs: 1_000,
          metadata: { unsafe: Number.MAX_SAFE_INTEGER + 1 },
          resources: [],
          references: [],
        },
      }),
    ).rejects.toBeInstanceOf(NativeContractError);
    expect(native.clientCreateRecord).not.toHaveBeenCalled();
  });

  it("requires explicit reset confirmation before invoking native recovery", async () => {
    const native = bridge();
    const client = createNativeClientPort(native);

    await expect(
      client.resetLocalInstallation({ confirmed: false } as never),
    ).rejects.toThrow("requires explicit confirmation");
    expect(native.clientResetLocalInstallation).not.toHaveBeenCalled();

    await expect(
      client.resetLocalInstallation({ confirmed: true }),
    ).resolves.toBeUndefined();
    expect(native.clientResetLocalInstallation).toHaveBeenCalledExactlyOnceWith({
      confirmation: "RESET_LOCAL_INSTALLATION",
    });
  });

  it("validates pairing invitations and the verified native handshake result", async () => {
    const native = bridge();
    const client = createNativeClientPort(native);
    const qr = "fractonica-pairing:v1:abc_DEF-123";
    await expect(client.claimPairingInvitation(qr)).resolves.toMatchObject({
      confirmationOctal: "0123456701",
      endpoint: "http://127.0.0.1:8787",
    });
    expect(native.clientClaimPairingInvitation).toHaveBeenCalledExactlyOnceWith({ qr });
    await expect(client.acceptPairingInvitation("1".repeat(32))).resolves.toMatchObject({
      confirmationOctal: "0123456701",
    });
    expect(native.clientAcceptPairingInvitation).toHaveBeenCalledExactlyOnceWith({
      invitationId: "1".repeat(32),
    });

    const lanClient = createNativeClientPort(bridge({
      clientClaimPairingInvitation: vi.fn(async () => ({
        invitationId: "1".repeat(32),
        responderNodeId: `node:ed25519:${HASH}`,
        spaceId: `space:${HASH}`,
        endpoint: "http://192.168.0.24:60743",
        confirmationOctal: "0123456701",
        grantOperationId: `sha-256:${OTHER_HASH}`,
      })),
    }));
    await expect(lanClient.claimPairingInvitation(qr)).resolves.toMatchObject({
      endpoint: "http://192.168.0.24:60743",
    });

    const publicClient = createNativeClientPort(bridge({
      clientClaimPairingInvitation: vi.fn(async () => ({
        invitationId: "1".repeat(32),
        responderNodeId: `node:ed25519:${HASH}`,
        spaceId: `space:${HASH}`,
        endpoint: "http://8.8.8.8:60743",
        confirmationOctal: "0123456701",
        grantOperationId: `sha-256:${OTHER_HASH}`,
      })),
    }));
    await expect(publicClient.claimPairingInvitation(qr)).rejects.toBeInstanceOf(
      NativeContractError,
    );

    await expect(client.claimPairingInvitation("not-a-qr")).rejects.toBeInstanceOf(
      NativeContractError,
    );
    expect(native.clientClaimPairingInvitation).toHaveBeenCalledOnce();
    await expect(client.acceptPairingInvitation("not-an-id")).rejects.toBeInstanceOf(
      NativeContractError,
    );
  });

  it("recognizes only the coded recovery error, including a wrapped cause", () => {
    expect(
      isRecoveryRequiredError({ code: "ERR_FRACTONICA_RECOVERY_REQUIRED" }),
    ).toBe(true);
    expect(
      isRecoveryRequiredError({
        code: "ERR_UNEXPECTED",
        cause: { code: "ERR_FRACTONICA_RECOVERY_REQUIRED" },
      }),
    ).toBe(true);
    expect(isRecoveryRequiredError(new Error("recovery required"))).toBe(false);
  });
});

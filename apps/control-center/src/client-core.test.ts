import { describe, expect, it, vi } from "vitest";
import { createClientCore } from "./client-core";

const OPERATION_ID = `sha-256:${"a".repeat(64)}`;
const ENTITY_ID = "019f6576-f20d-7ba0-a718-e1db44d6c9b2";

describe("native client core adapter", () => {
  it("decodes native status and public record documents", async () => {
    const invoke = vi.fn(async (command: string) => {
      if (command === "client_status") {
        return {
          phase: "ready",
          nodeId: `node:ed25519:${"1".repeat(64)}`,
          actorId: `actor:ed25519:${"2".repeat(64)}`,
          spaceId: `space:${"3".repeat(64)}`,
          syncRunning: true,
          cycle: 4,
          pendingOperations: 1,
          rejectedOperations: 0,
          waitingUploads: 0,
          pendingUploads: 0,
          pendingDownloads: 0,
          rejectedResources: 0,
          synchronizedBytes: 12,
          totalBytes: 12,
        };
      }
      return [{
        operationId: OPERATION_ID,
        entityId: ENTITY_ID,
        schema: "record",
        visibility: "public",
        conflicted: false,
        tombstone: false,
        startAtUnixMs: 1_784_265_600_000,
        resourceCount: 0,
        mediaBytes: 0,
        document: {
          startAtUnixMs: 1_784_265_600_000,
          emoji: "✦",
          text: "Local first",
          metadata: { source: "test" },
        },
      }];
    });
    const client = createClientCore(invoke);

    expect((await client.status()).pendingOperations).toBe(1);
    const records = await client.listRecords();

    expect(records[0].document).toEqual(expect.objectContaining({
      text: "Local first",
      resources: [],
      references: [],
    }));
    expect(invoke).toHaveBeenCalledWith("client_list_records", { limit: 200 });
  });

  it("sends semantic commands and rejects malformed native responses", async () => {
    const invoke = vi.fn(async () => ({
      localSequence: 7,
      operationId: OPERATION_ID,
      replayed: false,
      queuedPeers: 1,
    }));
    const client = createClientCore(invoke);
    const payload = {
      visibility: "public" as const,
      document: {
        startAtUnixMs: 1_784_265_600_000,
        metadata: {},
        resources: [],
        references: [],
      },
    };

    await client.createRecord(payload);
    await client.updateRecord(ENTITY_ID, payload);
    await client.deleteRecord(ENTITY_ID);

    expect(invoke).toHaveBeenNthCalledWith(1, "client_create_record", { payload });
    expect(invoke).toHaveBeenNthCalledWith(2, "client_update_record", {
      entityId: ENTITY_ID,
      payload,
    });
    expect(invoke).toHaveBeenNthCalledWith(3, "client_delete", {
      entityId: ENTITY_ID,
      schema: "record",
    });

    const malformed = createClientCore(vi.fn().mockResolvedValue({ phase: "ready" }));
    await expect(malformed.status()).rejects.toThrow("expected schema");
  });

  it("imports attachment references without sending file bytes or paths through JavaScript", async () => {
    const resource = {
      contentId: `sha-256:${"b".repeat(64)}`,
      byteLength: 1_024,
      mediaType: "image/jpeg",
      role: "record.media",
      originalName: "eclipse.jpg",
    };
    const invoke = vi.fn().mockResolvedValue([resource]);
    const client = createClientCore(invoke);

    await expect(client.importAttachments(64)).resolves.toEqual([resource]);
    expect(invoke).toHaveBeenCalledWith("client_import_attachments", { limit: 64 });

    const malformed = createClientCore(vi.fn().mockResolvedValue([{
      ...resource,
      role: "unexpected.role",
    }]));
    await expect(malformed.importAttachments(64)).rejects.toThrow("expected schema");
    await expect(client.importAttachments(0)).rejects.toThrow("between 1 and 64");
  });

  it("claims and accepts pairing below the desktop JavaScript boundary", async () => {
    const claim = {
      invitationId: "1".repeat(32),
      responderNodeId: `node:ed25519:${"2".repeat(64)}`,
      spaceId: `space:${"3".repeat(64)}`,
      endpoint: "http://192.168.1.20:8787",
      confirmationOctal: "0123456701",
      grantOperationId: `sha-256:${"4".repeat(64)}`,
      localRecordCount: 3,
    };
    const invoke = vi.fn().mockResolvedValue(claim);
    const client = createClientCore(invoke);
    const invitation = "fractonica-pairing:v1:Abc_123";

    await expect(client.claimPairing(invitation)).resolves.toEqual(claim);
    await expect(client.acceptPairing(claim.invitationId, "merge")).resolves.toEqual(claim);
    expect(invoke).toHaveBeenNthCalledWith(1, "client_claim_pairing_invitation", {
      qr: invitation,
    });
    expect(invoke).toHaveBeenNthCalledWith(2, "client_accept_pairing_invitation", {
      invitationId: claim.invitationId,
      recordPolicy: "merge",
    });
  });

  it("requires the native reset confirmation phrase below the JavaScript boundary", async () => {
    const invoke = vi.fn().mockResolvedValue(undefined);
    const client = createClientCore(invoke);

    await client.resetInstallation?.();

    expect(invoke).toHaveBeenCalledWith("client_reset_local_installation", {
      confirmation: "RESET LOCAL INSTALLATION",
    });
  });

  it("decodes the native workspace list independently of node status", async () => {
    const workspace = {
      spaceId: `space:${"1".repeat(64)}`,
      displayName: "Personal",
      genesisOperationId: `sha-256:${"2".repeat(64)}`,
      initialGrantOperationId: `sha-256:${"3".repeat(64)}`,
      controllerActorId: `actor:ed25519:${"4".repeat(64)}`,
      localWriterActorId: `actor:ed25519:${"5".repeat(64)}`,
      createdAtUnixMs: 1_800_000_000_000,
    };
    const invoke = vi.fn().mockResolvedValue([workspace]);
    const client = createClientCore(invoke);

    await expect(client.listWorkspaces?.()).resolves.toEqual([workspace]);
    expect(invoke).toHaveBeenCalledWith("client_list_workspaces");
  });
});

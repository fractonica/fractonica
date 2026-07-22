import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { act } from "react";
import { describe, expect, it, vi } from "vitest";
import App from "./App";
import type { NodeClient, NodeSnapshot } from "./api";
import type { ClientCore, ClientRecord } from "./client-core";
import { READY_SNAPSHOT, SAROS_SNAPSHOT } from "./test/fixtures";

function deferred<T>() {
  let resolve!: (value: T) => void;
  let reject!: (reason?: unknown) => void;
  const promise = new Promise<T>((resolvePromise, rejectPromise) => {
    resolve = resolvePromise;
    reject = rejectPromise;
  });
  return { promise, reject, resolve };
}

function makeClient(readStatus: NodeClient["readStatus"]): NodeClient {
  return {
    baseUrl: "http://127.0.0.1:8789",
    pairingEndpointHints: ["http://127.0.0.1:8789"],
    readStatus,
    createPairing: vi.fn(),
    readPairing: vi.fn(),
    confirmPairing: vi.fn(),
    cancelPairing: vi.fn(),
    listPairedDevices: vi.fn().mockResolvedValue([]),
    revokePairedDevice: vi.fn(),
  };
}

function makeClientCore(records: ClientRecord[] = []): ClientCore {
  return {
    status: vi.fn().mockResolvedValue({
      phase: "ready",
      nodeId: `node:ed25519:${"1".repeat(64)}`,
      actorId: `actor:ed25519:${"2".repeat(64)}`,
      spaceId: `space:${"3".repeat(64)}`,
      syncRunning: true,
      cycle: 1,
      pendingOperations: 0,
      rejectedOperations: 0,
      waitingUploads: 0,
      pendingUploads: 0,
      pendingDownloads: 0,
      rejectedResources: 0,
      synchronizedBytes: 0,
      totalBytes: 0,
    }),
    listRecords: vi.fn().mockResolvedValue(records),
    importAttachments: vi.fn().mockResolvedValue([]),
    createRecord: vi.fn().mockResolvedValue({
      localSequence: 1,
      operationId: `sha-256:${"4".repeat(64)}`,
      replayed: false,
      queuedPeers: 1,
    }),
    updateRecord: vi.fn().mockResolvedValue({
      localSequence: 2,
      operationId: `sha-256:${"5".repeat(64)}`,
      replayed: false,
      queuedPeers: 1,
    }),
    deleteRecord: vi.fn().mockResolvedValue({
      localSequence: 3,
      operationId: `sha-256:${"6".repeat(64)}`,
      replayed: false,
      queuedPeers: 1,
    }),
    claimPairing: vi.fn(),
    acceptPairing: vi.fn(),
    createWorkspace: vi.fn().mockResolvedValue(undefined),
    activateWorkspace: vi.fn().mockResolvedValue(undefined),
    deleteWorkspace: vi.fn().mockResolvedValue(undefined),
  };
}

describe("control center", () => {
  it("starts at the workspace root and creates an isolated workspace", async () => {
    const nodeClient = makeClient(vi.fn().mockResolvedValue(READY_SNAPSHOT));
    const clientCore = makeClientCore();
    const user = userEvent.setup();

    render(<App client={nodeClient} clientCore={clientCore} />);

    expect(await screen.findByRole("heading", { name: "Workspaces" })).toBeInTheDocument();
    await user.type(screen.getByLabelText("Name"), "Travel vault");
    await user.click(screen.getByRole("button", { name: "Create workspace" }));
    expect(clientCore.createWorkspace).toHaveBeenCalledWith("Travel vault");
  });

  it("shows a loading state before rendering a ready node", async () => {
    const request = deferred<NodeSnapshot>();
    const client = makeClient(vi.fn(() => request.promise));

    render(<App client={client} />);

    expect(screen.getByText("Finding your Fractonica node")).toBeInTheDocument();
    expect(screen.getAllByText("Connecting").length).toBeGreaterThan(0);

    await act(async () => request.resolve(READY_SNAPSHOT));

    expect((await screen.findAllByText("Studio node")).length).toBeGreaterThan(0);
    expect(screen.getByText("SQLite")).toBeInTheDocument();
    expect(screen.getByText("Ready")).toBeInTheDocument();
    expect(screen.getByText("1d 1h 2m")).toBeInTheDocument();
    expect(screen.getByText("replication")).toBeInTheDocument();
  });

  it("describes the stateless Saros profile without implying local SQLite storage", async () => {
    const client = makeClient(vi.fn().mockResolvedValue(SAROS_SNAPSHOT));

    render(<App client={client} />);

    expect((await screen.findAllByText("Saros engine")).length).toBeGreaterThan(0);
    expect(screen.getByText("Stateless")).toBeInTheDocument();
    expect(screen.getByText("No local storage configured")).toBeInTheDocument();
    expect(screen.getByText("Stateless Saros engine")).toBeInTheDocument();
  });

  it("recovers from an offline state when the user retries", async () => {
    const readStatus = vi
      .fn<NodeClient["readStatus"]>()
      .mockRejectedValueOnce(new Error("Connection refused."))
      .mockResolvedValueOnce(READY_SNAPSHOT);
    const client = makeClient(readStatus);
    const user = userEvent.setup();

    render(<App client={client} />);

    expect(await screen.findByText("Node unreachable")).toBeInTheDocument();
    expect(screen.getByText("Connection refused.")).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Try again" }));

    expect((await screen.findAllByText("Studio node")).length).toBeGreaterThan(0);
    expect(readStatus).toHaveBeenCalledTimes(2);
  });

  it("keeps workspace creation visible when node status is temporarily offline", async () => {
    const client = makeClient(vi.fn().mockRejectedValue(new Error("Status request failed.")));
    const clientCore = makeClientCore();

    render(<App client={client} clientCore={clientCore} />);

    expect(await screen.findByRole("heading", { name: "Workspaces" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Create workspace" })).toBeInTheDocument();
    expect(await screen.findByText("Node status unavailable")).toBeInTheDocument();
    expect(screen.getByText("Status request failed.")).toBeInTheDocument();
  });

  it("creates an invitation and requires both confirmation glyphs before authorization", async () => {
    const invitationId = "7".repeat(32);
    const spaceId = READY_SNAPSHOT.node.spaces![0].spaceId;
    const created = {
      invitationId,
      spaceId,
      state: "created" as const,
      expiresAtUnixMs: Date.now() + 300_000,
    };
    const claimed = {
      ...created,
      state: "claimed" as const,
      joinerNodeId: `node:ed25519:${"2".repeat(64)}`,
      subjectActorId: `actor:ed25519:${"3".repeat(64)}`,
      confirmationOctal: "0123456701",
    };
    const completed = {
      ...claimed,
      state: "completed" as const,
      grantOperationId: `sha-256:${"4".repeat(64)}`,
    };
    const client = makeClient(vi.fn().mockResolvedValue(READY_SNAPSHOT));
    vi.mocked(client.createPairing).mockResolvedValue({
      qr: "fractonica-pairing:v1:Abc_123",
      session: created,
    });
    vi.mocked(client.readPairing)
      .mockResolvedValueOnce(created)
      .mockResolvedValue(claimed);
    vi.mocked(client.confirmPairing).mockResolvedValue(completed);
    const user = userEvent.setup();

    render(<App client={client} />);
    await user.click(screen.getByRole("button", { name: "Link devices" }));
    await screen.findByRole("heading", { name: "Link a device" });
    await user.click(screen.getByRole("button", { name: "Create invitation" }));

    expect(await screen.findByText("Scan from the joining client")).toBeInTheDocument();
    expect(screen.queryByText(invitationId)).not.toBeInTheDocument();
    expect(client.createPairing).toHaveBeenCalledWith(
      expect.objectContaining({
        spaceId,
        expiresInMs: 300_000,
        endpointHints: [client.baseUrl],
        capability: expect.objectContaining({
          actions: ["appendOperation", "readSpace", "writeContent", "linkWorkspace"],
          delegationDepth: 0,
        }),
      }),
    );

    await user.click(screen.getByRole("button", { name: "Check claim" }));
    expect(await screen.findByText("Scan from the joining client")).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Check claim" }));
    expect(await screen.findByText("Compare both glyphs")).toBeInTheDocument();
    expect(screen.getByLabelText("Confirmation code 0123456701")).toBeInTheDocument();

    expect(screen.queryByText(claimed.joinerNodeId)).not.toBeInTheDocument();
    vi.mocked(client.readPairing).mockResolvedValue(completed);
    await user.click(screen.getByRole("button", { name: "Refresh status" }));
    expect(await screen.findByText("Device authorized")).toBeInTheDocument();
    expect(screen.queryByText(completed.grantOperationId)).not.toBeInTheDocument();
  });

  it("does not invite into the node's stale local space while a linked workspace is active", async () => {
    const client = makeClient(vi.fn().mockResolvedValue(READY_SNAPSHOT));
    const clientCore = makeClientCore();
    const user = userEvent.setup();

    render(<App client={client} clientCore={clientCore} />);
    await user.click(screen.getByRole("button", { name: "Link devices" }));

    expect(
      await screen.findByRole("heading", { name: "Link from a device that hosts this workspace" }),
    ).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Create invitation" })).not.toBeInTheDocument();
    expect(client.createPairing).not.toHaveBeenCalled();
  });

  it("creates a record through the native local-first client", async () => {
    const nodeClient = makeClient(vi.fn().mockResolvedValue(READY_SNAPSHOT));
    const clientCore = makeClientCore();
    const attachment = {
      contentId: `sha-256:${"8".repeat(64)}`,
      byteLength: 24_000,
      mediaType: "image/jpeg",
      role: "record.media",
      originalName: "moon.jpg",
    };
    vi.mocked(clientCore.importAttachments).mockResolvedValue([attachment]);
    const user = userEvent.setup();

    render(<App client={nodeClient} clientCore={clientCore} />);

    await user.click(await screen.findByRole("button", { name: "Records" }));
    expect(await screen.findByRole("heading", { name: "Records" })).toBeInTheDocument();
    await user.type(screen.getByLabelText("Record emoji"), "🌒");
    await user.type(screen.getByLabelText("Record text"), "A local moment");
    await user.click(screen.getByRole("button", { name: "Attach files" }));
    expect(await screen.findByText("moon.jpg")).toBeInTheDocument();
    expect(screen.getByText("Photo · 24.0 kB")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Save locally" }));

    expect(clientCore.createRecord).toHaveBeenCalledWith({
      visibility: "public",
      document: expect.objectContaining({
        emoji: "🌒",
        text: "A local moment",
        metadata: {},
        resources: [attachment],
        references: [],
      }),
    });
    expect(clientCore.importAttachments).toHaveBeenCalledTimes(1);
  });

  it("edits without dropping resources and requires delete confirmation", async () => {
    const record: ClientRecord = {
      operationId: `sha-256:${"7".repeat(64)}`,
      entityId: "019f6576-f20d-7ba0-a718-e1db44d6c9b2",
      schema: "record",
      visibility: "public",
      conflicted: false,
      tombstone: false,
      startAtUnixMs: 1_784_265_600_000,
      resourceCount: 1,
      mediaBytes: 12,
      document: {
        startAtUnixMs: 1_784_265_600_000,
        emoji: "☀️",
        text: "Original",
        metadata: { source: "fixture" },
        resources: [{
          contentId: `sha-256:${"8".repeat(64)}`,
          byteLength: 12,
          mediaType: "image/jpeg",
          role: "record.media",
          originalName: "sun.jpg",
        }],
        references: [],
      },
    };
    const nodeClient = makeClient(vi.fn().mockResolvedValue(READY_SNAPSHOT));
    const clientCore = makeClientCore([record]);
    const imported = {
      contentId: `sha-256:${"9".repeat(64)}`,
      byteLength: 3_200,
      mediaType: "audio/mpeg",
      role: "record.media",
      originalName: "voice.mp3",
    };
    vi.mocked(clientCore.importAttachments).mockResolvedValue([imported]);
    const user = userEvent.setup();

    render(<App client={nodeClient} clientCore={clientCore} />);
    await user.click(await screen.findByRole("button", { name: "Records" }));
    await user.click(await screen.findByRole("button", { name: /Original/ }));
    await user.clear(screen.getByLabelText("Record text"));
    await user.type(screen.getByLabelText("Record text"), "Revised");
    await user.click(screen.getByRole("button", { name: "Attach files" }));
    expect(await screen.findByText("voice.mp3")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Save changes" }));

    expect(clientCore.updateRecord).toHaveBeenCalledWith(
      record.entityId,
      expect.objectContaining({
        document: expect.objectContaining({
          resources: [...(record.document?.resources ?? []), imported],
        }),
      }),
    );

    await user.click(screen.getByRole("button", { name: "Remove sun.jpg" }));
    await user.click(screen.getByRole("button", { name: "Save changes" }));
    expect(clientCore.updateRecord).toHaveBeenLastCalledWith(
      record.entityId,
      expect.objectContaining({
        document: expect.objectContaining({ resources: [] }),
      }),
    );

    await user.click(screen.getByRole("button", { name: "Delete" }));
    expect(clientCore.deleteRecord).not.toHaveBeenCalled();
    await user.click(screen.getByRole("button", { name: "Confirm delete" }));
    expect(clientCore.deleteRecord).toHaveBeenCalledWith(record.entityId);
  });
});

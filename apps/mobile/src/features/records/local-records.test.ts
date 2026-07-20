import { describe, expect, it, vi } from "vitest";

import type { ClientRecordPreview, ClientStatus } from "../../core/contracts";
import type { NativeClientPort } from "../../core/native-client";
import {
  commitPublicRecordDraft,
  LOCAL_RECORD_PAGE_SIZE,
  readLocalRecordSnapshot,
} from "./local-records";

const HASH = "a".repeat(64);

function status(phase: ClientStatus["phase"], lastError?: string): ClientStatus {
  return {
    phase,
    ...(phase === "ready"
      ? {
          nodeId: `node:ed25519:${HASH}`,
          actorId: `actor:ed25519:${HASH}`,
          spaceId: `space:${HASH}`,
        }
      : {}),
    syncRunning: false,
    cycle: 0,
    pendingOperations: 0,
    rejectedOperations: 0,
    waitingUploads: 0,
    pendingUploads: 0,
    pendingDownloads: 0,
    rejectedResources: 0,
    synchronizedBytes: 0,
    totalBytes: 0,
    ...(lastError === undefined ? {} : { lastError }),
  };
}

function record(time: number, suffix: string): ClientRecordPreview {
  return {
    operationId: `sha-256:${suffix.repeat(64)}`,
    entityId: `31000000-0000-4000-8000-00000000000${suffix}`,
    schema: "record",
    visibility: "public",
    conflicted: false,
    tombstone: false,
    startAtUnixMs: time,
    resourceCount: 0,
    mediaBytes: 0,
    previewTruncated: false,
  };
}

function client(overrides: Partial<NativeClientPort> = {}): NativeClientPort {
  return {
    status: vi.fn(async () => status("ready")),
    listRecords: vi.fn(async () => []),
    getRecord: vi.fn(async () => undefined),
    createRecord: vi.fn(async () => ({
      localSequence: 1,
      operationId: `sha-256:${HASH}`,
      replayed: false,
      queuedPeers: 0,
    })),
    resetLocalInstallation: vi.fn(async () => undefined),
    ...overrides,
  };
}

describe("local record boundary", () => {
  it("waits for startup without querying the record projection", async () => {
    const local = client({ status: vi.fn(async () => status("starting")) });

    await expect(readLocalRecordSnapshot(local)).resolves.toMatchObject({ kind: "starting" });
    expect(local.listRecords).not.toHaveBeenCalled();
  });

  it("reports native startup failure without querying records", async () => {
    const local = client({
      status: vi.fn(async () => status("failed", "identity mismatch")),
    });

    await expect(readLocalRecordSnapshot(local)).resolves.toEqual({
      kind: "failed",
      status: status("failed", "identity mismatch"),
      message: "identity mismatch",
    });
    expect(local.listRecords).not.toHaveBeenCalled();
  });

  it("requests exactly one bounded page and sorts it by record time", async () => {
    const older = record(10, "1");
    const newer = record(20, "2");
    const local = client({ listRecords: vi.fn(async () => [older, newer]) });

    await expect(readLocalRecordSnapshot(local)).resolves.toMatchObject({
      kind: "ready",
      records: [newer, older],
    });
    expect(local.listRecords).toHaveBeenCalledExactlyOnceWith(LOCAL_RECORD_PAGE_SIZE);
  });

  it("does not resolve creation before the native durable commit resolves", async () => {
    let resolveCommit: ((value: Awaited<ReturnType<NativeClientPort["createRecord"]>>) => void) | undefined;
    const nativeCommit = new Promise<Awaited<ReturnType<NativeClientPort["createRecord"]>>>(
      (resolve) => {
        resolveCommit = resolve;
      },
    );
    const local = client({ createRecord: vi.fn(() => nativeCommit) });
    let settled = false;

    const pending = commitPublicRecordDraft(local, {
      emoji: " 🌒 ",
      text: " observed ",
      now: 42,
    }).then((result) => {
      settled = true;
      return result;
    });
    await Promise.resolve();

    expect(settled).toBe(false);
    expect(local.createRecord).toHaveBeenCalledWith({
      visibility: "public",
      document: {
        startAtUnixMs: 42,
        emoji: "🌒",
        text: "observed",
        metadata: {},
        resources: [],
        references: [],
      },
    });

    resolveCommit?.({
      localSequence: 7,
      operationId: `sha-256:${HASH}`,
      replayed: false,
      queuedPeers: 0,
    });
    await expect(pending).resolves.toMatchObject({ localSequence: 7 });
    expect(settled).toBe(true);
  });

  it("propagates a rejected local commit to the composer", async () => {
    const local = client({
      createRecord: vi.fn(async () => {
        throw new Error("disk full");
      }),
    });

    await expect(
      commitPublicRecordDraft(local, { emoji: "🌒", text: "keep this", now: 42 }),
    ).rejects.toThrow("disk full");
  });
});

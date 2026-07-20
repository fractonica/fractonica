import { describe, expect, it } from "vitest";

import type { ClientRecordPreview } from "../../core/contracts";
import { makePublicRecordPayload, sortRecordsNewestFirst } from "./record-domain";

const HASH = "a".repeat(64);

function record(entityId: string, time: number): ClientRecordPreview {
  return {
    operationId: `sha-256:${HASH}`,
    entityId,
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

describe("record domain", () => {
  it("builds the smallest canonical public document", () => {
    expect(makePublicRecordPayload({ emoji: "  🌒 ", text: "  observed ", now: 42 })).toEqual({
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
  });

  it("does not create empty records", () => {
    expect(() => makePublicRecordPayload({ emoji: " ", text: "\n", now: 42 })).toThrow(
      "Add an emoji or a note",
    );
  });

  it("orders all loaded records by their start time without mutating the source", () => {
    const older = record("31000000-0000-4000-8000-000000000001", 100);
    const newer = record("31000000-0000-4000-8000-000000000002", 200);
    const source = [older, newer];
    expect(sortRecordsNewestFirst(source)).toEqual([newer, older]);
    expect(source).toEqual([older, newer]);
  });
});

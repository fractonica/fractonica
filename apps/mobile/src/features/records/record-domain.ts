import type { ClientRecordPreview, PublicRecordPayload } from "../../core/contracts";

export interface NewRecordInput {
  emoji: string;
  text: string;
  now?: number;
}

export function makePublicRecordPayload(input: NewRecordInput): PublicRecordPayload {
  const now = input.now ?? Date.now();
  if (!Number.isSafeInteger(now) || now < 0) {
    throw new RangeError("Record time must be a non-negative Unix millisecond value.");
  }
  const emoji = input.emoji.trim();
  const text = input.text.trim();
  if (emoji.length > 32) throw new RangeError("Record emoji is too long.");
  if (text.length > 100_000) throw new RangeError("Record text is too long.");
  if (emoji.length === 0 && text.length === 0) {
    throw new Error("Add an emoji or a note before creating the record.");
  }

  return {
    visibility: "public",
    document: {
      startAtUnixMs: now,
      ...(emoji.length === 0 ? {} : { emoji }),
      ...(text.length === 0 ? {} : { text }),
      metadata: {},
      resources: [],
      references: [],
    },
  };
}

function recordStart(record: ClientRecordPreview): number {
  return record.startAtUnixMs ?? 0;
}

export function sortRecordsNewestFirst(
  records: readonly ClientRecordPreview[],
): ClientRecordPreview[] {
  return [...records].sort((left, right) => {
    const byTime = recordStart(right) - recordStart(left);
    return byTime === 0 ? right.operationId.localeCompare(left.operationId) : byTime;
  });
}

export function recordDateLabel(record: ClientRecordPreview): string {
  const start = record.startAtUnixMs;
  if (start === undefined) return "Encrypted time";
  return new Date(start).toLocaleString([], {
    dateStyle: "medium",
    timeStyle: "short",
  });
}

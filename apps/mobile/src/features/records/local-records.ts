import type { ClientRecordPreview, ClientStatus, CommitResult } from "../../core/contracts";
import type { NativeClientPort } from "../../core/native-client";
import {
  makePublicRecordPayload,
  type NewRecordInput,
  sortRecordsNewestFirst,
} from "./record-domain";

/**
 * The first mobile slice intentionally reads one bounded local page. Pagination
 * comes later; silently widening this value would make bridge payloads grow with
 * the database and undermine the local-first performance boundary.
 */
export const LOCAL_RECORD_PAGE_SIZE = 100;

export type LocalRecordSnapshot =
  | { kind: "starting"; status: ClientStatus }
  | { kind: "ready"; status: ClientStatus; records: ClientRecordPreview[] }
  | { kind: "failed"; status: ClientStatus; message: string };

/**
 * Reads only from the linked native client. A record query is never issued
 * until the native runtime reports that its local store is ready.
 */
export async function readLocalRecordSnapshot(
  client: NativeClientPort,
): Promise<LocalRecordSnapshot> {
  const status = await client.status();
  if (status.phase === "starting") return { kind: "starting", status };
  if (status.phase === "failed") {
    return {
      kind: "failed",
      status,
      message: status.lastError ?? "The native client could not start.",
    };
  }

  const records = await client.listRecords(LOCAL_RECORD_PAGE_SIZE);
  return {
    kind: "ready",
    status,
    records: sortRecordsNewestFirst(records),
  };
}

/**
 * Resolves only after the native client confirms its local durable commit.
 * Network delivery is deliberately not part of this operation.
 */
export function commitPublicRecordDraft(
  client: NativeClientPort,
  input: NewRecordInput,
): Promise<CommitResult> {
  return client.createRecord(makePublicRecordPayload(input));
}

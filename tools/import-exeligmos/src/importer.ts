import { createHash } from "node:crypto";

import { loadCheckpoint, newCheckpoint, saveCheckpoint } from "./checkpoint.ts";
import {
  idempotencyKeyForOperation,
  operationIdForOriginRevision,
} from "./deterministic.ts";
import { ExeligmosClient } from "./exeligmos-client.ts";
import {
  FractonicaClient,
  MAX_TUS_CHUNK_BYTES,
  type TusPatchResult,
} from "./fractonica-client.ts";
import { mapRecord, UnsupportedRecordError, type MappedBlob } from "./mapping.ts";
import type {
  ExeligmosRecord,
  ExeligmosTag,
  ImportCheckpoint,
  ImportSummary,
  MediaCheckpoint,
  OperationSubmission,
  RecordCheckpoint,
  StoredOperation,
} from "./types.ts";

export interface ImportOptions {
  readonly sourceBaseUrl: string;
  readonly destinationBaseUrl: string;
  readonly sourceToken: string;
  readonly destinationToken?: string;
  readonly checkpointPath: string;
  readonly dryRun: boolean;
  readonly verify: boolean;
  readonly log?: (message: string) => void;
}

export async function importExeligmos(options: ImportOptions): Promise<ImportSummary> {
  const log = options.log ?? (() => undefined);
  const checkpoint = options.dryRun
    ? newCheckpoint(options.sourceBaseUrl, options.destinationBaseUrl)
    : await loadCheckpoint(
        options.checkpointPath,
        options.sourceBaseUrl,
        options.destinationBaseUrl,
      );
  const source = new ExeligmosClient(options.sourceBaseUrl, options.sourceToken);
  const destination = new FractonicaClient(
    options.destinationBaseUrl,
    options.destinationToken,
  );
  const summary = emptySummary();

  log("Reading the Exeligmos tag catalog...");
  const tags = await readTags(source);
  summary.tags = tags.size;
  log(`Found ${tags.size} tags.`);

  // A completed checkpoint starts a fresh, idempotent scan. This discovers
  // records added since an earlier run without discarding verified progress.
  if (checkpoint.recordsComplete) {
    checkpoint.recordsComplete = false;
    delete checkpoint.recordsCursor;
    await persist(options, checkpoint);
  }

  const seenCursors = new Set<string>();
  let cursor = options.dryRun ? undefined : checkpoint.recordsCursor;
  log(
    cursor === undefined
      ? "Scanning Exeligmos records from the first page..."
      : "Resuming Exeligmos records from the saved page cursor...",
  );

  for (;;) {
    const page = await source.listRecords(cursor);
    for (const record of page.data) {
      await processRecord(
        record,
        tags,
        source,
        destination,
        checkpoint,
        summary,
        options,
      );
    }

    if (!page.hasMore) {
      checkpoint.recordsComplete = true;
      delete checkpoint.recordsCursor;
      await persist(options, checkpoint);
      break;
    }
    const next = page.nextCursor;
    if (next === undefined || next === cursor || seenCursors.has(next)) {
      throw new Error("Exeligmos returned a repeated or missing record cursor");
    }
    seenCursors.add(next);
    cursor = next;
    checkpoint.recordsCursor = next;
    await persist(options, checkpoint);
  }

  if (!options.dryRun) {
    log(`Checkpoint saved at ${options.checkpointPath}.`);
  }
  return summary;
}

async function processRecord(
  record: ExeligmosRecord,
  tags: ReadonlyMap<string, ExeligmosTag>,
  source: ExeligmosClient,
  destination: FractonicaClient,
  checkpoint: ImportCheckpoint,
  summary: ImportSummary,
  options: ImportOptions,
): Promise<void> {
  summary.recordsSeen += 1;
  summary.mediaObjects += record.media.length;
  summary.mediaBytes += record.media.reduce((total, media) => total + media.byteLength, 0);
  if (record.visibility === "public") summary.publicRecords += 1;
  else summary.privateRecords += 1;

  let mapped;
  try {
    mapped = mapRecord(record, tags);
  } catch (error) {
    if (!(error instanceof UnsupportedRecordError)) throw error;
    summary.recordsSkipped += 1;
    summary.warnings.push(error.message);
    const key = `skipped:${record.originId}:revision:${record.revision}`;
    if (!options.dryRun && checkpoint.records[key] === undefined) {
      checkpoint.records[key] = {
        sourceRecordId: record.id,
        sourceOriginId: record.originId,
        sourceRevision: record.revision,
        entityId: record.originId,
        operationId: key,
        status: "skipped",
        mediaIds: record.media.map((media) => media.id),
        warning: error.message,
      };
      await persist(options, checkpoint);
    }
    options.log?.(`Skipped ${record.id}: ${error.message}`);
    return;
  }

  summary.warnings.push(...mapped.warnings.map((warning) => `${record.id}: ${warning}`));
  if (options.dryRun) {
    options.log?.(
      `Planned ${record.id} (${record.visibility}, ${mapped.operation.body.document.resources.length} resources).`,
    );
    return;
  }

  const key = mapped.operation.operationId;
  let recordCheckpoint = checkpoint.records[key];
  let operation: OperationSubmission;
  if (
    recordCheckpoint !== undefined &&
    (recordCheckpoint.status === "imported" || recordCheckpoint.status === "verified")
  ) {
    operation = {
      ...mapped.operation,
      causalParents:
        recordCheckpoint.causalParents ??
        attachPriorRevisionParent(mapped.operation, record.revision, checkpoint).causalParents,
    };
  } else {
    operation = await preflightDestinationOperation(mapped.operation, record, destination);
  }
  if (recordCheckpoint === undefined) {
    recordCheckpoint = {
      sourceRecordId: record.id,
      sourceOriginId: record.originId,
      sourceRevision: record.revision,
      entityId: operation.entityId,
      operationId: operation.operationId,
      status: "planned",
      causalParents: [...operation.causalParents],
      mediaIds: mapped.blobs.map((blob) => blob.checkpointSourceId),
    };
    checkpoint.records[key] = recordCheckpoint;
    await persist(options, checkpoint);
  } else {
    validateRecordCheckpoint(recordCheckpoint, record, operation);
    if (recordCheckpoint.status === "planned") {
      recordCheckpoint.causalParents = [...operation.causalParents];
      await persist(options, checkpoint);
    }
  }

  if (recordCheckpoint.status === "skipped") {
    summary.recordsSkipped += 1;
    return;
  }
  if (recordCheckpoint.status === "imported" || recordCheckpoint.status === "verified") {
    if (options.verify) {
      const sequence = requireSequence(recordCheckpoint);
      await destination.verifyStoredOperation(operation, sequence);
      recordCheckpoint.causalParents = [...operation.causalParents];
      recordCheckpoint.status = "verified";
      summary.verifiedRecords += 1;
      await persist(options, checkpoint);
    }
    options.log?.(`Already imported ${record.id}; checkpoint verified.`);
    return;
  }

  await ensureBlobs(
    mapped.blobs,
    source,
    destination,
    checkpoint,
    summary,
    options,
  );
  // Media transfer can be long. Refresh the causal view immediately before
  // append so a destination change during upload is not silently ignored.
  operation = await preflightDestinationOperation(mapped.operation, record, destination);
  recordCheckpoint.causalParents = [...operation.causalParents];
  await persist(options, checkpoint);
  const submitted = await destination.submitOperation(
    operation,
    idempotencyKeyForOperation(operation.operationId),
  );
  if (submitted.stored.operation.operationId !== operation.operationId) {
    throw new Error(`destination returned the wrong operation for record ${record.id}`);
  }
  recordCheckpoint.destinationLocalSequence = submitted.stored.localSequence;
  recordCheckpoint.causalParents = [...operation.causalParents];
  recordCheckpoint.status = "imported";
  if (submitted.replayed) summary.recordsReplayed += 1;
  else summary.recordsImported += 1;
  await persist(options, checkpoint);

  if (options.verify) {
    await destination.verifyStoredOperation(
      operation,
      submitted.stored.localSequence,
    );
    recordCheckpoint.status = "verified";
    summary.verifiedRecords += 1;
    await persist(options, checkpoint);
  }
  options.log?.(
    `${submitted.replayed ? "Replayed" : "Imported"} ${record.id} as ${operation.entityId}.`,
  );
}

async function preflightDestinationOperation(
  operation: OperationSubmission,
  record: ExeligmosRecord,
  destination: FractonicaClient,
): Promise<OperationSubmission> {
  const state = await destination.entityState(operation.entityId);
  if (state === undefined) return operation;
  if (state.entityId.toLowerCase() !== operation.entityId.toLowerCase()) {
    throw checkpointRecoveryError(operation.entityId, "the entity endpoint returned another ID");
  }

  const matchingCurrent = state.heads.filter(
    (head) => head.operation.operationId === operation.operationId,
  );
  if (matchingCurrent.length > 0) {
    if (matchingCurrent.length !== 1 || state.heads.length !== 1) {
      throw checkpointRecoveryError(
        operation.entityId,
        "the current imported operation is one of several conflicting heads",
      );
    }
    const current = matchingCurrent[0];
    if (current === undefined) {
      throw checkpointRecoveryError(operation.entityId, "the matching head disappeared");
    }
    const causalParents = parseCausalParents(current, operation.entityId);
    const replay = { ...operation, causalParents };
    try {
      destination.assertStoredOperationMatches(replay, current);
    } catch (error) {
      throw checkpointRecoveryError(
        operation.entityId,
        "the deterministic operation ID already exists with different content",
        error,
      );
    }
    return replay;
  }

  const causalParents: string[] = [];
  for (const head of state.heads) {
    const revision = recognizedExeligmosRevision(head, record);
    if (revision >= record.revision) {
      throw checkpointRecoveryError(
        operation.entityId,
        `destination head revision ${revision} is not older than source revision ${record.revision}`,
      );
    }
    causalParents.push(head.operation.operationId);
  }
  causalParents.sort();
  return { ...operation, causalParents };
}

function recognizedExeligmosRevision(
  head: StoredOperation,
  record: ExeligmosRecord,
): number {
  const operation = head.operation as unknown as Record<string, unknown>;
  const body = asObject(operation.body);
  const document = asObject(body?.document);
  const metadata = asObject(document?.metadata);
  const migration = asObject(metadata?.migration);
  const revision = migration?.sourceRevision;
  if (
    operation.protocolVersion !== 1 ||
    operation.entityId !== record.originId.toLowerCase() ||
    operation.schema !== "record.v1" ||
    body?.kind !== "put" ||
    migration?.mapping !== "exeligmos-record-v1" ||
    typeof migration.sourceOriginId !== "string" ||
    migration.sourceOriginId.toLowerCase() !== record.originId.toLowerCase() ||
    typeof revision !== "number" ||
    !Number.isSafeInteger(revision) ||
    revision < 1
  ) {
    throw checkpointRecoveryError(
      record.originId,
      `head ${head.operation.operationId} is not a recognized Exeligmos importer operation`,
    );
  }
  const expectedOperationId = operationIdForOriginRevision(
    record.originId,
    revision,
    "destination migration provenance",
  );
  if (head.operation.operationId !== expectedOperationId) {
    throw checkpointRecoveryError(
      record.originId,
      `head ${head.operation.operationId} does not match its deterministic revision identity`,
    );
  }
  return revision;
}

function parseCausalParents(
  stored: StoredOperation,
  entityId: string,
): string[] {
  const value = (stored.operation as unknown as Record<string, unknown>).causalParents;
  if (
    !Array.isArray(value) ||
    value.length > 64 ||
    !value.every((item) => typeof item === "string") ||
    new Set(value).size !== value.length
  ) {
    throw checkpointRecoveryError(entityId, "the stored operation has invalid causal parents");
  }
  return [...value];
}

function asObject(value: unknown): Record<string, unknown> | undefined {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : undefined;
}

function checkpointRecoveryError(
  entityId: string,
  reason: string,
  cause?: unknown,
): Error {
  const message = `cannot safely continue entity ${entityId} from destination state: ${reason}. Restore the original checkpoint if one existed, or inspect and explicitly merge the destination entity before retrying; no operation was submitted.`;
  return cause === undefined ? new Error(message) : new Error(message, { cause });
}

async function ensureBlobs(
  blobs: readonly MappedBlob[],
  source: ExeligmosClient,
  destination: FractonicaClient,
  checkpoint: ImportCheckpoint,
  summary: ImportSummary,
  options: ImportOptions,
): Promise<void> {
  if (blobs.length === 0) return;
  const availability = await destination.blobAvailability(
    blobs.map((blob) => blob.resource.contentId),
  );
  const available = new Map(
    availability.available.map((descriptor) => [descriptor.contentId, descriptor]),
  );

  for (const blob of blobs) {
    const descriptor = available.get(blob.resource.contentId);
    let mediaCheckpoint = getOrCreateMediaCheckpoint(checkpoint, blob);
    if (descriptor !== undefined) {
      if (descriptor.byteLength !== blob.resource.byteLength) {
        throw new Error(
          `destination content ${descriptor.contentId} has ${descriptor.byteLength} bytes; expected ${blob.resource.byteLength}`,
        );
      }
      mediaCheckpoint.completed = true;
      mediaCheckpoint.verified = true;
      mediaCheckpoint.uploadOffset = blob.resource.byteLength;
      summary.mediaAlreadyAvailable += 1;
      await persist(options, checkpoint);
      continue;
    }
    mediaCheckpoint = await uploadBlob(
      blob,
      mediaCheckpoint,
      source,
      destination,
      checkpoint,
      options,
    );
    const verification = await destination.blobAvailability([blob.resource.contentId]);
    const verified = verification.available.find(
      (candidate) => candidate.contentId === blob.resource.contentId,
    );
    if (verified === undefined || verified.byteLength !== blob.resource.byteLength) {
      throw new Error(`uploaded blob ${blob.resource.contentId} is not available with the expected length`);
    }
    mediaCheckpoint.completed = true;
    mediaCheckpoint.verified = true;
    await persist(options, checkpoint);
    summary.mediaUploaded += 1;
  }
}

async function uploadBlob(
  blob: MappedBlob,
  mediaCheckpoint: MediaCheckpoint,
  source: ExeligmosClient,
  destination: FractonicaClient,
  checkpoint: ImportCheckpoint,
  options: ImportOptions,
): Promise<MediaCheckpoint> {
  let offset = 0;
  if (mediaCheckpoint.uploadUrl !== undefined) {
    try {
      const state = await destination.headUpload(mediaCheckpoint.uploadUrl);
      if (state.length !== blob.resource.byteLength) {
        throw new Error(
          `resumable upload length ${state.length} does not match ${blob.resource.byteLength}`,
        );
      }
      if (state.offset > state.length) {
        throw new Error(`resumable upload offset ${state.offset} exceeds length ${state.length}`);
      }
      offset = state.offset;
      if (state.contentId !== undefined && state.contentId !== blob.resource.contentId) {
        throw new Error(`resumable upload completed as unexpected ${state.contentId}`);
      }
    } catch (error) {
      if (!destination.isUploadGone(error)) throw error;
      delete mediaCheckpoint.uploadUrl;
      mediaCheckpoint.uploadOffset = 0;
      mediaCheckpoint.completed = false;
      mediaCheckpoint.verified = false;
      await persist(options, checkpoint);
    }
  }
  if (mediaCheckpoint.uploadUrl === undefined) {
    const created = await destination.createUpload(blob.resource.byteLength, {
      ...(blob.resource.originalName === undefined
        ? {}
        : { filename: blob.resource.originalName }),
      mediaType: blob.resource.mediaType,
      contentId: blob.resource.contentId,
    });
    mediaCheckpoint.uploadUrl = created.uploadUrl;
    mediaCheckpoint.uploadOffset = 0;
    offset = 0;
    await persist(options, checkpoint);
  }
  const uploadUrl = mediaCheckpoint.uploadUrl;
  if (uploadUrl === undefined) throw new Error("upload URL disappeared from checkpoint");

  const digest = createHash("sha256");
  let sourceBytes = 0;
  let pendingLength = 0;
  const pending = Buffer.allocUnsafe(
    Math.max(1, Math.min(MAX_TUS_CHUNK_BYTES, blob.resource.byteLength - offset)),
  );
  const chunks = await sourceChunks(blob, source);
  for await (const chunk of chunks) {
    digest.update(chunk);
    const chunkStart = sourceBytes;
    sourceBytes += chunk.byteLength;
    if (sourceBytes > blob.resource.byteLength) {
      throw new Error(`source ${blob.checkpointSourceId} exceeded its declared byte length`);
    }
    let position = Math.max(0, offset - chunkStart);
    while (position < chunk.byteLength) {
      const capacity = pending.byteLength - pendingLength;
      const count = Math.min(capacity, chunk.byteLength - position);
      Buffer.from(chunk.buffer, chunk.byteOffset + position, count).copy(
        pending,
        pendingLength,
      );
      pendingLength += count;
      position += count;
      if (pendingLength === pending.byteLength) {
        const result = await patchWithRecovery(
          destination,
          uploadUrl,
          offset,
          pending.subarray(0, pendingLength),
        );
        offset = result.offset;
        validateCompletionContentId(result, blob.resource.contentId);
        pendingLength = 0;
        mediaCheckpoint.uploadOffset = offset;
        await persist(options, checkpoint);
      }
    }
  }
  if (sourceBytes !== blob.resource.byteLength) {
    throw new Error(
      `source ${blob.checkpointSourceId} returned ${sourceBytes} bytes; expected ${blob.resource.byteLength}`,
    );
  }
  const actualSha256 = digest.digest("hex");
  if (actualSha256 !== mediaCheckpoint.sha256) {
    throw new Error(
      `source ${blob.checkpointSourceId} SHA-256 is ${actualSha256}; expected ${mediaCheckpoint.sha256}`,
    );
  }
  if (pendingLength > 0) {
    const result = await patchWithRecovery(
      destination,
      uploadUrl,
      offset,
      pending.subarray(0, pendingLength),
    );
    offset = result.offset;
    validateCompletionContentId(result, blob.resource.contentId);
    mediaCheckpoint.uploadOffset = offset;
    await persist(options, checkpoint);
  }
  if (offset !== blob.resource.byteLength) {
    throw new Error(`upload stopped at ${offset}; expected ${blob.resource.byteLength}`);
  }
  const completed = await destination.headUpload(uploadUrl);
  if (completed.offset !== completed.length || completed.contentId !== blob.resource.contentId) {
    throw new Error(`destination did not finalize ${blob.resource.contentId}`);
  }
  mediaCheckpoint.completed = true;
  return mediaCheckpoint;
}

async function patchWithRecovery(
  destination: FractonicaClient,
  uploadUrl: string,
  offset: number,
  bytes: Uint8Array,
): Promise<TusPatchResult> {
  let lastError: unknown;
  for (let attempt = 1; attempt <= 4; attempt += 1) {
    try {
      return await destination.patchUpload(uploadUrl, offset, bytes);
    } catch (error) {
      lastError = error;
      let state;
      try {
        state = await destination.headUpload(uploadUrl);
      } catch {
        if (attempt === 4) throw error;
        await delay(250 * 2 ** (attempt - 1));
        continue;
      }
      if (state.offset === offset + bytes.byteLength) {
        return {
          offset: state.offset,
          ...(state.contentId === undefined ? {} : { contentId: state.contentId }),
        };
      }
      if (state.offset !== offset) {
        throw new Error(
          `TUS upload moved to unexpected offset ${state.offset} after a failed PATCH`,
          { cause: error },
        );
      }
      if (attempt < 4) await delay(250 * 2 ** (attempt - 1));
    }
  }
  throw lastError instanceof Error ? lastError : new Error("TUS PATCH failed");
}

async function sourceChunks(
  blob: MappedBlob,
  source: ExeligmosClient,
): Promise<AsyncIterable<Uint8Array>> {
  if (blob.source.kind === "bytes") {
    const bytes = blob.source.bytes;
    return (async function* bytesSource() {
      yield bytes;
    })();
  }
  const response = await source.downloadMedia(blob.source.media);
  if (response.body === null) throw new Error(`media ${blob.source.media.id} returned no body`);
  return streamChunks(response.body);
}

export async function* streamChunks(
  stream: ReadableStream<Uint8Array>,
): AsyncGenerator<Uint8Array> {
  const reader = stream.getReader();
  let reachedEnd = false;
  try {
    for (;;) {
      const result = await reader.read();
      if (result.done) {
        reachedEnd = true;
        break;
      }
      yield result.value;
    }
  } finally {
    if (!reachedEnd) {
      await reader.cancel("source media processing ended before EOF").catch(() => undefined);
    }
    reader.releaseLock();
  }
}

function getOrCreateMediaCheckpoint(
  checkpoint: ImportCheckpoint,
  blob: MappedBlob,
): MediaCheckpoint {
  const key = blob.resource.contentId;
  const existing = checkpoint.media[key];
  const sha256 = key.slice("sha-256:".length);
  if (existing !== undefined) {
    if (existing.sha256 !== sha256 || existing.byteLength !== blob.resource.byteLength) {
      throw new Error(`checkpoint content metadata disagrees for ${key}`);
    }
    return existing;
  }
  const created: MediaCheckpoint = {
    sourceMediaId: blob.checkpointSourceId,
    sha256,
    byteLength: blob.resource.byteLength,
    contentId: key,
    uploadOffset: 0,
    completed: false,
    verified: false,
  };
  checkpoint.media[key] = created;
  return created;
}

function attachPriorRevisionParent(
  operation: OperationSubmission,
  sourceRevision: number,
  checkpoint: ImportCheckpoint,
): OperationSubmission {
  const prior = Object.values(checkpoint.records)
    .filter(
      (candidate) =>
        candidate.sourceOriginId.toLowerCase() === operation.entityId.toLowerCase() &&
        candidate.sourceRevision < sourceRevision &&
        (candidate.status === "imported" || candidate.status === "verified"),
    )
    .sort((left, right) => right.sourceRevision - left.sourceRevision)[0];
  return prior === undefined
    ? operation
    : { ...operation, causalParents: [prior.operationId] };
}

function validateRecordCheckpoint(
  checkpoint: RecordCheckpoint,
  record: ExeligmosRecord,
  operation: OperationSubmission,
): void {
  if (
    checkpoint.sourceRecordId !== record.id ||
    checkpoint.sourceOriginId.toLowerCase() !== record.originId.toLowerCase() ||
    checkpoint.sourceRevision !== record.revision ||
    checkpoint.entityId.toLowerCase() !== operation.entityId.toLowerCase() ||
    checkpoint.operationId !== operation.operationId
  ) {
    throw new Error(`checkpoint identity disagrees with source record ${record.id}`);
  }
}

async function readTags(source: ExeligmosClient): Promise<Map<string, ExeligmosTag>> {
  const tags = new Map<string, ExeligmosTag>();
  const seen = new Set<string>();
  let cursor: string | undefined;
  for (;;) {
    const page = await source.listTags(cursor);
    for (const tag of page.data) {
      if (tags.has(tag.id)) throw new Error(`tag ${tag.id} appeared more than once`);
      tags.set(tag.id, tag);
    }
    if (!page.hasMore) return tags;
    const next = page.nextCursor;
    if (next === undefined || next === cursor || seen.has(next)) {
      throw new Error("Exeligmos returned a repeated or missing tag cursor");
    }
    seen.add(next);
    cursor = next;
  }
}

function validateCompletionContentId(
  result: TusPatchResult,
  expected: `sha-256:${string}`,
): void {
  if (result.contentId !== undefined && result.contentId !== expected) {
    throw new Error(`destination finalized content as ${result.contentId}, expected ${expected}`);
  }
}

function requireSequence(checkpoint: RecordCheckpoint): number {
  const sequence = checkpoint.destinationLocalSequence;
  if (sequence === undefined) {
    throw new Error(`checkpoint for ${checkpoint.sourceRecordId} has no destination sequence`);
  }
  return sequence;
}

async function persist(
  options: ImportOptions,
  checkpoint: ImportCheckpoint,
): Promise<void> {
  if (!options.dryRun) await saveCheckpoint(options.checkpointPath, checkpoint);
}

function emptySummary(): ImportSummary {
  return {
    tags: 0,
    recordsSeen: 0,
    recordsImported: 0,
    recordsReplayed: 0,
    recordsSkipped: 0,
    publicRecords: 0,
    privateRecords: 0,
    mediaObjects: 0,
    mediaBytes: 0,
    mediaUploaded: 0,
    mediaAlreadyAvailable: 0,
    verifiedRecords: 0,
    warnings: [],
  };
}

function delay(milliseconds: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

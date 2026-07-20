import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { once } from "node:events";
import { test } from "node:test";

import { importExeligmos, streamChunks } from "./importer.ts";
import { mapRecord } from "./mapping.ts";
import type { ExeligmosPublicRecord } from "./types.ts";

const SOURCE_TOKEN = "source-secret";
const DESTINATION_TOKEN = "destination-secret";
const mediaBytes = Buffer.from("streamed media payload");
const mediaSha256 = createHash("sha256").update(mediaBytes).digest("hex");
const contentId = `sha-256:${mediaSha256}`;

test("HTTP importer streams content, checkpoints, submits, verifies, and resumes idempotently", async () => {
  const source = createServer(sourceHandler);
  const destinationState = {
    upload: Buffer.alloc(0),
    available: false,
    operation: undefined as Record<string, unknown> | undefined,
    operationPosts: 0,
    dropNextPatchResponse: true,
    droppedPatchResponses: 0,
  };
  const destination = createServer((request, response) =>
    destinationHandler(destinationState, request, response),
  );
  const directory = await mkdtemp(join(tmpdir(), "fractonica-import-http-"));
  try {
    const sourceUrl = await listen(source);
    const destinationUrl = await listen(destination);
    const checkpointPath = join(directory, "checkpoint.json");
    const summary = await importExeligmos({
      sourceBaseUrl: sourceUrl,
      destinationBaseUrl: destinationUrl,
      sourceToken: SOURCE_TOKEN,
      destinationToken: DESTINATION_TOKEN,
      checkpointPath,
      dryRun: false,
      verify: true,
    });
    assert.equal(summary.recordsImported, 1);
    assert.equal(summary.mediaUploaded, 1);
    assert.equal(summary.verifiedRecords, 1);
    assert.deepEqual(destinationState.upload, mediaBytes);
    assert.equal(destinationState.operationPosts, 1);
    assert.equal(destinationState.droppedPatchResponses, 1);
    const checkpointText = await readFile(checkpointPath, "utf8");
    assert.equal(checkpointText.includes(SOURCE_TOKEN), false);
    assert.equal(checkpointText.includes(DESTINATION_TOKEN), false);

    const second = await importExeligmos({
      sourceBaseUrl: sourceUrl,
      destinationBaseUrl: destinationUrl,
      sourceToken: SOURCE_TOKEN,
      destinationToken: DESTINATION_TOKEN,
      checkpointPath,
      dryRun: false,
      verify: true,
    });
    assert.equal(second.recordsImported, 0);
    assert.equal(second.verifiedRecords, 1);
    assert.equal(destinationState.operationPosts, 1);
  } finally {
    source.close();
    destination.close();
    await Promise.all([once(source, "close"), once(destination, "close")]);
    await rm(directory, { recursive: true, force: true });
  }
});

test("dry run performs no destination requests", async () => {
  const source = createServer(sourceHandler);
  try {
    const sourceUrl = await listen(source);
    const summary = await importExeligmos({
      sourceBaseUrl: sourceUrl,
      destinationBaseUrl: "http://127.0.0.1:1",
      sourceToken: SOURCE_TOKEN,
      checkpointPath: "/unused/dry-run-checkpoint.json",
      dryRun: true,
      verify: true,
    });
    assert.equal(summary.recordsSeen, 1);
    assert.equal(summary.mediaObjects, 1);
  } finally {
    source.close();
    await once(source, "close");
  }
});

test("signed-v2 destination is rejected before source reads or destination writes", async () => {
  let sourceRequests = 0;
  let destinationWrites = 0;
  const destinationRequests: string[] = [];
  const source = createServer((request, response) => {
    sourceRequests += 1;
    sourceHandler(request, response);
  });
  const destination = createServer((request, response) => {
    destinationRequests.push(`${request.method ?? "GET"} ${request.url ?? ""}`);
    if (request.method !== "GET") destinationWrites += 1;
    if (request.headers.authorization !== `Bearer ${DESTINATION_TOKEN}`) {
      response.writeHead(401).end();
      return;
    }
    if (request.method === "GET" && request.url?.startsWith("/api/v1/operations?") === true) {
      json(response, 410, {
        type: "about:blank",
        title: "Gone",
        status: 410,
        code: "operation_v1_obsolete",
        detail: "Unsigned operation protocol v1 is obsolete.",
      });
      return;
    }
    response.writeHead(500).end();
  });
  const directory = await mkdtemp(join(tmpdir(), "fractonica-import-v2-guard-"));
  try {
    const sourceUrl = await listen(source);
    const destinationUrl = await listen(destination);
    const checkpointPath = join(directory, "checkpoint.json");
    await assert.rejects(
      importExeligmos({
        sourceBaseUrl: sourceUrl,
        destinationBaseUrl: destinationUrl,
        sourceToken: SOURCE_TOKEN,
        destinationToken: DESTINATION_TOKEN,
        checkpointPath,
        dryRun: false,
        verify: true,
      }),
      (error: unknown) => {
        assert.ok(error instanceof Error);
        assert.equal(error.name, "LegacyV1CompatibilityError");
        assert.match(error.message, /only emits unsigned Fractonica operation protocol v1/);
        assert.match(error.message, /explicitly retired operation protocol v1 \(HTTP 410\)/);
        assert.match(error.message, /client-side actor-key\/signing adapter/);
        return true;
      },
    );
    assert.equal(sourceRequests, 0);
    assert.equal(destinationWrites, 0);
    assert.deepEqual(destinationRequests, ["GET /api/v1/operations?after=0&limit=1"]);
    await assert.rejects(readFile(checkpointPath), { code: "ENOENT" });
  } finally {
    source.close();
    destination.close();
    await Promise.all([once(source, "close"), once(destination, "close")]);
    await rm(directory, { recursive: true, force: true });
  }
});

test("source stream is cancelled when its consumer stops before EOF", async () => {
  let cancelled = false;
  const stream = new ReadableStream<Uint8Array>({
    start(controller) {
      controller.enqueue(Uint8Array.of(1, 2, 3));
    },
    cancel() {
      cancelled = true;
    },
  });
  const iterator = streamChunks(stream);
  assert.deepEqual((await iterator.next()).value, Uint8Array.of(1, 2, 3));
  await iterator.return(undefined);
  assert.equal(cancelled, true);
});

test("missing checkpoint continues a newer revision from recognized destination heads", async () => {
  const revisionOne = sourceRecord(1, "Initial revision");
  const revisionTwo = sourceRecord(2, "Revised after checkpoint loss");
  const priorOperation = mapRecord(revisionOne, new Map()).operation;
  const source = createServer(sourceHandlerFor(revisionTwo));
  const destinationState = {
    upload: Buffer.from(mediaBytes),
    available: true,
    operation: structuredClone(priorOperation) as unknown as Record<string, unknown>,
    operationPosts: 0,
    dropNextPatchResponse: false,
    droppedPatchResponses: 0,
  };
  const destination = createServer((request, response) =>
    destinationHandler(destinationState, request, response),
  );
  const directory = await mkdtemp(join(tmpdir(), "fractonica-import-recovery-"));
  try {
    const sourceUrl = await listen(source);
    const destinationUrl = await listen(destination);
    const checkpointPath = join(directory, "new-checkpoint.json");
    const summary = await importExeligmos({
      sourceBaseUrl: sourceUrl,
      destinationBaseUrl: destinationUrl,
      sourceToken: SOURCE_TOKEN,
      destinationToken: DESTINATION_TOKEN,
      checkpointPath,
      dryRun: false,
      verify: false,
    });
    assert.equal(summary.recordsImported, 1);
    assert.equal(destinationState.operationPosts, 1);
    assert.deepEqual(destinationState.operation?.causalParents, [priorOperation.operationId]);
    const checkpoint = JSON.parse(await readFile(checkpointPath, "utf8")) as {
      records: Record<string, { causalParents?: string[] }>;
    };
    assert.deepEqual(Object.values(checkpoint.records)[0]?.causalParents, [
      priorOperation.operationId,
    ]);
  } finally {
    source.close();
    destination.close();
    await Promise.all([once(source, "close"), once(destination, "close")]);
    await rm(directory, { recursive: true, force: true });
  }
});

test("missing checkpoint aborts before writes for an unrecognized destination head", async () => {
  const source = createServer(sourceHandlerFor(sourceRecord(2, "Unsafe revision")));
  const manualOperation = structuredClone(
    mapRecord(sourceRecord(1, "Manual collision"), new Map()).operation,
  ) as unknown as Record<string, unknown>;
  manualOperation.operationId = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
  const body = manualOperation.body as { document: { metadata: Record<string, unknown> } };
  body.document.metadata = { owner: "manual" };
  const destinationState = {
    upload: Buffer.alloc(0),
    available: false,
    operation: manualOperation,
    operationPosts: 0,
    dropNextPatchResponse: false,
    droppedPatchResponses: 0,
  };
  const destination = createServer((request, response) =>
    destinationHandler(destinationState, request, response),
  );
  const directory = await mkdtemp(join(tmpdir(), "fractonica-import-unsafe-recovery-"));
  try {
    const sourceUrl = await listen(source);
    const destinationUrl = await listen(destination);
    const checkpointPath = join(directory, "new-checkpoint.json");
    await assert.rejects(
      importExeligmos({
        sourceBaseUrl: sourceUrl,
        destinationBaseUrl: destinationUrl,
        sourceToken: SOURCE_TOKEN,
        destinationToken: DESTINATION_TOKEN,
        checkpointPath,
        dryRun: false,
        verify: false,
      }),
      /cannot safely continue entity .* from destination state/,
    );
    assert.equal(destinationState.operationPosts, 0);
    assert.equal(destinationState.upload.byteLength, 0);
    await assert.rejects(readFile(checkpointPath), { code: "ENOENT" });
  } finally {
    source.close();
    destination.close();
    await Promise.all([once(source, "close"), once(destination, "close")]);
    await rm(directory, { recursive: true, force: true });
  }
});

function sourceHandler(request: IncomingMessage, response: ServerResponse): void {
  sourceHandlerFor(sourceRecord(1, "Imported over HTTP"))(request, response);
}

function sourceHandlerFor(
  record: ExeligmosPublicRecord,
): (request: IncomingMessage, response: ServerResponse) => void {
  return (request, response) => {
    if (request.headers.authorization !== `Bearer ${SOURCE_TOKEN}`) {
      response.writeHead(401).end();
      return;
    }
    if (request.url?.startsWith("/v1/tags") === true) {
      json(response, 200, { data: [], hasMore: false });
      return;
    }
    if (request.url?.startsWith("/v1/records") === true) {
      json(response, 200, {
        data: [record],
        hasMore: false,
      });
      return;
    }
    if (request.url?.includes("/v1/media/") === true) {
      response.writeHead(200, {
        "Content-Type": "application/octet-stream",
        "Content-Length": String(mediaBytes.byteLength),
        "X-Content-SHA256": mediaSha256,
      });
      response.end(mediaBytes);
      return;
    }
    response.writeHead(404).end();
  };
}

function sourceRecord(revision: number, text: string): ExeligmosPublicRecord {
  return {
    id: "Rec01",
    originId: "11111111-1111-4111-8111-111111111111",
    userId: "22222222-2222-4222-8222-222222222222",
    deviceId: "33333333-3333-4333-8333-333333333333",
    visibility: "public",
    revision,
    createdAt: "2026-07-10T10:00:00.000Z",
    updatedAt: `2026-07-${String(10 + revision).padStart(2, "0")}T10:00:00.000Z`,
    occurredAt: "2026-07-09T10:00:00.000Z",
    payload: { text, emoji: "🌀" },
    tagIds: [],
    tags: [],
    metadata: {},
    references: [],
    media: [
      {
        id: "44444444-4444-4444-8444-444444444444",
        userId: "22222222-2222-4222-8222-222222222222",
        deviceId: "33333333-3333-4333-8333-333333333333",
        fileName: "sample.bin",
        contentType: "application/octet-stream",
        byteLength: mediaBytes.byteLength,
        sha256: mediaSha256,
        revision: 1,
        createdAt: "2026-07-09T10:00:01.000Z",
        contentUrl: "/v1/media/44444444-4444-4444-8444-444444444444/content",
      },
    ],
  };
}

async function destinationHandler(
  state: {
    upload: Buffer;
    available: boolean;
    operation: Record<string, unknown> | undefined;
    operationPosts: number;
    dropNextPatchResponse: boolean;
    droppedPatchResponses: number;
  },
  request: IncomingMessage,
  response: ServerResponse,
): Promise<void> {
  if (request.headers.authorization !== `Bearer ${DESTINATION_TOKEN}`) {
    response.writeHead(401).end();
    return;
  }
  if (request.method === "GET" && request.url?.startsWith("/api/v1/entities/") === true) {
    if (state.operation === undefined) {
      json(response, 404, { code: "entity_not_found" });
    } else {
      const operation = state.operation;
      json(response, 200, {
        entityId: operation.entityId,
        schema: "record.v1",
        operationCount: 1,
        conflicted: false,
        heads: [stored(operation)],
      });
    }
    return;
  }
  if (request.method === "POST" && request.url === "/api/v1/blobs/availability") {
    json(
      response,
      200,
      state.available
        ? { available: [{ contentId, byteLength: mediaBytes.byteLength }], missing: [] }
        : { available: [], missing: [contentId] },
    );
    return;
  }
  if (request.method === "POST" && request.url === "/api/v1/uploads") {
    assert.equal(request.headers["tus-resumable"], "1.0.0");
    assert.equal(request.headers["upload-length"], String(mediaBytes.byteLength));
    response.writeHead(201, {
      Location: "/api/v1/uploads/test-upload",
      "Tus-Resumable": "1.0.0",
      "Upload-Offset": "0",
    }).end();
    return;
  }
  if (request.method === "HEAD" && request.url === "/api/v1/uploads/test-upload") {
    response.writeHead(200, {
      "Tus-Resumable": "1.0.0",
      "Upload-Length": String(mediaBytes.byteLength),
      "Upload-Offset": String(state.upload.byteLength),
      ...(state.available ? { "Fractonica-Content-Id": contentId } : {}),
    }).end();
    return;
  }
  if (request.method === "PATCH" && request.url === "/api/v1/uploads/test-upload") {
    const body = await readBody(request);
    assert.equal(request.headers["upload-offset"], String(state.upload.byteLength));
    assert.equal(
      request.headers["upload-checksum"],
      `sha256 ${createHash("sha256").update(body).digest("base64")}`,
    );
    state.upload = Buffer.concat([state.upload, body]);
    state.available = state.upload.byteLength === mediaBytes.byteLength;
    if (state.dropNextPatchResponse) {
      state.dropNextPatchResponse = false;
      state.droppedPatchResponses += 1;
      request.socket.destroy();
      return;
    }
    response.writeHead(204, {
      "Tus-Resumable": "1.0.0",
      "Upload-Offset": String(state.upload.byteLength),
      ...(state.available ? { "Fractonica-Content-Id": contentId } : {}),
    }).end();
    return;
  }
  if (request.method === "POST" && request.url === "/api/v1/operations") {
    state.operationPosts += 1;
    state.operation = JSON.parse((await readBody(request)).toString("utf8")) as Record<string, unknown>;
    json(response, 201, stored(state.operation));
    return;
  }
  if (request.method === "GET" && request.url?.startsWith("/api/v1/operations?") === true) {
    json(response, 200, {
      operations: state.operation === undefined ? [] : [stored(state.operation)],
      nextAfter: state.operation === undefined ? 0 : 1,
      hasMore: false,
    });
    return;
  }
  response.writeHead(404).end();
}

function stored(operation: Record<string, unknown>): Record<string, unknown> {
  return {
    localSequence: 1,
    operation: {
      ...operation,
      actorId: "99999999-9999-4999-8999-999999999999",
    },
  };
}

async function listen(server: ReturnType<typeof createServer>): Promise<string> {
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const address = server.address();
  if (address === null || typeof address === "string") throw new Error("server has no TCP address");
  return `http://127.0.0.1:${address.port}`;
}

async function readBody(request: IncomingMessage): Promise<Buffer> {
  const chunks: Buffer[] = [];
  for await (const chunk of request) chunks.push(Buffer.from(chunk as Uint8Array));
  return Buffer.concat(chunks);
}

function json(response: ServerResponse, status: number, value: unknown): void {
  const body = Buffer.from(JSON.stringify(value));
  response.writeHead(status, {
    "Content-Type": "application/json",
    "Content-Length": String(body.byteLength),
  });
  response.end(body);
}

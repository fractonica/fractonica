import { describe, expect, it, vi } from "vitest";

import { FractonicaNodeClient } from "./node-client";
import type { OperationId, SignedOperation, SpaceId } from "./types";

const spaceId = `space:${"1".repeat(64)}` as SpaceId;
const operationId = `sha-256:${"2".repeat(64)}` as OperationId;
const entityId = "019f75cd-77cf-76b1-b7c9-ad88db284f8e";

function operation(): SignedOperation {
  return {
    protocolVersion: 1,
    operationId,
    spaceId,
    actorId: `actor:ed25519:${"3".repeat(64)}`,
    entityId,
    schema: "record",
    causalParents: [],
    authorization: [`sha-256:${"4".repeat(64)}`],
    occurredAtUnixMs: 1,
    nonce: "5".repeat(32),
    body: {
      kind: "putRecord",
      payload: {
        visibility: "public",
        document: { startAtUnixMs: 1, metadata: {} },
      },
    },
    coseSign1: "Abc_123",
  };
}

function json(value: unknown, status = 200): Response {
  return new Response(JSON.stringify(value), {
    status,
    headers: { "content-type": "application/json" },
  });
}

function stored() {
  return { localSequence: 1, receivedAtUnixMs: 2, operation: operation() };
}

describe("FractonicaNodeClient", () => {
  it("uses the complete opaque keyset cursor for record pagination", async () => {
    const fetcher = vi.fn<typeof fetch>().mockResolvedValue(
      json({
        spaceId,
        schema: "record",
        items: [],
        nextCursor: { sortNumber: 10, entityId, operationId },
      }),
    );
    const client = new FractonicaNodeClient("http://127.0.0.1:8789/ignored", { fetcher });
    const page = await client.listRecords(spaceId, {
      limit: 25,
      cursor: { sortNumber: 20, entityId, operationId },
    });
    expect(page.nextCursor?.sortNumber).toBe(10);
    const url = new URL(String(fetcher.mock.calls[0]?.[0]));
    expect(url.pathname).toBe(`/api/spaces/${encodeURIComponent(spaceId)}/records`);
    expect(Object.fromEntries(url.searchParams)).toEqual({
      limit: "25",
      sortNumber: "20",
      entityId,
      operationId,
    });
  });

  it("submits an already-signed operation without a browser signing endpoint", async () => {
    const fetcher = vi.fn<typeof fetch>().mockResolvedValue(json(stored(), 201));
    const client = new FractonicaNodeClient("http://127.0.0.1:8789", {
      fetcher,
      bearerToken: "secret",
    });
    await expect(client.submit(operation())).resolves.toEqual(stored());
    const init = fetcher.mock.calls[0]?.[1];
    expect(init?.method).toBe("POST");
    expect(new Headers(init?.headers).get("authorization")).toBe("Bearer secret");
    expect(JSON.parse(String(init?.body))).toEqual(operation());
  });

  it("rejects response drift instead of silently accepting unknown fields", async () => {
    const fetcher = vi.fn<typeof fetch>().mockResolvedValue(
      json({ spaceId, schema: "record", items: [], unexpected: true }),
    );
    const client = new FractonicaNodeClient("http://127.0.0.1:8789", { fetcher });
    await expect(client.listRecords(spaceId)).rejects.toMatchObject({
      code: "invalid_contract_response",
    });
  });

  it("preserves structured problem codes", async () => {
    const fetcher = vi.fn<typeof fetch>().mockResolvedValue(
      json(
        {
          type: "https://fractonica.com/problems/space-not-found",
          title: "Space not found",
          status: 404,
          code: "space_not_found",
        },
        404,
      ),
    );
    const client = new FractonicaNodeClient("http://127.0.0.1:8789", { fetcher });
    await expect(client.stats(spaceId)).rejects.toMatchObject({
      status: 404,
      code: "space_not_found",
    });
  });
});

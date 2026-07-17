import { describe, expect, it, vi } from "vitest";
import { createNodeClient, DEFAULT_NODE_URL, resolveNodeBaseUrl } from "./api";

function jsonResponse(value: unknown, status = 200): Response {
  return new Response(JSON.stringify(value), {
    headers: { "Content-Type": "application/json" },
    status,
  });
}

const NODE_READY_RESPONSE = {
  status: "ready",
  profile: "node",
  storage: { kind: "sqlite", status: "ready", schemaVersion: 7 },
};

const NODE_RESPONSE = {
  installationId: "node-01",
  profile: "node",
  displayName: "Desk node",
  version: "0.1.0",
  startedAt: "2026-07-17T08:00:00.000Z",
  uptimeSeconds: 123,
  capabilities: ["records"],
};

const SAROS_READY_RESPONSE = {
  status: "ready",
  profile: "saros",
  storage: { kind: "none", status: "notConfigured" },
};

const SAROS_NODE_RESPONSE = {
  installationId: "saros-engine",
  profile: "saros",
  displayName: "Saros engine",
  version: "0.1.0",
  startedAt: "2026-07-17T08:00:00.000Z",
  uptimeSeconds: 123,
  capabilities: ["saros-calculation"],
};

describe("node client", () => {
  it("uses the loopback URL by default", () => {
    expect(resolveNodeBaseUrl("")).toBe(DEFAULT_NODE_URL);
  });

  it("fetches and validates both status endpoints", async () => {
    const fetcher = vi
      .fn<typeof fetch>()
      .mockResolvedValueOnce(jsonResponse(NODE_READY_RESPONSE))
      .mockResolvedValueOnce(jsonResponse(NODE_RESPONSE));
    const client = createNodeClient("http://127.0.0.1:8789", fetcher);

    await expect(client.readStatus()).resolves.toEqual({
      readiness: NODE_READY_RESPONSE,
      node: NODE_RESPONSE,
    });
    expect(fetcher).toHaveBeenCalledTimes(2);
    expect(fetcher.mock.calls.map(([url]) => url)).toEqual([
      "http://127.0.0.1:8789/health/ready",
      "http://127.0.0.1:8789/api/v1/node",
    ]);
  });

  it("accepts the stateless Saros profile without a schema version", async () => {
    const fetcher = vi
      .fn<typeof fetch>()
      .mockResolvedValueOnce(jsonResponse(SAROS_READY_RESPONSE))
      .mockResolvedValueOnce(jsonResponse(SAROS_NODE_RESPONSE));
    const client = createNodeClient("http://127.0.0.1:8789", fetcher);

    await expect(client.readStatus()).resolves.toEqual({
      readiness: SAROS_READY_RESPONSE,
      node: SAROS_NODE_RESPONSE,
    });
  });

  it("rejects a response that does not match the contract", async () => {
    const fetcher = vi
      .fn<typeof fetch>()
      .mockResolvedValueOnce(jsonResponse({ ...NODE_READY_RESPONSE, status: "starting" }))
      .mockResolvedValueOnce(jsonResponse(NODE_RESPONSE));
    const client = createNodeClient("http://127.0.0.1:8789", fetcher);

    await expect(client.readStatus()).rejects.toThrow(
      "The readiness response did not match the expected schema.",
    );
  });

  it("rejects incoherent profile and storage combinations", async () => {
    const fetcher = vi
      .fn<typeof fetch>()
      .mockResolvedValueOnce(
        jsonResponse({
          ...SAROS_READY_RESPONSE,
          storage: NODE_READY_RESPONSE.storage,
        }),
      )
      .mockResolvedValueOnce(jsonResponse(SAROS_NODE_RESPONSE));
    const client = createNodeClient("http://127.0.0.1:8789", fetcher);

    await expect(client.readStatus()).rejects.toThrow(
      "The readiness response did not match the expected schema.",
    );
  });

  it("rejects unexpected fields from either status contract", async () => {
    const fetcher = vi
      .fn<typeof fetch>()
      .mockResolvedValueOnce(jsonResponse(NODE_READY_RESPONSE))
      .mockResolvedValueOnce(jsonResponse({ ...NODE_RESPONSE, unexpected: true }));
    const client = createNodeClient("http://127.0.0.1:8789", fetcher);

    await expect(client.readStatus()).rejects.toThrow(
      "The node response did not match the expected schema.",
    );
  });

  it("rejects readiness and node responses from different profiles", async () => {
    const fetcher = vi
      .fn<typeof fetch>()
      .mockResolvedValueOnce(jsonResponse(NODE_READY_RESPONSE))
      .mockResolvedValueOnce(jsonResponse(SAROS_NODE_RESPONSE));
    const client = createNodeClient("http://127.0.0.1:8789", fetcher);

    await expect(client.readStatus()).rejects.toThrow(
      "The readiness and node profiles did not match.",
    );
  });

  it("sends the supervisor bearer token without exposing it in the base URL", async () => {
    const fetcher = vi
      .fn<typeof fetch>()
      .mockResolvedValueOnce(jsonResponse(NODE_READY_RESPONSE))
      .mockResolvedValueOnce(jsonResponse(NODE_RESPONSE));
    const token = "0123456789abcdef0123456789abcdef";
    const client = createNodeClient("http://127.0.0.1:49152", fetcher, 5_000, token);

    await client.readStatus();

    for (const [, request] of fetcher.mock.calls) {
      expect(request?.headers).toMatchObject({ Authorization: `Bearer ${token}` });
    }
    expect(client.baseUrl).toBe("http://127.0.0.1:49152");
    expect(client.baseUrl).not.toContain(token);
  });
});

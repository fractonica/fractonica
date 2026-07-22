import { describe, expect, it, vi } from "vitest";
import {
  createNodeClient,
  decodeDesktopNodeConnection,
  DEFAULT_NODE_URL,
  resolveNodeBaseUrl,
} from "./api";
import type { CreatePairingRequest } from "./api";

function jsonResponse(value: unknown, status = 200): Response {
  return new Response(JSON.stringify(value), {
    headers: { "Content-Type": "application/json" },
    status,
  });
}

const NODE_READY_RESPONSE = {
  status: "ready",
  profile: "node",
  storage: { kind: "sqlite", status: "ready" },
};

const NODE_RESPONSE = {
  installationId: "node-01",
  nodeId: `node:ed25519:${"2".repeat(64)}`,
  spaces: [{
    spaceId: `space:${"1".repeat(64)}`,
    displayName: "Personal space",
    genesisOperationId: `sha-256:${"3".repeat(64)}`,
    initialGrantOperationId: `sha-256:${"4".repeat(64)}`,
    controllerActorId: `actor:ed25519:${"5".repeat(64)}`,
    localWriterActorId: `actor:ed25519:${"6".repeat(64)}`,
    createdAtUnixMs: 1_784_265_600_000,
  }],
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
  it("decodes the exact desktop handoff", () => {
    const token = "0123456789abcdef0123456789abcdef";
    expect(decodeDesktopNodeConnection({
      baseUrl: "http://127.0.0.1:49152",
      bearerToken: token,
      pairingEndpointHints: ["http://192.168.1.12:49152"],
    })).toEqual({
      baseUrl: "http://127.0.0.1:49152",
      bearerToken: token,
      pairingEndpointHints: ["http://192.168.1.12:49152"],
    });
    expect(() => decodeDesktopNodeConnection({
      base_url: "http://127.0.0.1:49152",
      bearer_token: token,
    })).toThrow("expected schema");
  });

  it("keeps the desktop control handoff loopback-only", () => {
    expect(() => decodeDesktopNodeConnection({
      baseUrl: "http://192.168.1.12:49152",
      bearerToken: "0123456789abcdef0123456789abcdef",
      pairingEndpointHints: [],
    })).toThrow("non-loopback");
  });

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
      "http://127.0.0.1:8789/api/node",
    ]);
  });

  it("accepts the stateless Saros profile", async () => {
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

  it("creates, reads, confirms, and cancels strict pairing sessions with bearer auth", async () => {
    const invitationId = "7".repeat(32);
    const spaceId = `space:${"1".repeat(64)}`;
    const created = {
      invitationId,
      spaceId,
      state: "created",
      expiresAtUnixMs: 1_784_265_900_000,
    };
    const claimed = {
      ...created,
      state: "claimed",
      joinerNodeId: `node:ed25519:${"2".repeat(64)}`,
      subjectActorId: `actor:ed25519:${"3".repeat(64)}`,
      confirmationOctal: "0123456701",
    };
    const completed = {
      ...claimed,
      state: "completed",
      grantOperationId: `sha-256:${"4".repeat(64)}`,
    };
    const cancelled = { ...created, state: "cancelled" };
    const fetcher = vi
      .fn<typeof fetch>()
      .mockResolvedValueOnce(
        jsonResponse({ qr: "fractonica-pairing:v1:Abc_123", session: created }, 201),
      )
      .mockResolvedValueOnce(jsonResponse(claimed))
      .mockResolvedValueOnce(jsonResponse(completed))
      .mockResolvedValueOnce(jsonResponse(cancelled));
    const token = "0123456789abcdef0123456789abcdef";
    const client = createNodeClient("http://127.0.0.1:8789", fetcher, 5_000, token);
    const request: CreatePairingRequest = {
      spaceId,
      expiresInMs: 300_000,
      endpointHints: ["http://127.0.0.1:8789"],
      capability: {
        actions: ["appendOperation", "readSpace", "writeContent"],
        schemas: ["record", "event", "tag", "profile"],
        visibilities: ["public", "private"],
        contentRoles: ["record.media"],
        maxResourceByteLength: 1_073_741_824,
        delegationDepth: 0,
        label: "Personal device",
      },
    };

    await expect(client.createPairing(request)).resolves.toMatchObject({ session: created });
    await expect(client.readPairing(invitationId)).resolves.toEqual(claimed);
    await expect(client.confirmPairing(invitationId, "0123456701")).resolves.toEqual(completed);
    await expect(client.cancelPairing(invitationId)).resolves.toEqual(cancelled);

    expect(fetcher.mock.calls.map(([url, init]) => [url, init?.method])).toEqual([
      ["http://127.0.0.1:8789/api/pairing/invitations", "POST"],
      [`http://127.0.0.1:8789/api/pairing/invitations/${invitationId}`, "GET"],
      [`http://127.0.0.1:8789/api/pairing/invitations/${invitationId}/confirm`, "POST"],
      [`http://127.0.0.1:8789/api/pairing/invitations/${invitationId}`, "DELETE"],
    ]);
    for (const [, init] of fetcher.mock.calls) {
      expect(init?.headers).toMatchObject({ Authorization: `Bearer ${token}` });
    }
  });

  it("rejects pairing projections with unknown fields", async () => {
    const fetcher = vi.fn<typeof fetch>().mockResolvedValueOnce(
      jsonResponse({
        invitationId: "7".repeat(32),
        spaceId: `space:${"1".repeat(64)}`,
        state: "created",
        expiresAtUnixMs: 1_784_265_900_000,
        secret: "must-not-cross-this-boundary",
      }),
    );
    const client = createNodeClient("http://127.0.0.1:8789", fetcher);

    await expect(client.readPairing("7".repeat(32))).rejects.toThrow(
      "The pairing response did not match the expected schema.",
    );
  });
});

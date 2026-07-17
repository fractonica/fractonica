import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { act } from "react";
import { describe, expect, it, vi } from "vitest";
import App from "./App";
import type { NodeClient, NodeSnapshot } from "./api";
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
    readStatus,
  };
}

describe("control center", () => {
  it("shows a loading state before rendering a ready node", async () => {
    const request = deferred<NodeSnapshot>();
    const client = makeClient(vi.fn(() => request.promise));

    render(<App client={client} />);

    expect(screen.getByText("Finding your Fractonica node")).toBeInTheDocument();
    expect(screen.getAllByText("Connecting").length).toBeGreaterThan(0);

    await act(async () => request.resolve(READY_SNAPSHOT));

    expect((await screen.findAllByText("Studio node")).length).toBeGreaterThan(0);
    expect(screen.getByText("SQLite")).toBeInTheDocument();
    expect(screen.getByText("Ready · schema version 14")).toBeInTheDocument();
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
});

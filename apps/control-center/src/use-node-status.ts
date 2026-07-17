import { useCallback, useEffect, useRef, useState } from "react";
import type { NodeClient, NodeSnapshot } from "./api";

export type ConnectionPhase = "loading" | "offline" | "ready";

export interface NodeStatusState {
  phase: ConnectionPhase;
  snapshot: NodeSnapshot | null;
  error: string | null;
  lastCheckedAt: Date | null;
  refreshing: boolean;
}

const INITIAL_STATE: NodeStatusState = {
  phase: "loading",
  snapshot: null,
  error: null,
  lastCheckedAt: null,
  refreshing: true,
};

function describeError(error: unknown): string {
  if (error instanceof DOMException && error.name === "TimeoutError") {
    return "The node did not answer within five seconds.";
  }

  if (error instanceof Error && error.message) {
    return error.message;
  }

  return "The local node could not be reached.";
}

export function useNodeStatus(client: NodeClient, refreshIntervalMs = 15_000) {
  const [state, setState] = useState<NodeStatusState>(INITIAL_STATE);
  const requestRef = useRef<AbortController | null>(null);
  const sequenceRef = useRef(0);

  const refresh = useCallback(async () => {
    requestRef.current?.abort();
    const request = new AbortController();
    const sequence = ++sequenceRef.current;
    requestRef.current = request;

    setState((current) => ({
      ...current,
      phase: current.snapshot ? current.phase : "loading",
      error: current.snapshot ? current.error : null,
      refreshing: true,
    }));

    try {
      const snapshot = await client.readStatus(request.signal);
      if (sequence !== sequenceRef.current) return;

      setState({
        phase: "ready",
        snapshot,
        error: null,
        lastCheckedAt: new Date(),
        refreshing: false,
      });
    } catch (error) {
      if (request.signal.aborted || sequence !== sequenceRef.current) return;

      setState((current) => ({
        phase: "offline",
        snapshot: current.snapshot,
        error: describeError(error),
        lastCheckedAt: new Date(),
        refreshing: false,
      }));
    }
  }, [client]);

  useEffect(() => {
    void refresh();
    const interval = window.setInterval(() => void refresh(), refreshIntervalMs);
    const reconnect = () => void refresh();
    const refreshWhenVisible = () => {
      if (document.visibilityState === "visible") void refresh();
    };

    window.addEventListener("online", reconnect);
    document.addEventListener("visibilitychange", refreshWhenVisible);

    return () => {
      window.clearInterval(interval);
      window.removeEventListener("online", reconnect);
      document.removeEventListener("visibilitychange", refreshWhenVisible);
      sequenceRef.current += 1;
      requestRef.current?.abort();
    };
  }, [refresh, refreshIntervalMs]);

  return { ...state, refresh };
}

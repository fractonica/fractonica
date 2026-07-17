import { useMemo } from "react";
import { Button, Metric, Panel, Skeleton, StatusBadge } from "@fractonica/ui";
import { createRuntimeNodeClient } from "./api";
import type { NodeClient, NodeSnapshot } from "./api";
import { formatCheckedAt, formatLocalDateTime, formatUptime } from "./format";
import { useNodeStatus } from "./use-node-status";
import "./app.css";

export interface AppProps {
  client?: NodeClient;
}

function FractonicaMark() {
  return (
    <svg aria-hidden="true" className="brand-mark" viewBox="0 0 48 48">
      <circle cx="24" cy="24" r="4.5" />
      <path d="M24 19.5V7.5m0 33V28.5M19.9 21.6 9.5 15.5m28.9 17L28 26.4M19.9 26.4 9.5 32.5m28.9-17L28 21.6" />
      <path className="brand-mark__faint" d="m24 7.5 5.5 3.2M9.5 15.5v6.3m0 10.7 5.5 3.2m9 4.8 5.5-3.2m8.9-4.8v-6.3m0-10.7-5.5-3.2" />
    </svg>
  );
}

function toneForPhase(phase: "loading" | "offline" | "ready") {
  if (phase === "ready") return "ready" as const;
  if (phase === "offline") return "offline" as const;
  return "busy" as const;
}

function labelForPhase(phase: "loading" | "offline" | "ready") {
  if (phase === "ready") return "Node ready";
  if (phase === "offline") return "Node offline";
  return "Connecting";
}

function LoadingOverview({ baseUrl }: { baseUrl: string }) {
  return (
    <Panel aria-busy="true" className="hero hero--loading">
      <div className="hero__copy" role="status">
        <StatusBadge tone="busy">Connecting</StatusBadge>
        <div>
          <p className="section-kicker">Local node</p>
          <h2>Finding your Fractonica node</h2>
          <p className="hero__description">
            Checking readiness and reading the local installation profile.
          </p>
        </div>
        <code className="endpoint-chip">{baseUrl}</code>
      </div>
      <div aria-hidden="true" className="loading-stack">
        <Skeleton height="0.72rem" width="42%" />
        <Skeleton height="2.35rem" width="76%" />
        <Skeleton height="0.72rem" width="58%" />
      </div>
    </Panel>
  );
}

interface OfflineOverviewProps {
  baseUrl: string;
  error: string | null;
  refreshing: boolean;
  onRetry(): void;
}

function OfflineOverview({
  baseUrl,
  error,
  onRetry,
  refreshing,
}: OfflineOverviewProps) {
  return (
    <Panel className="hero hero--offline">
      <div className="hero__copy" role="alert">
        <StatusBadge tone="offline">Node offline</StatusBadge>
        <div>
          <p className="section-kicker">Connection interrupted</p>
          <h2>Node unreachable</h2>
          <p className="hero__description">
            {error ?? "The control center could not reach the configured node."}
          </p>
        </div>
        <div className="hero__actions">
          <Button disabled={refreshing} onClick={onRetry}>
            {refreshing ? "Checking…" : "Try again"}
          </Button>
          <code className="endpoint-chip">{baseUrl}</code>
        </div>
      </div>
      <div aria-hidden="true" className="signal-visual signal-visual--offline">
        <span className="signal-visual__orbit" />
        <span className="signal-visual__core" />
      </div>
    </Panel>
  );
}

function ReadyOverview({ snapshot }: { snapshot: NodeSnapshot }) {
  const isSarosProfile = snapshot.node.profile === "saros";
  const storage = snapshot.readiness.storage;

  return (
    <>
      <Panel className="hero hero--ready">
        <div className="hero__copy">
          <StatusBadge tone="ready">Node ready</StatusBadge>
          <div>
            <p className="section-kicker">
              {isSarosProfile ? "Stateless Saros engine" : "Local node"}
            </p>
            <h2>{snapshot.node.displayName}</h2>
            <p className="hero__description">
              {isSarosProfile
                ? "The stateless Saros engine is healthy and ready to answer temporal and geometry requests."
                : "The node and its SQLite storage are healthy and ready to accept local control requests."}
            </p>
          </div>
          <div className="hero__meta">
            <span>Fractonica {snapshot.node.version}</span>
            <span aria-hidden="true">·</span>
            <span>{isSarosProfile ? "Saros profile" : "Node profile"}</span>
            <span aria-hidden="true">·</span>
            <span>{snapshot.node.capabilities.length} capabilities</span>
          </div>
        </div>
        <div aria-hidden="true" className="signal-visual signal-visual--ready">
          <span className="signal-visual__orbit" />
          <span className="signal-visual__core" />
          <span className="signal-visual__ping" />
        </div>
      </Panel>

      <div className="metric-grid">
        <Panel className="metric-card">
          <Metric
            detail={`Started ${formatLocalDateTime(snapshot.node.startedAt)}`}
            label="Runtime"
            value={formatUptime(snapshot.node.uptimeSeconds)}
          />
        </Panel>
        <Panel className="metric-card">
          <Metric
            detail={
              storage.kind === "sqlite"
                ? `Ready · schema version ${storage.schemaVersion}`
                : "No local storage configured"
            }
            label="Storage"
            value={storage.kind === "sqlite" ? "SQLite" : "Stateless"}
          />
        </Panel>
        <Panel className="metric-card">
          <Metric
            detail="Node software"
            label="Version"
            value={snapshot.node.version}
          />
        </Panel>
      </div>

      <div className="detail-grid">
        <Panel className="detail-panel" eyebrow="Identity" title="Installation">
          <dl className="detail-list">
            <div>
              <dt>Display name</dt>
              <dd>{snapshot.node.displayName}</dd>
            </div>
            <div>
              <dt>Installation ID</dt>
              <dd className="mono-value">{snapshot.node.installationId}</dd>
            </div>
          </dl>
        </Panel>

        <Panel className="detail-panel" eyebrow="Node profile" title="Capabilities">
          {snapshot.node.capabilities.length > 0 ? (
            <ul className="capability-list" aria-label="Node capabilities">
              {snapshot.node.capabilities.map((capability) => (
                <li key={capability}>{capability}</li>
              ))}
            </ul>
          ) : (
            <p className="empty-note">No optional capabilities reported.</p>
          )}
        </Panel>
      </div>
    </>
  );
}

export default function App({ client: suppliedClient }: AppProps) {
  const client = useMemo(() => suppliedClient ?? createRuntimeNodeClient(), [suppliedClient]);
  const { error, lastCheckedAt, phase, refresh, refreshing, snapshot } = useNodeStatus(client);

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand-lockup">
          <FractonicaMark />
          <div>
            <strong>Fractonica</strong>
            <span>Control center</span>
          </div>
        </div>

        <nav aria-label="Control center">
          <span className="nav-label">Local workspace</span>
          <a aria-current="page" className="nav-item" href="#overview">
            <span aria-hidden="true" className="nav-item__glyph">◈</span>
            Node overview
          </a>
        </nav>

        <div className="sidebar__status">
          <StatusBadge tone={toneForPhase(phase)}>{labelForPhase(phase)}</StatusBadge>
          <span>{formatCheckedAt(lastCheckedAt)}</span>
          <code title={client.baseUrl}>{client.baseUrl}</code>
        </div>
      </aside>

      <main id="overview">
        <header className="page-header">
          <div>
            <p className="section-kicker">Control plane · local</p>
            <h1>Node overview</h1>
            <p>Observe the local Fractonica runtime from one quiet surface.</p>
          </div>
          <Button
            aria-label={refreshing ? "Checking node status" : "Refresh node status"}
            disabled={refreshing}
            onClick={() => void refresh()}
            variant="quiet"
          >
            <span aria-hidden="true" className={refreshing ? "refresh-icon is-spinning" : "refresh-icon"}>↻</span>
            {refreshing ? "Checking" : "Refresh"}
          </Button>
        </header>

        <div aria-live="polite" className="content-stack">
          {phase === "loading" ? <LoadingOverview baseUrl={client.baseUrl} /> : null}
          {phase === "offline" ? (
            <OfflineOverview
              baseUrl={client.baseUrl}
              error={error}
              onRetry={() => void refresh()}
              refreshing={refreshing}
            />
          ) : null}
          {phase === "ready" && snapshot ? <ReadyOverview snapshot={snapshot} /> : null}
        </div>

        <footer className="page-footer">
          <span>Fractonica local control center</span>
          <span>Read-only node status</span>
        </footer>
      </main>
    </div>
  );
}

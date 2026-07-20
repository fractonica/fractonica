import { useEffect, useMemo, useState } from "react";
import { OctalGlyph } from "@fractonica/glyph-react";
import { Button, Metric, Panel, Skeleton, StatusBadge } from "@fractonica/ui";
import { QRCodeSVG } from "qrcode.react";
import { createRuntimeNodeClient } from "./api";
import type {
  NodeClient,
  NodeSnapshot,
  PairingInvitation,
  PairingSession,
  SpaceDescriptor,
} from "./api";
import { formatCheckedAt, formatLocalDateTime, formatUptime } from "./format";
import { createRuntimeClientCore } from "./client-core";
import type { ClientCore } from "./client-core";
import { RecordsWorkspace } from "./RecordsWorkspace";
import { useNodeStatus } from "./use-node-status";
import "./app.css";

export interface AppProps {
  client?: NodeClient;
  clientCore?: ClientCore | null;
}

function FractonicaMark() {
  return <OctalGlyph decorative className="brand-mark" depth={6} value="777777" />;
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

function OfflineOverview({ baseUrl, error, onRetry, refreshing }: OfflineOverviewProps) {
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
          <Metric detail="Node software" label="Version" value={snapshot.node.version} />
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
            {snapshot.node.nodeId ? (
              <div>
                <dt>Node identity</dt>
                <dd className="mono-value">{snapshot.node.nodeId}</dd>
              </div>
            ) : null}
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

function ConfirmationGlyphs({ value }: { value: string }) {
  return (
    <div aria-label={`Confirmation code ${value}`} className="confirmation-glyphs">
      {[value.slice(0, 5), value.slice(5)].map((half, index) => (
        <div className="confirmation-glyph" key={`${half}-${index}`}>
          <OctalGlyph decorative depth={5} value={half} />
          <code>{half}</code>
        </div>
      ))}
    </div>
  );
}

function PairingIdentity({ session }: { session: PairingSession }) {
  return (
    <dl className="pairing-identity">
      {session.joinerNodeId ? (
        <div>
          <dt>Joining node</dt>
          <dd>{session.joinerNodeId}</dd>
        </div>
      ) : null}
      {session.subjectActorId ? (
        <div>
          <dt>Joining actor</dt>
          <dd>{session.subjectActorId}</dd>
        </div>
      ) : null}
      {session.grantOperationId ? (
        <div>
          <dt>Capability grant</dt>
          <dd>{session.grantOperationId}</dd>
        </div>
      ) : null}
    </dl>
  );
}

interface PairingPanelProps {
  client: NodeClient;
  snapshot: NodeSnapshot;
}

function PairingPanel({ client, snapshot }: PairingPanelProps) {
  const spaces = snapshot.node.spaces ?? [];
  const [spaceId, setSpaceId] = useState(spaces[0]?.spaceId ?? "");
  const [invitation, setInvitation] = useState<PairingInvitation | null>(null);
  const [busy, setBusy] = useState(false);
  const [copied, setCopied] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const pairingAvailable = snapshot.node.capabilities.includes("noise-pairing");
  const session = invitation?.session;
  const qr = invitation?.qr ?? "";
  const terminal = session && ["completed", "cancelled", "expired"].includes(session.state);

  useEffect(() => {
    if (!session || terminal) return;
    let stopped = false;
    let timer = 0;
    const poll = async () => {
      try {
        const next = await client.readPairing(session.invitationId);
        if (!stopped) {
          setInvitation((current) => (current ? { qr: "", session: next } : null));
          setError(null);
          if (!["completed", "cancelled", "expired"].includes(next.state)) {
            timer = window.setTimeout(() => void poll(), 1_000);
          }
        }
      } catch (reason) {
        if (!stopped) {
          setError(reason instanceof Error ? reason.message : "Could not refresh pairing state.");
          timer = window.setTimeout(() => void poll(), 2_000);
        }
      }
    };
    timer = window.setTimeout(() => void poll(), 750);
    return () => {
      stopped = true;
      window.clearTimeout(timer);
    };
  }, [client, session?.invitationId, session?.state, terminal]);

  const create = async () => {
    setBusy(true);
    setError(null);
    setCopied(false);
    try {
      setInvitation(
        await client.createPairing({
          spaceId,
          expiresInMs: 5 * 60 * 1_000,
          capability: {
            actions: ["appendOperation", "readSpace", "writeContent"],
            schemas: ["record", "event", "tag", "profile"],
            visibilities: ["public", "private"],
            contentRoles: ["record.media"],
            maxResourceByteLength: 1_073_741_824,
            delegationDepth: 0,
            label: "Personal device",
          },
        }),
      );
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Could not create a pairing invitation.");
    } finally {
      setBusy(false);
    }
  };

  const refresh = async () => {
    if (!session) return;
    setBusy(true);
    setError(null);
    try {
      const next = await client.readPairing(session.invitationId);
      setInvitation((current) => (current ? { qr: next.state === "created" ? current.qr : "", session: next } : null));
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Could not refresh pairing state.");
    } finally {
      setBusy(false);
    }
  };

  const confirm = async () => {
    if (!session?.confirmationOctal) return;
    setBusy(true);
    setError(null);
    try {
      const next = await client.confirmPairing(session.invitationId, session.confirmationOctal);
      setInvitation({ qr: "", session: next });
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Could not authorize the joining device.");
    } finally {
      setBusy(false);
    }
  };

  const cancel = async () => {
    if (!session) return;
    setBusy(true);
    setError(null);
    try {
      setInvitation({ qr: "", session: await client.cancelPairing(session.invitationId) });
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Could not cancel the invitation.");
    } finally {
      setBusy(false);
    }
  };

  const copyInvitation = async () => {
    if (!invitation?.qr) return;
    try {
      await navigator.clipboard.writeText(invitation.qr);
      setCopied(true);
    } catch {
      setError("The invitation could not be copied. Use the QR code instead.");
    }
  };

  const reset = () => {
    setInvitation(null);
    setError(null);
    setCopied(false);
  };

  return (
    <section aria-labelledby="pairing-title" className="pairing-section" id="pairing">
      <header className="section-header">
        <div>
          <p className="section-kicker">Local authority</p>
          <h2 id="pairing-title">Pair a device</h2>
          <p>
            Grant a new actor access without copying this node’s private keys. The invitation expires
            after five minutes and can be claimed once.
          </p>
        </div>
        {pairingAvailable ? <StatusBadge tone="ready">Noise ready</StatusBadge> : null}
      </header>

      {!pairingAvailable || snapshot.node.profile !== "node" ? (
        <Panel className="pairing-card pairing-card--notice">
          <h3>Pairing is unavailable in this profile</h3>
          <p>Start the full local node profile to create durable device capabilities.</p>
        </Panel>
      ) : null}

      {pairingAvailable && snapshot.node.profile === "node" && !session ? (
        <Panel className="pairing-card pairing-setup">
          <div>
            <p className="pairing-step">Step 1 · Scope</p>
            <h3>Personal device</h3>
            <p>
              Read the selected space, append public or private records, and transfer record media.
              This grant cannot issue or revoke other capabilities.
            </p>
          </div>
          <label className="field-label">
            Trusted space
            <select value={spaceId} onChange={(event) => setSpaceId(event.target.value)}>
              {spaces.map((space: SpaceDescriptor) => (
                <option key={space.spaceId} value={space.spaceId}>
                  {space.displayName}
                </option>
              ))}
            </select>
          </label>
          <ul className="grant-summary" aria-label="Requested device capability">
            <li>Read space</li>
            <li>Create and revise records</li>
            <li>Public and private visibility</li>
            <li>Record media up to 1 GiB each</li>
            <li>No delegation</li>
          </ul>
          <div className="pairing-actions">
            <Button disabled={busy || !spaceId} onClick={() => void create()}>
              {busy ? "Creating…" : "Create invitation"}
            </Button>
          </div>
        </Panel>
      ) : null}

      {session?.state === "created" && qr ? (
        <Panel className="pairing-card pairing-invitation">
          <div className="qr-frame">
            <QRCodeSVG bgColor="#ffffff" fgColor="#07110e" level="M" marginSize={2} size={244} value={qr} />
          </div>
          <div className="pairing-copy">
            <p className="pairing-step">Step 2 · One-time invitation</p>
            <h3>Scan from the joining client</h3>
            <p>
              The QR contains a short-lived secret. Fractonica never writes it to SQLite, logs, URLs,
              or the signed graph.
            </p>
            <p className="security-note">
              Network binding is still loopback-only. This invitation currently works with local
              protocol clients; LAN discovery remains intentionally disabled.
            </p>
            <dl className="pairing-facts">
              <div><dt>Expires</dt><dd>{new Date(session.expiresAtUnixMs).toLocaleString()}</dd></div>
              <div><dt>Invitation</dt><dd>{session.invitationId}</dd></div>
            </dl>
            <div className="pairing-actions">
              <Button disabled={busy} onClick={() => void refresh()} variant="quiet">Check claim</Button>
              <Button disabled={busy} onClick={() => void copyInvitation()} variant="quiet">
                {copied ? "Copied" : "Copy payload"}
              </Button>
              <Button className="danger-button" disabled={busy} onClick={() => void cancel()} variant="quiet">Cancel</Button>
            </div>
          </div>
        </Panel>
      ) : null}

      {(session?.state === "claimed" || session?.state === "confirmed") && session.confirmationOctal ? (
        <Panel className="pairing-card pairing-confirmation">
          <div>
            <p className="pairing-step">Step 3 · Human confirmation</p>
            <h3>Compare both glyphs</h3>
            <p>
              Verify that these two five-digit glyphs and all ten octal digits exactly match the
              joining device. A partial match is not sufficient.
            </p>
          </div>
          <ConfirmationGlyphs value={session.confirmationOctal} />
          <PairingIdentity session={session} />
          <div className="pairing-actions">
            <Button disabled={busy} onClick={() => void confirm()}>
              {busy ? "Authorizing…" : session.state === "confirmed" ? "Finish authorization" : "Codes match · authorize"}
            </Button>
            <Button className="danger-button" disabled={busy} onClick={() => void cancel()} variant="quiet">Reject and cancel</Button>
          </div>
        </Panel>
      ) : null}

      {session?.state === "completed" ? (
        <Panel className="pairing-card pairing-complete">
          <StatusBadge tone="ready">Device authorized</StatusBadge>
          <div>
            <p className="pairing-step">Complete</p>
            <h3>Capability admitted</h3>
            <p>The joining actor now has exactly the bounded authority shown above.</p>
          </div>
          <PairingIdentity session={session} />
          <Button onClick={reset} variant="quiet">Pair another device</Button>
        </Panel>
      ) : null}

      {(session?.state === "cancelled" || session?.state === "expired") ? (
        <Panel className="pairing-card pairing-card--notice">
          <StatusBadge tone="offline">Invitation {session.state}</StatusBadge>
          <h3>No authority was issued</h3>
          <p>Create a fresh one-time invitation when the joining device is ready.</p>
          <Button onClick={reset} variant="quiet">Start again</Button>
        </Panel>
      ) : null}

      {error ? <p className="pairing-error" role="alert">{error}</p> : null}
    </section>
  );
}

type WorkspaceView = "records" | "node" | "pairing";

export default function App({ client: suppliedClient, clientCore: suppliedClientCore }: AppProps) {
  const client = useMemo(() => suppliedClient ?? createRuntimeNodeClient(), [suppliedClient]);
  const clientCore = useMemo(
    () => suppliedClientCore === undefined ? createRuntimeClientCore() : suppliedClientCore,
    [suppliedClientCore],
  );
  const [view, setView] = useState<WorkspaceView>(() => clientCore ? "records" : "node");
  const { error, lastCheckedAt, phase, refresh, refreshing, snapshot } = useNodeStatus(client);

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand-lockup">
          <FractonicaMark />
          <div><strong>Fractonica</strong><span>Control center</span></div>
        </div>
        <nav aria-label="Control center">
          <span className="nav-label">Local workspace</span>
          <button className={`nav-item${view === "records" ? "" : " nav-item--secondary"}`} onClick={() => setView("records")} type="button"><span aria-hidden="true" className="nav-item__glyph">✦</span>Records</button>
          <button className={`nav-item${view === "node" ? "" : " nav-item--secondary"}`} onClick={() => setView("node")} type="button"><span aria-hidden="true" className="nav-item__glyph">◈</span>Node overview</button>
          <button className={`nav-item${view === "pairing" ? "" : " nav-item--secondary"}`} onClick={() => setView("pairing")} type="button"><span aria-hidden="true" className="nav-item__glyph">⌁</span>Pair devices</button>
        </nav>
        <div className="sidebar__status">
          <StatusBadge tone={toneForPhase(phase)}>{labelForPhase(phase)}</StatusBadge>
          <span>{formatCheckedAt(lastCheckedAt)}</span>
          <code title={client.baseUrl}>{client.baseUrl}</code>
        </div>
      </aside>

      <main id={view}>
        {view === "records" && clientCore ? <RecordsWorkspace client={clientCore} /> : null}
        {view === "records" && !clientCore ? (
          <>
            <header className="page-header">
              <div><p className="section-kicker">Native workspace</p><h1>Records</h1><p>The local-first editor lives inside the Fractonica desktop application.</p></div>
            </header>
            <Panel className="desktop-required-panel">
              <FractonicaMark />
              <div><h2>Open the desktop client</h2><p>The browser control center can inspect a node, but it cannot access private client SQLite, keys, or local content. Launch Fractonica Desktop to create and edit records.</p></div>
              <code>pnpm desktop:dev</code>
            </Panel>
          </>
        ) : null}

        {view === "node" ? (
          <>
            <header className="page-header">
              <div>
                <p className="section-kicker">Control plane · local</p>
                <h1>Node overview</h1>
                <p>Observe the runtime and its protected local installation.</p>
              </div>
              <Button aria-label={refreshing ? "Checking node status" : "Refresh node status"} disabled={refreshing} onClick={() => void refresh()} variant="quiet">
                <span aria-hidden="true" className={refreshing ? "refresh-icon is-spinning" : "refresh-icon"}>↻</span>
                {refreshing ? "Checking" : "Refresh"}
              </Button>
            </header>
            <div aria-live="polite" className="content-stack">
              {phase === "loading" ? <LoadingOverview baseUrl={client.baseUrl} /> : null}
              {phase === "offline" ? <OfflineOverview baseUrl={client.baseUrl} error={error} onRetry={() => void refresh()} refreshing={refreshing} /> : null}
              {phase === "ready" && snapshot ? <ReadyOverview snapshot={snapshot} /> : null}
            </div>
          </>
        ) : null}

        {view === "pairing" ? (
          <>
            {phase === "loading" ? <LoadingOverview baseUrl={client.baseUrl} /> : null}
            {phase === "offline" ? <OfflineOverview baseUrl={client.baseUrl} error={error} onRetry={() => void refresh()} refreshing={refreshing} /> : null}
            {phase === "ready" && snapshot ? <PairingPanel client={client} snapshot={snapshot} /> : null}
          </>
        ) : null}

        <footer className="page-footer">
          <span>Fractonica local control center</span>
          <span>Loopback authority boundary</span>
        </footer>
      </main>
    </div>
  );
}

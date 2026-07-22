import { useEffect, useMemo, useState } from "react";
import { OctalGlyph } from "@fractonica/glyph-react";
import { Button, Metric, Panel, Skeleton, StatusBadge } from "@fractonica/ui";
import { QRCodeSVG } from "qrcode.react";
import { createRuntimeNodeClient } from "./api";
import type {
  NodeClient,
  NodeSnapshot,
  PairingInvitation,
  PairedDevice,
  PairingSession,
  SpaceDescriptor,
} from "./api";
import { formatCheckedAt, formatLocalDateTime, formatUptime } from "./format";
import { createRuntimeClientCore } from "./client-core";
import type { ClientCore, PairingClaim, PrePairRecordPolicy } from "./client-core";
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

function nativeErrorMessage(reason: unknown, fallback: string): string {
  if (reason instanceof Error) return reason.message;
  if (typeof reason === "string" && reason.trim()) return reason;
  if (
    typeof reason === "object" &&
    reason !== null &&
    "message" in reason &&
    typeof reason.message === "string" &&
    reason.message.trim()
  ) {
    return reason.message;
  }
  return fallback;
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
                ? "Ready"
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
  const rows = [value.slice(0, 5), value.slice(5)];
  return (
    <div aria-label={`Confirmation code ${value}`} className="confirmation-sequence">
      <div className="confirmation-glyphs">
        {rows.map((half, index) => (
          <div className="confirmation-glyph" key={`${half}-${index}`}>
            <OctalGlyph decorative depth={5} value={half} />
          </div>
        ))}
      </div>
      <div aria-hidden="true" className="confirmation-digit-grid">
        {rows.map((row, rowIndex) => (
          <div className="confirmation-digit-row" key={`${row}-${rowIndex}`}>
            {[...row].map((digit, index) => (
              <span key={`${digit}-${index}`}>{digit}</span>
            ))}
          </div>
        ))}
      </div>
    </div>
  );
}

function pairingDeepLink(invitation: string) {
  return `fractonica://pair?invitation=${encodeURIComponent(invitation)}`;
}

interface PairingPanelProps {
  client: NodeClient;
  clientCore: ClientCore | null;
  snapshot: NodeSnapshot;
}

function PairingPanel({ client, clientCore, snapshot }: PairingPanelProps) {
  const spaces = snapshot.node.spaces ?? [];
  const [spaceId, setSpaceId] = useState(spaces[0]?.spaceId ?? "");
  const [invitation, setInvitation] = useState<PairingInvitation | null>(null);
  const [busy, setBusy] = useState(false);
  const [copied, setCopied] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [devices, setDevices] = useState<PairedDevice[]>([]);
  const [revoking, setRevoking] = useState<string | null>(null);
  const [joinPayload, setJoinPayload] = useState("");
  const [joinClaim, setJoinClaim] = useState<PairingClaim | null>(null);
  const [joinComplete, setJoinComplete] = useState(false);
  const [joining, setJoining] = useState(false);
  const [activeSpaceId, setActiveSpaceId] = useState<string | null | undefined>(
    clientCore ? undefined : null,
  );
  const pairingAvailable = snapshot.node.capabilities.includes("noise-pairing");
  const pairingEndpointAvailable = client.pairingEndpointHints.length > 0;
  const activeWorkspaceHostedLocally =
    activeSpaceId == null || spaces.some((space) => space.spaceId === activeSpaceId);
  const session = invitation?.session;
  const qr = invitation?.qr ?? "";
  const terminal = session && ["completed", "cancelled", "expired"].includes(session.state);

  useEffect(() => {
    if (!clientCore) return;
    let stopped = false;
    void clientCore.status().then(
      (status) => {
        if (!stopped) setActiveSpaceId(status.spaceId ?? null);
      },
      (reason) => {
        if (!stopped) {
          setError(nativeErrorMessage(reason, "Could not identify the active workspace."));
          setActiveSpaceId(null);
        }
      },
    );
    return () => {
      stopped = true;
    };
  }, [clientCore]);

  useEffect(() => {
    if (!pairingAvailable || snapshot.node.profile !== "node") return;
    let stopped = false;
    let timer = 0;
    const poll = async () => {
      try {
        const next = await client.listPairedDevices();
        if (!stopped) setDevices(next);
      } catch (reason) {
        if (!stopped) setError(reason instanceof Error ? reason.message : "Could not read linked devices.");
      } finally {
        if (!stopped) timer = window.setTimeout(() => void poll(), 5_000);
      }
    };
    void poll();
    return () => {
      stopped = true;
      window.clearTimeout(timer);
    };
  }, [client, pairingAvailable, snapshot.node.profile]);

  useEffect(() => {
    if (!session || terminal) return;
    let stopped = false;
    let timer = 0;
    const poll = async () => {
      try {
        const next = await client.readPairing(session.invitationId);
        if (!stopped) {
          setInvitation((current) => (current ? { qr: current.qr, session: next } : null));
          setError(null);
          if (!["completed", "cancelled", "expired"].includes(next.state)) {
            timer = window.setTimeout(() => void poll(), 1_000);
          }
        }
      } catch (reason) {
        if (!stopped) {
          setError(reason instanceof Error ? reason.message : "Could not refresh link state.");
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
          endpointHints: [...client.pairingEndpointHints],
          capability: {
            actions: ["appendOperation", "readSpace", "writeContent", "linkWorkspace"],
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
      setError(reason instanceof Error ? reason.message : "Could not create a link invitation.");
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
      setInvitation((current) => (current ? { qr: current.qr, session: next } : null));
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Could not refresh link state.");
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

  const revoke = async (device: PairedDevice) => {
    if (!window.confirm("Remove this device's access? Its signed audit entry will remain visible.")) return;
    setRevoking(device.invitationId);
    setError(null);
    try {
      const revoked = await client.revokePairedDevice(device.invitationId);
      setDevices((current) => current.map((item) => item.invitationId === revoked.invitationId ? revoked : item));
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Could not remove the linked device.");
    } finally {
      setRevoking(null);
    }
  };

  const claimRemote = async () => {
    if (!clientCore) return;
    setJoining(true);
    setError(null);
    try {
      const value = joinPayload.trim();
      const payload = value.startsWith("fractonica://")
        ? new URL(value).searchParams.get("invitation") ?? ""
        : value;
      setJoinClaim(await clientCore.claimPairing(payload));
      setJoinComplete(false);
    } catch (reason) {
      setError(nativeErrorMessage(reason, "Could not claim the remote invitation."));
    } finally {
      setJoining(false);
    }
  };

  const acceptRemote = async (recordPolicy: PrePairRecordPolicy) => {
    if (!clientCore || !joinClaim) return;
    setJoining(true);
    setError(null);
    try {
      await clientCore.acceptPairing(joinClaim.invitationId, recordPolicy);
      setJoinComplete(true);
    } catch (reason) {
      setError(nativeErrorMessage(reason, "Could not complete the desktop link."));
    } finally {
      setJoining(false);
    }
  };

  return (
    <section aria-labelledby="pairing-title" className="pairing-section" id="pairing">
      <header className="section-header">
        <div>
          <p className="section-kicker">Local authority</p>
          <h2 id="pairing-title">Link a device</h2>
          <p>
            Grant a new actor access without copying this node’s private keys. The invitation expires
            after five minutes and can be claimed once.
          </p>
        </div>
        {pairingAvailable ? <StatusBadge tone="ready">Noise ready</StatusBadge> : null}
      </header>

      {!pairingAvailable || snapshot.node.profile !== "node" ? (
        <Panel className="pairing-card pairing-card--notice">
          <h3>Device linking is unavailable in this profile</h3>
          <p>Start the full local node profile to create durable device capabilities.</p>
        </Panel>
      ) : null}

      {pairingAvailable && snapshot.node.profile === "node" && !session && !activeWorkspaceHostedLocally ? (
        <Panel className="pairing-card pairing-card--notice">
          <h3>Link from a device that hosts this workspace</h3>
          <p>
            This desktop is displaying a workspace joined through another device, but its local
            Windows node owns a different workspace. Creating an invitation here would link the
            joining device to that other workspace instead of the records currently shown.
          </p>
          <p className="security-note">
            Create the invitation on the Mac that introduced this workspace. Windows can still
            join invitations and will continue synchronizing through its existing link.
          </p>
        </Panel>
      ) : null}

      {pairingAvailable && snapshot.node.profile === "node" && !session && activeWorkspaceHostedLocally ? (
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
            <Button disabled={busy || !spaceId || !pairingEndpointAvailable || activeSpaceId === undefined} onClick={() => void create()}>
              {busy ? "Creating…" : "Create invitation"}
            </Button>
          </div>
          {!pairingEndpointAvailable ? (
            <p className="security-note">
              The node is running, but the desktop could not find a private-LAN address. Connect
              this Mac to the same Wi-Fi as the phone and relaunch Fractonica.
            </p>
          ) : null}
        </Panel>
      ) : null}

      {session?.state === "created" && qr ? (
        <Panel className="pairing-card pairing-invitation">
          <div className="qr-frame">
            <QRCodeSVG bgColor="#ffffff" fgColor="#07110e" level="M" marginSize={2} size={244} value={pairingDeepLink(qr)} />
          </div>
          <div className="pairing-copy">
            <p className="pairing-step">Step 2 · One-time invitation</p>
            <h3>Scan from the joining client</h3>
            <p>
              Scanning opens Fractonica directly. The deep link carries a short-lived invitation;
              the app verifies and claims it below JavaScript.
            </p>
            <p className="security-note">
              The invitation uses the desktop’s private-LAN address and is intended only for a
              trusted local network.
            </p>
            <dl className="pairing-facts">
              <div><dt>Expires</dt><dd>{new Date(session.expiresAtUnixMs).toLocaleString()}</dd></div>
              <div>
                <dt>Addresses</dt>
                <dd>{client.pairingEndpointHints.join(", ")}</dd>
              </div>
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
            <p>Verify every octal digit and both five-digit glyphs. The joining device admits the grant only when its Link button is pressed.</p>
          </div>
          <ConfirmationGlyphs value={session.confirmationOctal} />
          <div className="pairing-actions">
            <Button disabled={busy} onClick={() => void refresh()} variant="quiet">Refresh status</Button>
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
          <Button onClick={reset} variant="quiet">Link another device</Button>
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

      {pairingAvailable && snapshot.node.profile === "node" ? (
        <Panel className="pairing-card paired-devices">
          <div>
            <p className="pairing-step">Authorized peers</p>
            <h3>Linked devices</h3>
            <p>Online means the node verified this device's token and active capability within the last 15 seconds.</p>
          </div>
          {devices.length === 0 ? <p className="empty-note">No devices have completed linking yet.</p> : (
            <ul className="paired-device-list">
              {devices.map((device) => {
                const revoked = Boolean(device.revocationOperationId);
                return (
                  <li className="paired-device" key={device.invitationId}>
                    <div>
                      <div className="paired-device__title">
                        <strong>{device.nodeId.slice(0, 22)}…</strong>
                        <StatusBadge tone={revoked ? "offline" : device.online ? "ready" : "busy"}>
                          {revoked ? "Revoked" : device.online ? "Online" : "Offline"}
                        </StatusBadge>
                      </div>
                      <span>Linked {new Date(device.pairedAtUnixMs).toLocaleString()}</span>
                      <span>{device.lastSeenAtUnixMs ? `Last seen ${new Date(device.lastSeenAtUnixMs).toLocaleString()}` : "Not seen since linking"}</span>
                    </div>
                    {!revoked ? (
                      <Button className="danger-button" disabled={revoking === device.invitationId} onClick={() => void revoke(device)} variant="quiet">
                        {revoking === device.invitationId ? "Revoking…" : "Revoke"}
                      </Button>
                    ) : null}
                  </li>
                );
              })}
            </ul>
          )}
        </Panel>
      ) : null}

      {clientCore ? (
        <Panel className="pairing-card pairing-join">
          {!joinClaim ? (
            <>
              <div>
                <p className="pairing-step">Link another node</p>
                <h3>Link this desktop</h3>
                <p>
                  Create an invitation on the other desktop, copy its payload, and paste it here.
                  Protected node and actor keys stay in this app’s native Rust runtime.
                </p>
              </div>
              <label className="field-label">
                Link invitation
                <textarea
                  onChange={(event) => setJoinPayload(event.target.value)}
                  placeholder="fractonica-pairing:v1:…"
                  rows={4}
                  value={joinPayload}
                />
              </label>
              <div className="pairing-actions">
                <Button disabled={joining || joinPayload.trim().length === 0} onClick={() => void claimRemote()}>
                  {joining ? "Verifying…" : "Verify invitation"}
                </Button>
              </div>
            </>
          ) : !joinComplete ? (
            <>
              <div>
                <p className="pairing-step">Human confirmation</p>
                <h3>Compare both desktops</h3>
                <p>
                  Confirm that these two five-digit glyphs and all ten octal digits exactly match
                  the inviting desktop before linking.
                </p>
              </div>
              <ConfirmationGlyphs value={joinClaim.confirmationOctal} />
              <dl className="pairing-facts">
                <div><dt>Remote node</dt><dd>{joinClaim.responderNodeId}</dd></div>
                <div><dt>Local records</dt><dd>{joinClaim.localRecordCount}</dd></div>
              </dl>
              {joinClaim.localRecordCount > 0 ? (
                <p className="security-note">
                  Merge copies these records into the joined space. Keep separate leaves them in
                  this desktop’s original local space; Fractonica never silently deletes them.
                </p>
              ) : null}
              <div className="pairing-actions">
                <Button disabled={joining} onClick={() => void acceptRemote("merge")}>
                  {joining ? "Linking…" : joinClaim.localRecordCount > 0 ? "Link and merge" : "Link"}
                </Button>
                {joinClaim.localRecordCount > 0 ? (
                  <Button disabled={joining} onClick={() => void acceptRemote("discard")} variant="quiet">
                    Link and keep separate
                  </Button>
                ) : null}
                <Button disabled={joining} onClick={() => setJoinClaim(null)} variant="quiet">Cancel</Button>
              </div>
            </>
          ) : (
            <>
              <StatusBadge tone="ready">Desktop linked</StatusBadge>
              <div>
                <p className="pairing-step">Complete</p>
                <h3>Remote workspace connected</h3>
                <p>Operations and record media now synchronize through the linked node.</p>
              </div>
              <Button onClick={() => { setJoinClaim(null); setJoinComplete(false); setJoinPayload(""); }} variant="quiet">
                Link another node
              </Button>
            </>
          )}
        </Panel>
      ) : null}

      {error ? <p className="pairing-error" role="alert">{error}</p> : null}
    </section>
  );
}

interface WorkspaceManagerProps {
  clientCore: ClientCore;
  snapshot: NodeSnapshot;
  onRefresh: () => Promise<void>;
  activeSpaceId?: string;
  onActiveChange: (spaceId?: string) => void;
}

function WorkspaceManager({
  clientCore,
  snapshot,
  onRefresh,
  activeSpaceId,
  onActiveChange,
}: WorkspaceManagerProps) {
  const [displayName, setDisplayName] = useState("");
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const spaces = snapshot.node.spaces ?? [];

  const create = async () => {
    if (!clientCore.createWorkspace) return;
    setBusy("create");
    setError(null);
    try {
      await clientCore.createWorkspace(displayName);
      setDisplayName("");
      const status = await clientCore.status();
      onActiveChange(status.spaceId);
      await onRefresh();
    } catch (reason) {
      setError(nativeErrorMessage(reason, "Workspace could not be created."));
    } finally {
      setBusy(null);
    }
  };

  const activate = async (spaceId: string) => {
    if (!clientCore.activateWorkspace) return;
    setBusy(spaceId);
    setError(null);
    try {
      await clientCore.activateWorkspace(spaceId);
      onActiveChange(spaceId);
    } catch (reason) {
      setError(nativeErrorMessage(reason, "Workspace could not be opened."));
    } finally {
      setBusy(null);
    }
  };

  const remove = async (spaceId: string) => {
    if (!clientCore.deleteWorkspace) return;
    setBusy(spaceId);
    setError(null);
    try {
      await clientCore.deleteWorkspace(spaceId);
      const status = await clientCore.status();
      onActiveChange(status.spaceId);
      await onRefresh();
    } catch (reason) {
      setError(nativeErrorMessage(reason, "Workspace could not be deleted."));
    } finally {
      setBusy(null);
    }
  };

  return (
    <>
      <header className="page-header">
        <div>
          <p className="section-kicker">Vault root</p>
          <h1>Workspaces</h1>
          <p>Each workspace has an independent record graph and device network.</p>
        </div>
      </header>
      <div className="content-stack">
        <Panel>
          <h2>Create workspace</h2>
          <div className="pairing-form">
            <label>
              <span>Name</span>
              <input
                maxLength={128}
                onChange={(event) => setDisplayName(event.target.value)}
                placeholder="Personal"
                value={displayName}
              />
            </label>
            <Button disabled={busy !== null || !displayName.trim()} onClick={() => void create()}>
              {busy === "create" ? "Creating…" : "Create workspace"}
            </Button>
          </div>
        </Panel>
        {spaces.length === 0 ? (
          <Panel>
            <h2>No workspace selected</h2>
            <p>This installation is an empty node. Create a workspace or link one from another device.</p>
          </Panel>
        ) : (
          spaces.map((space) => (
            <Panel key={space.spaceId}>
              <div className="pairing-device__header">
                <div>
                  <h2>{space.displayName}</h2>
                  <code>{space.spaceId}</code>
                </div>
                {activeSpaceId === space.spaceId ? <StatusBadge tone="ready">Open</StatusBadge> : null}
              </div>
              <div className="pairing-actions">
                <Button
                  disabled={busy !== null || activeSpaceId === space.spaceId}
                  onClick={() => void activate(space.spaceId)}
                >
                  Open workspace
                </Button>
                <Button disabled={busy !== null} onClick={() => void remove(space.spaceId)} variant="quiet">
                  Delete workspace
                </Button>
              </div>
            </Panel>
          ))
        )}
        {error ? <p className="pairing-error" role="alert">{error}</p> : null}
      </div>
    </>
  );
}

type WorkspaceView = "workspaces" | "records" | "node" | "pairing";

export default function App({ client: suppliedClient, clientCore: suppliedClientCore }: AppProps) {
  const client = useMemo(() => suppliedClient ?? createRuntimeNodeClient(), [suppliedClient]);
  const clientCore = useMemo(
    () => suppliedClientCore === undefined ? createRuntimeClientCore() : suppliedClientCore,
    [suppliedClientCore],
  );
  const [view, setView] = useState<WorkspaceView>(() => clientCore ? "workspaces" : "node");
  const [activeWorkspaceId, setActiveWorkspaceId] = useState<string | undefined>();
  const [resetArmed, setResetArmed] = useState(false);
  const [resetting, setResetting] = useState(false);
  const [resetError, setResetError] = useState<string | null>(null);
  const { error, lastCheckedAt, phase, refresh, refreshing, snapshot } = useNodeStatus(client);

  useEffect(() => {
    if (!clientCore) return;
    void clientCore.status().then((status) => setActiveWorkspaceId(status.spaceId));
  }, [clientCore]);

  const resetInstallation = async () => {
    if (!clientCore?.resetInstallation) return;
    if (!resetArmed) {
      setResetArmed(true);
      setResetError(null);
      return;
    }
    setResetting(true);
    setResetError(null);
    try {
      await clientCore.resetInstallation();
    } catch (reason) {
      setResetError(nativeErrorMessage(reason, "Local storage could not be reset."));
      setResetting(false);
      setResetArmed(false);
    }
  };

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand-lockup">
          <FractonicaMark />
          <div><strong>Fractonica</strong><span>Control center</span></div>
        </div>
        <nav aria-label="Control center">
          <span className="nav-label">Vaults</span>
          <button className={`nav-item${view === "workspaces" ? "" : " nav-item--secondary"}`} onClick={() => setView("workspaces")} type="button"><span aria-hidden="true" className="nav-item__glyph">◇</span>Workspaces</button>
          <button className={`nav-item${view === "records" ? "" : " nav-item--secondary"}`} onClick={() => setView("records")} type="button"><span aria-hidden="true" className="nav-item__glyph">✦</span>Records</button>
          <button className={`nav-item${view === "node" ? "" : " nav-item--secondary"}`} onClick={() => setView("node")} type="button"><span aria-hidden="true" className="nav-item__glyph">◈</span>Node overview</button>
          <button className={`nav-item${view === "pairing" ? "" : " nav-item--secondary"}`} onClick={() => setView("pairing")} type="button"><span aria-hidden="true" className="nav-item__glyph">⌁</span>Link devices</button>
        </nav>
        <div className="sidebar__status">
          <StatusBadge tone={toneForPhase(phase)}>{labelForPhase(phase)}</StatusBadge>
          <span>{formatCheckedAt(lastCheckedAt)}</span>
          <code title={client.baseUrl}>{client.baseUrl}</code>
        </div>
      </aside>

      <main id={view}>
        {view === "workspaces" && phase === "ready" && snapshot && clientCore ? (
          <WorkspaceManager
            activeSpaceId={activeWorkspaceId}
            clientCore={clientCore}
            onActiveChange={setActiveWorkspaceId}
            onRefresh={refresh}
            snapshot={snapshot}
          />
        ) : null}
        {view === "records" && clientCore && activeWorkspaceId ? <RecordsWorkspace client={clientCore} /> : null}
        {view === "records" && clientCore && !activeWorkspaceId ? (
          <Panel><h2>No open workspace</h2><p>Create or open a workspace from the Workspaces root first.</p></Panel>
        ) : null}
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
              {clientCore?.resetInstallation ? (
                <Panel className="reset-installation-panel">
                  <div>
                    <h2>Reset local installation</h2>
                    <p>Erase this desktop's records, attachments, link state, and node identity, then restart as a new device.</p>
                    {resetError ? <p className="pairing-error" role="alert">{resetError}</p> : null}
                  </div>
                  <div className="reset-installation-panel__actions">
                    <Button disabled={resetting} onClick={() => void resetInstallation()} variant="quiet">
                      {resetting ? "Resetting…" : resetArmed ? "Confirm erase and restart" : "Reset local storage"}
                    </Button>
                    {resetArmed && !resetting ? (
                      <Button onClick={() => setResetArmed(false)} variant="quiet">Cancel</Button>
                    ) : null}
                  </div>
                </Panel>
              ) : null}
            </div>
          </>
        ) : null}

        {view === "pairing" ? (
          <>
            {phase === "loading" ? <LoadingOverview baseUrl={client.baseUrl} /> : null}
            {phase === "offline" ? <OfflineOverview baseUrl={client.baseUrl} error={error} onRetry={() => void refresh()} refreshing={refreshing} /> : null}
            {phase === "ready" && snapshot ? <PairingPanel client={client} clientCore={clientCore} snapshot={snapshot} /> : null}
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

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { Button, Panel, Skeleton, StatusBadge } from "@fractonica/ui";
import type {
  ClientCore,
  ClientRecord,
  ClientStatus,
  JsonObject,
  RecordDocument,
  ResourceReference,
} from "./client-core";

interface RecordsWorkspaceProps {
  client: ClientCore;
}

const MAX_RECORD_ATTACHMENTS = 64;

interface EditorDraft {
  record: ClientRecord | null;
  start: string;
  end: string;
  emoji: string;
  text: string;
  metadata: string;
  resources: RecordDocument["resources"];
  references: RecordDocument["references"];
}

function localInputValue(unixMs: number): string {
  const date = new Date(unixMs);
  return new Date(unixMs - date.getTimezoneOffset() * 60_000).toISOString().slice(0, 16);
}

function newDraft(): EditorDraft {
  return {
    record: null,
    start: localInputValue(Date.now()),
    end: "",
    emoji: "",
    text: "",
    metadata: "{}",
    resources: [],
    references: [],
  };
}

function draftFor(record: ClientRecord): EditorDraft | null {
  if (!record.document) return null;
  return {
    record,
    start: localInputValue(record.document.startAtUnixMs),
    end:
      record.document.endAtUnixMs === undefined
        ? ""
        : localInputValue(record.document.endAtUnixMs),
    emoji: record.document.emoji ?? "",
    text: record.document.text ?? "",
    metadata: JSON.stringify(record.document.metadata, null, 2),
    resources: record.document.resources,
    references: record.document.references,
  };
}

function formatBytes(bytes: number): string {
  if (bytes < 1_000) return `${bytes} B`;
  if (bytes < 1_000_000) return `${(bytes / 1_000).toFixed(1)} kB`;
  if (bytes < 1_000_000_000) return `${(bytes / 1_000_000).toFixed(1)} MB`;
  return `${(bytes / 1_000_000_000).toFixed(1)} GB`;
}

function attachmentCategory(mediaType: string): string {
  if (mediaType.startsWith("image/")) return "Photo";
  if (mediaType.startsWith("audio/")) return "Audio";
  if (mediaType.startsWith("video/")) return "Video";
  return "File";
}

function attachmentName(resource: ResourceReference, index: number): string {
  return resource.originalName || `Attachment ${index + 1}`;
}

function mergeAttachments(
  current: ResourceReference[],
  imported: ResourceReference[],
): ResourceReference[] {
  const known = new Set(current.map((resource) => resource.contentId));
  return [
    ...current,
    ...imported.filter((resource) => {
      if (known.has(resource.contentId)) return false;
      known.add(resource.contentId);
      return true;
    }),
  ];
}

function formatRecordDate(record: ClientRecord): string {
  const start = record.document?.startAtUnixMs ?? record.startAtUnixMs;
  if (start === undefined) return "Encrypted time";
  const startLabel = new Date(start).toLocaleString([], {
    dateStyle: "medium",
    timeStyle: "short",
  });
  const end = record.document?.endAtUnixMs ?? record.endAtUnixMs;
  if (end === undefined || end === start) return startLabel;
  return `${startLabel} – ${new Date(end).toLocaleString([], {
    dateStyle: "medium",
    timeStyle: "short",
  })}`;
}

function syncLabel(status: ClientStatus | null): string {
  if (!status || status.phase === "starting") return "Starting client";
  if (status.phase === "failed") return "Client unavailable";
  if (status.rejectedOperations > 0 || status.rejectedResources > 0) return "Needs attention";
  const pending = status.pendingOperations + status.pendingUploads + status.pendingDownloads;
  return pending > 0 ? `Syncing ${pending}` : "In sync";
}

function syncTone(status: ClientStatus | null): "busy" | "offline" | "ready" {
  if (!status || status.phase === "starting") return "busy";
  if (
    status.phase === "failed" ||
    status.rejectedOperations > 0 ||
    status.rejectedResources > 0
  ) {
    return "offline";
  }
  const pending = status.pendingOperations + status.pendingUploads + status.pendingDownloads;
  return pending > 0 ? "busy" : "ready";
}

function RecordCard({
  active,
  onSelect,
  record,
}: {
  active: boolean;
  onSelect(): void;
  record: ClientRecord;
}) {
  const text = record.document?.text?.trim();
  return (
    <button
      aria-pressed={active}
      className={`record-card${active ? " record-card--active" : ""}`}
      onClick={onSelect}
      type="button"
    >
      <span aria-hidden="true" className="record-card__emoji">
        {record.visibility === "private" ? "⌑" : record.document?.emoji || "·"}
      </span>
      <span className="record-card__body">
        <span className="record-card__date">{formatRecordDate(record)}</span>
        <strong>{record.visibility === "private" ? "Private record" : text || "Untitled moment"}</strong>
        {text ? <span className="record-card__excerpt">{text}</span> : null}
        <span className="record-card__meta">
          {record.resourceCount > 0
            ? `${record.resourceCount} attachment${record.resourceCount === 1 ? "" : "s"} · ${formatBytes(record.mediaBytes)}`
            : "No attachments"}
          {record.conflicted ? " · concurrent versions" : ""}
        </span>
      </span>
      <span aria-hidden="true" className="record-card__chevron">›</span>
    </button>
  );
}

export function RecordsWorkspace({ client }: RecordsWorkspaceProps) {
  const [status, setStatus] = useState<ClientStatus | null>(null);
  const [records, setRecords] = useState<ClientRecord[]>([]);
  const [draft, setDraft] = useState<EditorDraft>(() => newDraft());
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [importing, setImporting] = useState(false);
  const [deleteArmed, setDeleteArmed] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const lastLoadedCycle = useRef<number | null>(null);

  const loadRecords = useCallback(async () => {
    const next = await client.listRecords(200);
    setRecords(next);
    setDraft((current) => {
      const selectedId = current.record?.entityId;
      if (!selectedId) return current;
      const selected = next.find((item) => item.entityId === selectedId);
      return selected ? draftFor(selected) ?? current : newDraft();
    });
  }, [client]);

  const refresh = useCallback(async () => {
    setError(null);
    try {
      const nextStatus = await client.status();
      setStatus(nextStatus);
      if (nextStatus.phase === "ready") {
        await loadRecords();
        lastLoadedCycle.current = nextStatus.cycle;
      }
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "The native client could not be read.");
    } finally {
      setLoading(false);
    }
  }, [client, loadRecords]);

  useEffect(() => {
    let disposed = false;
    let running = false;
    const tick = async () => {
      if (running) return;
      running = true;
      try {
        const next = await client.status();
        if (disposed) return;
        setStatus(next);
        if (next.phase === "ready" && lastLoadedCycle.current !== next.cycle) {
          const listed = await client.listRecords(200);
          if (disposed) return;
          setRecords(listed);
          lastLoadedCycle.current = next.cycle;
        }
        setError(next.phase === "failed" ? next.lastError ?? "The native client failed." : null);
      } catch (reason) {
        if (!disposed) {
          setError(
            reason instanceof Error ? reason.message : "The native client could not be read.",
          );
        }
      } finally {
        if (!disposed) setLoading(false);
        running = false;
      }
    };
    void tick();
    const timer = window.setInterval(() => void tick(), 1_250);
    return () => {
      disposed = true;
      window.clearInterval(timer);
    };
  }, [client]);

  const totalMedia = useMemo(
    () => records.reduce((total, record) => total + record.mediaBytes, 0),
    [records],
  );

  const select = (record: ClientRecord) => {
    setDeleteArmed(false);
    setError(null);
    const next = draftFor(record);
    if (next) setDraft(next);
    else {
      setDraft({ ...newDraft(), record });
    }
  };

  const reset = () => {
    setDraft(newDraft());
    setDeleteArmed(false);
    setError(null);
  };

  const save = async () => {
    setSaving(true);
    setDeleteArmed(false);
    setError(null);
    try {
      const startAtUnixMs = new Date(draft.start).getTime();
      const endAtUnixMs = draft.end ? new Date(draft.end).getTime() : undefined;
      if (!Number.isFinite(startAtUnixMs)) throw new Error("Choose a valid start time.");
      if (endAtUnixMs !== undefined && endAtUnixMs < startAtUnixMs) {
        throw new Error("The end time cannot be earlier than the start time.");
      }
      const parsedMetadata: unknown = JSON.parse(draft.metadata || "{}");
      if (
        typeof parsedMetadata !== "object" ||
        parsedMetadata === null ||
        Array.isArray(parsedMetadata)
      ) {
        throw new Error("Metadata must be a JSON object.");
      }
      const document: RecordDocument = {
        startAtUnixMs,
        ...(endAtUnixMs === undefined ? {} : { endAtUnixMs }),
        ...(draft.emoji.trim() ? { emoji: draft.emoji.trim() } : {}),
        ...(draft.text.trim() ? { text: draft.text.trim() } : {}),
        metadata: parsedMetadata as JsonObject,
        resources: draft.resources,
        references: draft.references,
      };
      if (draft.record) {
        if (!draft.record.document) throw new Error("Encrypted records cannot be edited yet.");
        await client.updateRecord(draft.record.entityId, { visibility: "public", document });
      } else {
        await client.createRecord({ visibility: "public", document });
      }
      await refresh();
      if (!draft.record) setDraft(newDraft());
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "The record could not be saved.");
    } finally {
      setSaving(false);
    }
  };

  const importAttachments = async () => {
    const remaining = MAX_RECORD_ATTACHMENTS - draft.resources.length;
    if (remaining < 1) return;
    setImporting(true);
    setError(null);
    try {
      const imported = await client.importAttachments(remaining);
      if (imported.length > 0) {
        setDraft((current) => ({
          ...current,
          resources: mergeAttachments(current.resources, imported),
        }));
      }
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "The files could not be imported.");
    } finally {
      setImporting(false);
    }
  };

  const removeAttachment = (contentId: string) => {
    setDraft((current) => ({
      ...current,
      resources: current.resources.filter((resource) => resource.contentId !== contentId),
    }));
  };

  const remove = async () => {
    if (!draft.record) return;
    if (!deleteArmed) {
      setDeleteArmed(true);
      return;
    }
    setSaving(true);
    setError(null);
    try {
      await client.deleteRecord(draft.record.entityId);
      setDraft(newDraft());
      setDeleteArmed(false);
      await refresh();
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "The record could not be deleted.");
    } finally {
      setSaving(false);
    }
  };

  const privateSelected = draft.record?.visibility === "private";

  return (
    <>
      <header className="page-header records-header">
        <div>
          <p className="section-kicker">Local-first workspace</p>
          <h1>Records</h1>
          <p>Create locally, keep working offline, and let the native client synchronize quietly.</p>
        </div>
        <div className="records-header__actions">
          <StatusBadge tone={syncTone(status)}>{syncLabel(status)}</StatusBadge>
          <Button onClick={reset}>New record</Button>
        </div>
      </header>

      <div className="records-metrics" aria-label="Local record summary">
        <span><strong>{records.length}</strong> local records shown</span>
        <span><strong>{formatBytes(totalMedia)}</strong> referenced media</span>
        <span><strong>{status?.pendingOperations ?? 0}</strong> operations queued</span>
      </div>

      {error ? <p className="workspace-error" role="alert">{error}</p> : null}

      <div className="records-layout">
        <Panel className="record-list-panel">
          <div className="record-list__header">
            <div><span className="section-kicker">Timeline</span><strong>Newest first</strong></div>
            <Button disabled={loading} onClick={() => void refresh()} variant="quiet">
              {loading ? "Loading…" : "Refresh"}
            </Button>
          </div>
          <div className="record-list" aria-busy={loading}>
            {loading && records.length === 0 ? (
              <div className="record-list__loading">
                <Skeleton height="5rem" /><Skeleton height="5rem" /><Skeleton height="5rem" />
              </div>
            ) : null}
            {!loading && records.length === 0 ? (
              <div className="record-list__empty">
                <span aria-hidden="true">✦</span>
                <strong>Your local timeline is ready.</strong>
                <p>Create the first record. It will be durable before any network request begins.</p>
                <Button onClick={reset}>Create a record</Button>
              </div>
            ) : null}
            {records.map((record) => (
              <RecordCard
                active={draft.record?.entityId === record.entityId}
                key={record.operationId}
                onSelect={() => select(record)}
                record={record}
              />
            ))}
          </div>
        </Panel>

        <Panel className="record-editor-panel">
          <div className="record-editor__header">
            <div>
              <span className="section-kicker">{draft.record ? "Selected moment" : "New moment"}</span>
              <h2>{privateSelected ? "Encrypted record" : draft.record ? "Edit record" : "Capture record"}</h2>
            </div>
            {draft.record?.conflicted ? <StatusBadge tone="offline">Concurrent heads</StatusBadge> : null}
          </div>

          {privateSelected ? (
            <div className="private-record-note">
              <span aria-hidden="true">⌑</span>
              <strong>Content stays encrypted</strong>
              <p>Private-key decryption is not connected to this editor yet. You can retain or delete this record without exposing its content.</p>
            </div>
          ) : (
            <form className="record-form" onSubmit={(event) => { event.preventDefault(); void save(); }}>
              <div className="record-form__lead">
                <label className="field-label record-emoji-field">
                  Emoji
                  <input
                    aria-label="Record emoji"
                    maxLength={16}
                    onChange={(event) => setDraft((value) => ({ ...value, emoji: event.target.value }))}
                    placeholder="✦"
                    value={draft.emoji}
                  />
                </label>
                <label className="field-label">
                  Start
                  <input
                    aria-label="Record start"
                    onChange={(event) => setDraft((value) => ({ ...value, start: event.target.value }))}
                    required
                    type="datetime-local"
                    value={draft.start}
                  />
                </label>
                <label className="field-label">
                  End · optional
                  <input
                    aria-label="Record end"
                    onChange={(event) => setDraft((value) => ({ ...value, end: event.target.value }))}
                    type="datetime-local"
                    value={draft.end}
                  />
                </label>
              </div>
              <label className="field-label">
                What happened?
                <textarea
                  aria-label="Record text"
                  maxLength={16_384}
                  onChange={(event) => setDraft((value) => ({ ...value, text: event.target.value }))}
                  placeholder="Write as much or as little as the moment needs…"
                  rows={8}
                  value={draft.text}
                />
              </label>
              <details className="metadata-editor">
                <summary>Structured metadata</summary>
                <label className="field-label">
                  JSON object
                  <textarea
                    aria-label="Record metadata"
                    onChange={(event) => setDraft((value) => ({ ...value, metadata: event.target.value }))}
                    rows={6}
                    spellCheck={false}
                    value={draft.metadata}
                  />
                </label>
              </details>
              <section className="attachment-editor" aria-busy={importing} aria-label="Attachments">
                <div className="attachment-editor__header">
                  <div>
                    <strong>Attachments</strong>
                    <span>{draft.resources.length}/{MAX_RECORD_ATTACHMENTS} files · imported directly into the private local store.</span>
                  </div>
                  <Button
                    disabled={saving || importing || draft.resources.length >= MAX_RECORD_ATTACHMENTS}
                    onClick={() => void importAttachments()}
                    type="button"
                    variant="quiet"
                  >
                    {importing
                      ? "Choosing files…"
                      : draft.resources.length >= MAX_RECORD_ATTACHMENTS
                        ? "Attachment limit reached"
                        : "Attach files"}
                  </Button>
                </div>
                {draft.resources.length > 0 ? (
                  <ul className="attachment-list">
                    {draft.resources.map((resource, index) => {
                      const name = attachmentName(resource, index);
                      return (
                        <li className="attachment-row" key={resource.contentId}>
                          <span aria-hidden="true" className="attachment-row__icon">
                            {resource.mediaType.startsWith("image/")
                              ? "▧"
                              : resource.mediaType.startsWith("audio/")
                                ? "♪"
                                : resource.mediaType.startsWith("video/")
                                  ? "▷"
                                  : "◇"}
                          </span>
                          <span className="attachment-row__body">
                            <strong>{name}</strong>
                            <span>{attachmentCategory(resource.mediaType)} · {formatBytes(resource.byteLength)}</span>
                          </span>
                          <Button
                            aria-label={`Remove ${name}`}
                            disabled={saving || importing}
                            onClick={() => removeAttachment(resource.contentId)}
                            type="button"
                            variant="quiet"
                          >
                            Remove
                          </Button>
                        </li>
                      );
                    })}
                  </ul>
                ) : (
                  <p className="attachment-list__empty">No files attached.</p>
                )}
              </section>
              {draft.references.length > 0 ? (
                <p className="preserved-data-note">
                  Preserving {draft.references.length} reference{draft.references.length === 1 ? "" : "s"}.
                </p>
              ) : null}
              <div className="record-editor__actions">
                <Button disabled={saving || importing} type="submit">{saving ? "Saving locally…" : draft.record ? "Save changes" : "Save locally"}</Button>
                {draft.record ? (
                  <Button className={deleteArmed ? "danger-button delete-confirm" : "danger-button"} disabled={saving || importing} onClick={() => void remove()} variant="quiet">
                    {deleteArmed ? "Confirm delete" : "Delete"}
                  </Button>
                ) : null}
              </div>
            </form>
          )}

          {privateSelected && draft.record ? (
            <div className="record-editor__actions">
              <Button className={deleteArmed ? "danger-button delete-confirm" : "danger-button"} disabled={saving} onClick={() => void remove()} variant="quiet">
                {deleteArmed ? "Confirm delete" : "Delete encrypted record"}
              </Button>
            </div>
          ) : null}
        </Panel>
      </div>
    </>
  );
}

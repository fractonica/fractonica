import { useCallback, useEffect, useMemo, useReducer, useRef, useState } from "react";
import {
  ActivityIndicator,
  Alert,
  FlatList,
  KeyboardAvoidingView,
  Modal,
  Platform,
  Pressable,
  RefreshControl,
  StyleSheet,
  Text,
  TextInput,
  View,
} from "react-native";
import { SafeAreaView } from "react-native-safe-area-context";
import { OctalGlyph } from "@fractonica/glyph-react-native";

import type {
  ClientRecordPreview,
  ClientStatus,
  PairingClaim,
  PrePairRecordPolicy,
} from "../../core/contracts";
import { discoverNativeClient } from "../../core/native-client-discovery";
import {
  isRecoveryRequiredError,
  type NativeClientPort,
} from "../../core/native-client";
import { colors, radius } from "../../ui/theme";
import {
  EMPTY_COMPOSER_STATE,
  reduceComposerState,
} from "./composer-state";
import {
  commitPublicRecordDraft,
  type LocalRecordSnapshot,
  readLocalRecordSnapshot,
} from "./local-records";
import { recordDateLabel } from "./record-domain";

type CoreState =
  | { kind: "booting" }
  | { kind: "starting"; client: NativeClientPort; status: ClientStatus }
  | { kind: "unavailable"; reason: string }
  | { kind: "ready"; client: NativeClientPort; status: ClientStatus }
  | { kind: "recovery"; client: NativeClientPort; message: string }
  | { kind: "failed"; message: string; client?: NativeClientPort };

function errorMessage(reason: unknown): string {
  return reason instanceof Error ? reason.message : "The local client returned an unknown error.";
}

function formatBytes(bytes: number): string {
  if (bytes < 1_000) return `${bytes} B`;
  if (bytes < 1_000_000) return `${(bytes / 1_000).toFixed(1)} kB`;
  if (bytes < 1_000_000_000) return `${(bytes / 1_000_000).toFixed(1)} MB`;
  return `${(bytes / 1_000_000_000).toFixed(1)} GB`;
}

function statusLabel(state: CoreState): string {
  if (state.kind === "booting" || state.kind === "starting") return "Starting";
  if (state.kind === "ready") {
    const pending =
      state.status.pendingOperations +
      state.status.pendingUploads +
      state.status.pendingDownloads;
    return pending > 0 ? `${pending} pending` : "On device";
  }
  return "Core offline";
}

function stateForSnapshot(
  client: NativeClientPort,
  snapshot: LocalRecordSnapshot,
): CoreState {
  if (snapshot.kind === "failed") {
    return { kind: "failed", message: snapshot.message, client };
  }
  if (snapshot.kind === "starting") {
    return { kind: "starting", client, status: snapshot.status };
  }
  return { kind: "ready", client, status: snapshot.status };
}

function RecordCard({ record }: { record: ClientRecordPreview }) {
  const privateRecord = record.visibility === "private";
  const text = record.textPreview?.trim();
  const emoji = privateRecord ? "⌑" : record.emoji?.trim() || "·";
  return (
    <View style={styles.recordCard}>
      <View style={styles.recordTopLine}>
        <Text style={styles.recordEmoji}>{emoji}</Text>
        <View style={styles.recordHeading}>
          <Text style={styles.recordDate}>{recordDateLabel(record)}</Text>
          <Text numberOfLines={1} style={styles.recordTitle}>
            {privateRecord ? "Private record" : text || "Untitled moment"}
          </Text>
        </View>
      </View>
      {text ? (
        <Text numberOfLines={3} style={styles.recordText}>
          {text}
        </Text>
      ) : null}
      <View style={styles.recordFooter}>
        <Text style={styles.recordMeta}>
          {record.resourceCount === 0
            ? "No attachments"
            : `${record.resourceCount} ${record.resourceCount === 1 ? "attachment" : "attachments"} · ${formatBytes(record.mediaBytes)}`}
        </Text>
        {record.conflicted ? <Text style={styles.conflict}>CONCURRENT</Text> : null}
      </View>
    </View>
  );
}

function CoreNotice({
  state,
  recovering,
  onRecover,
  onRetry,
}: {
  state: CoreState;
  recovering: boolean;
  onRecover(): void;
  onRetry(): void;
}) {
  if (state.kind === "booting" || state.kind === "starting") {
    return (
      <View style={styles.notice}>
        <ActivityIndicator color={colors.accent} />
        <Text style={styles.noticeTitle}>Opening local storage</Text>
        <Text style={styles.noticeText}>Establishing this device’s native Fractonica identity.</Text>
      </View>
    );
  }
  const message =
    state.kind === "unavailable"
      ? state.reason
      : state.kind === "failed" || state.kind === "recovery"
        ? state.message
        : "";
  const title =
    state.kind === "recovery"
      ? "Local installation needs recovery"
      : state.kind === "failed"
        ? "Native core failed"
        : "Native core unavailable";
  return (
    <View style={styles.notice}>
      <View style={styles.noticeGlyph}>
        <OctalGlyph decorative depth={6} foreground={colors.accent} size={30} value="777777" />
      </View>
      <Text style={styles.noticeKicker}>DEVELOPMENT BUILD</Text>
      <Text style={styles.noticeTitle}>{title}</Text>
      <Text style={styles.noticeText}>{message}</Text>
      <Text style={styles.noticeFootnote}>
        {state.kind === "recovery"
          ? "Fractonica will never replace an identity silently. Recovery permanently deletes this device’s local records and protected identity, then creates a new local installation."
          : "Records are never substituted with sample data, and this screen never falls back to a server API."}
      </Text>
      {state.kind === "recovery" ? (
        <Pressable
          accessibilityRole="button"
          disabled={recovering}
          onPress={onRecover}
          style={({ pressed }) => [
            styles.dangerButton,
            pressed && styles.pressed,
            recovering && styles.disabled,
          ]}
        >
          {recovering ? (
            <ActivityIndicator color={colors.background} />
          ) : (
            <Text style={styles.dangerButtonText}>Reset local installation</Text>
          )}
        </Pressable>
      ) : null}
      <Pressable
        accessibilityRole="button"
        disabled={recovering}
        onPress={onRetry}
        style={({ pressed }) => [
          styles.secondaryButton,
          pressed && styles.pressed,
          recovering && styles.disabled,
        ]}
      >
        <Text style={styles.secondaryButtonText}>Try again</Text>
      </Pressable>
    </View>
  );
}

function Composer({
  open,
  saving,
  onClose,
  onCreate,
}: {
  open: boolean;
  saving: boolean;
  onClose(): void;
  onCreate(input: { emoji: string; text: string }): Promise<void>;
}) {
  const [draft, dispatch] = useReducer(reduceComposerState, EMPTY_COMPOSER_STATE);
  const submissionInFlight = useRef(false);
  const mounted = useRef(false);

  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
    };
  }, []);

  const close = () => {
    if (saving || submissionInFlight.current) return;
    dispatch({ type: "discard" });
    onClose();
  };
  const submit = async () => {
    if (saving || submissionInFlight.current) return;
    submissionInFlight.current = true;
    dispatch({ type: "submit" });
    try {
      await onCreate({ emoji: draft.emoji, text: draft.text });
      if (!mounted.current) return;
      dispatch({ type: "committed" });
      onClose();
    } catch (reason) {
      if (!mounted.current) return;
      dispatch({ type: "failed", message: errorMessage(reason) });
    } finally {
      submissionInFlight.current = false;
    }
  };

  return (
    <Modal animationType="slide" onRequestClose={close} presentationStyle="pageSheet" visible={open}>
      <KeyboardAvoidingView behavior={Platform.OS === "ios" ? "padding" : undefined} style={styles.composerShell}>
        <SafeAreaView edges={["top", "bottom"]} style={styles.composerSafeArea}>
          <View style={styles.composerHeader}>
            <Pressable accessibilityRole="button" disabled={saving} onPress={close} hitSlop={12}>
              <Text style={styles.composerCancel}>Cancel</Text>
            </Pressable>
            <Text style={styles.composerTitle}>New record</Text>
            <View style={styles.composerSpacer} />
          </View>
          <View style={styles.composerBody}>
            <Text style={styles.inputLabel}>SYMBOL</Text>
            <TextInput
              accessibilityLabel="Record emoji"
              autoCapitalize="none"
              editable={!saving}
              maxLength={32}
              onChangeText={(value) => dispatch({ type: "changeEmoji", value })}
              placeholder="◇"
              placeholderTextColor={colors.textMuted}
              style={styles.emojiInput}
              value={draft.emoji}
            />
            <Text style={styles.inputLabel}>WHAT HAPPENED?</Text>
            <TextInput
              accessibilityLabel="Record text"
              editable={!saving}
              multiline
              onChangeText={(value) => dispatch({ type: "changeText", value })}
              placeholder="Capture a moment…"
              placeholderTextColor={colors.textMuted}
              style={styles.textInput}
              textAlignVertical="top"
              value={draft.text}
            />
            <View style={styles.localPromise}>
              <Text style={styles.localPromiseIcon}>↓</Text>
              <Text style={styles.localPromiseText}>
                Saved to this device first. Network delivery is handled later by the native client.
              </Text>
            </View>
            {draft.error ? <Text style={styles.errorText}>{draft.error}</Text> : null}
          </View>
          <Pressable
            accessibilityRole="button"
            disabled={saving}
            onPress={() => void submit()}
            style={({ pressed }) => [styles.createButton, pressed && styles.pressed, saving && styles.disabled]}
          >
            {saving ? <ActivityIndicator color={colors.background} /> : <Text style={styles.createButtonText}>Create locally</Text>}
          </Pressable>
        </SafeAreaView>
      </KeyboardAvoidingView>
    </Modal>
  );
}

function PairingModal({
  client,
  invitation,
  open,
  onClose,
}: {
  client?: NativeClientPort;
  invitation?: string;
  open: boolean;
  onClose(): void;
}) {
  const [qr, setQr] = useState("");
  const [claim, setClaim] = useState<PairingClaim | null>(null);
  const [accepted, setAccepted] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [working, setWorking] = useState(false);
  const [recordPolicy, setRecordPolicy] = useState<PrePairRecordPolicy>("merge");
  const autoSubmitted = useRef(false);

  useEffect(() => {
    if (open) return;
    setQr("");
    setClaim(null);
    setAccepted(false);
    setError(null);
    setWorking(false);
    setRecordPolicy("merge");
    autoSubmitted.current = false;
  }, [open]);

  useEffect(() => {
    if (!open || !invitation) return;
    // Deep links can replace a cancelled/failed invitation while this screen
    // remains mounted. Treat the new signed payload as a fresh ceremony.
    setQr(invitation);
    setClaim(null);
    setAccepted(false);
    setError(null);
    setWorking(false);
    setRecordPolicy("merge");
    autoSubmitted.current = false;
  }, [invitation, open]);

  const submit = async (value = qr) => {
    if (!client || working) return;
    setWorking(true);
    setError(null);
    try {
      setClaim(await client.claimPairingInvitation(value.trim()));
    } catch (reason) {
      setError(errorMessage(reason));
    } finally {
      setWorking(false);
    }
  };

  useEffect(() => {
    if (!open || !client || !invitation || claim || working || autoSubmitted.current) return;
    autoSubmitted.current = true;
    setQr(invitation);
    void submit(invitation);
  }, [claim, client, invitation, open, working]);

  const accept = async () => {
    if (!client || !claim || working) return;
    setWorking(true);
    setError(null);
    try {
      await client.acceptPairingInvitation(claim.invitationId, recordPolicy);
      setAccepted(true);
    } catch (reason) {
      setError(errorMessage(reason));
    } finally {
      setWorking(false);
    }
  };

  const digitRows = claim
    ? [claim.confirmationOctal.slice(0, 5), claim.confirmationOctal.slice(5)]
    : [];

  return (
    <Modal animationType="slide" onRequestClose={onClose} presentationStyle="pageSheet" visible={open}>
      <SafeAreaView edges={["top", "bottom"]} style={styles.pairingSafeArea}>
        <View style={styles.composerHeader}>
          <Pressable accessibilityRole="button" disabled={working} hitSlop={12} onPress={onClose}>
            <Text style={styles.composerCancel}>Close</Text>
          </Pressable>
          <Text style={styles.composerTitle}>Link a node</Text>
          <View style={styles.composerSpacer} />
        </View>

        {claim ? (
          <View style={styles.pairingResult}>
            <Text style={styles.pairingKicker}>
              {accepted ? "LINK COMPLETE" : "COMPARE WITH THE DESKTOP"}
            </Text>
            <Text style={styles.pairingTitle}>
              {accepted ? "Node linked" : "Do both sequences match?"}
            </Text>
            <Text style={styles.pairingText}>
              {accepted
                ? "The verified peer is stored on this device and record and media synchronization can continue in the background."
                : "Check every octal digit and both glyphs. Press Link only when the desktop shows the same sequence."}
            </Text>
            {!accepted && claim.localRecordCount > 0 ? (
              <View style={styles.recordPolicy}>
                <Text style={styles.recordPolicyTitle}>
                  {claim.localRecordCount} local {claim.localRecordCount === 1 ? "record" : "records"}
                </Text>
                <Text style={styles.recordPolicyText}>
                  Choose what happens to records created before this device was linked.
                </Text>
                <View style={styles.recordPolicyChoices}>
                  <Pressable
                    accessibilityRole="radio"
                    accessibilityState={{ checked: recordPolicy === "merge" }}
                    onPress={() => setRecordPolicy("merge")}
                    style={[styles.recordPolicyChoice, recordPolicy === "merge" && styles.recordPolicyChoiceSelected]}
                  >
                    <Text style={styles.recordPolicyChoiceTitle}>Merge</Text>
                    <Text style={styles.recordPolicyChoiceText}>Copy into the linked node and sync media.</Text>
                  </Pressable>
                  <Pressable
                    accessibilityRole="radio"
                    accessibilityState={{ checked: recordPolicy === "discard" }}
                    onPress={() => setRecordPolicy("discard")}
                    style={[styles.recordPolicyChoice, recordPolicy === "discard" && styles.recordPolicyChoiceSelected]}
                  >
                    <Text style={styles.recordPolicyChoiceTitle}>Discard</Text>
                    <Text style={styles.recordPolicyChoiceText}>Do not copy them into this linked space.</Text>
                  </Pressable>
                </View>
              </View>
            ) : null}
            <Pressable
              accessibilityLabel={`Link with confirmation ${claim.confirmationOctal}`}
              accessibilityRole="button"
              disabled={working || accepted}
              onPress={() => void accept()}
              style={({ pressed }) => [
                styles.confirmationButton,
                pressed && styles.pressed,
                (working || accepted) && styles.disabled,
              ]}
            >
              <View style={styles.confirmationGlyphs}>
                {digitRows.map((digits) => (
                  <OctalGlyph
                    background={colors.accentWash}
                    depth={5}
                    foreground={colors.accent}
                    key={digits}
                    size={92}
                    value={digits}
                  />
                ))}
              </View>
              <View accessibilityElementsHidden style={styles.confirmationGrid}>
                {digitRows.map((digits) => (
                  <View key={digits} style={styles.confirmationRow}>
                    {[...digits].map((digit, index) => (
                      <Text key={`${digit}-${index}`} style={styles.confirmationDigit}>{digit}</Text>
                    ))}
                  </View>
                ))}
              </View>
              <Text style={styles.confirmationButtonText}>
                {working ? "Linking…" : accepted ? "Linked" : "Link"}
              </Text>
            </Pressable>
            {error ? <Text accessibilityRole="alert" style={styles.errorText}>{error}</Text> : null}
            <Text style={styles.pairingFootnote}>{claim.endpoint}</Text>
          </View>
        ) : (
          <View style={styles.pairingBody}>
            <Text style={styles.pairingKicker}>LOCAL NETWORK LINK</Text>
            <Text style={styles.pairingTitle}>Paste a link invitation</Text>
            <Text style={styles.pairingText}>
              Create a short-lived invitation in the desktop node, then paste its Fractonica v1 payload here. The protected device keys never enter JavaScript.
            </Text>
            <TextInput
              accessibilityLabel="Link invitation"
              autoCapitalize="none"
              autoCorrect={false}
              editable={!working}
              multiline
              onChangeText={setQr}
              placeholder="fractonica-pairing:v1:…"
              placeholderTextColor={colors.textMuted}
              style={styles.pairingInput}
              value={qr}
            />
            {error ? <Text accessibilityRole="alert" style={styles.errorText}>{error}</Text> : null}
            <Pressable
              accessibilityRole="button"
              disabled={!client || working || qr.trim().length === 0}
              onPress={() => void submit()}
              style={({ pressed }) => [
                styles.createButton,
                styles.pairingButton,
                pressed && styles.pressed,
                (!client || working || qr.trim().length === 0) && styles.disabled,
              ]}
            >
              {working ? (
                <ActivityIndicator color={colors.background} />
              ) : (
                <Text style={styles.createButtonText}>Verify and claim</Text>
              )}
            </Pressable>
            <Text style={styles.pairingFootnote}>
              Both devices must be on the same local network. Fractonica authenticates the link with the confirmation glyphs before synchronizing records.
            </Text>
          </View>
        )}
      </SafeAreaView>
    </Modal>
  );
}

export interface RecordsScreenProps {
  pairingInvitation?: string;
  onClosePairing?: () => void;
}

export function RecordsScreen({ pairingInvitation, onClosePairing }: RecordsScreenProps = {}) {
  const [core, setCore] = useState<CoreState>({ kind: "booting" });
  const [records, setRecords] = useState<ClientRecordPreview[]>([]);
  const [refreshing, setRefreshing] = useState(false);
  const [composerOpen, setComposerOpen] = useState(false);
  const [pairingOpen, setPairingOpen] = useState(false);
  const [saving, setSaving] = useState(false);
  const [recovering, setRecovering] = useState(false);
  const [timelineError, setTimelineError] = useState<string | null>(null);
  const loadGeneration = useRef(0);
  const mounted = useRef(false);
  const recoveryInFlight = useRef(false);
  const recoveryPromptOpen = useRef(false);

  const loadKnownClient = useCallback(
    async (
      client: NativeClientPort,
      options: { preserveReadyOnThrownError?: boolean } = {},
    ) => {
      if (!mounted.current) return;
      const generation = ++loadGeneration.current;
      try {
        const snapshot = await readLocalRecordSnapshot(client);
        if (!mounted.current || generation !== loadGeneration.current) return;
        if (snapshot.kind === "ready") {
          setRecords(snapshot.records);
          setTimelineError(null);
        }
        setCore(stateForSnapshot(client, snapshot));
      } catch (reason) {
        if (!mounted.current || generation !== loadGeneration.current) return;
        const message = errorMessage(reason);
        if (isRecoveryRequiredError(reason)) {
          setCore({ kind: "recovery", message, client });
          return;
        }
        if (options.preserveReadyOnThrownError) {
          setTimelineError(`The record is stored locally, but the timeline could not refresh: ${message}`);
          return;
        }
        setCore({ kind: "failed", message, client });
      }
    },
    [],
  );

  const boot = useCallback(async () => {
    if (!mounted.current) return;
    const generation = ++loadGeneration.current;
    setCore({ kind: "booting" });
    setTimelineError(null);
    try {
      const discovery = await discoverNativeClient();
      if (!mounted.current || generation !== loadGeneration.current) return;
      if (discovery.kind === "unavailable") {
        setCore(discovery);
        setRecords([]);
        return;
      }
      await loadKnownClient(discovery.client);
    } catch (reason) {
      if (!mounted.current || generation !== loadGeneration.current) return;
      setCore({
        kind: "failed",
        message: errorMessage(reason),
      });
    }
  }, [loadKnownClient]);

  useEffect(() => {
    mounted.current = true;
    void boot();
    return () => {
      mounted.current = false;
      loadGeneration.current += 1;
    };
  }, [boot]);

  useEffect(() => {
    if (pairingInvitation) setPairingOpen(true);
  }, [pairingInvitation]);

  useEffect(() => {
    if (core.kind !== "starting") return;
    const timer = setTimeout(() => void loadKnownClient(core.client), 500);
    return () => clearTimeout(timer);
  }, [core, loadKnownClient]);

  const refresh = useCallback(async () => {
    if (core.kind !== "ready") {
      await boot();
      return;
    }
    setRefreshing(true);
    try {
      await loadKnownClient(core.client);
    } finally {
      if (mounted.current) setRefreshing(false);
    }
  }, [boot, core, loadKnownClient]);

  const confirmRecovery = useCallback(() => {
    if (
      core.kind !== "recovery" ||
      recovering ||
      recoveryInFlight.current ||
      recoveryPromptOpen.current
    ) return;
    const client = core.client;
    recoveryPromptOpen.current = true;
    Alert.alert(
      "Reset this local installation?",
      "This permanently deletes every record stored only on this device and removes its protected identity. This cannot be undone.",
      [
        {
          text: "Cancel",
          style: "cancel",
          onPress: () => {
            recoveryPromptOpen.current = false;
          },
        },
        {
          text: "Delete local data",
          style: "destructive",
          onPress: () => {
            recoveryPromptOpen.current = false;
            if (recoveryInFlight.current) return;
            recoveryInFlight.current = true;
            setRecovering(true);
            void (async () => {
              try {
                await client.resetLocalInstallation({ confirmed: true });
                if (!mounted.current) return;
                setRecords([]);
                await boot();
              } catch (reason) {
                if (!mounted.current) return;
                setCore({
                  kind: isRecoveryRequiredError(reason) ? "recovery" : "failed",
                  client,
                  message: errorMessage(reason),
                });
              } finally {
                recoveryInFlight.current = false;
                if (mounted.current) setRecovering(false);
              }
            })();
          },
        },
      ],
      {
        onDismiss: () => {
          recoveryPromptOpen.current = false;
        },
      },
    );
  }, [boot, core, recovering]);

  const create = async (input: { emoji: string; text: string }) => {
    if (core.kind !== "ready") throw new Error("The native client is not ready.");
    const client = core.client;
    setSaving(true);
    try {
      await commitPublicRecordDraft(client, input);
      if (mounted.current) {
        void loadKnownClient(client, { preserveReadyOnThrownError: true });
      }
    } finally {
      if (mounted.current) setSaving(false);
    }
  };

  const totalMedia = useMemo(
    () => records.reduce((sum, record) => sum + record.resourceCount, 0),
    [records],
  );
  const coreReady = core.kind === "ready" && core.status.phase === "ready";

  return (
    <SafeAreaView edges={["top", "bottom"]} style={styles.safeArea}>
      <View style={styles.screen}>
        <View style={styles.header}>
          <View style={styles.brand}>
            <OctalGlyph
              background={colors.background}
              decorative
              depth={6}
              foreground={colors.accent}
              size={42}
              value="777777"
            />
            <View>
              <Text style={styles.eyebrow}>FRACTONICA</Text>
              <Text style={styles.title}>Records</Text>
            </View>
          </View>
          <View style={styles.headerActions}>
            <Pressable
              accessibilityRole="button"
              disabled={!coreReady}
              onPress={() => setPairingOpen(true)}
              style={({ pressed }) => [styles.pairButton, pressed && styles.pressed, !coreReady && styles.disabled]}
            >
              <Text style={styles.pairButtonText}>Link</Text>
            </Pressable>
            <View style={[styles.statusPill, coreReady && styles.statusPillReady]}>
              <View style={[styles.statusDot, coreReady && styles.statusDotReady]} />
              <Text style={[styles.statusText, coreReady && styles.statusTextReady]}>{statusLabel(core)}</Text>
            </View>
          </View>
        </View>

        <FlatList
          contentContainerStyle={styles.listContent}
          data={coreReady ? records : []}
          keyExtractor={(record) => record.operationId}
          ListHeaderComponent={
            <>
              <Text style={styles.lede}>A local-first timeline that belongs to this device.</Text>
              <View style={styles.stats}>
                <View style={styles.statBlock}>
                  <Text style={styles.statValue}>{records.length}</Text>
                  <Text style={styles.statLabel}>LOCAL PAGE</Text>
                </View>
                <View style={styles.statDivider} />
                <View style={styles.statBlock}>
                  <Text style={styles.statValue}>{totalMedia}</Text>
                  <Text style={styles.statLabel}>PAGE MEDIA</Text>
                </View>
              </View>
              {!coreReady ? (
                <CoreNotice
                  onRecover={confirmRecovery}
                  onRetry={() => void boot()}
                  recovering={recovering}
                  state={core}
                />
              ) : null}
              {coreReady && timelineError ? (
                <View accessibilityRole="alert" style={styles.timelineError}>
                  <Text style={styles.timelineErrorText}>{timelineError}</Text>
                  <Pressable
                    accessibilityRole="button"
                    onPress={() => void refresh()}
                    style={({ pressed }) => [styles.timelineRetry, pressed && styles.pressed]}
                  >
                    <Text style={styles.timelineRetryText}>Refresh</Text>
                  </Pressable>
                </View>
              ) : null}
              {coreReady && records.length > 0 ? <Text style={styles.sectionLabel}>LATEST</Text> : null}
            </>
          }
          ListEmptyComponent={
            coreReady ? (
              <View style={styles.emptyState}>
                <OctalGlyph decorative depth={6} foreground={colors.accent} size={38} value="777777" />
                <Text style={styles.emptyTitle}>The timeline starts here</Text>
                <Text style={styles.emptyText}>Create a record. It will be committed locally before any future network activity.</Text>
              </View>
            ) : null
          }
          refreshControl={
            <RefreshControl
              colors={[colors.accent]}
              onRefresh={() => void refresh()}
              refreshing={refreshing}
              tintColor={colors.accent}
            />
          }
          renderItem={({ item }) => <RecordCard record={item} />}
          showsVerticalScrollIndicator={false}
        />

        <Pressable
          accessibilityHint={coreReady ? "Creates a record on this device" : "Requires the native client"}
          accessibilityRole="button"
          disabled={!coreReady}
          onPress={() => setComposerOpen(true)}
          style={({ pressed }) => [styles.fab, pressed && styles.pressed, !coreReady && styles.fabDisabled]}
        >
          <Text style={styles.fabPlus}>＋</Text>
          <Text style={styles.fabText}>New record</Text>
        </Pressable>

        <Composer onClose={() => setComposerOpen(false)} onCreate={create} open={composerOpen} saving={saving} />
        <PairingModal
          client={core.kind === "ready" ? core.client : undefined}
          invitation={pairingInvitation}
          onClose={() => {
            setPairingOpen(false);
            onClosePairing?.();
          }}
          open={pairingOpen}
        />
      </View>
    </SafeAreaView>
  );
}

const styles = StyleSheet.create({
  safeArea: { flex: 1, backgroundColor: colors.background },
  screen: { flex: 1, backgroundColor: colors.background },
  header: { flexDirection: "row", alignItems: "center", justifyContent: "space-between", paddingHorizontal: 22, paddingTop: 14, paddingBottom: 12 },
  brand: { flexDirection: "row", alignItems: "center", gap: 13 },
  headerActions: { flexDirection: "row", alignItems: "center", gap: 8 },
  pairButton: { borderColor: colors.border, borderWidth: 1, borderRadius: radius.pill, paddingHorizontal: 12, paddingVertical: 8, backgroundColor: colors.surface },
  pairButtonText: { color: colors.text, fontSize: 12, fontWeight: "700" },
  eyebrow: { color: colors.accent, fontSize: 11, fontWeight: "700", letterSpacing: 2.5 },
  title: { color: colors.text, fontSize: 36, fontWeight: "700", letterSpacing: -1.4, marginTop: 2 },
  statusPill: { flexDirection: "row", alignItems: "center", gap: 7, borderColor: colors.border, borderWidth: 1, borderRadius: radius.pill, paddingHorizontal: 12, paddingVertical: 8, backgroundColor: colors.surface },
  statusPillReady: { borderColor: colors.borderStrong, backgroundColor: colors.accentWash },
  statusDot: { width: 7, height: 7, borderRadius: 4, backgroundColor: colors.warning },
  statusDotReady: { backgroundColor: colors.accent },
  statusText: { color: colors.textMuted, fontSize: 12, fontWeight: "600" },
  statusTextReady: { color: colors.accent },
  listContent: { paddingHorizontal: 18, paddingBottom: 120 },
  lede: { color: colors.textMuted, fontSize: 16, lineHeight: 23, maxWidth: 330, marginTop: 8, marginBottom: 22 },
  stats: { flexDirection: "row", alignItems: "center", backgroundColor: colors.surface, borderColor: colors.border, borderWidth: 1, borderRadius: radius.medium, paddingVertical: 16, marginBottom: 22 },
  statBlock: { flex: 1, paddingHorizontal: 18 },
  statValue: { color: colors.text, fontSize: 22, fontWeight: "700", fontVariant: ["tabular-nums"] },
  statLabel: { color: colors.textMuted, fontSize: 9, fontWeight: "700", letterSpacing: 1.4, marginTop: 4 },
  statDivider: { width: 1, height: 34, backgroundColor: colors.border },
  sectionLabel: { color: colors.textMuted, fontSize: 10, fontWeight: "700", letterSpacing: 2, marginTop: 4, marginBottom: 11, marginLeft: 4 },
  recordCard: { backgroundColor: colors.surface, borderColor: colors.border, borderWidth: 1, borderRadius: radius.large, marginBottom: 12, padding: 17 },
  recordTopLine: { flexDirection: "row", alignItems: "center" },
  recordEmoji: { color: colors.text, fontSize: 30, lineHeight: 38, width: 48 },
  recordHeading: { flex: 1 },
  recordDate: { color: colors.accent, fontSize: 11, fontWeight: "600", letterSpacing: 0.4, marginBottom: 4 },
  recordTitle: { color: colors.text, fontSize: 18, fontWeight: "600" },
  recordText: { color: colors.text, fontSize: 15, lineHeight: 22, marginTop: 15 },
  recordFooter: { flexDirection: "row", alignItems: "center", justifyContent: "space-between", marginTop: 16 },
  recordMeta: { color: colors.textMuted, fontSize: 11 },
  conflict: { color: colors.warning, fontSize: 9, fontWeight: "800", letterSpacing: 1 },
  notice: { alignItems: "center", backgroundColor: colors.surface, borderColor: colors.border, borderWidth: 1, borderRadius: radius.large, paddingHorizontal: 24, paddingVertical: 28 },
  noticeGlyph: { width: 54, height: 54, alignItems: "center", justifyContent: "center", borderColor: colors.borderStrong, borderWidth: 1, borderRadius: 27, backgroundColor: colors.accentWash, marginBottom: 17 },
  noticeKicker: { color: colors.warning, fontSize: 9, fontWeight: "800", letterSpacing: 1.7, marginBottom: 7 },
  noticeTitle: { color: colors.text, fontSize: 20, fontWeight: "700", textAlign: "center", marginTop: 10 },
  noticeText: { color: colors.textMuted, fontSize: 14, lineHeight: 21, textAlign: "center", marginTop: 8 },
  noticeFootnote: { color: colors.textMuted, fontSize: 11, lineHeight: 17, textAlign: "center", marginTop: 15 },
  secondaryButton: { borderColor: colors.borderStrong, borderWidth: 1, borderRadius: radius.pill, paddingHorizontal: 20, paddingVertical: 11, marginTop: 21 },
  secondaryButtonText: { color: colors.accent, fontSize: 13, fontWeight: "700" },
  dangerButton: { minWidth: 210, minHeight: 44, alignItems: "center", justifyContent: "center", backgroundColor: colors.danger, borderRadius: radius.pill, paddingHorizontal: 20, paddingVertical: 11, marginTop: 21 },
  dangerButtonText: { color: colors.background, fontSize: 13, fontWeight: "800" },
  timelineError: { flexDirection: "row", alignItems: "center", gap: 12, backgroundColor: colors.surface, borderColor: colors.danger, borderWidth: 1, borderRadius: radius.medium, paddingHorizontal: 14, paddingVertical: 12, marginBottom: 18 },
  timelineErrorText: { flex: 1, color: colors.danger, fontSize: 12, lineHeight: 18 },
  timelineRetry: { borderColor: colors.danger, borderWidth: 1, borderRadius: radius.pill, paddingHorizontal: 12, paddingVertical: 7 },
  timelineRetryText: { color: colors.danger, fontSize: 11, fontWeight: "800" },
  emptyState: { alignItems: "center", paddingHorizontal: 30, paddingVertical: 52 },
  emptyTitle: { color: colors.text, fontSize: 19, fontWeight: "700", marginTop: 14 },
  emptyText: { color: colors.textMuted, fontSize: 14, lineHeight: 21, textAlign: "center", marginTop: 8 },
  fab: { position: "absolute", right: 20, bottom: 24, flexDirection: "row", alignItems: "center", gap: 6, backgroundColor: colors.accent, borderRadius: radius.pill, paddingLeft: 15, paddingRight: 20, paddingVertical: 14, shadowColor: "#000", shadowOffset: { width: 0, height: 8 }, shadowOpacity: 0.35, shadowRadius: 14, elevation: 8 },
  fabDisabled: { backgroundColor: colors.surfaceRaised, borderColor: colors.border, borderWidth: 1, opacity: 0.65 },
  fabPlus: { color: colors.background, fontSize: 20, fontWeight: "500", lineHeight: 20 },
  fabText: { color: colors.background, fontSize: 14, fontWeight: "800" },
  pressed: { opacity: 0.72 },
  disabled: { opacity: 0.55 },
  composerShell: { flex: 1, backgroundColor: colors.background },
  composerSafeArea: { flex: 1, paddingHorizontal: 20 },
  composerHeader: { flexDirection: "row", alignItems: "center", justifyContent: "space-between", paddingVertical: 16 },
  composerCancel: { color: colors.accent, fontSize: 15, fontWeight: "600" },
  composerTitle: { color: colors.text, fontSize: 17, fontWeight: "700" },
  composerSpacer: { width: 52 },
  composerBody: { flex: 1, paddingTop: 18 },
  inputLabel: { color: colors.textMuted, fontSize: 10, fontWeight: "800", letterSpacing: 1.8, marginBottom: 9, marginLeft: 3 },
  emojiInput: { color: colors.text, fontSize: 35, backgroundColor: colors.surface, borderColor: colors.border, borderWidth: 1, borderRadius: radius.medium, height: 66, paddingHorizontal: 16, marginBottom: 24 },
  textInput: { minHeight: 180, color: colors.text, fontSize: 18, lineHeight: 27, backgroundColor: colors.surface, borderColor: colors.border, borderWidth: 1, borderRadius: radius.large, paddingHorizontal: 17, paddingVertical: 16 },
  localPromise: { flexDirection: "row", alignItems: "flex-start", gap: 11, backgroundColor: colors.accentWash, borderRadius: radius.medium, padding: 14, marginTop: 17 },
  localPromiseIcon: { color: colors.accent, fontSize: 18, lineHeight: 20 },
  localPromiseText: { flex: 1, color: colors.textMuted, fontSize: 12, lineHeight: 18 },
  errorText: { color: colors.danger, fontSize: 13, lineHeight: 19, marginTop: 14 },
  createButton: { alignItems: "center", justifyContent: "center", minHeight: 54, backgroundColor: colors.accent, borderRadius: radius.medium, marginBottom: 8 },
  createButtonText: { color: colors.background, fontSize: 15, fontWeight: "800" },
  pairingSafeArea: { flex: 1, backgroundColor: colors.background, paddingHorizontal: 20 },
  pairingBody: { flex: 1, paddingTop: 36 },
  pairingKicker: { color: colors.accent, fontSize: 10, fontWeight: "800", letterSpacing: 2, textAlign: "center" },
  pairingTitle: { color: colors.text, fontSize: 26, fontWeight: "700", letterSpacing: -0.6, textAlign: "center", marginTop: 12 },
  pairingText: { color: colors.textMuted, fontSize: 14, lineHeight: 21, textAlign: "center", marginTop: 10 },
  pairingInput: { minHeight: 132, color: colors.text, fontSize: 13, lineHeight: 19, backgroundColor: colors.surface, borderColor: colors.border, borderWidth: 1, borderRadius: radius.large, paddingHorizontal: 15, paddingVertical: 14, marginTop: 28, textAlignVertical: "top" },
  pairingButton: { marginTop: 18, flex: 0 },
  pairingFootnote: { color: colors.textMuted, fontSize: 11, lineHeight: 17, textAlign: "center", marginTop: 18 },
  pairingResult: { flex: 1, alignItems: "center", paddingTop: 32 },
  recordPolicy: { width: "100%", backgroundColor: colors.surface, borderColor: colors.border, borderWidth: 1, borderRadius: radius.medium, padding: 14, marginTop: 18 },
  recordPolicyTitle: { color: colors.text, fontSize: 15, fontWeight: "700" },
  recordPolicyText: { color: colors.textMuted, fontSize: 12, lineHeight: 18, marginTop: 4 },
  recordPolicyChoices: { flexDirection: "row", gap: 10, marginTop: 12 },
  recordPolicyChoice: { flex: 1, borderColor: colors.border, borderWidth: 1, borderRadius: radius.medium, padding: 12 },
  recordPolicyChoiceSelected: { borderColor: colors.accent, backgroundColor: colors.accentWash },
  recordPolicyChoiceTitle: { color: colors.text, fontSize: 13, fontWeight: "800" },
  recordPolicyChoiceText: { color: colors.textMuted, fontSize: 10, lineHeight: 15, marginTop: 4 },
  confirmationButton: { width: "100%", alignItems: "center", backgroundColor: colors.accentWash, borderColor: colors.borderStrong, borderWidth: 1, borderRadius: radius.large, paddingHorizontal: 18, paddingVertical: 20, marginTop: 24 },
  confirmationGlyphs: { flexDirection: "row", alignItems: "center", justifyContent: "center", gap: 18 },
  confirmationGrid: { gap: 7, marginTop: 14 },
  confirmationRow: { flexDirection: "row", justifyContent: "center", gap: 7 },
  confirmationDigit: { width: 31, height: 34, color: colors.text, backgroundColor: colors.surface, borderColor: colors.border, borderWidth: 1, borderRadius: 7, fontSize: 21, fontWeight: "700", lineHeight: 32, textAlign: "center", fontVariant: ["tabular-nums"] },
  confirmationButtonText: { color: colors.accent, fontSize: 17, fontWeight: "800", marginTop: 17 },
});

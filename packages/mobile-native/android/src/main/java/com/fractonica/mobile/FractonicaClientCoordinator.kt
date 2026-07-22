package com.fractonica.mobile

import android.content.Context
import com.fractonica.mobile.core.MobileClientBootstrap
import com.fractonica.mobile.core.MobileClientCore
import com.fractonica.mobile.core.MobileClientException
import com.fractonica.mobile.core.MobileClientStatus
import com.fractonica.mobile.core.MobileIdentityAction
import com.fractonica.mobile.core.MobilePairingClaim
import com.fractonica.mobile.core.MobilePrePairRecordPolicy
import com.fractonica.mobile.core.MobileRecordDetail
import com.fractonica.mobile.core.MobileRecordPreview
import com.fractonica.mobile.core.generateIdentityMaterial
import com.fractonica.mobile.core.mobileCoreBridgeStatus
import expo.modules.kotlin.exception.CodedException
import org.json.JSONObject
import java.io.File

internal class FractonicaClientBridgeException(
  code: String,
  message: String,
  cause: Throwable? = null,
) : CodedException(code, message, cause)

/**
 * Serial native owner of the Rust runtime. Neither the app-private path nor
 * protected identity material is exposed through an Expo return value.
 */
internal class FractonicaClientCoordinator(context: Context) {
  private val identities = FractonicaIdentityStore(context)
  private val clientDirectory = File(context.noBackupFilesDir, "fractonica-client")
  private var bootstrap: MobileClientBootstrap? = null
  private var client: MobileClientCore? = null
  private var closed = false

  @Synchronized
  fun bridgeStatus(): Map<String, Any> {
    ensureCoordinatorOpen()
    val status = mobileCoreBridgeStatus()
    if (status.apiVersion != 1U || !status.rustCoreLinked) throw unavailable()
    return mapOf(
      "apiVersion" to 1,
      "implementation" to "expo-native-shell",
      "rustCoreLinked" to true,
    )
  }

  @Synchronized
  fun status(): Map<String, Any?> = nativeCall { statusMap(ensureClient().status()) }

  @Synchronized
  fun listRecords(options: Map<String, Any?>): List<Map<String, Any?>> {
    val rawLimit = (options["limit"] as? Number)?.toDouble() ?: throw invalidRequest()
    if (!rawLimit.isFinite() || rawLimit % 1.0 != 0.0 || rawLimit !in 1.0..200.0) {
      throw invalidRequest()
    }
    val limit = rawLimit.toInt()
    return nativeCall { ensureClient().listRecords(limit.toUInt()) }.map(::recordPreviewMap)
  }

  @Synchronized
  fun getRecord(options: Map<String, Any?>): Map<String, Any?>? {
    val operationId = options["operationId"] as? String ?: throw invalidRequest()
    val entityId = options["entityId"] as? String ?: throw invalidRequest()
    return nativeCall { ensureClient().getRecord(operationId, entityId) }?.let(::recordDetailMap)
  }

  @Synchronized
  fun createRecord(options: Map<String, Any?>): Map<String, Any> {
    val payload = options["payload"] as? Map<*, *> ?: throw invalidRequest()
    val result = nativeCall {
      ensureClient().createPublicRecord(JSONObject(payload).toString())
    }
    return mapOf(
      "localSequence" to safeNumber(result.localSequence),
      "operationId" to result.operationId,
      "replayed" to result.replayed,
      "queuedPeers" to safeNumber(result.queuedPeers),
    )
  }

  @Synchronized
  fun claimPairingInvitation(options: Map<String, Any?>): Map<String, Any> {
    if (options.size != 1) throw invalidRequest()
    val qr = options["qr"] as? String ?: throw invalidRequest()
    if (qr.isEmpty()) throw invalidRequest()
    return nativeCall { pairingClaimMap(ensureClient().claimPairingInvitation(qr)) }
  }

  @Synchronized
  fun acceptPairingInvitation(options: Map<String, Any?>): Map<String, Any> {
    if (options.size != 2) throw invalidRequest()
    val invitationId = options["invitationId"] as? String ?: throw invalidRequest()
    if (invitationId.isEmpty()) throw invalidRequest()
    val recordPolicy = when (options["recordPolicy"] as? String) {
      "merge" -> MobilePrePairRecordPolicy.MERGE
      "discard" -> MobilePrePairRecordPolicy.DISCARD
      else -> throw invalidRequest()
    }
    return nativeCall {
      pairingClaimMap(ensureClient().acceptPairingInvitation(invitationId, recordPolicy))
    }
  }

  @Synchronized
  fun resetLocalInstallation(options: Map<String, Any?>) {
    ensureCoordinatorOpen()
    if (options.size != 1 || options["confirmation"] != RESET_CONFIRMATION) {
      throw invalidRequest()
    }

    closeCurrentClient()
    val recovery = nativeCall {
      MobileClientBootstrap(clientDirectory.absolutePath, "Personal space")
    }
    try {
      // Delete local data first. If protected-state deletion then fails, the
      // retained identity forces another explicit recovery instead of silent
      // replacement beside an old database.
      nativeCall { recovery.resetLocalInstallation(RESET_CONFIRMATION) }
      nativeCall { identities.delete() }
    } finally {
      recovery.close()
    }
  }

  @Synchronized
  fun shutdown() {
    if (closed) return
    closed = true
    closeCurrentClient()
  }

  private fun ensureClient(): MobileClientCore {
    ensureCoordinatorOpen()
    client?.let { return it }
    val stored = identities.load()
    var candidateBootstrap: MobileClientBootstrap? = null
    var candidateClient: MobileClientCore? = null
    try {
      val bootstrap = nativeCall {
        MobileClientBootstrap(clientDirectory.absolutePath, "Personal space")
      }
      candidateBootstrap = bootstrap
      val action = nativeCall { bootstrap.prepare(stored != null) }
      val identity = when (action) {
        MobileIdentityAction.CREATE_OR_RESUME -> stored ?: createIdentity()
        MobileIdentityAction.OPEN_EXISTING -> stored ?: throw unavailable()
      }

      val material = identity.material.copyOf()
      try {
        val client = nativeCall { bootstrap.open(material) }
        candidateClient = client
        // If the process died after Rust established SQLite but before this
        // outer marker update, restart still passes `identityPresent = true`,
        // reopens the same installation, and retries this transition.
        identities.markEstablished(identity)
        this.bootstrap = bootstrap
        this.client = client
        candidateBootstrap = null
        candidateClient = null
        return client
      } finally {
        material.fill(0)
        identity.material.fill(0)
      }
    } catch (error: Throwable) {
      // `open` may succeed before KeyStore lifecycle finalization fails. Do
      // not leave that runtime waiting for a later GC pass to release it.
      runCatching { candidateClient?.shutdown() }
      runCatching { candidateClient?.close() }
      runCatching { candidateBootstrap?.close() }
      throw error
    } finally {
      stored?.material?.fill(0)
    }
  }

  private fun closeCurrentClient() {
    val currentClient = client
    val currentBootstrap = bootstrap
    client = null
    bootstrap = null
    runCatching { currentClient?.shutdown() }
    runCatching { currentClient?.close() }
    runCatching { currentBootstrap?.close() }
  }

  private fun ensureCoordinatorOpen() {
    if (closed) throw unavailable()
  }

  private fun createIdentity(): FractonicaStoredIdentity {
    val generated = nativeCall { generateIdentityMaterial() }
    return try {
      identities.createInitializing(generated)
    } finally {
      generated.fill(0)
    }
  }

  private fun statusMap(status: MobileClientStatus): Map<String, Any?> = buildMap {
    put("phase", status.phase)
    status.nodeId?.let { put("nodeId", it) }
    status.actorId?.let { put("actorId", it) }
    status.spaceId?.let { put("spaceId", it) }
    put("syncRunning", status.syncRunning)
    put("cycle", safeNumber(status.cycle))
    put("pendingOperations", safeNumber(status.pendingOperations))
    put("rejectedOperations", safeNumber(status.rejectedOperations))
    put("waitingUploads", safeNumber(status.waitingUploads))
    put("pendingUploads", safeNumber(status.pendingUploads))
    put("pendingDownloads", safeNumber(status.pendingDownloads))
    put("rejectedResources", safeNumber(status.rejectedResources))
    put("synchronizedBytes", safeNumber(status.synchronizedBytes))
    put("totalBytes", safeNumber(status.totalBytes))
    status.lastError?.let { put("lastError", it) }
  }

  private fun recordPreviewMap(record: MobileRecordPreview): Map<String, Any?> = buildMap {
    put("operationId", record.operationId)
    put("entityId", record.entityId)
    put("schema", record.schema)
    put("visibility", record.visibility)
    put("conflicted", record.conflicted)
    put("tombstone", record.tombstone)
    record.startAtUnixMs?.let { put("startAtUnixMs", safeNumber(it)) }
    record.endAtUnixMs?.let { put("endAtUnixMs", safeNumber(it)) }
    record.sortText?.let { put("sortText", it) }
    put("resourceCount", safeNumber(record.resourceCount))
    put("mediaBytes", safeNumber(record.mediaBytes))
    record.emoji?.let { put("emoji", it) }
    record.textPreview?.let { put("textPreview", it) }
    put("previewTruncated", record.previewTruncated)
  }

  private fun recordDetailMap(record: MobileRecordDetail): Map<String, Any?> = buildMap {
    put("operationId", record.operationId)
    put("entityId", record.entityId)
    put("schema", record.schema)
    put("visibility", record.visibility)
    put("conflicted", record.conflicted)
    put("tombstone", record.tombstone)
    record.startAtUnixMs?.let { put("startAtUnixMs", safeNumber(it)) }
    record.endAtUnixMs?.let { put("endAtUnixMs", safeNumber(it)) }
    record.sortText?.let { put("sortText", it) }
    put("resourceCount", safeNumber(record.resourceCount))
    put("mediaBytes", safeNumber(record.mediaBytes))
    // Parsing this through JSONObject would silently narrow exact canonical
    // metadata integers when the value reaches JavaScript.
    record.documentJson?.let { put("documentJson", it) }
  }

  private fun pairingClaimMap(claim: MobilePairingClaim): Map<String, Any> = mapOf(
    "invitationId" to claim.invitationId,
    "responderNodeId" to claim.responderNodeId,
    "spaceId" to claim.spaceId,
    "endpoint" to claim.endpoint,
    "confirmationOctal" to claim.confirmationOctal,
    "grantOperationId" to claim.grantOperationId,
    "localRecordCount" to safeNumber(claim.localRecordCount),
  )

  private fun safeNumber(value: ULong): Double {
    if (value > MAX_SAFE_JAVASCRIPT_INTEGER) throw unavailable()
    return value.toDouble()
  }

  private fun safeNumber(value: Long): Double {
    if (value !in -MAX_SAFE_JAVASCRIPT_INTEGER_LONG..MAX_SAFE_JAVASCRIPT_INTEGER_LONG) {
      throw unavailable()
    }
    return value.toDouble()
  }

  private inline fun <T> nativeCall(block: () -> T): T = try {
    block()
  } catch (error: FractonicaIdentityStoreException) {
    if (error.requiresRecovery) throw recoveryRequired(error)
    throw unavailable(error)
  } catch (error: MobileClientException.InvalidIdentity) {
    throw recoveryRequired(error)
  } catch (error: MobileClientException.RecoveryRequired) {
    throw recoveryRequired(error)
  } catch (error: MobileClientException.InvalidRecord) {
    throw invalidRequest(error)
  } catch (error: MobileClientException.InvalidPairingInvitation) {
    throw invalidRequest(error)
  } catch (error: MobileClientException.PairingFailed) {
    throw pairingFailed(error)
  } catch (error: MobileClientException.PairingTransportUnavailable) {
    throw linkUnreachable(error)
  } catch (error: FractonicaClientBridgeException) {
    throw error
  } catch (error: Throwable) {
    throw unavailable(error)
  }

  private fun invalidRequest(cause: Throwable? = null) = FractonicaClientBridgeException(
    "ERR_FRACTONICA_INVALID_REQUEST",
    "The native client request is invalid.",
    cause,
  )

  private fun recoveryRequired(cause: Throwable? = null) = FractonicaClientBridgeException(
    "ERR_FRACTONICA_RECOVERY_REQUIRED",
    "The local installation requires explicit recovery.",
    cause,
  )

  private fun unavailable(cause: Throwable? = null) = FractonicaClientBridgeException(
    "ERR_FRACTONICA_CLIENT_UNAVAILABLE",
    "The local Fractonica client is unavailable.",
    cause,
  )

  private fun pairingFailed(cause: Throwable? = null) = FractonicaClientBridgeException(
    "ERR_FRACTONICA_PAIRING_FAILED",
    "The pairing invitation could not be claimed or completed. Create a new invitation and try again.",
    cause,
  )

  private fun linkUnreachable(cause: Throwable? = null) = FractonicaClientBridgeException(
    "ERR_FRACTONICA_LINK_UNREACHABLE",
    "The linked node could not be reached. Confirm both devices are on the same local network.",
    cause,
  )

  private companion object {
    const val RESET_CONFIRMATION = "RESET_LOCAL_INSTALLATION"
    const val MAX_SAFE_JAVASCRIPT_INTEGER_LONG = 9_007_199_254_740_991L
    val MAX_SAFE_JAVASCRIPT_INTEGER = 9_007_199_254_740_991UL
  }
}

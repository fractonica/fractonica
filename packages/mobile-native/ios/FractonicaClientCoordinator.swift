import Foundation
import ExpoModulesCore

final class FractonicaClientModuleError: Exception, @unchecked Sendable {
  private let clientReason: String

  private init(code: String, reason: String) {
    clientReason = reason
    super.init(name: "FractonicaClientModuleError", description: reason, code: code)
  }

  override var reason: String { clientReason }

  static var invalidRequest: FractonicaClientModuleError {
    FractonicaClientModuleError(
      code: "ERR_FRACTONICA_INVALID_REQUEST",
      reason: "The native client request is invalid."
    )
  }

  static var recoveryRequired: FractonicaClientModuleError {
    FractonicaClientModuleError(
      code: "ERR_FRACTONICA_RECOVERY_REQUIRED",
      reason: "The local installation requires explicit recovery."
    )
  }

  static var unavailable: FractonicaClientModuleError {
    FractonicaClientModuleError(
      code: "ERR_FRACTONICA_CLIENT_UNAVAILABLE",
      reason: "The local Fractonica client is unavailable."
    )
  }
}

/// Serial native owner of the Rust runtime. Paths and protected identity bytes
/// remain below this type and are never represented in a JavaScript value.
final class FractonicaClientCoordinator {
  private let resetConfirmation = "RESET_LOCAL_INSTALLATION"
  private let identities = FractonicaIdentityStore()
  private var bootstrap: MobileClientBootstrap?
  private var client: MobileClientCore?

  func bridgeStatus() throws -> [String: Any] {
    let status = mobileCoreBridgeStatus()
    guard status.apiVersion == 1, status.rustCoreLinked else {
      throw FractonicaClientModuleError.unavailable
    }
    return [
      "apiVersion": 1,
      "implementation": "expo-native-shell",
      "rustCoreLinked": true,
    ]
  }

  func status() throws -> [String: Any] {
    let status = try nativeCall { try ensureClient().status() }
    var result: [String: Any] = [
      "phase": status.phase,
      "syncRunning": status.syncRunning,
      "cycle": try safeNumber(status.cycle),
      "pendingOperations": try safeNumber(status.pendingOperations),
      "rejectedOperations": try safeNumber(status.rejectedOperations),
      "waitingUploads": try safeNumber(status.waitingUploads),
      "pendingUploads": try safeNumber(status.pendingUploads),
      "pendingDownloads": try safeNumber(status.pendingDownloads),
      "rejectedResources": try safeNumber(status.rejectedResources),
      "synchronizedBytes": try safeNumber(status.synchronizedBytes),
      "totalBytes": try safeNumber(status.totalBytes),
    ]
    status.nodeId.map { result["nodeId"] = $0 }
    status.actorId.map { result["actorId"] = $0 }
    status.spaceId.map { result["spaceId"] = $0 }
    status.lastError.map { result["lastError"] = $0 }
    return result
  }

  func listRecords(options: [String: Any]) throws -> [[String: Any]] {
    guard let limitNumber = options["limit"] as? NSNumber else {
      throw FractonicaClientModuleError.invalidRequest
    }
    let rawLimit = limitNumber.doubleValue
    guard rawLimit.isFinite,
      rawLimit.rounded(.towardZero) == rawLimit,
      rawLimit >= 1,
      rawLimit <= 200,
      let limit = UInt32(exactly: rawLimit)
    else {
      throw FractonicaClientModuleError.invalidRequest
    }
    return try nativeCall {
      try ensureClient().listRecords(limit: limit).map(recordPreviewDictionary)
    }
  }

  func getRecord(options: [String: Any]) throws -> [String: Any]? {
    guard let operationId = options["operationId"] as? String,
      let entityId = options["entityId"] as? String
    else {
      throw FractonicaClientModuleError.invalidRequest
    }
    return try nativeCall {
      try ensureClient().getRecord(operationId: operationId, entityId: entityId)
        .map(recordDetailDictionary)
    }
  }

  func createRecord(options: [String: Any]) throws -> [String: Any] {
    guard let payload = options["payload"] as? [String: Any],
      JSONSerialization.isValidJSONObject(payload)
    else {
      throw FractonicaClientModuleError.invalidRequest
    }
    let data = try JSONSerialization.data(withJSONObject: payload, options: [.sortedKeys])
    guard let json = String(data: data, encoding: .utf8) else {
      throw FractonicaClientModuleError.invalidRequest
    }
    let result = try nativeCall {
      try ensureClient().createPublicRecord(payloadJson: json)
    }
    return [
      "localSequence": try safeNumber(result.localSequence),
      "operationId": result.operationId,
      "replayed": result.replayed,
      "queuedPeers": try safeNumber(result.queuedPeers),
    ]
  }

  func resetLocalInstallation(options: [String: Any]) throws {
    guard options.count == 1,
      let confirmation = options["confirmation"] as? String,
      confirmation == resetConfirmation
    else {
      throw FractonicaClientModuleError.invalidRequest
    }

    closeCurrentClient()
    let recovery = try nativeCall {
      try MobileClientBootstrap(
        storageDir: clientStorageURL().path,
        displayName: "Personal space"
      )
    }
    // Rust deletes the database and content first. Keychain removal follows,
    // so a crash between the two steps returns to explicit recovery instead
    // of silently creating a replacement identity beside old data.
    try nativeCall {
      try recovery.resetLocalInstallation(confirmation: confirmation)
    }
    try nativeCall { try identities.delete() }
  }

  func shutdown() {
    closeCurrentClient()
  }

  private func ensureClient() throws -> MobileClientCore {
    if let client {
      return client
    }

    let stored = try identities.load()
    let bootstrap = try MobileClientBootstrap(
      storageDir: clientStorageURL().path,
      displayName: "Personal space"
    )
    let action = try bootstrap.prepare(identityPresent: stored != nil)
    let identity: FractonicaStoredIdentity
    switch action {
    case .createOrResume:
      if let stored {
        identity = stored
      } else {
        var generated = try generateIdentityMaterial()
        defer { generated.resetBytes(in: 0..<generated.count) }
        identity = try identities.createInitializing(material: generated)
      }
    case .openExisting:
      guard let stored else {
        throw FractonicaClientModuleError.unavailable
      }
      identity = stored
    }

    var material = identity.material
    defer { material.resetBytes(in: 0..<material.count) }
    let client = try bootstrap.open(identityMaterial: material)
    // This transition intentionally follows Rust open. A crash after Rust has
    // established SQLite but before this update restarts with a complete
    // `.initializing` identity, opens the same database, and retries the mark.
    do {
      try identities.markEstablished(identity)
    } catch {
      // UniFFI objects otherwise wait for ARC to release them. Explicitly stop
      // a successfully opened core when the outer lifecycle commit fails.
      try? client.shutdown()
      throw error
    }
    self.bootstrap = bootstrap
    self.client = client
    return client
  }

  private func closeCurrentClient() {
    let currentClient = client
    client = nil
    bootstrap = nil
    try? currentClient?.shutdown()
  }

  private func clientStorageURL() throws -> URL {
    guard let applicationSupport = FileManager.default.urls(
      for: .applicationSupportDirectory,
      in: .userDomainMask
    ).first else {
      throw FractonicaClientModuleError.unavailable
    }
    return applicationSupport
      .appendingPathComponent("Fractonica", isDirectory: true)
      .appendingPathComponent("Client", isDirectory: true)
  }

  private func recordPreviewDictionary(_ record: MobileRecordPreview) throws -> [String: Any] {
    var result: [String: Any] = [
      "operationId": record.operationId,
      "entityId": record.entityId,
      "schema": record.schema,
      "visibility": record.visibility,
      "conflicted": record.conflicted,
      "tombstone": record.tombstone,
      "resourceCount": try safeNumber(record.resourceCount),
      "mediaBytes": try safeNumber(record.mediaBytes),
      "previewTruncated": record.previewTruncated,
    ]
    if let start = record.startAtUnixMs { result["startAtUnixMs"] = try safeNumber(start) }
    if let end = record.endAtUnixMs { result["endAtUnixMs"] = try safeNumber(end) }
    record.sortText.map { result["sortText"] = $0 }
    record.emoji.map { result["emoji"] = $0 }
    record.textPreview.map { result["textPreview"] = $0 }
    return result
  }

  private func recordDetailDictionary(_ record: MobileRecordDetail) throws -> [String: Any] {
    var result: [String: Any] = [
      "operationId": record.operationId,
      "entityId": record.entityId,
      "schema": record.schema,
      "visibility": record.visibility,
      "conflicted": record.conflicted,
      "tombstone": record.tombstone,
      "resourceCount": try safeNumber(record.resourceCount),
      "mediaBytes": try safeNumber(record.mediaBytes),
    ]
    if let start = record.startAtUnixMs { result["startAtUnixMs"] = try safeNumber(start) }
    if let end = record.endAtUnixMs { result["endAtUnixMs"] = try safeNumber(end) }
    record.sortText.map { result["sortText"] = $0 }
    // Keep the exact JSON text opaque. Parsing through JSONSerialization would
    // round canonical metadata integers outside JavaScript's safe range.
    record.documentJson.map { result["documentJson"] = $0 }
    return result
  }

  private func safeNumber(_ value: UInt64) throws -> Double {
    guard value <= 9_007_199_254_740_991 else {
      throw FractonicaClientModuleError.unavailable
    }
    return Double(value)
  }

  private func safeNumber(_ value: Int64) throws -> Double {
    guard value >= -9_007_199_254_740_991, value <= 9_007_199_254_740_991 else {
      throw FractonicaClientModuleError.unavailable
    }
    return Double(value)
  }

  private func nativeCall<T>(_ body: () throws -> T) throws -> T {
    do {
      return try body()
    } catch let error as FractonicaClientModuleError {
      throw error
    } catch FractonicaIdentityStoreError.corrupt,
      FractonicaIdentityStoreError.conflict,
      MobileClientError.InvalidIdentity
    {
      throw FractonicaClientModuleError.recoveryRequired
    } catch MobileClientError.RecoveryRequired {
      throw FractonicaClientModuleError.recoveryRequired
    } catch MobileClientError.InvalidRecord {
      throw FractonicaClientModuleError.invalidRequest
    } catch {
      throw FractonicaClientModuleError.unavailable
    }
  }
}

import Foundation
import ExpoModulesCore
import Security

enum FractonicaIdentityLifecycle: UInt8 {
  case initializing = 1
  case established = 2
}

struct FractonicaStoredIdentity {
  let lifecycle: FractonicaIdentityLifecycle
  let material: Data

  func changingLifecycle(to lifecycle: FractonicaIdentityLifecycle) -> Self {
    Self(
      lifecycle: lifecycle,
      material: material
    )
  }

  func hasSameMaterial(as other: Self) -> Bool {
    material == other.material
  }
}

enum FractonicaIdentityStoreError: CodedError {
  case unavailable
  case corrupt
  case randomSource
  case conflict

  var code: String {
    switch self {
    case .unavailable: "ERR_FRACTONICA_IDENTITY_UNAVAILABLE"
    case .corrupt: "ERR_FRACTONICA_IDENTITY_CORRUPT"
    case .randomSource: "ERR_FRACTONICA_RANDOM_SOURCE"
    case .conflict: "ERR_FRACTONICA_IDENTITY_CONFLICT"
    }
  }

  var description: String {
    switch self {
    case .unavailable: "The protected Fractonica identity is temporarily unavailable."
    case .corrupt: "The protected Fractonica identity is incomplete or corrupt."
    case .randomSource: "Secure identity material could not be generated."
    case .conflict: "The protected Fractonica identity changed during initialization."
    }
  }
}

final class FractonicaIdentityStore {
  private let service = "com.fractonica.mobile.identity"
  private let account = "installation-v1"
  private let magic = Data("FRACTKS1".utf8)
  private let maximumMaterialBytes = 1_024

  func load() throws -> FractonicaStoredIdentity? {
    var query = baseQuery()
    query[kSecReturnData as String] = true
    query[kSecMatchLimit as String] = kSecMatchLimitOne
    var result: CFTypeRef?
    let status = SecItemCopyMatching(query as CFDictionary, &result)
    switch status {
    case errSecSuccess:
      guard let data = result as? Data else {
        throw FractonicaIdentityStoreError.corrupt
      }
      return try decode(data)
    case errSecItemNotFound:
      return nil
    case errSecInteractionNotAllowed, errSecNotAvailable:
      throw FractonicaIdentityStoreError.unavailable
    default:
      throw FractonicaIdentityStoreError.corrupt
    }
  }

  func createInitializing(material: Data) throws -> FractonicaStoredIdentity {
    if let existing = try load() {
      return existing
    }
    guard !material.isEmpty, material.count <= maximumMaterialBytes else {
      throw FractonicaIdentityStoreError.corrupt
    }
    let identity = FractonicaStoredIdentity(
      lifecycle: .initializing,
      material: material
    )
    var query = baseQuery()
    query[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
    query[kSecValueData as String] = encode(identity)
    let status = SecItemAdd(query as CFDictionary, nil)
    if status == errSecDuplicateItem, let existing = try load() {
      return existing
    }
    guard status == errSecSuccess else {
      throw FractonicaIdentityStoreError.unavailable
    }
    return identity
  }

  func markEstablished(_ expected: FractonicaStoredIdentity) throws {
    guard let current = try load(), current.hasSameMaterial(as: expected) else {
      throw FractonicaIdentityStoreError.conflict
    }
    if current.lifecycle == .established {
      return
    }
    let attributes = [
      kSecValueData as String: encode(current.changingLifecycle(to: .established)),
    ]
    let status = SecItemUpdate(baseQuery() as CFDictionary, attributes as CFDictionary)
    guard status == errSecSuccess else {
      throw FractonicaIdentityStoreError.unavailable
    }
  }

  /// Removes the protected identity only as the second half of an explicit
  /// local-installation reset. This method never runs during normal startup.
  func delete() throws {
    let status = SecItemDelete(baseQuery() as CFDictionary)
    switch status {
    case errSecSuccess, errSecItemNotFound:
      return
    case errSecInteractionNotAllowed, errSecNotAvailable:
      throw FractonicaIdentityStoreError.unavailable
    default:
      throw FractonicaIdentityStoreError.corrupt
    }
  }

  private func baseQuery() -> [String: Any] {
    [
      kSecClass as String: kSecClassGenericPassword,
      kSecAttrService as String: service,
      kSecAttrAccount as String: account,
      kSecAttrSynchronizable as String: false,
    ]
  }

  private func encode(_ identity: FractonicaStoredIdentity) -> Data {
    var data = magic
    data.append(identity.lifecycle.rawValue)
    data.append(identity.material)
    return data
  }

  private func decode(_ data: Data) throws -> FractonicaStoredIdentity {
    guard data.count > magic.count + 1,
      data.count <= magic.count + 1 + maximumMaterialBytes,
      data.prefix(magic.count) == magic
    else {
      throw FractonicaIdentityStoreError.corrupt
    }
    let lifecycleOffset = magic.count
    guard let lifecycle = FractonicaIdentityLifecycle(rawValue: data[lifecycleOffset]) else {
      throw FractonicaIdentityStoreError.corrupt
    }
    return FractonicaStoredIdentity(
      lifecycle: lifecycle,
      material: Data(data[(lifecycleOffset + 1)...])
    )
  }
}

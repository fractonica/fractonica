import ExpoModulesCore

public final class FractonicaClientModule: Module {
  private let clientQueue = DispatchQueue(label: "org.fractonica.mobile.client", qos: .userInitiated)
  private let coordinator = FractonicaClientCoordinator()

  public func definition() -> ModuleDefinition {
    Name("FractonicaClient")

    AsyncFunction("bridgeStatus") { () throws -> [String: Any] in
      try self.coordinator.bridgeStatus()
    }.runOnQueue(clientQueue)

    AsyncFunction("clientStatus") { () throws -> [String: Any] in
      try self.coordinator.status()
    }.runOnQueue(clientQueue)

    AsyncFunction("clientListRecords") { (options: [String: Any]) throws -> [[String: Any]] in
      try self.coordinator.listRecords(options: options)
    }.runOnQueue(clientQueue)

    AsyncFunction("clientGetRecord") { (options: [String: Any]) throws -> [String: Any]? in
      try self.coordinator.getRecord(options: options)
    }.runOnQueue(clientQueue)

    AsyncFunction("clientCreateRecord") { (options: [String: Any]) throws -> [String: Any] in
      try self.coordinator.createRecord(options: options)
    }.runOnQueue(clientQueue)

    AsyncFunction("clientClaimPairingInvitation") { (options: [String: Any]) throws -> [String: Any] in
      try self.coordinator.claimPairingInvitation(options: options)
    }.runOnQueue(clientQueue)

    AsyncFunction("clientAcceptPairingInvitation") { (options: [String: Any]) throws -> [String: Any] in
      try self.coordinator.acceptPairingInvitation(options: options)
    }.runOnQueue(clientQueue)

    AsyncFunction("clientResetLocalInstallation") { (options: [String: Any]) throws in
      try self.coordinator.resetLocalInstallation(options: options)
    }.runOnQueue(clientQueue)

    OnDestroy {
      self.clientQueue.async {
        self.coordinator.shutdown()
      }
    }
  }
}

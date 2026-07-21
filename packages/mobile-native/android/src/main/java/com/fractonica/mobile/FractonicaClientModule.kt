package com.fractonica.mobile

import expo.modules.kotlin.modules.Module
import expo.modules.kotlin.modules.ModuleDefinition
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.asCoroutineDispatcher
import kotlinx.coroutines.cancel
import java.util.concurrent.Executors

class FractonicaClientModule : Module() {
  private val dispatcher = Executors.newSingleThreadExecutor { runnable ->
    Thread(runnable, "fractonica-mobile-client")
  }.asCoroutineDispatcher()
  private val clientScope = CoroutineScope(SupervisorJob() + dispatcher)
  private var coordinator: FractonicaClientCoordinator? = null
  private var destroyed = false

  override fun definition() = ModuleDefinition {
    Name("FractonicaClient")

    AsyncFunction("bridgeStatus") {
      coordinator().bridgeStatus()
    }.runOnQueue(clientScope)

    AsyncFunction("clientStatus") {
      coordinator().status()
    }.runOnQueue(clientScope)

    AsyncFunction("clientListRecords") { options: Map<String, Any?> ->
      coordinator().listRecords(options)
    }.runOnQueue(clientScope)

    AsyncFunction("clientGetRecord") { options: Map<String, Any?> ->
      coordinator().getRecord(options)
    }.runOnQueue(clientScope)

    AsyncFunction("clientCreateRecord") { options: Map<String, Any?> ->
      coordinator().createRecord(options)
    }.runOnQueue(clientScope)

    AsyncFunction("clientClaimPairingInvitation") { options: Map<String, Any?> ->
      coordinator().claimPairingInvitation(options)
    }.runOnQueue(clientScope)

    AsyncFunction("clientAcceptPairingInvitation") { options: Map<String, Any?> ->
      coordinator().acceptPairingInvitation(options)
    }.runOnQueue(clientScope)

    AsyncFunction("clientResetLocalInstallation") { options: Map<String, Any?> ->
      coordinator().resetLocalInstallation(options)
    }.runOnQueue(clientScope)

    OnDestroy {
      val current = takeCoordinatorForDestroy()
      current?.shutdown()
      clientScope.cancel()
      dispatcher.close()
    }
  }

  @Synchronized
  private fun coordinator(): FractonicaClientCoordinator {
    if (destroyed) {
      throw FractonicaClientBridgeException(
        "ERR_FRACTONICA_CLIENT_UNAVAILABLE",
        "The local Fractonica client is unavailable.",
      )
    }
    coordinator?.let { return it }
    val context = appContext.reactContext?.applicationContext
      ?: throw FractonicaClientBridgeException(
        "ERR_FRACTONICA_CLIENT_UNAVAILABLE",
        "The local Fractonica client is unavailable.",
      )
    return FractonicaClientCoordinator(context).also { coordinator = it }
  }

  @Synchronized
  private fun takeCoordinatorForDestroy(): FractonicaClientCoordinator? {
    destroyed = true
    return coordinator.also { coordinator = null }
  }
}

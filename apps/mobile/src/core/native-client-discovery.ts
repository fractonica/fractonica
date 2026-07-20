import { requireOptionalNativeModule } from "expo";
import {
  decodeMobileBridgeStatus,
  MOBILE_NATIVE_MODULE_NAME,
} from "@fractonica/mobile-native";

import { createNativeClientPort } from "./native-client";
import type { NativeClientBridge, NativeClientPort } from "./native-client";

export const NATIVE_CLIENT_MODULE_NAME = MOBILE_NATIVE_MODULE_NAME;

interface NativeBridgeStatusModule extends Partial<NativeClientBridge> {
  bridgeStatus(): Promise<unknown>;
}

export type NativeClientDiscovery =
  | { kind: "ready"; client: NativeClientPort }
  | { kind: "unavailable"; reason: string };

function isBridge(value: unknown): value is NativeClientBridge {
  if (typeof value !== "object" || value === null) return false;
  const candidate = value as Partial<NativeClientBridge>;
  return (
    typeof candidate.clientStatus === "function" &&
    typeof candidate.clientListRecords === "function" &&
    typeof candidate.clientGetRecord === "function" &&
    typeof candidate.clientCreateRecord === "function" &&
    typeof candidate.clientResetLocalInstallation === "function"
  );
}

export async function discoverNativeClient(): Promise<NativeClientDiscovery> {
  const statusModule = requireOptionalNativeModule<NativeBridgeStatusModule>(
    NATIVE_CLIENT_MODULE_NAME,
  );
  if (!statusModule) {
    return {
      kind: "unavailable",
      reason:
        "The Fractonica native shell is not linked into this development build yet.",
    };
  }

  const bridgeStatus = decodeMobileBridgeStatus(await statusModule.bridgeStatus());
  if (!bridgeStatus.rustCoreLinked) {
    return {
      kind: "unavailable",
      reason:
        "The native shell is ready, but the Rust Fractonica client has not been linked yet.",
    };
  }

  if (!isBridge(statusModule)) {
    return {
      kind: "unavailable",
      reason:
        "The Rust core is linked, but this build does not expose the expected client methods.",
    };
  }
  return { kind: "ready", client: createNativeClientPort(statusModule) };
}

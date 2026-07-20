export const MOBILE_BRIDGE_API_VERSION = 1 as const;
export const MOBILE_NATIVE_MODULE_NAME = "FractonicaClient" as const;

export interface MobileBridgeStatus {
  readonly apiVersion: typeof MOBILE_BRIDGE_API_VERSION;
  readonly implementation: "expo-native-shell";
  readonly rustCoreLinked: boolean;
}

export class MobileBridgeContractError extends Error {
  override readonly name = "MobileBridgeContractError";
}

export function decodeMobileBridgeStatus(value: unknown): MobileBridgeStatus {
  if (
    typeof value !== "object" ||
    value === null ||
    Array.isArray(value) ||
    Object.keys(value).length !== 3 ||
    !("apiVersion" in value) ||
    value.apiVersion !== MOBILE_BRIDGE_API_VERSION ||
    !("implementation" in value) ||
    value.implementation !== "expo-native-shell" ||
    !("rustCoreLinked" in value) ||
    typeof value.rustCoreLinked !== "boolean"
  ) {
    throw new MobileBridgeContractError(
      "The Fractonica native module returned an incompatible bridge status.",
    );
  }
  return value as MobileBridgeStatus;
}

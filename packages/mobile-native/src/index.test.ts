import { describe, expect, it } from "vitest";

import {
  decodeMobileBridgeStatus,
  MOBILE_BRIDGE_API_VERSION,
  MobileBridgeContractError,
} from "./contract";

describe("mobile native bridge contract", () => {
  it("accepts the exact versioned native shell status", () => {
    expect(
      decodeMobileBridgeStatus({
        apiVersion: MOBILE_BRIDGE_API_VERSION,
        implementation: "expo-native-shell",
        rustCoreLinked: false,
      }),
    ).toEqual({
      apiVersion: 1,
      implementation: "expo-native-shell",
      rustCoreLinked: false,
    });
  });

  it("rejects version drift and unknown fields", () => {
    expect(() =>
      decodeMobileBridgeStatus({
        apiVersion: 2,
        implementation: "expo-native-shell",
        rustCoreLinked: false,
      }),
    ).toThrow(MobileBridgeContractError);
    expect(() =>
      decodeMobileBridgeStatus({
        apiVersion: 1,
        implementation: "expo-native-shell",
        rustCoreLinked: false,
        databasePath: "/private/client.sqlite3",
      }),
    ).toThrow(MobileBridgeContractError);
  });
});

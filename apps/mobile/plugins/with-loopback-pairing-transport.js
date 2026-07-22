const fs = require("node:fs");
const path = require("node:path");
const {
  AndroidConfig,
  withAndroidManifest,
  withDangerousMod,
  withInfoPlist,
} = require("expo/config-plugins");

const NETWORK_SECURITY_CONFIG = `<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
  <base-config cleartextTrafficPermitted="false" />
  <domain-config cleartextTrafficPermitted="true">
    <domain includeSubdomains="false">localhost</domain>
    <domain includeSubdomains="false">127.0.0.1</domain>
  </domain-config>
</network-security-config>
`;

/**
 * Linking v1 uses plain HTTP only for private/local IP origins because the
 * invitation's Noise handshake supplies authentication and confidentiality.
 * Native Rust rejects public-network hints; these platform exceptions let the
 * bounded transport reach a node on the same local network.
 */
module.exports = function withLoopbackPairingTransport(config) {
  config = withInfoPlist(config, (iosConfig) => {
    iosConfig.modResults.NSLocalNetworkUsageDescription =
      "Fractonica links your devices and synchronizes records over your local network.";
    iosConfig.modResults.NSAppTransportSecurity = {
      ...(iosConfig.modResults.NSAppTransportSecurity ?? {}),
      NSAllowsLocalNetworking: true,
    };
    return iosConfig;
  });

  config = withAndroidManifest(config, (androidConfig) => {
    const application = AndroidConfig.Manifest.getMainApplicationOrThrow(
      androidConfig.modResults,
    );
    application.$["android:networkSecurityConfig"] =
      "@xml/fractonica_network_security_config";
    application.$["android:usesCleartextTraffic"] = "false";
    return androidConfig;
  });

  return withDangerousMod(config, [
    "android",
    async (androidConfig) => {
      const xmlDirectory = path.join(
        androidConfig.modRequest.platformProjectRoot,
        "app",
        "src",
        "main",
        "res",
        "xml",
      );
      fs.mkdirSync(xmlDirectory, { recursive: true });
      fs.writeFileSync(
        path.join(xmlDirectory, "fractonica_network_security_config.xml"),
        NETWORK_SECURITY_CONFIG,
        "utf8",
      );
      return androidConfig;
    },
  ]);
};

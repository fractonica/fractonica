const { withXcodeProject } = require("expo/config-plugins");

/**
 * React Native's release bundle phase runs Node across the workspace and writes
 * into Xcode's build products directory. Xcode cannot infer those dynamic paths,
 * so its user-script sandbox rejects legitimate reads during device archives.
 * Keep the setting in prebuild configuration rather than patching the generated
 * Xcode project by hand.
 */
module.exports = function withUserScriptSandboxingDisabled(config) {
  return withXcodeProject(config, (projectConfig) => {
    projectConfig.modResults.addBuildProperty(
      "ENABLE_USER_SCRIPT_SANDBOXING",
      "NO",
    );
    return projectConfig;
  });
};

import { cpSync, mkdirSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";

const scriptDirectory = dirname(fileURLToPath(import.meta.url));
const repositoryRoot = resolve(scriptDirectory, "../../..");
const release = process.argv.includes("--release");
const profile = release ? "release" : "debug";

function option(name) {
  const direct = process.argv.find((argument) => argument.startsWith(`${name}=`));
  if (direct) return direct.slice(name.length + 1);
  const index = process.argv.indexOf(name);
  return index >= 0 ? process.argv[index + 1] : undefined;
}

function run(command, args) {
  const result = spawnSync(command, args, {
    cwd: repositoryRoot,
    encoding: "utf8",
    stdio: ["inherit", "pipe", "inherit"],
  });
  if (result.status !== 0) process.exit(result.status ?? 1);
  return result.stdout.trim();
}

const rustVersion = run("rustc", ["-vV"]);
const host = rustVersion
  .split("\n")
  .find((line) => line.startsWith("host: "))
  ?.slice("host: ".length);
if (!host) throw new Error("Could not determine the Rust host target.");

const metadata = JSON.parse(
  run("cargo", ["metadata", "--format-version", "1", "--no-deps", "--locked"]),
);
if (typeof metadata.target_directory !== "string") {
  throw new Error("Cargo metadata did not contain a target directory.");
}
const cargoTargetDirectory = metadata.target_directory;
const requestedTarget = option("--target") ?? process.env.CARGO_BUILD_TARGET;
const target = requestedTarget ?? host;

function extensionFor(targetTriple) {
  return targetTriple.includes("windows") ? ".exe" : "";
}

function buildFor(targetTriple, explicitTarget) {
  const cargoArguments = ["build", "--locked", "-p", "fractonica-node"];
  if (release) cargoArguments.push("--release");
  if (explicitTarget) cargoArguments.push("--target", targetTriple);
  run("cargo", cargoArguments);

  const directory = explicitTarget
    ? resolve(cargoTargetDirectory, targetTriple, profile)
    : resolve(cargoTargetDirectory, profile);
  return resolve(directory, `fractonica-node${extensionFor(targetTriple)}`);
}

const binariesDirectory = resolve(repositoryRoot, "apps/desktop/src-tauri/binaries");
mkdirSync(binariesDirectory, { recursive: true });
const destination = resolve(
  binariesDirectory,
  `fractonica-node-${target}${extensionFor(target)}`,
);

if (target === "universal-apple-darwin") {
  if (process.platform !== "darwin") {
    throw new Error("Universal Apple sidecars can only be assembled on macOS.");
  }
  const arm = buildFor("aarch64-apple-darwin", true);
  const intel = buildFor("x86_64-apple-darwin", true);
  run("lipo", ["-create", arm, intel, "-output", destination]);
} else {
  const source = buildFor(target, Boolean(requestedTarget));
  cpSync(source, destination);
}

process.stdout.write(`Prepared ${destination}\n`);

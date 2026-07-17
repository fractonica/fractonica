import { spawnSync } from "node:child_process";

const argumentsToTauri = process.argv.slice(2);
if (argumentsToTauri[0] === "--") argumentsToTauri.shift();

function option(name) {
  const direct = argumentsToTauri.find((argument) => argument.startsWith(`${name}=`));
  if (direct) return direct.slice(name.length + 1);
  const index = argumentsToTauri.indexOf(name);
  return index >= 0 ? argumentsToTauri[index + 1] : undefined;
}

function run(args) {
  const command = process.platform === "win32" ? "pnpm.cmd" : "pnpm";
  const result = spawnSync(command, args, { stdio: "inherit" });
  if (result.status !== 0) process.exit(result.status ?? 1);
}

const target = option("--target");
const prepareArguments = ["prepare:sidecar", "--", "--release"];
if (target) prepareArguments.push("--target", target);

run(prepareArguments);
run(["exec", "tauri", "build", ...argumentsToTauri]);

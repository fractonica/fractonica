#!/usr/bin/env node

import { resolve } from "node:path";

import { normalizeBaseUrl } from "./checkpoint.ts";
import { importExeligmos } from "./importer.ts";

interface CliOptions {
  readonly sourceBaseUrl: string;
  readonly destinationBaseUrl: string;
  readonly sourceToken: string;
  readonly destinationToken?: string;
  readonly checkpointPath: string;
  readonly dryRun: boolean;
  readonly verify: boolean;
  readonly quiet: boolean;
}

async function main(): Promise<void> {
  const options = parseArguments(process.argv.slice(2));
  process.stderr.write(
    "Important: keep the Exeligmos source quiescent during migration; its cursor is not a snapshot boundary.\n",
  );
  if (options.dryRun) {
    process.stderr.write("Dry run: no requests that mutate Fractonica will be made.\n");
  }
  const summary = await importExeligmos({
    sourceBaseUrl: options.sourceBaseUrl,
    destinationBaseUrl: options.destinationBaseUrl,
    sourceToken: options.sourceToken,
    ...(options.destinationToken === undefined
      ? {}
      : { destinationToken: options.destinationToken }),
    checkpointPath: options.checkpointPath,
    dryRun: options.dryRun,
    verify: options.verify,
    ...(options.quiet
      ? {}
      : { log: (message: string) => process.stderr.write(`${message}\n`) }),
  });
  process.stdout.write(`${JSON.stringify(summary, null, 2)}\n`);
  if (summary.recordsSkipped > 0) process.exitCode = 2;
}

function parseArguments(arguments_: readonly string[]): CliOptions {
  if (arguments_.includes("--help") || arguments_.includes("-h")) {
    process.stdout.write(usage());
    process.exit(0);
  }
  const values = new Map<string, string>();
  const flags = new Set<string>();
  const valueOptions = new Set([
    "--source",
    "--destination",
    "--source-token",
    "--destination-token",
    "--checkpoint",
  ]);
  const flagOptions = new Set(["--dry-run", "--no-verify", "--quiet"]);
  for (let index = 0; index < arguments_.length; index += 1) {
    const argument = arguments_[index];
    if (argument === undefined) continue;
    if (argument === "--") continue;
    if (flagOptions.has(argument)) {
      flags.add(argument);
      continue;
    }
    if (!valueOptions.has(argument)) throw usageError(`unknown argument ${argument}`);
    const value = arguments_[index + 1];
    if (value === undefined || value.startsWith("--")) {
      throw usageError(`${argument} requires a value`);
    }
    if (values.has(argument)) throw usageError(`${argument} was supplied more than once`);
    values.set(argument, value);
    index += 1;
  }

  const source = values.get("--source");
  const destination = values.get("--destination");
  if (source === undefined) throw usageError("--source is required");
  if (destination === undefined) throw usageError("--destination is required");
  const sourceToken = values.get("--source-token") ?? process.env.EXELIGMOS_TOKEN;
  if (sourceToken === undefined || sourceToken === "") {
    throw usageError("set EXELIGMOS_TOKEN or pass --source-token");
  }
  const destinationToken =
    values.get("--destination-token") ?? process.env.FRACTONICA_TOKEN;
  const checkpointPath = resolve(
    values.get("--checkpoint") ?? ".fractonica/import-exeligmos-checkpoint.json",
  );
  return {
    sourceBaseUrl: normalizeBaseUrl(source),
    destinationBaseUrl: normalizeBaseUrl(destination),
    sourceToken,
    ...(destinationToken === undefined || destinationToken === ""
      ? {}
      : { destinationToken }),
    checkpointPath,
    dryRun: flags.has("--dry-run"),
    verify: !flags.has("--no-verify"),
    quiet: flags.has("--quiet"),
  };
}

function usageError(message: string): Error {
  return new Error(`${message}\n\n${usage()}`);
}

function usage(): string {
  return `Usage:
  pnpm --filter @fractonica/import-exeligmos start -- \\
    --source http://127.0.0.1:8788 \\
    --destination http://127.0.0.1:8789 \\
    [--checkpoint PATH] [--dry-run] [--no-verify] [--quiet]

Authentication:
  EXELIGMOS_TOKEN   Bearer JWT or API key with records:read, tags:read,
                    and media:read scopes (required).
  FRACTONICA_TOKEN  Destination bearer token, when the node requires one.

Tokens may also be passed with --source-token and --destination-token, but
environment variables avoid exposing secrets in shell history. The checkpoint
never stores tokens. A dry run reads and validates the complete source but does
not mutate the destination or write a checkpoint.

Transport:
  Plain HTTP is accepted only for localhost, 127.0.0.0/8, and [::1].
  Every LAN or internet source and destination must use HTTPS.
`;
}

main().catch((error: unknown) => {
  const message = error instanceof Error ? error.stack ?? error.message : String(error);
  process.stderr.write(`${message}\n`);
  process.exitCode = 1;
});

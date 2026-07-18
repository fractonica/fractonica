import { mkdir, open, readFile, rename, rm } from "node:fs/promises";
import { basename, dirname, join } from "node:path";

import type { ImportCheckpoint } from "./types.ts";

export function normalizeBaseUrl(value: string): string {
  const url = new URL(value);
  if (url.protocol !== "http:" && url.protocol !== "https:") {
    throw new Error(`only http and https server URLs are supported: ${value}`);
  }
  if (url.username !== "" || url.password !== "") {
    throw new Error("server URLs must not contain credentials; use bearer-token options instead");
  }
  if (url.protocol === "http:" && !isLoopbackHostname(url.hostname)) {
    throw new Error(
      `plain HTTP is allowed only for localhost, 127.0.0.0/8, or [::1]; use HTTPS for ${url.hostname}`,
    );
  }
  url.hash = "";
  url.search = "";
  url.pathname = url.pathname.replace(/\/+$/, "");
  return url.toString().replace(/\/$/, "");
}

export function newCheckpoint(
  sourceBaseUrl: string,
  destinationBaseUrl: string,
): ImportCheckpoint {
  return {
    version: 1,
    mappingVersion: "exeligmos-record-v1",
    sourceBaseUrl: normalizeBaseUrl(sourceBaseUrl),
    destinationBaseUrl: normalizeBaseUrl(destinationBaseUrl),
    recordsComplete: false,
    media: {},
    records: {},
    updatedAt: new Date().toISOString(),
  };
}

export async function loadCheckpoint(
  path: string,
  sourceBaseUrl: string,
  destinationBaseUrl: string,
): Promise<ImportCheckpoint> {
  const expectedSource = normalizeBaseUrl(sourceBaseUrl);
  const expectedDestination = normalizeBaseUrl(destinationBaseUrl);
  let decoded: unknown;
  try {
    decoded = JSON.parse(await readFile(path, "utf8"));
  } catch (error) {
    if (isErrno(error, "ENOENT")) {
      return newCheckpoint(expectedSource, expectedDestination);
    }
    throw new Error(`cannot read checkpoint ${path}: ${errorMessage(error)}`, {
      cause: error,
    });
  }

  if (!isCheckpoint(decoded)) {
    throw new Error(`checkpoint ${path} is malformed or uses an unsupported version`);
  }
  if (normalizeBaseUrl(decoded.sourceBaseUrl) !== expectedSource) {
    throw new Error(
      `checkpoint source is ${decoded.sourceBaseUrl}, not requested source ${expectedSource}`,
    );
  }
  if (normalizeBaseUrl(decoded.destinationBaseUrl) !== expectedDestination) {
    throw new Error(
      `checkpoint destination is ${decoded.destinationBaseUrl}, not requested destination ${expectedDestination}`,
    );
  }
  validateCheckpointUploadOrigins(decoded, expectedDestination, path);
  return decoded;
}

/** Atomically replaces the checkpoint and keeps bearer tokens out of it. */
export async function saveCheckpoint(
  path: string,
  checkpoint: ImportCheckpoint,
): Promise<void> {
  checkpoint.updatedAt = new Date().toISOString();
  const parent = dirname(path);
  await mkdir(parent, { recursive: true, mode: 0o700 });
  const temporary = join(
    parent,
    `.${basename(path)}.${process.pid}.${Date.now()}.tmp`,
  );
  const file = await open(temporary, "wx", 0o600);
  try {
    try {
      await file.writeFile(`${JSON.stringify(checkpoint, null, 2)}\n`, "utf8");
      await file.sync();
    } finally {
      await file.close();
    }
    await rename(temporary, path);
  } catch (error) {
    await rm(temporary, { force: true });
    throw error;
  }
  try {
    const directory = await open(parent, "r");
    try {
      await directory.sync();
    } finally {
      await directory.close();
    }
  } catch (error) {
    // Directory handles/fsync are unsupported on some Windows filesystems.
    // The same-directory atomic rename above remains the durability boundary.
    if (!isIgnorableDirectorySyncError(error)) throw error;
  }
}

function isCheckpoint(value: unknown): value is ImportCheckpoint {
  if (!isObject(value)) return false;
  return (
    value.version === 1 &&
    value.mappingVersion === "exeligmos-record-v1" &&
    typeof value.sourceBaseUrl === "string" &&
    typeof value.destinationBaseUrl === "string" &&
    typeof value.recordsComplete === "boolean" &&
    isObject(value.media) &&
    Object.values(value.media).every(isMediaCheckpoint) &&
    isObject(value.records) &&
    Object.values(value.records).every(isRecordCheckpoint) &&
    isDateTime(value.updatedAt) &&
    (value.recordsCursor === undefined || typeof value.recordsCursor === "string")
  );
}

function isMediaCheckpoint(value: unknown): boolean {
  if (!isObject(value)) return false;
  return (
    typeof value.sourceMediaId === "string" &&
    typeof value.sha256 === "string" &&
    /^[0-9a-f]{64}$/.test(value.sha256) &&
    value.contentId === `sha-256:${value.sha256}` &&
    isNonnegativeSafeInteger(value.byteLength) &&
    isNonnegativeSafeInteger(value.uploadOffset) &&
    value.uploadOffset <= value.byteLength &&
    typeof value.completed === "boolean" &&
    typeof value.verified === "boolean" &&
    (!value.verified || value.completed) &&
    (value.uploadUrl === undefined || typeof value.uploadUrl === "string")
  );
}

function isRecordCheckpoint(value: unknown): boolean {
  if (!isObject(value)) return false;
  const status = value.status;
  const hasSequence = isPositiveSafeInteger(value.destinationLocalSequence);
  return (
    typeof value.sourceRecordId === "string" &&
    typeof value.sourceOriginId === "string" &&
    isNonnegativeSafeInteger(value.sourceRevision) &&
    typeof value.entityId === "string" &&
    typeof value.operationId === "string" &&
    (status === "planned" ||
      status === "imported" ||
      status === "verified" ||
      status === "skipped") &&
    (value.destinationLocalSequence === undefined || hasSequence) &&
    (status === "imported" || status === "verified" ? hasSequence : true) &&
    (value.causalParents === undefined ||
      (Array.isArray(value.causalParents) &&
        value.causalParents.length <= 64 &&
        value.causalParents.every((item) => typeof item === "string") &&
        new Set(value.causalParents).size === value.causalParents.length)) &&
    Array.isArray(value.mediaIds) &&
    value.mediaIds.every((item) => typeof item === "string") &&
    (value.warning === undefined || typeof value.warning === "string")
  );
}

function validateCheckpointUploadOrigins(
  checkpoint: ImportCheckpoint,
  destinationBaseUrl: string,
  path: string,
): void {
  const expectedOrigin = new URL(destinationBaseUrl).origin;
  for (const media of Object.values(checkpoint.media)) {
    if (media.uploadUrl === undefined) continue;
    let uploadUrl: URL;
    try {
      uploadUrl = new URL(media.uploadUrl);
    } catch {
      throw new Error(`checkpoint ${path} contains an invalid TUS upload URL`);
    }
    if (uploadUrl.origin !== expectedOrigin) {
      throw new Error(
        `checkpoint ${path} contains a cross-origin TUS upload URL; refusing to send destination credentials`,
      );
    }
  }
}

function isObject(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function isErrno(error: unknown, code: string): boolean {
  return (
    error !== null &&
    typeof error === "object" &&
    "code" in error &&
    (error as { readonly code?: unknown }).code === code
  );
}

function isDateTime(value: unknown): boolean {
  return typeof value === "string" && Number.isFinite(Date.parse(value));
}

function isNonnegativeSafeInteger(value: unknown): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 0;
}

function isPositiveSafeInteger(value: unknown): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 1;
}

function isIgnorableDirectorySyncError(error: unknown): boolean {
  if (error === null || typeof error !== "object" || !("code" in error)) return false;
  const code = (error as { readonly code?: unknown }).code;
  return code === "EINVAL" || code === "EPERM" || code === "EISDIR" || code === "ENOTSUP";
}

function isLoopbackHostname(value: string): boolean {
  const hostname = value.toLowerCase().replace(/\.$/, "");
  if (hostname === "localhost" || hostname === "[::1]" || hostname === "::1") {
    return true;
  }
  const octets = hostname.split(".");
  return (
    octets.length === 4 &&
    octets[0] === "127" &&
    octets.every((octet) => /^(0|[1-9][0-9]{0,2})$/.test(octet) && Number(octet) <= 255)
  );
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

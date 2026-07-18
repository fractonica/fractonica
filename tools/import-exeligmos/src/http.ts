const MAX_ERROR_BODY_BYTES = 16 * 1024;

export interface FetchCheckedOptions extends RequestInit {
  readonly token?: string | undefined;
  readonly expectedStatuses?: readonly number[];
  readonly retryable?: boolean;
  readonly attempts?: number;
  readonly timeoutMs?: number;
}

export class HttpError extends Error {
  readonly status: number;
  readonly method: string;
  readonly url: string;
  readonly responseBody: string;

  constructor(
    status: number,
    method: string,
    url: string,
    responseBody: string,
  ) {
    super(`${method} ${url} returned HTTP ${status}${responseBody === "" ? "" : `: ${responseBody}`}`);
    this.name = "HttpError";
    this.status = status;
    this.method = method;
    this.url = url;
    this.responseBody = responseBody;
  }
}

export function resolveUrl(baseUrl: string, pathOrUrl: string): URL {
  if (/^https?:\/\//i.test(pathOrUrl)) return new URL(pathOrUrl);
  const base = new URL(baseUrl);
  if (pathOrUrl.startsWith("/")) return new URL(pathOrUrl, base);
  const normalizedBase = base.toString().endsWith("/")
    ? base.toString()
    : `${base.toString()}/`;
  return new URL(pathOrUrl, normalizedBase);
}

export async function fetchChecked(
  url: URL | string,
  options: FetchCheckedOptions = {},
): Promise<Response> {
  const {
    token,
    expectedStatuses: expected = [200],
    retryable = false,
    attempts = retryable ? 4 : 1,
    timeoutMs = 30_000,
    ...requestOptions
  } = options;
  const method = (requestOptions.method ?? "GET").toUpperCase();
  const headers = new Headers(requestOptions.headers);
  if (token !== undefined && token !== "") {
    headers.set("Authorization", `Bearer ${token}`);
  }
  let lastError: unknown;

  for (let attempt = 1; attempt <= attempts; attempt += 1) {
    try {
      const response = await fetch(url, {
        ...requestOptions,
        headers,
        signal: AbortSignal.timeout(timeoutMs),
      });
      if (expected.includes(response.status)) return response;
      const body = await boundedResponseText(response);
      const error = new HttpError(response.status, method, response.url, body);
      if (!retryable || !isRetryableStatus(response.status) || attempt === attempts) {
        throw error;
      }
      lastError = error;
    } catch (error) {
      if (error instanceof HttpError && !isRetryableStatus(error.status)) throw error;
      if (!retryable || attempt === attempts) throw error;
      lastError = error;
    }
    await delay(retryDelayMs(attempt));
  }
  throw lastError instanceof Error ? lastError : new Error("HTTP request failed");
}

export async function requestJson<T>(
  url: URL | string,
  options: FetchCheckedOptions = {},
): Promise<T> {
  const headers = new Headers(options.headers);
  headers.set("Accept", "application/json");
  const response = await fetchChecked(url, { ...options, headers });
  const contentType = response.headers.get("content-type") ?? "";
  if (!contentType.toLowerCase().includes("json")) {
    await response.body?.cancel();
    throw new Error(`${response.url} returned ${contentType || "an unknown media type"}, expected JSON`);
  }
  return (await response.json()) as T;
}

export function jsonBody(value: unknown): {
  readonly body: string;
  readonly headers: Headers;
} {
  const headers = new Headers({
    Accept: "application/json",
    "Content-Type": "application/json",
  });
  return { body: JSON.stringify(value), headers };
}

async function boundedResponseText(response: Response): Promise<string> {
  if (response.body === null) return "";
  const reader = response.body.getReader();
  const chunks: Buffer[] = [];
  let capturedBytes = 0;
  let reachedEnd = false;
  let truncated = false;
  try {
    while (capturedBytes <= MAX_ERROR_BODY_BYTES) {
      const result = await reader.read();
      if (result.done) {
        reachedEnd = true;
        break;
      }
      if (result.value.byteLength === 0) continue;
      const wanted = MAX_ERROR_BODY_BYTES + 1 - capturedBytes;
      const kept = result.value.subarray(0, wanted);
      // Copy only the bounded prefix so a large fetch-provided ArrayBuffer is
      // not retained through a small subarray view.
      chunks.push(Buffer.from(kept));
      capturedBytes += kept.byteLength;
      if (kept.byteLength < result.value.byteLength || capturedBytes > MAX_ERROR_BODY_BYTES) {
        truncated = true;
        break;
      }
    }
  } finally {
    if (!reachedEnd) {
      await reader.cancel("error response capture limit reached").catch(() => undefined);
    }
    reader.releaseLock();
  }

  const captured = Buffer.concat(chunks, capturedBytes);
  const suffix = truncated ? "…" : "";
  const suffixBytes = Buffer.byteLength(suffix, "utf8");
  return `${decodeUtf8Within(captured, MAX_ERROR_BODY_BYTES - suffixBytes)}${suffix}`;
}

function decodeUtf8Within(bytes: Uint8Array, maximumBytes: number): string {
  const decoded = new TextDecoder().decode(bytes.subarray(0, maximumBytes));
  let result = "";
  let encodedBytes = 0;
  for (const character of decoded) {
    const length = Buffer.byteLength(character, "utf8");
    if (encodedBytes + length > maximumBytes) break;
    result += character;
    encodedBytes += length;
  }
  return result;
}

function isRetryableStatus(status: number): boolean {
  return status === 408 || status === 429 || (status >= 500 && status <= 504);
}

function retryDelayMs(attempt: number): number {
  return Math.min(250 * 2 ** (attempt - 1), 2_000);
}

function delay(milliseconds: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

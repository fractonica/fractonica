import assert from "node:assert/strict";
import { test } from "node:test";

import { fetchChecked, HttpError } from "./http.ts";

test("error response capture is capped at 16 KiB and cancels the remainder", async (context) => {
  const originalFetch = globalThis.fetch;
  context.after(() => {
    globalThis.fetch = originalFetch;
  });
  let cancelled = false;
  let pulls = 0;
  globalThis.fetch = async () =>
    new Response(
      new ReadableStream<Uint8Array>({
        pull(controller) {
          pulls += 1;
          controller.enqueue(new Uint8Array(4_096).fill(0x78));
        },
        cancel() {
          cancelled = true;
        },
      }),
      { status: 500 },
    );

  let error: unknown;
  try {
    await fetchChecked("https://destination.test/failure");
  } catch (caught) {
    error = caught;
  }
  assert.ok(error instanceof HttpError);
  assert.ok(Buffer.byteLength(error.responseBody, "utf8") <= 16 * 1_024);
  assert.match(error.responseBody, /…$/u);
  assert.equal(cancelled, true);
  assert.ok(pulls < 10, `expected bounded pulls, received ${pulls}`);
});

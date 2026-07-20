import { describe, expect, it } from "vitest";

import { EMPTY_COMPOSER_STATE, reduceComposerState } from "./composer-state";

describe("record composer state", () => {
  it("keeps the complete draft when a local commit fails", () => {
    const draft = { emoji: "🌒", text: "still here", error: null };

    expect(
      reduceComposerState(draft, { type: "failed", message: "database is unavailable" }),
    ).toEqual({
      emoji: "🌒",
      text: "still here",
      error: "database is unavailable",
    });
  });

  it("clears the draft after a confirmed commit", () => {
    expect(
      reduceComposerState(
        { emoji: "🌒", text: "stored", error: "old error" },
        { type: "committed" },
      ),
    ).toEqual(EMPTY_COMPOSER_STATE);
  });
});

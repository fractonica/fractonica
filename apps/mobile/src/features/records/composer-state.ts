export interface ComposerState {
  emoji: string;
  text: string;
  error: string | null;
}

export type ComposerAction =
  | { type: "changeEmoji"; value: string }
  | { type: "changeText"; value: string }
  | { type: "submit" }
  | { type: "failed"; message: string }
  | { type: "committed" }
  | { type: "discard" };

export const EMPTY_COMPOSER_STATE: ComposerState = {
  emoji: "",
  text: "",
  error: null,
};

/** Draft fields are cleared only by an explicit discard or a durable commit. */
export function reduceComposerState(
  state: ComposerState,
  action: ComposerAction,
): ComposerState {
  switch (action.type) {
    case "changeEmoji":
      return { ...state, emoji: action.value };
    case "changeText":
      return { ...state, text: action.value };
    case "submit":
      return { ...state, error: null };
    case "failed":
      return { ...state, error: action.message };
    case "committed":
    case "discard":
      return EMPTY_COMPOSER_STATE;
  }
}

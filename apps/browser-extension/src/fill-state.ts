/**
 * Non-secret, per-document state for the issue #17 content script.
 * Keep this in the document's isolated world, not in a restartable worker.
 * This is duplicate/edit suppression, NOT origin or user-action authorization.
 */
export interface FillAttempt {
  readonly kind: "automatic" | "explicit";
}

export class FillOnceState {
  #automaticConsumed: boolean;
  #active = true;
  #pending: FillAttempt | null = null;

  /** A restored document must start with automatic fill suppressed. */
  constructor(restoredFromHistory = false) {
    this.#automaticConsumed = restoredFromHistory;
  }

  /** Call only after detecting an eligible form, before requesting a record. */
  beginAutomatic(): FillAttempt | null {
    if (this.#automaticConsumed) {
      return null;
    }
    return this.#begin("automatic");
  }

  /** The caller must independently verify a fresh extension-toolbar action. */
  beginExplicit(): FillAttempt | null {
    return this.#begin("explicit");
  }

  /** Consume before the DOM write; duplicate or stale completions fail closed. */
  complete(attempt: FillAttempt): boolean {
    if (!this.#active || this.#pending === null || this.#pending !== attempt) {
      return false;
    }
    this.#pending = null;
    return true;
  }

  /** Failure does not reset the automatic budget or cancel a newer attempt. */
  fail(attempt: FillAttempt): void {
    if (this.#pending === attempt) {
      this.#pending = null;
    }
  }

  /** Call on edits/deletions, including while a request is in flight. */
  noteEdit(): void {
    this.#automaticConsumed = true;
    this.#pending = null;
  }

  /** pagehide/navigation invalidates in-flight work, including BFCache work. */
  suspend(): void {
    this.#active = false;
    this.#automaticConsumed = true;
    this.#pending = null;
  }

  /** pageshow may allow an explicit action, but never restores the auto budget. */
  resume(): void {
    this.#active = true;
  }

  #begin(kind: FillAttempt["kind"]): FillAttempt | null {
    if (!this.#active || this.#pending !== null) {
      return null;
    }
    this.#automaticConsumed = true;
    const attempt = Object.freeze({ kind });
    this.#pending = attempt;
    return attempt;
  }
}

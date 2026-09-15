import assert from "node:assert/strict";
import test from "node:test";

import { FillOnceState } from "../dist/fill-state.js";

test("cannot complete without a live attempt even with an untyped null handle", () => {
  const state = new FillOnceState();
  for (const invalid of [null, undefined, {}, { kind: "automatic" }]) {
    assert.equal(state.complete(invalid), false);
  }
  const attempt = state.beginAutomatic();
  assert.equal(state.complete(attempt), true);
  assert.equal(state.complete(null), false);
});

test("reserves the only automatic attempt before any asynchronous lookup", () => {
  const state = new FillOnceState();
  const attempt = state.beginAutomatic();
  assert.equal(attempt.kind, "automatic");
  assert.equal(state.beginAutomatic(), null);
  assert.equal(state.beginExplicit(), null);
  assert.equal(state.complete(attempt), true);
  assert.equal(state.complete(attempt), false);
  assert.equal(state.beginAutomatic(), null);
});

test("failure, no match, lock, timeout, or host crash never trigger auto retry", () => {
  const state = new FillOnceState();
  const attempt = state.beginAutomatic();
  state.fail(attempt);
  assert.equal(state.complete(attempt), false);
  assert.equal(state.beginAutomatic(), null);
  const explicit = state.beginExplicit();
  assert.equal(explicit.kind, "explicit");
  assert.equal(state.complete(explicit), true);
  assert.equal(state.beginAutomatic(), null);
});

test("edits/deletions before or during a request suppress automatic filling", () => {
  const before = new FillOnceState();
  before.noteEdit();
  assert.equal(before.beginAutomatic(), null);

  const during = new FillOnceState();
  const attempt = during.beginAutomatic();
  during.noteEdit();
  assert.equal(during.complete(attempt), false);
  assert.equal(during.beginAutomatic(), null);
  const explicit = during.beginExplicit();
  assert.equal(during.complete(explicit), true);
});

test("a newer edit also cancels an explicit fill in flight", () => {
  const state = new FillOnceState();
  const attempt = state.beginExplicit();
  state.noteEdit();
  assert.equal(state.complete(attempt), false);
  const retry = state.beginExplicit();
  state.fail(attempt);
  assert.equal(state.complete(attempt), false);
  assert.equal(state.complete(retry), true);
});

test("repeated successful explicit actions never restore the automatic budget", () => {
  const state = new FillOnceState();
  for (let index = 0; index < 3; index += 1) {
    const attempt = state.beginExplicit();
    assert.equal(state.complete(attempt), true);
    assert.equal(state.beginAutomatic(), null);
  }
});

test("DOM churn and validation errors cannot reset the same document's budget", () => {
  const state = new FillOnceState();
  const attempt = state.beginAutomatic();
  state.complete(attempt);
  for (let index = 0; index < 10; index += 1) {
    assert.equal(state.beginAutomatic(), null);
  }
});

test("pagehide and BFCache restoration invalidate pending work and auto fill", () => {
  const state = new FillOnceState();
  const attempt = state.beginAutomatic();
  state.suspend();
  assert.equal(state.complete(attempt), false);
  assert.equal(state.beginExplicit(), null);
  state.resume();
  assert.equal(state.complete(attempt), false);
  assert.equal(state.beginAutomatic(), null);
  const explicit = state.beginExplicit();
  assert.equal(state.complete(explicit), true);

  const reconstructedHistoryDocument = new FillOnceState(true);
  assert.equal(reconstructedHistoryDocument.beginAutomatic(), null);
  assert.ok(reconstructedHistoryDocument.beginExplicit());
});

test("suspending before any attempt still prevents automatic fill on return", () => {
  const state = new FillOnceState();
  state.suspend();
  assert.equal(state.beginAutomatic(), null);
  state.resume();
  assert.equal(state.beginAutomatic(), null);
});

test("copied and previous attempt handles cannot consume another completion", () => {
  const state = new FillOnceState();
  const attempt = state.beginExplicit();
  assert.equal(state.complete({ ...attempt }), false);
  state.fail(attempt);
  const next = state.beginExplicit();
  assert.equal(state.complete(attempt), false);
  assert.equal(state.complete(next), true);
});

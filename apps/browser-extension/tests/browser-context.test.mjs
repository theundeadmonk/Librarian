import assert from "node:assert/strict";
import test from "node:test";

import {
  sameBrowserDocument,
  protocolDocumentId,
  validateBrowserDocument,
} from "../dist/browser-context.js";

const extensionId = "jiifjoajanfeoabbkmpodkgfmabhikkh";
const documentId = "12345678-1234-4234-8234-123456789abc";
const otherDocumentId = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const origin = "https://example.com";

function evidence() {
  return {
    sender: {
      id: extensionId, tab: { id: 7, url: `${origin}/login` },
      frameId: 0, documentId, documentLifecycle: "active",
      origin, url: `${origin}/login?next=%2Fhome`,
    },
    frame: {
      documentId, documentLifecycle: "active", frameType: "outermost_frame",
      parentFrameId: -1, errorOccurred: false, url: `${origin}/login`,
    },
  };
}

test("binds browser-observed top-level evidence without retaining URL details", () => {
  const { sender, frame } = evidence();
  assert.deepEqual(validateBrowserDocument(sender, frame, extensionId), {
    tabId: 7, frameId: 0, documentId, topLevelOrigin: origin, frameOrigin: origin,
  });
});

test("accepts the real Chromium compact uppercase document token without changing browser identity", () => {
  const { sender, frame } = evidence();
  // Observed from Edge 152 MessageSender and webNavigation.getFrame in an isolated fixture.
  sender.documentId = frame.documentId = "929E8A0FA9D51BCD679FF8FA08BA41EB";
  assert.deepEqual(validateBrowserDocument(sender, frame, extensionId), {
    tabId: 7, frameId: 0, documentId: sender.documentId, topLevelOrigin: origin, frameOrigin: origin,
  });
  frame.documentId = "929e8a0f-a9d5-1bcd-679f-f8fa08ba41eb";
  assert.equal(validateBrowserDocument(sender, frame, extensionId), null,
    "wire-equivalent spelling must not replace exact browser-owned identity equality");
});

test("document-token conversion is bounded and rejects null, malformed, and noncanonical spellings", () => {
  assert.equal(protocolDocumentId(documentId), documentId);
  assert.equal(protocolDocumentId("929E8A0FA9D51BCD679FF8FA08BA41EB"), "929e8a0f-a9d5-1bcd-679f-f8fa08ba41eb");
  assert.equal(protocolDocumentId("F".repeat(32)), "ffffffff-ffff-ffff-ffff-ffffffffffff");
  for (const value of [null, 17, "", "0".repeat(32), "00000000-0000-0000-0000-000000000000",
    "A".repeat(31), "A".repeat(33), "G".repeat(32), "a".repeat(32), "A".repeat(31) + "a",
    documentId.toUpperCase(), documentId + "\0", " " + documentId, documentId + "\n"]) {
    assert.equal(protocolDocumentId(value), null);
    const { sender, frame } = evidence();
    sender.documentId = frame.documentId = value;
    assert.equal(validateBrowserDocument(sender, frame, extensionId), null);
  }
});

test("rejects missing, opaque, embedded, inactive, and stale browser evidence", () => {
  const mutations = [
    ({ sender }) => { sender.id = "a".repeat(32); },
    ({ sender }) => { delete sender.documentId; },
    ({ sender }) => { sender.documentId = "00000000-0000-0000-0000-000000000000"; },
    ({ sender }) => { sender.documentId = "page-controlled"; },
    ({ sender }) => { delete sender.tab; },
    ({ sender }) => { sender.tab.id = -1; },
    ({ sender }) => { sender.tab.id = 1.5; },
    ({ sender }) => { sender.tab.id = Number.NaN; },
    ({ sender }) => { sender.tab.id = 0x80000000; },
    ({ sender }) => { sender.frameId = 1; },
    ({ sender }) => { sender.origin = "null"; },
    ({ sender }) => { sender.url = "about:blank"; },
    ({ sender }) => { sender.url = "blob:https://example.com/id"; },
    ({ sender }) => { sender.url = "https://login.example.com"; },
    ({ sender }) => { sender.tab.url = "https://evil.test"; },
    ({ sender }) => { sender.documentLifecycle = "cached"; },
    ({ sender }) => { sender.documentLifecycle = "prerender"; },
    ({ frame }) => { frame.documentId = otherDocumentId; },
    ({ frame }) => { frame.documentLifecycle = "pending_deletion"; },
    ({ frame }) => { frame.documentLifecycle = "cached"; },
    ({ frame }) => { frame.frameType = "sub_frame"; },
    ({ frame }) => { frame.frameType = "fenced_frame"; },
    ({ frame }) => { frame.parentFrameId = 0; },
    ({ frame }) => { frame.errorOccurred = true; },
    ({ frame }) => { frame.url = "https://example.com:8443"; },
    ({ frame }) => { frame.url = "http://example.com"; },
    ({ frame }) => { delete frame.documentLifecycle; },
    ({ frame }) => { delete frame.errorOccurred; },
  ];
  for (const mutate of mutations) {
    const snapshot = evidence();
    mutate(snapshot);
    assert.equal(validateBrowserDocument(snapshot.sender, snapshot.frame, extensionId), null);
  }
  const { sender, frame } = evidence();
  assert.equal(validateBrowserDocument(sender, frame, ""), null);
  for (const invalid of [null, undefined, [], {}, "page", 1]) {
    assert.equal(validateBrowserDocument(invalid, frame, extensionId), null);
    assert.equal(validateBrowserDocument(sender, invalid, extensionId), null);
  }
});

test("refuses the same origin in a new document or tab at final delivery", () => {
  const { sender, frame } = evidence();
  const admitted = validateBrowserDocument(sender, frame, extensionId);
  assert.equal(sameBrowserDocument(admitted,
    validateBrowserDocument(sender, frame, extensionId)), true);
  sender.documentId = otherDocumentId;
  frame.documentId = otherDocumentId;
  assert.equal(sameBrowserDocument(admitted,
    validateBrowserDocument(sender, frame, extensionId)), false);
  sender.documentId = documentId;
  frame.documentId = documentId;
  sender.tab.id = 8;
  assert.equal(sameBrowserDocument(admitted,
    validateBrowserDocument(sender, frame, extensionId)), false);
});

test("even an exact-origin iframe is unsupported in this conservative slice", () => {
  const { sender, frame } = evidence();
  sender.frameId = 3;
  frame.frameType = "sub_frame";
  frame.parentFrameId = 0;
  assert.equal(validateBrowserDocument(sender, frame, extensionId), null);
});

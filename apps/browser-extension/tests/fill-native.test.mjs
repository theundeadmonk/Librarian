import assert from "node:assert/strict";
import test from "node:test";
import { parseFillResponse, requestCredential } from "../dist/fill-native.js";

class EventSet {
  listeners = [];
  addListener(listener) { this.listeners.push(listener); }
  emit(value) { for (const listener of this.listeners) listener(value); }
}
class Port {
  onMessage = new EventSet();
  onDisconnect = new EventSet();
  sent = [];
  disconnected = 0;
  postMessage(message) { this.sent.push(message); }
  disconnect() { this.disconnected += 1; }
}
const random = { getRandomValues: (bytes) => bytes.fill(1) };
const context = { tabId: 7, frameId: 0, documentId: "12345678-1234-4234-8234-123456789abc",
  topLevelOrigin: "https://example.com", frameOrigin: "https://example.com" };
const id = "01".repeat(16);
const credential = { protocolVersion: 2, requestId: id, status: "credential", username: "user", password: "FILL-CANARY" };

test("fill opens a fresh port, sends only bound context, and returns one credential", async () => {
  const port = new Port();
  const request = requestCredential({ connectNative: () => port }, random, context, new AbortController().signal);
  assert.deepEqual(port.sent, [{ protocolVersion: 2, requestId: id, operation: "fillSingle",
    context: { kind: "exactHttps", ...context }, timeoutMs: 2000 }]);
  port.onMessage.emit(credential);
  assert.deepEqual(await request, { status: "credential", username: "user", password: "FILL-CANARY" });
  assert.equal(port.disconnected, 1);
  port.onMessage.emit({ ...credential, password: "LATE-CANARY" });
  assert.equal(port.disconnected, 1);
});

test("fill cancels before connection or during a request, without replay", async () => {
  const abort = new AbortController();
  abort.abort();
  assert.deepEqual(await requestCredential({ connectNative: () => assert.fail("must not connect") },
    random, context, abort.signal), { status: "cancelled" });
  const live = new AbortController();
  const port = new Port();
  const result = requestCredential({ connectNative: () => port }, random, context, live.signal);
  live.abort();
  port.onMessage.emit(credential);
  assert.deepEqual(await result, { status: "cancelled" });
  assert.equal(port.sent.length, 1);
  assert.equal(port.disconnected, 1);
});

test("compact browser tokens are converted only at the native wire boundary", async () => {
  const port = new Port();
  const abort = new AbortController();
  const browserContext = { ...context, documentId: "929E8A0FA9D51BCD679FF8FA08BA41EB" };
  const request = requestCredential({ connectNative: () => port }, random, browserContext, abort.signal);
  try {
    assert.equal(port.sent[0].context.documentId, "929e8a0f-a9d5-1bcd-679f-f8fa08ba41eb");
    assert.equal(browserContext.documentId, "929E8A0FA9D51BCD679FF8FA08BA41EB");
  } finally { abort.abort(); await request; }
});

test("invalid document tokens never open a native port", async () => {
  for (const documentId of ["0".repeat(32), "A".repeat(33), "page-controlled", "a".repeat(32)]) {
    assert.deepEqual(await requestCredential({ connectNative: () => assert.fail("must not connect") },
      random, { ...context, documentId }, new AbortController().signal), { status: "operationFailed" });
  }
});

test("fill fails closed on timeout, host crash, and unavailable native messaging", async () => {
  const timed = new Port();
  assert.deepEqual(await requestCredential({ connectNative: () => timed }, random, context,
    new AbortController().signal, 1), { status: "timedOut" });
  assert.equal(timed.disconnected, 1);
  const crashed = new Port();
  const request = requestCredential({ connectNative: () => crashed }, random, context, new AbortController().signal);
  crashed.onDisconnect.emit();
  assert.deepEqual(await request, { status: "unavailable" });
  assert.deepEqual(await requestCredential({ connectNative: () => { throw new Error("not installed"); } },
    random, context, new AbortController().signal), { status: "unavailable" });
});

test("fill parses only exact response schemas and bounded UTF-8 credential fields", () => {
  for (const malformed of [null, [], {}, { ...credential, protocolVersion: 1 },
    { ...credential, requestId: "02".repeat(16) }, { ...credential, masterPassword: "FORBIDDEN" },
    { ...credential, records: [] }, { ...credential, username: "u".repeat(1025) },
    { ...credential, password: "é".repeat(8193) }, { ...credential, password: null },
    { protocolVersion: 2, requestId: id, status: "noCredential", password: "FORBIDDEN" },
    { protocolVersion: 2, requestId: id, status: "error", error: "unknown" },
  ]) assert.deepEqual(parseFillResponse(malformed, id), { status: "protocolError" });
  assert.deepEqual(parseFillResponse({ protocolVersion: 2, requestId: id, status: "noCredential" }, id), { status: "noCredential" });
  for (const error of ["locked", "cancelled", "timedOut", "incompatible", "operationFailed"]) {
    assert.deepEqual(parseFillResponse({ protocolVersion: 2, requestId: id, status: "error", error }, id), { status: error });
  }
  assert.deepEqual(parseFillResponse({ ...credential, username: "u".repeat(1024), password: "é".repeat(8192) }, id),
    { status: "credential", username: "u".repeat(1024), password: "é".repeat(8192) });
});

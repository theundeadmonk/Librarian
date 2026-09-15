import assert from "node:assert/strict";
import test from "node:test";
import { setTimeout as delay } from "node:timers/promises";
import { installFillController } from "../dist/fill-controller.js";

class EventSet {
  listeners = [];
  addListener(listener) { this.listeners.push(listener); }
  emit(...args) { for (const listener of this.listeners) listener(...args); }
}
class Port {
  name = "librarian-fill-v1";
  onMessage = new EventSet();
  onDisconnect = new EventSet();
  sent = [];
  closed = false;
  constructor(sender) { this.sender = sender; }
  postMessage(message) { this.sent.push(message); }
  disconnect() { if (!this.closed) { this.closed = true; this.onDisconnect.emit(); } }
}
const extensionId = "jiifjoajanfeoabbkmpodkgfmabhikkh";
const documentId = "12345678-1234-4234-8234-123456789abc";
function fixture() {
  const sender = { id: extensionId, tab: { id: 7, url: "https://example.com/login" },
    frameId: 0, documentId, documentLifecycle: "active", origin: "https://example.com", url: "https://example.com/login" };
  const frame = { documentId, documentLifecycle: "active", frameType: "outermost_frame",
    parentFrameId: -1, errorOccurred: false, url: "https://example.com/login" };
  const native = [];
  const messages = [];
  const presentations = [];
  const api = {
    runtime: { id: extensionId, onConnect: new EventSet(), connectNative() { const port = new Port(); native.push(port); return port; } },
    webNavigation: { getFrame: async () => ({ ...frame }), onBeforeNavigate: new EventSet(), onCommitted: new EventSet(),
      onHistoryStateUpdated: new EventSet(), onReferenceFragmentUpdated: new EventSet() },
    tabs: { onRemoved: new EventSet(), sendMessage: async (...args) => { messages.push(args); return { started: true }; } },
    permissions: { contains: async () => true, onRemoved: new EventSet() },
  };
  let marker = 0;
  const controller = installFillController(api, { getRandomValues: (bytes) => bytes.fill(++marker) },
    (...args) => presentations.push(args));
  const connect = (message = { kind: "fill" }, supplied = sender) => {
    const port = new Port(supplied);
    api.runtime.onConnect.emit(port);
    if (!port.closed) port.onMessage.emit(message);
    return port;
  };
  const respond = (port = native.at(-1)) => port.onMessage.emit({ status: "credential", protocolVersion: 2,
    requestId: port.sent[0].requestId, username: "user", password: "CONTROLLER-CANARY" });
  return { api, controller, sender, frame, native, messages, presentations, connect, respond };
}

test("controller binds document context, strips page URLs, and admits auto only once", async () => {
  const f = fixture();
  const port = f.connect();
  await delay(0);
  assert.equal(f.native.length, 1);
  assert.deepEqual(f.native[0].sent[0].context, { kind: "exactHttps", tabId: 7, frameId: 0,
    documentId, topLevelOrigin: "https://example.com", frameOrigin: "https://example.com" });
  f.respond(); await delay(0);
  assert.deepEqual(port.sent, [{ status: "credential", username: "user", password: "CONTROLLER-CANARY" }]);
  f.connect(); await delay(0);
  assert.equal(f.native.length, 1);
});

test("compact browser identity stays exact through auto, toolbar grant, and final recheck", async () => {
  const f = fixture();
  const browserId = "929E8A0FA9D51BCD679FF8FA08BA41EB";
  const wireId = "929e8a0f-a9d5-1bcd-679f-f8fa08ba41eb";
  f.sender.documentId = f.frame.documentId = browserId;
  const automatic = f.connect(); await delay(0);
  assert.equal(f.native.length, 1);
  assert.equal(f.native[0].sent[0].context.documentId, wireId);
  f.respond(); await delay(0); assert.equal(automatic.sent[0].status, "credential");
  f.connect(); await delay(0); assert.equal(f.native.length, 1);
  await f.controller.explicit({id:7});
  assert.deepEqual(f.messages[0][2], {documentId:browserId});
  const nonce = f.messages[0][1].actionNonce;
  const explicit = f.connect({kind:"fill",actionNonce:nonce}); await delay(0);
  assert.equal(f.native.length, 2);
  assert.equal(f.native[1].sent[0].context.documentId, wireId);
  // Normalization must not let a changed browser snapshot pass final delivery.
  f.frame.documentId = wireId;
  f.respond(); await delay(0); assert.equal(explicit.sent.length, 0);
  f.frame.documentId = browserId;
  f.connect({kind:"fill",actionNonce:nonce}); await delay(0);
  assert.equal(f.native.length, 2);
});

test("controller rejects origin claims, embedded senders, and forged explicit intents", async () => {
  for (const message of [{ kind: "fill", origin: "https://evil.test" }, { kind: "fill", explicit: true },
    { kind: "fill", actionNonce: "01".repeat(16) }, { kind: "unknown" }]) {
    const f = fixture(); f.connect(message); await delay(0); assert.equal(f.native.length, 0);
  }
  for (const change of [{ frameId: 1 }, { id: "a".repeat(32) }, { origin: "null" },
    { url: "about:blank" }, { documentId: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa" }]) {
    const f = fixture(); f.connect({ kind: "fill" }, { ...f.sender, ...change });
    await delay(0); assert.equal(f.native.length, 0);
  }
});

test("a fresh toolbar nonce allows another attempt and is consumed once", async () => {
  const f = fixture();
  f.connect(); await delay(0); f.respond(); await delay(0);
  assert.equal(await f.controller.explicit({ id: 7 }), true);
  assert.deepEqual(f.messages[0][2], { documentId });
  const nonce = f.messages[0][1].actionNonce;
  const explicit = f.connect({ kind: "fill", actionNonce: nonce });
  await delay(0); assert.equal(f.native.length, 2); f.respond(); await delay(0);
  assert.equal(explicit.sent[0].status, "credential");
  f.connect({ kind: "fill", actionNonce: nonce }); await delay(0);
  assert.equal(f.native.length, 2);
});

test("navigation, edits/disconnect, and revoked permissions cancel native work", async () => {
  for (const interrupt of [
    (f) => f.api.webNavigation.onBeforeNavigate.emit({ tabId: 7, frameId: 0 }),
    (f) => f.api.webNavigation.onHistoryStateUpdated.emit({ tabId: 7, frameId: 0 }),
    (f) => f.api.permissions.onRemoved.emit(),
    (_, port) => port.disconnect(),
  ]) {
    const f = fixture(); const port = f.connect(); await delay(0);
    interrupt(f, port); f.respond(); await delay(0);
    assert.equal(f.native[0].closed, true);
    assert.equal(port.sent.length, 0);
  }
});

test("final recheck rejects same-origin document replacement and permission loss", async () => {
  for (const change of [
    (f) => { f.frame.documentId = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"; },
    (f) => { f.frame.url = "https://other.test"; },
    (f) => { f.api.permissions.contains = async () => false; },
  ]) {
    const f = fixture(); const port = f.connect(); await delay(0);
    change(f); f.respond(); await delay(0);
    assert.equal(port.sent.length, 0);
  }
});

test("denied website permission prevents agent access", async () => {
  const f = fixture(); f.api.permissions.contains = async () => false;
  f.connect(); await delay(0); assert.equal(f.native.length, 0);
});

test("navigation while browser context is pending never opens the native host", async () => {
  const f = fixture();
  let resolveFrame;
  f.api.webNavigation.getFrame = () => new Promise(resolve => { resolveFrame = resolve; });
  const port = f.connect();
  f.api.webNavigation.onBeforeNavigate.emit({ tabId: 7, frameId: 0 });
  resolveFrame(f.frame); await delay(0);
  assert.equal(f.native.length, 0);
  assert.equal(port.sent.length, 0);
});

test("toolbar grants cannot cross documents or survive navigation", async () => {
  for (const navigate of [
    f => { f.frame.documentId = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"; f.sender.documentId = f.frame.documentId; },
    f => f.api.webNavigation.onCommitted.emit({ tabId: 7, frameId: 0 }),
  ]) {
    const f = fixture();
    await f.controller.explicit({ id: 7 });
    const nonce = f.messages[0][1].actionNonce;
    navigate(f); f.connect({ kind: "fill", actionNonce: nonce }); await delay(0);
    assert.equal(f.native.length, 0);
  }
});

test("a second message on a content port cancels rather than retries", async () => {
  const f = fixture(); const port = f.connect(); await delay(0);
  port.onMessage.emit({ kind: "fill" }); f.respond(); await delay(0);
  assert.equal(f.native.length, 1);
  assert.equal(f.native[0].closed, true);
  assert.equal(port.sent.length, 0);
});

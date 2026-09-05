import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import test from "node:test";

import {
  BROWSER_PROTOCOL_VERSION,
  HOST_REQUEST_TIMEOUT_MS,
  NATIVE_HOST_NAME,
  createRequestId,
  probeNativeStatus,
} from "../dist/native.js";

class ListenerSet {
  listeners = [];

  addListener(listener) {
    this.listeners.push(listener);
  }

  emit(value) {
    for (const listener of this.listeners) {
      listener(value);
    }
  }
}

class FakePort {
  onMessage = new ListenerSet();
  onDisconnect = new ListenerSet();
  messages = [];
  disconnects = 0;

  postMessage(message) {
    this.messages.push(message);
  }

  disconnect() {
    this.disconnects += 1;
  }
}

function random(fill = 1) {
  return {
    getRandomValues(array) {
      array.fill(fill);
      return array;
    },
  };
}

function runtime(port) {
  return {
    applications: [],
    connectNative(application) {
      this.applications.push(application);
      return port;
    },
  };
}

test("sends one bounded status request and accepts the matching response", async () => {
  const port = new FakePort();
  const nativeRuntime = runtime(port);
  const result = probeNativeStatus(nativeRuntime, random());

  assert.deepEqual(nativeRuntime.applications, [NATIVE_HOST_NAME]);
  assert.deepEqual(port.messages, [
    {
      protocolVersion: BROWSER_PROTOCOL_VERSION,
      requestId: "01".repeat(16),
      operation: "status",
      context: { kind: "none" },
      timeoutMs: HOST_REQUEST_TIMEOUT_MS,
    },
  ]);
  port.onMessage.emit({
    status: "ok",
    protocolVersion: BROWSER_PROTOCOL_VERSION,
    requestId: "01".repeat(16),
    agentStatus: "locked",
  });

  assert.deepEqual(await result, { status: "available", agentStatus: "locked" });
  assert.equal(port.disconnects, 1);
});

test("maps a missing or crashed host to one non-secret unavailable state", async () => {
  const port = new FakePort();
  const result = probeNativeStatus(runtime(port), random());
  port.onDisconnect.emit();

  assert.deepEqual(await result, { status: "unavailable" });
  assert.equal(port.disconnects, 0);
});

test("disconnects a timed-out port instead of retrying the operation", async () => {
  const port = new FakePort();
  const result = probeNativeStatus(runtime(port), random(), { portTimeoutMs: 1 });

  assert.deepEqual(await result, { status: "timedOut" });
  assert.equal(port.messages.length, 1);
  assert.equal(port.disconnects, 1);
});

test("rejects stale, mismatched, and extended responses", async () => {
  const cases = [
    {
      status: "ok",
      protocolVersion: 0,
      requestId: "01".repeat(16),
      agentStatus: "unlocked",
    },
    {
      status: "ok",
      protocolVersion: 1,
      requestId: "02".repeat(16),
      agentStatus: "unlocked",
    },
    {
      status: "ok",
      protocolVersion: 1,
      requestId: "01".repeat(16),
      agentStatus: "unlocked",
      extra: true,
    },
  ];
  for (const response of cases) {
    const port = new FakePort();
    const result = probeNativeStatus(runtime(port), random());
    port.onMessage.emit(response);
    assert.deepEqual(await result, { status: "protocolError" });
  }
});

test("maps the closed native error set without preserving error details", async () => {
  const cases = new Map([
    ["incompatible", "incompatible"],
    ["agentUnavailable", "unavailable"],
    ["operationFailed", "operationFailed"],
    ["invalidRequest", "protocolError"],
  ]);
  for (const [error, expected] of cases) {
    const port = new FakePort();
    const result = probeNativeStatus(runtime(port), random());
    port.onMessage.emit({
      status: "error",
      protocolVersion: 1,
      requestId: "01".repeat(16),
      error,
    });
    assert.deepEqual(await result, { status: expected });
  }
});

test("uses nonzero random 128-bit request identifiers", () => {
  assert.equal(createRequestId(random(0xab)), "ab".repeat(16));
  assert.throws(() => createRequestId(random(0)), /random source/);
});

test("fails closed when the browser random source is invalid", async () => {
  const port = new FakePort();
  assert.deepEqual(await probeNativeStatus(runtime(port), random(0)), {
    status: "operationFailed",
  });
  assert.equal(port.messages.length, 0);
});

test("keeps the public development key and installer allowlist in sync", () => {
  const manifest = JSON.parse(
    readFileSync(new URL("../manifest.json", import.meta.url), "utf8"),
  );
  const publicKey = Buffer.from(manifest.key, "base64");
  const digest = createHash("sha256").update(publicKey).digest().subarray(0, 16);
  const alphabet = "abcdefghijklmnop";
  let extensionId = "";
  for (const byte of digest) {
    extensionId += alphabet[byte >> 4] + alphabet[byte & 15];
  }
  assert.equal(extensionId, "jiifjoajanfeoabbkmpodkgfmabhikkh");

  const installer = readFileSync(
    new URL("../../../scripts/build-installer.ps1", import.meta.url),
    "utf8",
  );
  assert.equal(
    installer.match(
      /\[string\]\$(?:Chrome|Edge)ExtensionId = "jiifjoajanfeoabbkmpodkgfmabhikkh"/g,
    )?.length,
    2,
  );
});

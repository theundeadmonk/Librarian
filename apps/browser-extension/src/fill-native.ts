import { createRequestId, HOST_REQUEST_TIMEOUT_MS, NATIVE_HOST_NAME,
  type NativeRuntime, type RandomSource } from "./native.js";
import { protocolDocumentId, type BrowserDocumentContext } from "./browser-context.js";

export type FillResult =
  | { readonly status: "credential"; readonly username: string; readonly password: string }
  | { readonly status: "noCredential" | "locked" | "cancelled" | "timedOut" |
      "unavailable" | "incompatible" | "protocolError" | "operationFailed" };

export function requestCredential(runtime: NativeRuntime, random: RandomSource,
  context: BrowserDocumentContext, signal: AbortSignal,
  portTimeoutMs = 2500,
): Promise<FillResult> {
  if (signal.aborted) return Promise.resolve({ status: "cancelled" });
  const documentId = protocolDocumentId(context.documentId);
  if (documentId === null) return Promise.resolve({ status: "operationFailed" });
  let requestId: string;
  try { requestId = createRequestId(random); }
  catch { return Promise.resolve({ status: "operationFailed" }); }
  return new Promise((resolve) => {
    let port: ReturnType<NativeRuntime["connectNative"]>;
    try { port = runtime.connectNative(NATIVE_HOST_NAME); }
    catch { resolve({ status: "unavailable" }); return; }
    let settled = false;
    const finish = (result: FillResult, disconnect = true): void => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      signal.removeEventListener("abort", abort);
      if (disconnect) { try { port.disconnect(); } catch { /* already closed */ } }
      resolve(result);
    };
    const abort = (): void => finish({ status: "cancelled" });
    const timer = setTimeout(() => finish({ status: "timedOut" }), portTimeoutMs);
    signal.addEventListener("abort", abort, { once: true });
    port.onDisconnect.addListener(() => {
      void runtime.lastError;
      finish({ status: "unavailable" }, false);
    });
    port.onMessage.addListener((message) => finish(parseFillResponse(message, requestId)));
    if (signal.aborted) { abort(); return; }
    try {
      port.postMessage({ protocolVersion: 2, requestId, operation: "fillSingle",
        context: { kind: "exactHttps", ...context, documentId }, timeoutMs: HOST_REQUEST_TIMEOUT_MS });
    } catch { finish({ status: "unavailable" }); }
  });
}

export function parseFillResponse(message: unknown, requestId: string): FillResult {
  if (!isRecord(message) || message.protocolVersion !== 2 || message.requestId !== requestId) {
    return { status: "protocolError" };
  }
  if (message.status === "credential" && exactKeys(message, ["protocolVersion", "requestId", "status", "username", "password"])
    && boundedText(message.username, 1024) && boundedText(message.password, 16384)) {
    return { status: "credential", username: message.username, password: message.password };
  }
  if (message.status === "noCredential" && exactKeys(message, ["protocolVersion", "requestId", "status"])) {
    return { status: "noCredential" };
  }
  if (message.status === "error" && exactKeys(message, ["protocolVersion", "requestId", "status", "error"])) {
    switch (message.error) {
      case "locked": case "cancelled": case "timedOut": case "incompatible": case "operationFailed":
        return { status: message.error };
      case "agentUnavailable": return { status: "unavailable" };
    }
  }
  return { status: "protocolError" };
}

export function boundedText(value: unknown, maximum: number): value is string {
  return typeof value === "string" && value.length <= maximum
    && new TextEncoder().encode(value).byteLength <= maximum;
}

export function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

export function exactKeys(value: Record<string, unknown>, keys: readonly string[]): boolean {
  return Object.keys(value).length === keys.length && keys.every((key) => Object.hasOwn(value, key));
}

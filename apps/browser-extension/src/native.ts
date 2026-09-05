export const NATIVE_HOST_NAME = "com.theundeadmonk.librarian";
export const BROWSER_PROTOCOL_VERSION = 1;
export const HOST_REQUEST_TIMEOUT_MS = 2_000;
const PORT_RESPONSE_TIMEOUT_MS = 2_500;

export type AgentStatus =
  | "starting"
  | "noVault"
  | "locked"
  | "unlocking"
  | "unlocked"
  | "updating"
  | "shuttingDown";

export type NativeStatusResult =
  | { readonly status: "available"; readonly agentStatus: AgentStatus }
  | { readonly status: "unavailable" }
  | { readonly status: "incompatible" }
  | { readonly status: "timedOut" }
  | { readonly status: "protocolError" }
  | { readonly status: "operationFailed" };

interface NativePort {
  readonly onMessage: {
    addListener(listener: (message: unknown) => void): void;
  };
  readonly onDisconnect: {
    addListener(listener: () => void): void;
  };
  postMessage(message: unknown): void;
  disconnect(): void;
}

export interface NativeRuntime {
  readonly lastError?: unknown;
  connectNative(application: string): NativePort;
}

export interface RandomSource {
  getRandomValues(array: Uint8Array<ArrayBuffer>): Uint8Array<ArrayBuffer>;
}

interface ProbeOptions {
  readonly portTimeoutMs?: number;
}

const AGENT_STATUSES = new Set<AgentStatus>([
  "starting",
  "noVault",
  "locked",
  "unlocking",
  "unlocked",
  "updating",
  "shuttingDown",
]);

const HOST_ERRORS = new Set([
  "invalidRequest",
  "incompatible",
  "agentUnavailable",
  "operationFailed",
]);

export function probeNativeStatus(
  runtime: NativeRuntime,
  random: RandomSource,
  options: ProbeOptions = {},
): Promise<NativeStatusResult> {
  let requestId: string;
  try {
    requestId = createRequestId(random);
  } catch {
    return Promise.resolve({ status: "operationFailed" });
  }
  const timeoutMs = options.portTimeoutMs ?? PORT_RESPONSE_TIMEOUT_MS;
  return new Promise((resolve) => {
    let port: NativePort;
    try {
      port = runtime.connectNative(NATIVE_HOST_NAME);
    } catch {
      resolve({ status: "unavailable" });
      return;
    }
    let settled = false;
    let timer: ReturnType<typeof setTimeout> | undefined;
    const finish = (result: NativeStatusResult, disconnect: boolean): void => {
      if (settled) {
        return;
      }
      settled = true;
      if (timer !== undefined) {
        clearTimeout(timer);
      }
      if (disconnect) {
        port.disconnect();
      }
      resolve(result);
    };
    port.onMessage.addListener((message) => {
      finish(parseResponse(message, requestId), true);
    });
    port.onDisconnect.addListener(() => {
      // Reading lastError acknowledges Chromium's disconnect diagnostic. Its
      // unstable message is deliberately neither retained nor displayed.
      void runtime.lastError;
      finish({ status: "unavailable" }, false);
    });
    timer = setTimeout(() => {
      finish({ status: "timedOut" }, true);
    }, timeoutMs);
    try {
      port.postMessage({
        protocolVersion: BROWSER_PROTOCOL_VERSION,
        requestId,
        operation: "status",
        context: { kind: "none" },
        timeoutMs: HOST_REQUEST_TIMEOUT_MS,
      });
    } catch {
      finish({ status: "unavailable" }, true);
    }
  });
}

export function createRequestId(random: RandomSource): string {
  const bytes = random.getRandomValues(new Uint8Array(16));
  if (bytes.every((byte) => byte === 0)) {
    throw new Error("The browser random source returned an invalid correlation identifier.");
  }
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

function parseResponse(message: unknown, requestId: string): NativeStatusResult {
  if (!isRecord(message) || message.protocolVersion !== BROWSER_PROTOCOL_VERSION) {
    return { status: "protocolError" };
  }
  if (message.status === "ok") {
    if (
      !hasExactKeys(message, [
        "status",
        "protocolVersion",
        "requestId",
        "agentStatus",
      ]) ||
      message.requestId !== requestId ||
      typeof message.agentStatus !== "string" ||
      !AGENT_STATUSES.has(message.agentStatus as AgentStatus)
    ) {
      return { status: "protocolError" };
    }
    return {
      status: "available",
      agentStatus: message.agentStatus as AgentStatus,
    };
  }
  if (
    message.status !== "error" ||
    !hasExactKeys(message, ["status", "protocolVersion", "requestId", "error"]) ||
    message.requestId !== requestId ||
    typeof message.error !== "string" ||
    !HOST_ERRORS.has(message.error)
  ) {
    return { status: "protocolError" };
  }
  switch (message.error) {
    case "incompatible":
      return { status: "incompatible" };
    case "agentUnavailable":
      return { status: "unavailable" };
    case "operationFailed":
      return { status: "operationFailed" };
    case "invalidRequest":
      return { status: "protocolError" };
    default:
      return { status: "protocolError" };
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function hasExactKeys(value: Record<string, unknown>, expected: readonly string[]): boolean {
  const keys = Object.keys(value);
  return keys.length === expected.length && expected.every((key) => keys.includes(key));
}

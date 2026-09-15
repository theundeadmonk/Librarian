import {
  originFromBrowserUrl,
  parseHttpsOrigin,
  type HttpsOrigin,
} from "./origin.js";

/** Non-secret binding; obtaining this value alone never authorizes disclosure. */
export interface BrowserDocumentContext {
  readonly tabId: number;
  readonly frameId: 0;
  // Keep the exact browser-owned spelling for getFrame/sendMessage and binding.
  readonly documentId: string;
  readonly topLevelOrigin: HttpsOrigin;
  readonly frameOrigin: HttpsOrigin;
}

/** Serialize the same 128 bits to the native protocol's canonical ID spelling. */
export function protocolDocumentId(value: unknown): string | null {
  if (typeof value !== "string") return null;
  // Chromium currently exposes document tokens as 32 uppercase hex digits.
  // Also retain the lowercase hyphenated spelling accepted by this protocol.
  if (/^[0-9A-F]{32}$/u.test(value) && value !== "0".repeat(32)) {
    const hex = value.toLowerCase();
    return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
  }
  return /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/u.test(value)
    && value !== "00000000-0000-0000-0000-000000000000" ? value : null;
}

/**
 * Inputs must come directly from runtime's MessageSender and a fresh
 * webNavigation.getFrame({tabId: sender.tab.id, frameId: 0}) call. Never accept
 * either snapshot from message payloads, DOM properties, or page postMessage.
 * Re-query and revalidate before delivery; target the original documentId.
 */
export function validateBrowserDocument(
  sender: unknown,
  currentFrame: unknown,
  extensionId: string,
): BrowserDocumentContext | null {
  if (
    !/^[a-p]{32}$/u.test(extensionId) ||
    !isObject(sender) ||
    !isObject(sender.tab) ||
    !isObject(currentFrame) ||
    sender.id !== extensionId ||
    sender.frameId !== 0 ||
    sender.documentLifecycle !== "active" ||
    typeof sender.tab.id !== "number" ||
    !Number.isSafeInteger(sender.tab.id) ||
    sender.tab.id < 0 ||
    sender.tab.id > 0x7fffffff ||
    typeof sender.documentId !== "string" ||
    protocolDocumentId(sender.documentId) === null ||
    currentFrame.documentId !== sender.documentId ||
    currentFrame.documentLifecycle !== "active" ||
    currentFrame.frameType !== "outermost_frame" ||
    currentFrame.parentFrameId !== -1 ||
    currentFrame.errorOccurred !== false
  ) {
    return null;
  }

  const origin = parseHttpsOrigin(sender.origin);
  if (
    origin === null ||
    originFromBrowserUrl(sender.url) !== origin ||
    originFromBrowserUrl(sender.tab.url) !== origin ||
    originFromBrowserUrl(currentFrame.url) !== origin
  ) {
    return null;
  }
  return Object.freeze({
    tabId: sender.tab.id,
    frameId: 0,
    documentId: sender.documentId,
    topLevelOrigin: origin,
    frameOrigin: origin,
  });
}

/** Same-origin navigations still invalidate a result when documentId changes. */
export function sameBrowserDocument(
  admitted: BrowserDocumentContext,
  current: BrowserDocumentContext,
): boolean {
  return (
    admitted.tabId === current.tabId &&
    admitted.frameId === current.frameId &&
    admitted.documentId === current.documentId &&
    admitted.topLevelOrigin === current.topLevelOrigin &&
    admitted.frameOrigin === current.frameOrigin
  );
}

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

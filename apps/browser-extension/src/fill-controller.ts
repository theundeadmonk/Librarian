import { sameBrowserDocument, validateBrowserDocument } from "./browser-context.js";
import { exactKeys, isRecord, requestCredential, type FillResult } from "./fill-native.js";
import { createRequestId, type RandomSource } from "./native.js";
import { originFromBrowserUrl } from "./origin.js";

export type FillPresentation = FillResult["status"] | "noForm";
export type BrowserApi = Pick<typeof chrome, "runtime" | "tabs" | "webNavigation" | "permissions">;

/** Only browser-owned sender/context evidence and real toolbar callbacks enter here. */
export function installFillController(api: BrowserApi, random: RandomSource,
  present: (status: FillPresentation, tabId: number) => void,
) {
  const active = new Map<chrome.runtime.Port, { tabId: number; abort: AbortController }>();
  const automatic = new Map<number, string>();
  const actions = new Map<number, { documentId: string; nonce: string; expires: number }>();

  function cancelTab(tabId: number): void {
    actions.delete(tabId);
    for (const [port, request] of active) {
      if (request.tabId === tabId) { request.abort.abort(); try { port.disconnect(); } catch { /* closed */ } }
    }
  }
  const navigated = ({ tabId, frameId }: { tabId: number; frameId: number }): void => {
    if (frameId === 0) cancelTab(tabId);
  };
  api.webNavigation.onBeforeNavigate.addListener(navigated);
  api.webNavigation.onCommitted.addListener(navigated);
  api.webNavigation.onHistoryStateUpdated.addListener(navigated);
  api.webNavigation.onReferenceFragmentUpdated.addListener(navigated);
  api.tabs.onRemoved.addListener((tabId) => { cancelTab(tabId); automatic.delete(tabId); });
  api.permissions.onRemoved.addListener(() => {
    actions.clear();
    for (const request of active.values()) request.abort.abort();
  });

  api.runtime.onConnect.addListener((port) => {
    const sender = port.sender;
    const tabId = sender?.tab?.id;
    if (port.name !== "librarian-fill-v1" || sender === undefined || sender.id !== api.runtime.id
      || sender.frameId !== 0 || typeof tabId !== "number" || active.size >= 32) {
      port.disconnect(); return;
    }
    const abort = new AbortController();
    active.set(port, { tabId, abort });
    let received = false;
    let finished = false;
    const close = (): void => {
      if (finished) return;
      finished = true;
      clearTimeout(timer);
      abort.abort();
      active.delete(port);
      try { port.disconnect(); } catch { /* closed */ }
    };
    const timer = setTimeout(close, 3000);
    port.onDisconnect.addListener(close);
    port.onMessage.addListener((message) => {
      if (received) { close(); return; }
      received = true;
      void run(message).catch(() => { if (!abort.signal.aborted) present("operationFailed", tabId); }).finally(close);
    });

    async function run(message: unknown): Promise<void> {
      if (!isRecord(message) || message.kind !== "fill"
        || !(exactKeys(message, ["kind"]) || exactKeys(message, ["kind", "actionNonce"]))) return;
      const initial = await api.webNavigation.getFrame({ tabId: tabId!, frameId: 0 });
      const context = validateBrowserDocument(sender, initial, api.runtime.id);
      if (context === null || abort.signal.aborted) return;
      if (Object.hasOwn(message, "actionNonce")) {
        const grant = actions.get(context.tabId);
        actions.delete(context.tabId);
        if (grant === undefined || grant.documentId !== context.documentId
          || grant.nonce !== message.actionNonce || performance.now() >= grant.expires) return;
      } else {
        if (automatic.get(context.tabId) === context.documentId
          || (automatic.size >= 256 && !automatic.has(context.tabId))) return;
        automatic.set(context.tabId, context.documentId);
      }
      const permission = { origins: [`https://${new URL(context.topLevelOrigin).hostname}/*`] };
      if (!await api.permissions.contains(permission) || abort.signal.aborted) return;
      const result = await requestCredential(api.runtime, random, context, abort.signal);
      if (abort.signal.aborted) return;
      const current = validateBrowserDocument(sender,
        await api.webNavigation.getFrame({ tabId: context.tabId, frameId: 0 }), api.runtime.id);
      if (current === null || !sameBrowserDocument(context, current)
        || !await api.permissions.contains(permission) || abort.signal.aborted) return;
      // Reply on the requesting document's own port, never to a tab broadcast.
      port.postMessage(result);
      present(result.status, context.tabId);
    }
  });

  return {
    async explicit(tab: chrome.tabs.Tab): Promise<boolean> {
      if (typeof tab.id !== "number") return false;
      const frame = await api.webNavigation.getFrame({ tabId: tab.id, frameId: 0 });
      if (frame?.documentId === undefined || frame.documentLifecycle !== "active"
        || frame.frameType !== "outermost_frame" || frame.parentFrameId !== -1
        || frame.errorOccurred !== false || originFromBrowserUrl(frame.url) === null) return false;
      if (actions.size >= 256 && !actions.has(tab.id)) return false;
      const nonce = createRequestId(random);
      actions.set(tab.id, { documentId: frame.documentId, nonce, expires: performance.now() + 3000 });
      try {
        const response = await api.tabs.sendMessage(tab.id, { kind: "explicitFill", actionNonce: nonce }, { documentId: frame.documentId });
        if (!isRecord(response) || !exactKeys(response, ["started"]) || response.started !== true) {
          actions.delete(tab.id);
          present("noForm", tab.id);
        }
      } catch { actions.delete(tab.id); present("noForm", tab.id); }
      return true;
    },
  };
}

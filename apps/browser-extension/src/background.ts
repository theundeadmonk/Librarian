import { probeNativeStatus, type NativeStatusResult } from "./native.js";
import { installFillController, type FillPresentation } from "./fill-controller.js";

const COLORS = Object.freeze({
  available: "#137333",
  attention: "#b06000",
  busy: "#1a73e8",
  failed: "#b3261e",
});

interface ActionPresentation {
  readonly badge: string;
  readonly color: string;
  readonly title: string;
}

export const foundationStatus = Object.freeze({
  credentialAccessImplemented: true,
  nativeMessagingImplemented: true,
});

async function refreshConnectionStatus(): Promise<void> {
  const result = await probeNativeStatus(chrome.runtime, globalThis.crypto);
  const presentation = present(result);
  await Promise.all([
    chrome.action.setBadgeText({ text: presentation.badge }),
    chrome.action.setBadgeBackgroundColor({ color: presentation.color }),
    chrome.action.setTitle({ title: presentation.title }),
  ]);
}

function present(result: NativeStatusResult): ActionPresentation {
  if (result.status === "available") {
    switch (result.agentStatus) {
      case "unlocked":
        return {
          badge: "ON",
          color: COLORS.available,
          title: "Librarian is connected and unlocked.",
        };
      case "locked":
        return {
          badge: "LOCK",
          color: COLORS.attention,
          title: "Librarian is connected but locked. Unlock it in the desktop app.",
        };
      case "noVault":
        return {
          badge: "SET",
          color: COLORS.attention,
          title: "Librarian is connected. Finish setup in the desktop app.",
        };
      case "starting":
      case "unlocking":
      case "updating":
      case "shuttingDown":
        return {
          badge: "...",
          color: COLORS.busy,
          title: "Librarian is temporarily busy. Try again shortly.",
        };
    }
  }
  if (result.status === "incompatible") {
    return {
      badge: "UP",
      color: COLORS.failed,
      title: "Librarian components are incompatible. Update or repair Librarian.",
    };
  }
  if (result.status === "unavailable") {
    return {
      badge: "!",
      color: COLORS.failed,
      title: "The Librarian app is unavailable. Install, start, or repair Librarian.",
    };
  }
  if (result.status === "timedOut") {
    return {
      badge: "!",
      color: COLORS.failed,
      title: "Librarian did not respond in time. Try again.",
    };
  }
  return {
    badge: "!",
    color: COLORS.failed,
    title: "Librarian could not verify its browser connection. Repair Librarian.",
  };
}

chrome.runtime.onInstalled.addListener(() => {
  void refreshConnectionStatus().catch(() => undefined);
});
chrome.runtime.onStartup.addListener(() => {
  void refreshConnectionStatus().catch(() => undefined);
});
const fill = installFillController(chrome, globalThis.crypto, (status, tabId) => {
  void presentFill(status, tabId).catch(() => undefined);
});

async function presentFill(status: FillPresentation, tabId: number): Promise<void> {
  const messages: Record<FillPresentation, string> = {
    credential: "Librarian supplied the saved account. Filling is skipped if the page or fields changed.",
    noCredential: "No single account matches this exact website. Check the accounts in Librarian.",
    noForm: "No supported sign-in form is available on this page.",
    locked: "Unlock Librarian in the desktop app, then click here to fill.",
    cancelled: "Filling was cancelled. Click here to try again.",
    timedOut: "Librarian did not respond in time. Click here to try again.",
    unavailable: "The Librarian app is unavailable. Install, start, or repair it.",
    incompatible: "Update or repair Librarian and its browser extension together.",
    protocolError: "Librarian could not verify the fill request. Repair Librarian.",
    operationFailed: "Librarian could not fill this account. Click here to try again.",
  };
  await Promise.all([
    chrome.action.setTitle({ tabId, title: messages[status] }),
    chrome.action.setBadgeText({ tabId, text: status === "credential" ? "" : status === "locked" ? "LOCK" : "!" }),
    chrome.action.setBadgeBackgroundColor({ tabId, color: status === "credential" ? COLORS.available : COLORS.attention }),
  ]);
}

chrome.action.onClicked.addListener((tab) => {
  void fill.explicit(tab).then((handled) => handled ? undefined : refreshConnectionStatus())
    .catch(() => refreshConnectionStatus().catch(() => undefined));
});

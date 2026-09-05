import { probeNativeStatus, type NativeStatusResult } from "./native.js";

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
  credentialAccessImplemented: false,
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
chrome.action.onClicked.addListener(() => {
  void refreshConnectionStatus().catch(() => undefined);
});

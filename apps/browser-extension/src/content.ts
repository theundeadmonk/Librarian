import { FillOnceState } from "./fill-state.js";
import { findFillTargets, type FillTargets } from "./forms.js";
import { boundedText, exactKeys, isRecord } from "./fill-native.js";

// The document owns this state. Background-worker restart cannot reset it.
const restored = (performance.getEntriesByType("navigation")[0] as PerformanceNavigationTiming | undefined)?.type === "back_forward";
const state = new FillOnceState(restored);
let autoStopped = restored;
let pendingPort: chrome.runtime.Port | null = null;
let pendingTimer: ReturnType<typeof setTimeout> | undefined;
let timer: ReturnType<typeof setTimeout> | undefined;
const setValue = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value")?.set;

function stopAutomatic(): void {
  autoStopped = true;
  clearTimeout(timer);
  timer = undefined;
  observer.disconnect();
}

function cancel(): void {
  clearTimeout(pendingTimer);
  pendingTimer = undefined;
  const port = pendingPort;
  pendingPort = null;
  try { port?.disconnect(); } catch { /* already closed */ }
}

function begin(explicitNonce?: string): boolean {
  if (window.top !== window || pendingPort !== null) return false;
  const targets = findFillTargets(document);
  if (targets === null || setValue === undefined) return false;
  const explicit = explicitNonce !== undefined;
  if (!explicit && (targets.password.value !== "" || (targets.username?.value ?? "") !== "")) {
    stopAutomatic();
    state.noteEdit();
    return false;
  }
  const attempt = explicit ? state.beginExplicit() : state.beginAutomatic();
  if (attempt === null) return false;
  stopAutomatic();
  const snapshot = { targets, username: targets.username?.value ?? "", password: targets.password.value, url: location.href };
  let port: chrome.runtime.Port;
  try { port = chrome.runtime.connect({ name: "librarian-fill-v1" }); }
  catch { state.fail(attempt); return false; }
  pendingPort = port;
  const timeout = setTimeout(() => { state.fail(attempt); cancel(); }, 3000);
  pendingTimer = timeout;
  port.onDisconnect.addListener(() => {
    void chrome.runtime.lastError;
    clearTimeout(timeout);
    state.fail(attempt);
    if (pendingPort === port) { pendingPort = null; pendingTimer = undefined; }
  });
  port.onMessage.addListener((message) => {
    clearTimeout(timeout);
    if (pendingPort !== port) return;
    pendingPort = null;
    pendingTimer = undefined;
    try { port.disconnect(); } catch { /* already closed */ }
    const current = findFillTargets(document);
    if (!isRecord(message) || message.status !== "credential"
      || !exactKeys(message, ["status", "username", "password"])
      || !boundedText(message.username, 1024) || !boundedText(message.password, 16384)
      || current === null || !sameTargets(snapshot.targets, current) || location.href !== snapshot.url
      || current.password.value !== snapshot.password || (current.username?.value ?? "") !== snapshot.username
      || !state.complete(attempt)) { state.fail(attempt); return; }
    writeFields(current, message.username, message.password);
  });
  try { port.postMessage(explicit ? { kind: "fill", actionNonce: explicitNonce } : { kind: "fill" }); }
  catch { state.fail(attempt); cancel(); clearTimeout(timeout); return false; }
  return true;
}

function sameTargets(left: FillTargets, right: FillTargets): boolean {
  return left.username === right.username && left.password === right.password
    && left.form === right.form && left.action === right.action;
}

function writeFields(targets: FillTargets, username: string, password: string): void {
  // Complete both native value writes before invoking any page input handlers.
  if (targets.username !== null) setValue!.call(targets.username, username);
  setValue!.call(targets.password, password);
  for (const input of [targets.username, targets.password]) {
    if (input === null) continue;
    input.dispatchEvent(new Event("input", { bubbles: true }));
    input.dispatchEvent(new Event("change", { bubbles: true }));
  }
}

function edited(event: Event): void {
  if (event.target instanceof HTMLInputElement) {
    stopAutomatic();
    state.noteEdit();
    cancel();
  }
}

function schedule(): void {
  if (autoStopped || timer !== undefined) return;
  timer = setTimeout(() => { timer = undefined; if (!autoStopped) begin(); }, 100);
}

document.addEventListener("input", edited, true);
document.addEventListener("change", edited, true);
window.addEventListener("pagehide", () => { stopAutomatic(); state.suspend(); cancel(); });
window.addEventListener("pageshow", (event) => {
  if (event.persisted) { stopAutomatic(); state.suspend(); state.resume(); }
  else schedule();
});
window.addEventListener("popstate", () => { stopAutomatic(); state.noteEdit(); cancel(); });
document.addEventListener("visibilitychange", () => {
  if (document.visibilityState !== "visible") { state.noteEdit(); stopAutomatic(); cancel(); }
  else schedule();
});
document.addEventListener("DOMContentLoaded", schedule, { once: true });
window.addEventListener("scroll", schedule, { passive: true });
const observer = new MutationObserver(schedule);
observer.observe(document, { childList: true, subtree: true, attributes: true,
  attributeFilter: ["type", "autocomplete", "hidden", "disabled", "readonly", "style", "class", "action", "formaction", "form", "name", "id"] });
if (restored) observer.disconnect();

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (sender.id !== chrome.runtime.id || sender.tab !== undefined || !isRecord(message)
    || !exactKeys(message, ["kind", "actionNonce"]) || message.kind !== "explicitFill"
    || typeof message.actionNonce !== "string" || !/^[0-9a-f]{32}$/u.test(message.actionNonce)) return;
  sendResponse({ started: begin(message.actionNonce) });
});
schedule();

// Opt-in real Chromium DOM tests, not installed-extension/native-host acceptance.
// Fetch interception serves every fixture without DNS, TLS trust changes, or a server.
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve, dirname, basename } from "node:path";
import { setTimeout as delay } from "node:timers/promises";

const executable = ({ edge: "C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe",
  chrome: "C:/Program Files/Google/Chrome/Application/chrome.exe" })[process.argv[2]] ?? process.argv[2];
assert.ok(executable, "Supply a Chrome or Edge executable as the first argument");
const profile = await mkdtemp(join(tmpdir(), "librarian-dom-"));
const content = await readFile(new URL("../dist/content.js", import.meta.url), "utf8");
const child = spawn(executable, ["--headless=new", "--no-first-run", "--no-default-browser-check",
  "--disable-background-networking", "--disable-component-update", "--remote-debugging-port=0",
  `--user-data-dir=${profile}`, "about:blank"], { windowsHide: true, stdio: "ignore" });
let socket;
let sequence = 0;
let session;
let fixture = "";
let startupError;
child.on("error", error => { startupError = error; });
const pending = new Map();
const failures = [];
const harness = `(() => {
  const ports = [], messages = [];
  const event = () => ({ listeners: [], addListener(fn) { this.listeners.push(fn); },
    emit(...args) { for (const fn of this.listeners) fn(...args); } });
  const onMessage = event();
  globalThis.chrome = { runtime: { id: 'fixture-extension', onMessage,
    connect(options) {
      const port = { onMessage: event(), onDisconnect: event(), closed: false,
        postMessage(message) { messages.push(message); }, disconnect() { this.closed = true; } };
      ports.push(port); return port;
    } } };
  // Test-only document identity, including insecure HTTP negative fixtures.
  globalThis.fixtureApi = { ports, messages, submits: 0, events: [], documentToken: Array.from(crypto.getRandomValues(new Uint32Array(4))).join('-'),
    reply(index = ports.length - 1, status = 'credential') {
      ports[index].onMessage.emit(status === 'credential'
        ? { status, username: 'DOM-CANARY-USER', password: 'DOM-CANARY-PASSWORD' } : { status });
    },
    explicit() {
      let response;
      onMessage.emit({ kind: 'explicitFill', actionNonce: '12'.repeat(16) },
        { id: 'fixture-extension' }, value => { response = value; });
      return response;
    }
  };
  document.addEventListener('submit', event => { event.preventDefault(); fixtureApi.submits++; });
  document.addEventListener('input', event => fixtureApi.events.push(event.target.id));
})();`;
const login = '<form action="/session"><input id="user" autocomplete="username"><input id="pass" type="password" autocomplete="current-password"><button>Sign in</button></form>';

function send(method, params = {}, target = session) {
  const id = ++sequence;
  return new Promise((resolve, reject) => {
    const timeout = setTimeout(() => { pending.delete(id); reject(new Error(`CDP timeout: ${method}`)); }, 10000);
    pending.set(id, { resolve, reject, timeout });
    socket.send(JSON.stringify({ id, method, params, ...(target ? { sessionId: target } : {}) }));
  });
}
async function evaluate(expression) {
  const result = await send("Runtime.evaluate", { expression, returnByValue: true, awaitPromise: true });
  assert.equal(result.exceptionDetails, undefined, "Fixture evaluation must not throw");
  return result.result.value;
}
async function until(expression) {
  for (let index = 0; index < 100; index++) {
    if (await evaluate(expression)) return;
    await delay(20);
  }
  assert.fail(`Fixture condition not reached: ${expression}`);
}
async function page(html = login, url = "https://librarian.test/login") {
  fixture = `<!doctype html><meta charset="utf-8"><title>Librarian disposable DOM fixture</title>${html}`;
  await send("Page.navigate", { url });
  await until("document.readyState === 'complete' && typeof fixtureApi !== 'undefined'");
  await delay(250);
}
async function check(name, action) {
  await action();
  assert.deepEqual(failures, [], "No uncaught browser exceptions");
  console.log(`PASS ${name}`);
}
try {
  let port;
  for (let index = 0; index < 200; index++) {
    if (startupError) throw startupError;
    try { port = (await readFile(join(profile, "DevToolsActivePort"), "utf8")).split("\n"); break; }
    catch { if (child.exitCode !== null) throw new Error("Browser exited during startup"); await delay(50); }
  }
  assert.ok(port, "Browser debugging endpoint must start");
  socket = new WebSocket(`ws://127.0.0.1:${port[0]}${port[1]}`);
  await new Promise((resolve, reject) => { socket.onopen = resolve; socket.onerror = reject; });
  socket.onmessage = ({ data }) => {
    const message = JSON.parse(data);
    if (message.id) {
      const request = pending.get(message.id);
      if (!request) return;
      pending.delete(message.id); clearTimeout(request.timeout);
      if (message.error) request.reject(new Error(message.error.message)); else request.resolve(message.result);
    } else if (message.method === "Fetch.requestPaused") {
      const html = message.params.resourceType === "Document" ? fixture : "";
      void send("Fetch.fulfillRequest", { requestId: message.params.requestId, responseCode: 200,
        responseHeaders: [{ name: "Content-Type", value: "text/html; charset=utf-8" }],
        body: Buffer.from(html).toString("base64") }, message.sessionId).catch(error => failures.push(error.message));
    } else if (message.method === "Runtime.exceptionThrown") failures.push("Uncaught browser exception");
  };
  const targets = await send("Target.getTargets");
  const version = await send("Browser.getVersion");
  console.log(`Browser: ${version.product}; ${version.userAgent}`);
  const target = targets.targetInfos.find(target => target.type === "page");
  session = (await send("Target.attachToTarget", { targetId: target.targetId, flatten: true })).sessionId;
  await send("Page.enable"); await send("Runtime.enable");
  await send("Fetch.enable", { patterns: [{ urlPattern: "*", requestStage: "Request" }] });
  await send("Page.addScriptToEvaluateOnNewDocument", { source: harness + "\n" + content });

  await check("unique login fills both fields, dispatches events, and never submits", async () => {
    await page(); assert.equal(await evaluate("fixtureApi.messages.length"), 1);
    await evaluate("fixtureApi.reply()");
    assert.deepEqual(await evaluate("[user.value, pass.value, fixtureApi.submits, fixtureApi.events]"),
      ["DOM-CANARY-USER", "DOM-CANARY-PASSWORD", 0, ["user", "pass"]]);
    await evaluate("pass.value = ''; pass.dispatchEvent(new Event('input', { bubbles: true })); document.body.append(document.createElement('div'))");
    await delay(250); assert.equal(await evaluate("fixtureApi.messages.length"), 1);
    assert.equal(await evaluate("fixtureApi.explicit().started"), true);
    await evaluate("fixtureApi.reply()"); assert.equal(await evaluate("pass.value"), "DOM-CANARY-PASSWORD");
  });
  for (const [name, html] of [
    ["registration", login.replace("current-password", "new-password")],
    ["ambiguous passwords", login + '<input type="password" autocomplete="current-password">'],
    ["hidden password", login.replace('id="pass"', 'id="pass" style="display:none"')],
    ["readonly password", login.replace('id="pass"', 'id="pass" readonly')],
    ["disabled form", `<fieldset disabled>${login}</fieldset>`],
    ["inert form", `<div inert>${login}</div>`],
    ["cross-origin submit", login.replace('/session', 'https://other.test/session')],
    ["submit override", login.replace('<button>', '<button formaction="https://other.test">')],
    ["existing username", login.replace('id="user"', 'id="user" value="edited"')],
    ["username-only step", '<input autocomplete="username">'],
  ]) await check(`${name} does not request a credential`, async () => {
    await page(html); assert.equal(await evaluate("fixtureApi.messages.length"), 0);
  });
  await check("HTTP pages do not request credentials", async () => {
    await page(login, "http://librarian.test/login"); assert.equal(await evaluate("fixtureApi.messages.length"), 0);
  });
  await check("dynamic login is detected once", async () => {
    await page('<div id="mount"></div>');
    await evaluate(`mount.innerHTML = ${JSON.stringify(login)}`);
    await until("fixtureApi.messages.length === 1"); await evaluate("fixtureApi.reply()");
    assert.equal(await evaluate("pass.value"), "DOM-CANARY-PASSWORD");
  });
  await check("form-less password does not fill an unrelated standalone email field", async () => {
    await page('<aside><input id="newsletter" type="email" autocomplete="email"></aside><main><input id="pass" type="password" autocomplete="current-password"></main>');
    assert.equal(await evaluate("fixtureApi.messages.length"), 1);
    await evaluate("fixtureApi.reply()");
    assert.deepEqual(await evaluate("[newsletter.value, pass.value, fixtureApi.events]"),
      ["", "DOM-CANARY-PASSWORD", ["pass"]]);
  });
  for (const [name, mutation] of [
    ["user edit", "pass.value = 'typed'; pass.dispatchEvent(new Event('input', { bubbles: true }))"],
    ["field replacement", "pass.replaceWith(pass.cloneNode())"],
    ["action change", "document.forms[0].action = 'https://other.test'"],
    ["history URL change", "history.pushState({}, '', '/replacement')"],
    ["page suspension", "dispatchEvent(new PageTransitionEvent('pagehide', { persisted: true }))"],
  ]) await check(`${name} discards a pending credential`, async () => {
    await page(); await evaluate(mutation); await evaluate("fixtureApi.reply()");
    assert.notEqual(await evaluate("pass.value"), "DOM-CANARY-PASSWORD");
    await delay(250); assert.equal(await evaluate("fixtureApi.messages.length"), 1);
  });
  await check("locked response consumes auto attempt; toolbar can retry", async () => {
    await page(); await evaluate("fixtureApi.reply(0, 'locked'); document.body.append(document.createElement('div'))");
    await delay(250); assert.equal(await evaluate("fixtureApi.messages.length"), 1);
    assert.equal(await evaluate("fixtureApi.explicit().started"), true);
    await evaluate("fixtureApi.reply()"); assert.equal(await evaluate("pass.value"), "DOM-CANARY-PASSWORD");
  });
  await check("validation error never automatically refills a cleared password", async () => {
    await page(); await evaluate("fixtureApi.reply(); pass.value = ''; pass.setCustomValidity('fixture rejection'); pass.reportValidity(); document.body.append(document.createElement('p'))");
    await delay(250); assert.equal(await evaluate("fixtureApi.messages.length"), 1);
    assert.equal(await evaluate("pass.value"), "");
  });
  await check("back navigation requires explicit filling", async () => {
    await page(login, "https://librarian.test/back-fixture"); await evaluate("fixtureApi.reply()");
    const originalDocument = await evaluate("fixtureApi.documentToken");
    await page(login, "https://librarian.test/next-fixture");
    const history = await send("Page.getNavigationHistory");
    await send("Page.navigateToHistoryEntry", { entryId: history.entries[history.currentIndex - 1].id });
    await until("location.pathname === '/back-fixture' && document.readyState === 'complete'");
    await delay(300);
    // A BFCache document retains its one consumed request; a restored new
    // document detects back_forward and starts with zero automatic requests.
    const count = await evaluate("fixtureApi.messages.length");
    assert.equal(count, await evaluate("fixtureApi.documentToken") === originalDocument ? 1 : 0);
    await evaluate("pass.value = ''; pass.dispatchEvent(new Event('input', { bubbles: true }))");
    await delay(250); assert.equal(await evaluate("fixtureApi.messages.length"), count);
    assert.equal(await evaluate("fixtureApi.explicit().started"), true);
    await evaluate("fixtureApi.reply()"); assert.equal(await evaluate("pass.value"), "DOM-CANARY-PASSWORD");
  });
  await check("same-origin iframe never starts filling", async () => {
    await page('<iframe srcdoc="&lt;input type=password autocomplete=current-password&gt;"></iframe>');
    assert.deepEqual(await evaluate("[fixtureApi.messages.length, frames[0].fixtureApi.messages.length]"), [0, 0]);
  });
  console.log("PASS real DOM suite (fake messaging; no native host or real credentials)");
} finally {
  if (socket?.readyState === WebSocket.OPEN) {
    try { await send("Browser.close", {}, null); } catch { /* browser closes its transport */ }
    socket.close();
  }
  if (child.exitCode === null) child.kill();
  for (const request of pending.values()) clearTimeout(request.timeout);
  // Only remove the exact mkdtemp-owned profile, never a user's browser profile.
  assert.equal(dirname(resolve(profile)), resolve(tmpdir()));
  assert.ok(basename(profile).startsWith("librarian-dom-"));
  await rm(profile, { recursive: true, force: true, maxRetries: 20, retryDelay: 100 });
}

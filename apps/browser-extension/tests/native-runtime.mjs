// Component integration, NOT installed-browser acceptance. Only the Chrome
// NativeRuntime port and Windows IPC transport are replaced. Request encoding,
// response validation, native JSON framing/parser, and encrypted vault runtime
// are production code. Every vault is NEW and all credentials are public dummies.
import { spawn } from "node:child_process";
import { createHash, webcrypto } from "node:crypto";
import { mkdtemp, readFile, writeFile } from "node:fs/promises";
import { basename, isAbsolute, join } from "node:path";
import { fileURLToPath } from "node:url";
import { requestCredential } from "../dist/fill-native.js";
import { NATIVE_HOST_NAME, probeNativeStatus } from "../dist/native.js";
import { originFromBrowserUrl } from "../dist/origin.js";

const executable = process.argv[2];
if (process.argv.length !== 3 || !executable || !isAbsolute(executable)
  || !["issue17-stdio.exe", "issue17-stdio"].includes(basename(executable))) {
  throw new Error("Supply the absolute path to the test-only issue17-stdio example.");
}
const artifactRoot = fileURLToPath(new URL("../../../artifacts/", import.meta.url));
const output = await mkdtemp(join(artifactRoot, "issue17-native-runtime-"));
const accounts = (await readFile(new URL("../../../tests/fixtures/issue17-accounts.tsv", import.meta.url), "utf8"))
  .split(/\r?\n/u).filter(line => line && !line.startsWith("#")).map(line => line.split("\t"));
if (accounts.length !== 5 || accounts.some(fields => fields.length !== 4)) throw new Error("Invalid fixed fixture inventory.");

class EventSet {
  listeners = [];
  addListener(listener) { this.listeners.push(listener); }
  emit(value) { for (const listener of this.listeners) listener(value); }
}

// A sequential stdio adapter; each request gets a fresh logical port and a
// fresh in-process agent connection. It does not emulate Chrome registration,
// OS peer authentication, process-per-port lifetime, or agent event transport.
class StdioRuntime {
  buffer = Buffer.alloc(0);
  pending;
  failure;
  diagnostics = "";
  connections = 0;
  messages = 0;
  lastRequest;
  async start(directory, locked = false) {
    this.child = spawn(executable, ["--new-directory", directory, ...(locked ? ["--locked"] : [])],
      { stdio: ["pipe", "pipe", "pipe"], windowsHide: true });
    this.exited = new Promise(resolve => this.child.once("close", (code, signal) => {
      this.exitResult = { code, signal };
      if (this.pending) this.fail("fixture exited during request");
      resolve(this.exitResult);
    }));
    this.ready = new Promise((resolve, reject) => {
      this.readyResolve = resolve;
      this.readyReject = reject;
    });
    this.child.on("error", () => this.fail("fixture launch failed"));
    this.child.stdin.on("error", () => this.fail("fixture input failed"));
    this.child.stdout.on("data", chunk => this.receive(chunk));
    this.child.stderr.on("data", chunk => {
      this.diagnostics += chunk.toString("utf8");
      if (this.diagnostics.length > 4096) this.fail("fixture diagnostic bound exceeded");
      else if (this.diagnostics === "ISSUE17_FIXTURE_READY\n") this.readyResolve();
      else if (this.diagnostics.includes("\n")) this.fail("fixture reported a failure");
    });
    const timer = setTimeout(() => this.fail("fixture readiness timed out"), 60000);
    try { await this.ready; } finally { clearTimeout(timer); }
    return this;
  }
  fail(message) {
    this.failure ??= message;
    this.readyReject?.(new Error(message));
    if (this.pending) {
      const pending = this.pending;
      this.pending = undefined;
      pending.complete();
      pending.port.onDisconnect.emit();
    }
  }
  receive(chunk) {
    this.buffer = Buffer.concat([this.buffer, chunk]);
    if (this.buffer.length > 128 * 1024 + 4) { this.fail("fixture output bound exceeded"); return; }
    if (this.buffer.length < 4) return;
    const length = this.buffer.readUInt32LE(0);
    if (length === 0 || length > 128 * 1024) { this.fail("invalid fixture frame length"); return; }
    if (this.buffer.length < length + 4) return;
    if (!this.pending || this.buffer.length !== length + 4) { this.fail("unexpected fixture output"); return; }
    let message;
    try { message = JSON.parse(this.buffer.subarray(4).toString("utf8")); }
    catch { this.fail("invalid fixture JSON"); return; }
    this.buffer.fill(0);
    this.buffer = Buffer.alloc(0);
    const pending = this.pending;
    this.pending = undefined;
    pending.complete();
    if (!pending.port.closed) pending.port.onMessage.emit(message);
    // No native response, account contents, selection IDs, or tokens are logged.
  }
  connectNative(name) {
    if (name !== NATIVE_HOST_NAME || this.pending || this.failure || this.exitResult) {
      throw new Error("invalid fixture connection");
    }
    this.connections++;
    const port = {
      onMessage: new EventSet(), onDisconnect: new EventSet(), closed: false,
      disconnect() { this.closed = true; },
      postMessage: message => {
        if (port.closed || this.pending) throw new Error("invalid fixture send");
        const body = Buffer.from(JSON.stringify(message), "utf8");
        if (body.length > 16 * 1024) throw new Error("fixture request bound exceeded");
        this.lastRequest = message;
        this.messages++;
        let complete;
        const idle = new Promise(resolve => { complete = resolve; });
        this.pending = { port, complete, idle };
        const header = Buffer.alloc(4);
        header.writeUInt32LE(body.length);
        this.child.stdin.write(Buffer.concat([header, body]));
      },
    };
    return port;
  }
  async idle() {
    if (!this.pending) return;
    let timer;
    try {
      await Promise.race([this.pending.idle, new Promise((_, reject) => {
        timer = setTimeout(() => reject(new Error("fixture response timed out")), 6000);
      })]);
    } finally { clearTimeout(timer); }
    if (this.failure) throw new Error(this.failure);
  }
  async stop() {
    if (!this.child) return;
    // Only ever terminates this owned test child, never a product process.
    let timer;
    this.child.stdin.end();
    try {
      await Promise.race([this.exited, new Promise((_, reject) => {
        timer = setTimeout(() => { this.child.kill(); reject(new Error("fixture shutdown timed out")); }, 10000);
      })]);
    } finally { clearTimeout(timer); }
    if (this.failure || this.exitResult.code !== 0 || this.exitResult.signal || this.buffer.length !== 0) {
      throw new Error("fixture did not shut down cleanly");
    }
  }
}

const report = {
  schemaVersion: 1, testOnly: true, outcome: "Failed", failure: null,
  evidenceScope: "extension request code + production native framing + isolated encrypted runtime",
  transport: "test stdio adapter and synthetic in-process agent connections",
  expectedAccountsPerVault: 5, createdAccounts: { unlocked: 0, locked: 0 }, existingVaultAccessed: false,
  installedBrowserAcceptance: "NotRun", uiAcceptance: "NotRun", osPeerAuthentication: "NotRun",
  checks: [],
};
let currentCheck = "fixture startup";
async function check(name, action) {
  currentCheck = name;
  const passed = await action();
  report.checks.push({ name, passed: passed === true });
  if (passed !== true) throw new Error("integration check failed");
  console.log(`PASS ${name}`);
}
const documentId = "929E8A0FA9D51BCD679FF8FA08BA41EB";
const context = origin => ({ tabId: 7, frameId: 0, documentId, topLevelOrigin: origin, frameOrigin: origin });
const runtime = new StdioRuntime();
const locked = new StdioRuntime();
const fill = (client, bound, signal = new AbortController().signal) => requestCredential(client, webcrypto, bound, signal);
function matches(result, account) {
  return result.status === "credential" && result.username === account[2] && result.password === account[3]
    && Object.keys(result).length === 3;
}
try {
  report.executableSha256 = createHash("sha256").update(await readFile(executable)).digest("hex");
  await runtime.start(join(output, "unlocked"));
  report.createdAccounts.unlocked = 5;
  await check("status crosses extension, native framing, and unlocked runtime", async () => {
    const status = await probeNativeStatus(runtime, webcrypto);
    return status.status === "available" && status.agentStatus === "unlocked";
  });
  for (const [name, url, index] of [
    ["exact origin returns only the unique stored dummy credential", "https://librarian.test", 0],
    ["browser path query fragment and default port normalize before native wire", "https://LIBRARIAN.test:443/login?next=private#part", 0],
    ["non-default port matches exactly", "https://ports.librarian.test:8443/login", 1],
    ["browser zero-padded port canonicalizes before native wire", "https://ports.librarian.test:08443", 1],
    ["Unicode browser host matches stored IDN account", "https://bücher.librarian.test/login", 2],
    ["punycode browser host matches same stored IDN account", "https://xn--bcher-kva.librarian.test", 2],
  ]) {
    await check(name, async () => {
      const origin = originFromBrowserUrl(url);
      if (origin === null) return false;
      const bound = context(origin);
      const result = await fill(runtime, bound);
      return matches(result, accounts[index]) && bound.documentId === documentId
        && runtime.lastRequest.context.documentId === "929e8a0f-a9d5-1bcd-679f-f8fa08ba41eb"
        && runtime.lastRequest.context.topLevelOrigin === origin
        && runtime.lastRequest.timeoutMs === 2000;
    });
  }
  await check("canonical UUID document token also crosses real parser", async () => matches(
    await fill(runtime, { ...context("https://librarian.test"), documentId: "12345678-1234-4234-8234-123456789abc" }), accounts[0]));
  for (const [name, origin] of [
    ["missing account returns no credential", "https://missing.librarian.test"],
    ["omitted non-default port refuses", "https://ports.librarian.test"],
    ["different non-default port refuses", "https://ports.librarian.test:8444"],
    ["IDN ASCII lookalike refuses", "https://bucher.librarian.test"],
    ["IDN subdomain refuses", "https://sub.xn--bcher-kva.librarian.test"],
    ["IDN different port refuses", "https://xn--bcher-kva.librarian.test:8443"],
    ["duplicate exact-origin accounts refuse", "https://duplicates.librarian.test"],
    ["hostname suffix refuses", "https://librarian.test.evil.test"],
  ]) await check(name, async () => (await fill(runtime, context(origin))).status === "noCredential");
  for (const [name, bound] of [
    ["native parser rejects raw HTTP", context("http://librarian.test")],
    ["native parser rejects raw Unicode", context("https://bücher.librarian.test")],
    ["native parser rejects raw default port", context("https://librarian.test:443")],
    ["native parser rejects raw path", context("https://librarian.test/login")],
    ["native parser rejects child frame", { ...context("https://librarian.test"), frameId: 1 }],
    ["native parser rejects mismatched frame origin", { ...context("https://librarian.test"), frameOrigin: "https://other.test" }],
    ["native parser rejects extra context fields", { ...context("https://librarian.test"), untrusted: true }],
  ]) await check(name, async () => (await fill(runtime, bound)).status === "protocolError");
  await check("invalid browser token never opens native transport", async () => {
    const before = runtime.connections;
    const result = await fill(runtime, { ...context("https://librarian.test"), documentId: "0".repeat(32) });
    return result.status === "operationFailed" && before === runtime.connections;
  });
  await check("pre-cancelled request never opens native transport", async () => {
    const before = runtime.connections;
    const abort = new AbortController(); abort.abort();
    return (await fill(runtime, context("https://librarian.test"), abort.signal)).status === "cancelled"
      && before === runtime.connections;
  });
  await check("cancellation discards the late real runtime response", async () => {
    const abort = new AbortController();
    const pending = fill(runtime, context("https://librarian.test"), abort.signal);
    abort.abort();
    const result = await pending;
    await runtime.idle();
    return result.status === "cancelled" && Object.keys(result).length === 1;
  });
  await check("fresh request after cancellation uses a new port and still succeeds", async () => {
    const before = runtime.connections;
    return matches(await fill(runtime, context("https://librarian.test")), accounts[0]) && runtime.connections === before + 1;
  });
  await runtime.stop();
  currentCheck = "locked fixture startup";
  await locked.start(join(output, "locked"), true);
  report.createdAccounts.locked = 5;
  await check("status crosses real parser and locked runtime", async () => {
    const status = await probeNativeStatus(locked, webcrypto);
    return status.status === "available" && status.agentStatus === "locked";
  });
  await check("locked runtime returns no credential fields through extension", async () => {
    const result = await fill(locked, context("https://librarian.test"));
    return result.status === "locked" && Object.keys(result).length === 1;
  });
  await locked.stop();
  if (report.checks.length !== 29 || report.checks.some(check => check.passed !== true)) {
    throw new Error("Incomplete integration matrix.");
  }
  report.outcome = "Passed";
} catch {
  // Do not print exception objects: an assertion or child error could carry
  // response data. Reports contain fixed check labels and boolean results only.
  report.failure = currentCheck;
  report.fixtureFailure = runtime.failure ?? locked.failure ?? null;
  process.exitCode = 1;
} finally {
  for (const client of [runtime, locked]) {
    if (client.child && !client.exitResult) {
      try { await client.stop(); }
      catch { report.outcome = "Failed"; report.failure ??= "fixture cleanup"; process.exitCode = 1; }
    }
  }
  const json = JSON.stringify(report, null, 2) + "\n";
  if (accounts.some(row => row.slice(2).some(value => json.includes(value)))) throw new Error("Unsafe integration report.");
  await writeFile(join(output, "report.json"), json, { flag: "wx" });
  console.log(`${report.outcome}: ${report.checks.filter(check => check.passed).length} native/runtime component checks`);
  console.log(`Report: ${join(output, "report.json")}`);
}

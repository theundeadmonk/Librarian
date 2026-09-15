// Local opt-in installed-chain probe. No extension/controller/native mocks.
// Only disposable page DOMs are scripted; vault/authentication UI is untouched.
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { open, readFile, writeFile, mkdtemp, stat } from 'node:fs/promises';
import { resolve, join, basename } from 'node:path';
import { hostname } from 'node:os';
import { setTimeout as delay } from 'node:timers/promises';
import {extendedCases,validateFixtureAccounts,canariesFor,validateCaseObservation} from './.codex-issue17-extended-cases.mjs';

const extensionId = 'jiifjoajanfeoabbkmpodkgfmabhikkh';
const login = '<form action="/session"><input id="user" autocomplete="username"><input id="pass" type="password" autocomplete="current-password"><button>Sign in</button></form>';
const fixtures = new Map();
const observer = `(() => {
  globalThis.fixtureApi = { submits: 0, inputs: [], changes: [] };
  document.addEventListener('submit', event => { event.preventDefault(); fixtureApi.submits++; }, true);
  document.addEventListener('input', event => fixtureApi.inputs.push(event.target.id));
  document.addEventListener('change', event => fixtureApi.changes.push(event.target.id));
})();`;
function documentBody(html, marker) {
  return `<!doctype html><meta charset="utf-8"><meta name="fixture-id" content="${marker}"><title>Librarian synthetic fixture</title>${html}`;
}
function route(request) {
  // Never forward requests, even unexpected subresources or form submissions.
  if (request.method !== 'GET') return { blocked: true };
  return fixtures.has(request.url) ? { body: fixtures.get(request.url) } : { blocked: true };
}
function check(condition, name) { if (!condition) throw new Error(name); }
// Process-owned CDP transport for browser-generated extension actions. No
// extension callback, nonce, permission, or production timeout is replaced.
class PipeSocket {
  readyState = 1;
  onmessage = () => {};
  onclose = () => {};
  constructor(writer, reader) {
    this.writer = writer; this.reader = reader; let pending = Buffer.alloc(0);
    reader.on('data', chunk => {
      pending = Buffer.concat([pending, chunk]);
      for (let end; (end = pending.indexOf(0)) !== -1;) {
        if (end > 131072) { this.close(); return; }
        const data = pending.subarray(0, end).toString('utf8'); pending = pending.subarray(end + 1);
        this.onmessage({data});
      }
      if (pending.length > 131072) this.close();
    });
    reader.on('close', () => this.close()); reader.on('error', () => this.close());
    writer.on('error', () => this.close());
  }
  send(text) { this.writer.write(text + '\0'); }
  close() {
    if (this.readyState !== 1) return;
    this.readyState = 3; this.writer.end(); this.reader.destroy(); this.onclose();
  }
}
class Cdp {
  constructor(socket) {
    this.socket = socket; this.sequence = 0; this.pending = new Map(); this.onEvent = () => {};
    socket.onmessage = ({ data }) => {
      if (typeof data !== 'string' || data.length > 131072) { socket.close(); return; }
      let message;
      try { message = JSON.parse(data); } catch { socket.close(); return; }
      if (message.id) {
        const request = this.pending.get(message.id);
        if (!request) return;
        this.pending.delete(message.id); clearTimeout(request.timer);
        if (message.error) {
          // Extension-management failures contain only browser/test identities,
          // never evaluated page values or native credential responses.
          const detail = request.method.startsWith('Extensions.') && typeof message.error.message === 'string'
            ? ': ' + message.error.message.slice(0,512) : '';
          const error = new Error(`CDP command rejected: ${request.method}${detail}`);
          error.code = message.error.code; request.reject(error);
        } else request.resolve(message.result);
      } else this.onEvent(message);
    };
    socket.onclose = () => {
      for (const request of this.pending.values()) {
        clearTimeout(request.timer); request.reject(new Error('Test browser connection closed'));
      }
      this.pending.clear();
    };
  }
  call(method, params = {}, sessionId) {
    if (this.socket.readyState !== WebSocket.OPEN) return Promise.reject(new Error('Test browser connection unavailable'));
    const id = ++this.sequence;
    return new Promise((resolvePromise, reject) => {
      const timer = setTimeout(() => { this.pending.delete(id); reject(new Error(`CDP timeout: ${method}`)); }, 10000);
      this.pending.set(id, { resolve: resolvePromise, reject, timer, method });
      this.socket.send(JSON.stringify({ id, method, params, ...(sessionId ? { sessionId } : {}) }));
    });
  }
  async evaluate(expression, session) {
    const result = await this.call('Runtime.evaluate', { expression, returnByValue: true, awaitPromise: true }, session);
    check(!result.exceptionDetails, 'Fixture evaluation failed');
    return result.result.value;
  }
}

async function connectCdp(url) {
  const socket = new WebSocket(url);
  await new Promise((res, rej) => {
    const timer = setTimeout(() => { socket.close(); rej(new Error('DevTools startup timeout')); }, 5000);
    socket.onopen = () => { clearTimeout(timer); res(); };
    socket.onerror = () => { clearTimeout(timer); rej(new Error('DevTools startup failed')); };
  });
  return new Cdp(socket);
}

async function labOperation(packageName, operation, state) {
  check(/^Librarian\.I17\.R[0-9a-f]{24}$/.test(packageName) &&
    ['--lock','--unlock-fixture'].includes(operation), 'Invalid fixed lab control');
  const executable = join('C:\\Program Files\\LibrarianIssue17Lab', packageName, 'Librarian.Windows.exe');
  const child = spawn(executable, [operation], {windowsHide:true, stdio:['ignore','pipe','pipe']});
  let output = '', bytes = 0;
  child.stdout.on('data', chunk => { bytes += chunk.length; if (bytes > 65536) child.kill(); else output += chunk.toString('utf8'); });
  child.stderr.on('data', chunk => { bytes += chunk.length; if (bytes > 65536) child.kill(); });
  const timeout = setTimeout(() => child.kill(), 10000);
  try {
    const code = await new Promise((res, rej) => {child.once('error', () => rej(new Error('Fixed lab control could not start'))); child.once('close', res);});
    check(code === 0 && bytes <= 65536, 'Fixed authenticated lab operation failed');
    const result = JSON.parse(output);
    check(result.testOnly === true && result.authenticatedWindowsIpc === true && result.outcome === 'Passed'
      && result.state === state && result.operation === operation, 'Invalid authenticated lab control evidence');
  } finally { clearTimeout(timeout); }
}

const toolbarObservation = `(async () => {
  const api = globalThis.chrome;
  if (!api?.runtime?.id || typeof api.action?.getBadgeText !== 'function' ||
      typeof api.action?.getTitle !== 'function' || typeof api.permissions?.contains !== 'function') {
    return {ready:false};
  }
  return {ready:true, id:api.runtime.id, badge:await api.action.getBadgeText({}),
    title:await api.action.getTitle({}), permitted:await api.permissions.contains({origins:['https://*/*']})};
})()`;

async function probe(config, transportOnly = false, contextOnly = false, actionOnly = false) {
  const batch = config.batch ?? 'Initial';
  const report = { outcome: 'Failed', purpose: actionOnly ? 'Browser action transport self-test only; no native permission, host, or vault' : contextOnly ? 'Browser context self-test only; no native permission, host, or vault' : transportOnly ? 'Fixture transport self-test only; no extension or vault' :
    config.labPackage ? `${batch} signed isolated lab chain with authenticated Windows IPC; not full production-install acceptance` :
    `${batch} installed-chain batch; not complete Issue 17 acceptance`, batch,
    tests: [], notRun: [
      ...(batch === 'Initial' ? ['duplicate accounts', 'positive non-default-port and IDN accounts'] :
        ['manual toolbar filling after edits and back navigation']),
      'worker restart', 'lock during in-flight requests', 'independent review'],
    networkForwarded: false, unexpectedRequests: 0, logCanaryScan: 'NotRun', cleanup: 'NotRun' };
  let child, cdp, workerCdp, stderr, outerTimer;
  let currentTest = 'preflight';
  let waitStage = 'preflight';
  let interceptedDocuments = 0, eventErrors = 0, submittedRequests = 0, pageExceptions = 0;
  let session, targetId, actionTargetId, workerTargetId;
  const profile = await mkdtemp(join(config.outputDirectory, 'fill-profile-'));
  report.profileRetainedInGuest = true;
  const log = join(profile, 'browser.log');
  const stderrPath = join(profile, 'stderr.log');
  try {
    stderr = await open(stderrPath, 'wx');
    const args = ['--headless=new', '--disable-gpu', '--no-first-run', '--no-default-browser-check',
      '--disable-background-networking', '--disable-component-update', '--disable-sync', '--metrics-recording-only',
      '--no-proxy-server', '--host-resolver-rules=MAP * ~NOTFOUND', '--enable-logging', `--log-file=${log}`,
      '--remote-debugging-port=0', `--user-data-dir=${profile}`,
      ...(config.labPackage || actionOnly ? ['--remote-debugging-pipe', '--enable-unsafe-extension-debugging'] : []),
      ...(transportOnly || config.labPackage || actionOnly ? [] : [`--disable-extensions-except=${config.extensionDirectory}`, `--load-extension=${config.extensionDirectory}`]),
      'about:blank'];
    child = spawn(config.executable, args, { windowsHide: true,
      stdio: ['ignore', 'ignore', stderr.fd, ...(config.labPackage || actionOnly ? ['pipe', 'pipe'] : [])] });
    if (config.labPackage || actionOnly) {
      cdp = new Cdp(new PipeSocket(child.stdio[3], child.stdio[4]));
      report.actionAutomation = 'Browser-generated action through isolated debugging pipe; not a physical toolbar click';
    }
    let startupFailed = false;
    child.on('error', () => { startupFailed = true; });
    let portLines;
    for (let i = 0; i < 150; ++i) {
      check(!startupFailed && child.exitCode === null, 'Test browser exited during startup');
      try { portLines = (await readFile(join(profile, 'DevToolsActivePort'), 'utf8')).trim().split(/\r?\n/); break; }
      catch { await delay(100); }
    }
    check(portLines?.length === 2 && /^\d+$/.test(portLines[0]) && Number(portLines[0]) > 0 && Number(portLines[0]) <= 65535 &&
      /^\/devtools\/browser\/[a-z0-9-]+$/i.test(portLines[1]), 'Invalid isolated DevTools endpoint');
    cdp ??= await connectCdp(`ws://127.0.0.1:${portLines[0]}${portLines[1]}`);
    report.browser = (await cdp.call('Browser.getVersion')).product;
    if (config.labPackage || actionOnly) {
      const loaded = await cdp.call('Extensions.loadUnpacked',{path:config.extensionDirectory});
      check(loaded.id === extensionId,'Browser loaded an unexpected test extension');
    }
    const targets = await cdp.call('Target.getTargets');
    const target = targets.targetInfos.find(t => t.type === 'page' && t.url === 'about:blank');
    check(target, 'Missing isolated fixture page'); targetId = target.targetId;
    const tabs = (await cdp.call('Target.getTargets', {filter:[{type:'tab',exclude:false},{exclude:true}]})).targetInfos
      .filter(t => t.type === 'tab' && t.url === 'about:blank');
    check(tabs.length === 1 && tabs[0].type === 'tab' && tabs[0].url === 'about:blank', 'Ambiguous isolated browser tab');
    actionTargetId = tabs[0].targetId;
    session = (await cdp.call('Target.attachToTarget', { targetId, flatten: true })).sessionId;
    cdp.onEvent = message => {
      if (message.method === 'Runtime.exceptionThrown') pageExceptions++;
      if (message.method !== 'Fetch.requestPaused') return;
      const request = message.params.request;
      const response = route(request);
      if (request.method !== 'GET') submittedRequests++;
      if (response.blocked) {
        // A browser favicon request is harmless but is still blocked locally.
        if (!request.url.endsWith('/favicon.ico')) report.unexpectedRequests++;
        void cdp.call('Fetch.failRequest', { requestId: message.params.requestId, errorReason: 'BlockedByClient' },
          message.sessionId).catch(() => { eventErrors++; });
      } else {
        if (message.params.resourceType === 'Document') interceptedDocuments++;
        void cdp.call('Fetch.fulfillRequest', { requestId: message.params.requestId, responseCode: 200,
          responseHeaders: [{ name: 'Content-Type', value: 'text/html; charset=utf-8' },
            { name: 'Content-Security-Policy', value: "default-src 'none'; form-action 'none'; frame-src 'self' https://librarian.test about:" }],
          body: Buffer.from(response.body).toString('base64') }, message.sessionId).catch(() => { eventErrors++; });
      }
    };
    await cdp.call('Page.enable', {}, session); await cdp.call('Runtime.enable', {}, session);
    await cdp.call('Fetch.enable', { patterns: [{ urlPattern: '*', requestStage: 'Request' }] }, session);
    await cdp.call('Page.addScriptToEvaluateOnNewDocument', { source: observer }, session);
    const evaluate = expression => cdp.evaluate(expression, session);
    async function until(expression, timeout = 6500, stage = 'credential or fixture assertion') {
      waitStage = stage;
      const deadline = Date.now() + timeout;
      while (Date.now() < deadline) { if (await evaluate(expression)) return; await delay(50); }
      throw new Error('Expected fixture condition not reached');
    }
    let number = 0;
    async function page(html = login, origin = config.account.origin, path = undefined) {
      const marker = String(++number);
      const url = new URL(path ?? `/case-${number}`, origin).href;
      fixtures.set(url, documentBody(html, marker));
      const result = await cdp.call('Page.navigate', { url }, session);
      check(!result.errorText, 'Fixture navigation failed');
      await until(`document.readyState === 'complete' && document.querySelector('meta[name="fixture-id"]')?.content === ${JSON.stringify(marker)} && typeof fixtureApi !== 'undefined'`, 6500, 'fixture document ready');
      return url;
    }
    const matches = `document.getElementById('pass')?.value === ${JSON.stringify(config.account.password)} &&
      (!document.getElementById('user') || document.getElementById('user').value === ${JSON.stringify(config.account.username)})`;
    const noSecrets = `Array.from(document.querySelectorAll('input')).every(e => e.value !== ${JSON.stringify(config.account.password)} && e.value !== ${JSON.stringify(config.account.username)})`;
    async function verify(name, action) {
      currentTest = name;
      await action();
      check(await evaluate('fixtureApi.submits === 0'), 'The extension attempted a form submission');
      check(submittedRequests === 0 && eventErrors === 0 && pageExceptions === 0 && report.unexpectedRequests === 0,
        'Unexpected network or browser error in fixture');
      report.tests.push({ name, outcome: 'Passed' });
      console.log(`PASS ${name}`);
    }
    async function noFill() { await delay(3400); check(await evaluate(noSecrets), 'Unexpected synthetic credential filling'); }
    async function nonWebPage(scheme) {
      check(['data','blob','about'].includes(scheme),'Unexpected non-web fixture scheme');
      let url;
      if (scheme === 'data') url = 'data:text/html,' + encodeURIComponent(documentBody(login, 'nonweb'));
      else if (scheme === 'blob') {
        await page('<main></main>');
        url = await evaluate(`URL.createObjectURL(new Blob([${JSON.stringify(documentBody(login,'nonweb'))}], {type:'text/html'}))`);
      } else url = 'about:blank';
      const navigation = await cdp.call('Page.navigate', {url}, session);
      check(!navigation.errorText, 'Non-web fixture navigation failed');
      await until(`location.protocol === ${JSON.stringify(scheme+':')} && document.readyState === 'complete' && typeof fixtureApi !== 'undefined'`);
      if (scheme === 'about') await evaluate(`document.body.innerHTML = ${JSON.stringify(login)}`);
      check(await evaluate("document.querySelectorAll('input').length === 2 && Array.from(document.querySelectorAll('input')).every(e => e.value === '')"), 'Non-web fixture fields missing or nonempty');
    }
    async function explicitFill() {
      try { await cdp.call('Extensions.triggerAction', { id: extensionId, targetId:actionTargetId }); }
      catch (error) {
        if (config.labPackage) throw error;
        if (error.code === -32601 || error.code === -32000) {
          report.notRun.push(currentTest + ' (browser extension-action test API unavailable)');
          return false;
        }
        throw error;
      }
      await until(matches); return true;
    }
    const suite = async () => {
      if (transportOnly) {
        if (batch === 'Extended') {
          for (const entry of extendedCases) await verify('transport only: ' + entry.name, async () => {
            await page(login,entry.origin,entry.path);
            check(await evaluate(`location.origin === ${JSON.stringify(new URL(entry.origin).origin)} &&
              isSecureContext === ${entry.origin.startsWith('https:')} && document.querySelectorAll('input').length === 2 &&
              Array.from(document.querySelectorAll('input')).every(e => e.value === '')`), 'Extended fixture transport mismatch');
          });
          return;
        }
        await verify('HTTPS intercepted fixture is secure and initially empty', async () => {
          await page(); check(await evaluate("isSecureContext && location.origin === 'https://librarian.test'"), 'Unexpected fixture security context');
          check(await evaluate(noSecrets), 'Fixture included credential values');
        });
        await verify('HTTP intercepted fixture keeps its actual scheme', async () => {
          await page(login, 'http://librarian.test'); check(await evaluate("location.protocol === 'http:'"), 'HTTP fixture upgraded unexpectedly');
        });
        for (const scheme of ['data','blob','about']) {
          await verify(`transport only: ${scheme} document has two empty fixture fields`, async () => {await nonWebPage(scheme);});
        }
        return;
      }
      async function connectWorker() {
      waitStage = 'discover extension worker';
      for (let i = 0; i < 150; ++i) {
        // Use the worker's own endpoint, as in the successful installed status
        // smoke. A browser-level flattened attachment timed out in guest Chrome.
        const response = await fetch(`http://127.0.0.1:${portLines[0]}/json/list`,
          {redirect:'error', signal:AbortSignal.timeout(3000)});
        check(response.ok, 'Worker endpoint discovery failed');
        const body = await response.text();
        check(body.length <= 131072, 'Worker endpoint inventory exceeds its bound');
        const list = JSON.parse(body);
        check(Array.isArray(list) && list.length <= 100, 'Invalid worker endpoint inventory');
        const worker = list.find(t => t.type === 'service_worker' &&
          t.url === `chrome-extension://${extensionId}/dist/background.js`);
        if (worker) {
          check(typeof worker.id === 'string' && /^[a-z0-9-]+$/i.test(worker.id) &&
            worker.webSocketDebuggerUrl === `ws://127.0.0.1:${portLines[0]}/devtools/page/${worker.id}`,
            'Worker endpoint does not belong to the isolated test browser');
          workerTargetId = worker.id;
          workerCdp = await connectCdp(worker.webSocketDebuggerUrl);
          report.workerTransport = 'direct worker endpoint';
          break;
        }
        await delay(100);
      }
      check(workerCdp, 'Installed extension worker did not start');
      waitStage = 'initialize extension worker runtime';
      await workerCdp.call('Runtime.enable');
      await workerCdp.call('Runtime.runIfWaitingForDebugger');
      }
      await connectWorker();
      if (actionOnly) {
        await page();
        await cdp.call('Extensions.triggerAction',{id:extensionId,targetId:actionTargetId});
        for (let attempt=0;attempt<100;attempt++) {
          if(await workerCdp.evaluate('globalThis.actionCount === 1')) {
            await verify('browser-generated action reached the non-native fixture once',async()=>{});
            return;
          }
          await delay(50);
        }
        throw new Error('Browser action did not reach the fixture');
      }
      if (contextOnly) {
        await page();
        for (let i = 0; i < 80; ++i) {
          const observations = await workerCdp.evaluate('globalThis.contextObservations ?? []');
          if (observations.length) {
            report.contextObservations = observations;
            await verify('real content-script sender and webNavigation metadata observed without native access', async () => {});
            return;
          }
          await delay(100);
        }
        throw new Error('The real content script did not open its diagnostic port');
      }
      let presentation;
      waitStage = 'observe native toolbar status';
      for (let i = 0; i < 100; ++i) {
        presentation = await workerCdp.evaluate(toolbarObservation);
        if (['ON', 'LOCK', 'SET', '!', 'UP'].includes(presentation?.badge)) break;
        await delay(100);
      }
      check(presentation?.id === extensionId && presentation.permitted === true, 'Extension identity or HTTPS permission mismatch');
      report.initialBadge = presentation.badge;
      check(presentation.badge === 'ON' && presentation.title === 'Librarian is connected and unlocked.',
        config.labPackage ? 'Authenticated lab fixture was not unlocked by its test client' :
          'Unlock Librarian in the VM and rerun this fill test; do not rerun the upgrade');
      if (batch === 'Extended') {
        report.fixturePrecondition = config.labPackage ? 'Five dummy accounts created through authenticated Desktop IPC in a new isolated lab package' :
          'User confirmed four additional synthetic accounts; duplicate count is not disclosed by the product API';
        for (const entry of extendedCases) await verify(entry.name, async () => {
          const url = await page(login,entry.origin,entry.path);
          const observation = `(() => {
            const user = document.getElementById('user'), pass = document.getElementById('pass');
            const values = Array.from(document.querySelectorAll('input'),e => e.value);
            return {inputCount:values.length,submissions:fixtureApi.submits,
              usernameMatches:${entry.expected ? `user?.value === ${JSON.stringify(entry.expected.username)}` : 'false'},
              passwordMatches:${entry.expected ? `pass?.value === ${JSON.stringify(entry.expected.password)}` : 'false'},
              allEmpty:values.every(v => v === ''),anyCanary:values.some(v => ${JSON.stringify(canariesFor('Extended'))}.includes(v)),
              inputs:fixtureApi.inputs,changes:fixtureApi.changes};
          })()`;
          if (entry.expected) {
            await until(`document.getElementById('user')?.value === ${JSON.stringify(entry.expected.username)} &&
              document.getElementById('pass')?.value === ${JSON.stringify(entry.expected.password)}`);
          } else {
            await delay(3400);
            if (entry.origin.startsWith('https:')) {
              // Empty fields alone would also pass if the extension never ran.
              // Require its real per-tab terminal noCredential presentation.
              const denied = await workerCdp.evaluate(`(async () => {
                const tabs = await chrome.tabs.query({}); const tab = tabs.find(t => t.url === ${JSON.stringify(url)});
                return !!tab && await chrome.action.getTitle({tabId:tab.id}) ===
                  'No single account matches this exact website. Check the accounts in Librarian.';
              })()`);
              check(denied,'Negative fixture did not reach the verified no-credential response');
            }
          }
          validateCaseObservation(await evaluate(observation),!!entry.expected);
        });
        return;
      }
      await verify('real installed chain fills the single exact-origin account without submission', async () => {
        await page(); await until(matches);
        check(await evaluate("JSON.stringify(fixtureApi.inputs) === '[\"user\",\"pass\"]' && JSON.stringify(fixtureApi.changes) === '[\"user\",\"pass\"]'"), 'Unexpected input/change events');
      });
      await verify('editing a filled password never automatically refills it', async () => {
        await evaluate("pass.value = ''; pass.dispatchEvent(new Event('input', {bubbles:true})); document.body.append(document.createElement('p'))");
        await delay(3400); check(await evaluate("pass.value === ''"), 'Edited password automatically refilled');
      });
      currentTest = 'real toolbar action explicitly fills again after an edit';
      if (await explicitFill()) await verify(currentTest, async () => {});
      await verify('default HTTPS port canonicalizes to the exact saved origin', async () => {
        await page(login, 'https://librarian.test:443'); await until(matches);
      });
      for (const [name, origin] of [['subdomain', 'https://sub.librarian.test'], ['different port', 'https://librarian.test:8443'],
        ['HTTP scheme', 'http://librarian.test'], ['ASCII lookalike', 'https://librar1an.test'],
        ['IDN lookalike', 'https://librari\u0430n.test']]) {
        await verify(`${name} receives no credential`, async () => { await page(login, origin); await noFill(); });
      }
      await verify('a dynamically added supported form fills once', async () => {
        await page('<main id="mount"></main>'); await delay(200);
        await evaluate(`mount.innerHTML = ${JSON.stringify(login)}`); await until(matches);
      });
      await verify('password-only current-password step fills', async () => {
        await page('<form action="/session"><input id="pass" type="password" autocomplete="current-password"></form>'); await until(matches);
      });
      for (const [name, html] of [
        ['new-password registration', login.replace('current-password', 'new-password')],
        ['ambiguous forms', login + login.replaceAll('id="user"', 'id="user2"').replaceAll('id="pass"', 'id="pass2"')],
        ['hidden password', login.replace('id="pass"', 'id="pass" hidden')],
        ['read-only password', login.replace('id="pass"', 'id="pass" readonly')],
        ['disabled form', `<fieldset disabled>${login}</fieldset>`],
        ['cross-origin action', login.replace('/session', 'https://other.test/session')],
        ['existing username', login.replace('id="user"', 'id="user" value="already-typed"')],
        ['username-only step', '<input id="user" autocomplete="username">'],
      ]) await verify(`${name} is not filled`, async () => { await page(html); await noFill(); });
      await verify('same-origin embedded frame is not filled', async () => {
        await page(`<iframe srcdoc="${login.replaceAll('"', '&quot;')}"></iframe>`);
        await delay(3400); check(await evaluate("frames[0].document.querySelectorAll('input').length === 2 && Array.from(frames[0].document.querySelectorAll('input')).every(e => e.value === '')"), 'Embedded frame fixture missing or filled');
      });
      await verify('shadow-DOM fields are not filled', async () => {
        await page('<div id="shadow"></div>'); await evaluate(`shadow.attachShadow({mode:'open'}).innerHTML = ${JSON.stringify(login)}`);
        await delay(3400); check(await evaluate("Array.from(shadow.shadowRoot.querySelectorAll('input')).every(e => e.value === '')"), 'Shadow fields were filled');
      });
      await verify('validation error does not cause an automatic refill', async () => {
        await page(); await until(matches);
        await evaluate("pass.value = ''; pass.setCustomValidity('fixture rejection'); pass.reportValidity(); document.body.append(document.createElement('p'))");
        await delay(3400); check(await evaluate("pass.value === ''"), 'Validation error caused automatic refill');
      });
      await verify('back navigation does not repeat automatic filling', async () => {
        const oldUrl = await page(login, config.account.origin, '/back-fixture'); await until(matches);
        await evaluate("pass.value = ''; pass.dispatchEvent(new Event('input', {bubbles:true}))");
        await page(login, config.account.origin, '/next-fixture'); await until(matches);
        const history = await cdp.call('Page.getNavigationHistory', {}, session);
        await cdp.call('Page.navigateToHistoryEntry', { entryId: history.entries[history.currentIndex - 1].id }, session);
        await until(`location.href === ${JSON.stringify(oldUrl)} && document.readyState === 'complete'`);
        await delay(3400); check(await evaluate("pass.value === ''"), 'Back navigation automatically refilled');
      });
      currentTest = 'real toolbar action fills after back navigation';
      if (await explicitFill()) await verify(currentTest, async () => {});
      if (config.labPackage) {
        await verify('lock wins while a browser fill is pending before native disclosure', async () => {
          const source = await readFile(join(config.extensionDirectory,'dist','background.js'),'utf8');
          const start = source.indexOf('function requestCredential(');
          const offset = source.indexOf('port = runtime.connectNative(NATIVE_HOST_NAME);',start);
          check(start >= 0 && offset > start, 'Production native-request breakpoint was not found');
          const lineNumber = source.slice(0,offset).split('\n').length - 1;
          await workerCdp.call('Debugger.enable');
          const breakpoint = await workerCdp.call('Debugger.setBreakpointByUrl', {
            url:`chrome-extension://${extensionId}/dist/background.js`,lineNumber});
          let paused = false, pauseTimer;
          const reached = new Promise((res, rej) => {
            pauseTimer = setTimeout(() => rej(new Error('Pending browser fill barrier was not reached')),4000);
            workerCdp.onEvent = message => {
              if (message.method === 'Debugger.paused') {paused=true;clearTimeout(pauseTimer);res();}
            };
          });
          void reached.catch(() => {});
          try {
            await page(); await reached;
            check(await evaluate(noSecrets), 'A credential was published before the pending-request barrier');
            await labOperation(config.labPackage,'--lock','Locked');
            report.lockOrdering = 'real browser fill paused at native-connect boundary; authenticated Lock acknowledged before resume';
          } finally {
            clearTimeout(pauseTimer);
            await workerCdp.call('Debugger.removeBreakpoint',{breakpointId:breakpoint.breakpointId});
            if(paused) await workerCdp.call('Debugger.resume');
            await workerCdp.call('Debugger.disable'); workerCdp.onEvent = () => {};
          }
          await noFill();
          const locked = await workerCdp.evaluate(`(async () => {
            const tab=(await chrome.tabs.query({})).find(t=>t.url?.startsWith('https://librarian.test/'));
            return !!tab && await chrome.action.getTitle({tabId:tab.id}) === 'Unlock Librarian in the desktop app, then click here to fill.';
          })()`);
          check(locked,'Pending fill did not terminate with the actual locked response');
          report.notRun = report.notRun.filter(item => item !== 'lock during in-flight requests');
        });
        await verify('unlock does not automatically retry the cancelled page fill', async () => {
          await labOperation(config.labPackage,'--unlock-fixture','Unlocked');
          await evaluate("document.body.append(document.createElement('p'))"); await noFill();
        });
        await verify('browser action explicitly fills again after authenticated unlock', async () => {await explicitFill();});
        await verify('worker termination preserves the document automatic-fill budget', async () => {
          await evaluate("pass.value = ''; pass.dispatchEvent(new Event('input', {bubbles:true})); fixtureApi.restartMarker = 'same-document'");
          const previous = workerTargetId;
          workerCdp.socket.close(); workerCdp = undefined;
          const stopped = await cdp.call('Target.closeTarget', {targetId:previous});
          check(stopped.success, 'Browser did not stop the extension worker');
          check(!(await cdp.call('Target.getTargets')).targetInfos.some(t => t.targetId === previous), 'Old worker target remains');
          await evaluate("document.body.append(document.createElement('p'))");
          await delay(3400);
          check(await evaluate("pass.value === '' && fixtureApi.restartMarker === 'same-document'"), 'Worker termination reset page or fill budget');
          report.workerTerminationObserved = true;
        });
        await verify('browser action starts a fresh worker and explicitly refills the same document', async () => {
          const previous = workerTargetId;
          await explicitFill();
          await connectWorker();
          check(workerTargetId !== previous && await evaluate("fixtureApi.restartMarker === 'same-document'"), 'Fresh worker or retained document not observed');
          report.notRun = report.notRun.filter(item => item !== 'worker restart');
        });
        await verify('credential-bearing origin embedded cross-origin receives no fill', async () => {
          const childUrl = 'https://librarian.test/embedded-negative';
          fixtures.set(childUrl, documentBody(login, 'embedded-negative'));
          await page(`<iframe src="${childUrl}"></iframe>`, 'https://other.librarian.test');
          let frame;
          for (let index = 0; index < 100; index++) {
            frame = (await cdp.call('Page.getFrameTree', {}, session)).frameTree.childFrames?.find(entry => entry.frame.url === childUrl)?.frame;
            if (frame) break;
            await delay(50);
          }
          check(frame, 'Cross-origin fixture frame did not load');
          const world = await cdp.call('Page.createIsolatedWorld', {frameId:frame.id, worldName:'librarian-fixture-observer'}, session);
          await delay(3400);
          const observed = await cdp.call('Runtime.evaluate', {contextId:world.executionContextId, returnByValue:true,
            expression:"document.readyState === 'complete' && location.origin === 'https://librarian.test' && document.querySelectorAll('input').length === 2 && Array.from(document.querySelectorAll('input')).every(e => e.value === '')"}, session);
          check(!observed.exceptionDetails && observed.result.value === true, 'Cross-origin fixture was missing or filled');
        });
        for (const scheme of ['data', 'blob', 'about']) {
          await verify(`${scheme} document refuses automatic and explicit credential filling`, async () => {
            await nonWebPage(scheme);
            await noFill();
            await cdp.call('Extensions.triggerAction', {id:extensionId,targetId:actionTargetId});
            await noFill();
          });
        }
      }
    };
    await Promise.race([suite(), new Promise((_, reject) => {
      outerTimer = setTimeout(() => reject(new Error('Browser fill batch exceeded its three-minute limit')), 180000);
    })]);
    check(interceptedDocuments > 0, 'No intercepted fixture documents were exercised');
    report.interceptedDocuments = interceptedDocuments;
    report.outcome = 'Passed';
  } catch (error) {
    // Errors only carry our fixed labels or CDP method names, never evaluated values.
    report.failure = error instanceof Error ? error.message : 'Fill test failed';
    report.failedTest = currentTest;
    report.waitStage = waitStage;
    report.interceptedDocuments = interceptedDocuments;
    report.eventErrors = eventErrors;
    report.pageExceptions = pageExceptions;
    if (cdp && session) {
      try {
        report.pageState = await cdp.evaluate(`(() => {
          const user = document.getElementById('user'), pass = document.getElementById('pass');
          return { ready: document.readyState, visible: document.visibilityState, secure: isSecureContext,
            expectedOrigin: location.origin === ${JSON.stringify(config.account.origin)},
            fixturePresent: !!document.querySelector('meta[name="fixture-id"]'), inputCount: document.querySelectorAll('input').length,
            usernameEmpty: user?.value === '', passwordEmpty: pass?.value === '',
            usernameMatches: user?.value === ${JSON.stringify(config.account.username)},
            passwordMatches: pass?.value === ${JSON.stringify(config.account.password)},
            passwordVisible: !!pass && pass.getClientRects().length > 0 && getComputedStyle(pass).visibility === 'visible',
            inputEvents: globalThis.fixtureApi?.inputs.length ?? 0, submissions: globalThis.fixtureApi?.submits ?? 0 };
        })()`, session);
      } catch { report.pageDiagnostics = 'Unavailable'; }
      if (workerCdp) {
        try {
          report.extensionState = await workerCdp.evaluate(`(async () => {
            const tabs = await chrome.tabs.query({});
            const tab = tabs.find(t => t.url?.startsWith('https://librarian.test/'));
            if (!tab) return { fixtureTabFound: false };
            const title = await chrome.action.getTitle({tabId:tab.id});
            const frame = await chrome.webNavigation.getFrame({tabId:tab.id,frameId:0});
            const titles = {
              'Librarian is connected and unlocked.':'connectedUnlocked',
              'Librarian supplied the saved account. Filling is skipped if the page or fields changed.':'credential',
              'No single account matches this exact website. Check the accounts in Librarian.':'noCredential',
              'No supported sign-in form is available on this page.':'noForm',
              'Unlock Librarian in the desktop app, then click here to fill.':'locked',
              'Librarian did not respond in time. Click here to try again.':'timedOut',
              'The Librarian app is unavailable. Install, start, or repair it.':'unavailable',
              'Update or repair Librarian and its browser extension together.':'incompatible',
              'Librarian could not verify the fill request. Repair Librarian.':'protocolError',
              'Librarian could not fill this account. Click here to try again.':'operationFailed'
            };
            return {fixtureTabFound:true, presentation:titles[title] ?? 'other',
              frameFound:!!frame, active:frame?.documentLifecycle === 'active',
              outermost:frame?.frameType === 'outermost_frame', parentIsNone:frame?.parentFrameId === -1,
              errorIsFalse:frame?.errorOccurred === false,
              canonicalDocumentId:typeof frame?.documentId === 'string' && /^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$/.test(frame.documentId),
              compactDocumentId:typeof frame?.documentId === 'string' && /^[0-9A-Fa-f]{32}$/.test(frame.documentId)};
          })()`);
        } catch { report.extensionDiagnostics = 'Unavailable'; }
      }
    }
  } finally {
    clearTimeout(outerTimer);
    workerCdp?.socket.close();
    if (cdp) {
      try { await cdp.call('Browser.close'); } catch { /* closing drops DevTools */ }
      cdp.socket.close();
    }
    if (child) {
      for (let i = 0; i < 50 && child.exitCode === null && child.signalCode === null; ++i) await delay(100);
      if (child.exitCode === null && child.signalCode === null) {
        child.kill(); report.outcome = 'Failed'; report.cleanup = 'Forced test-browser termination required';
      } else report.cleanup = 'Passed';
    }
    await stderr?.close();
    try {
      for (const path of [log, stderrPath]) {
        let info;
        try { info = await stat(path); } catch (error) { if (error.code === 'ENOENT') continue; throw error; }
        check(info.size <= 8 * 1024 * 1024, 'Browser diagnostic exceeds canary-scan limit');
        const text = await readFile(path, 'utf8');
        check(canariesFor('Extended').every(value => !text.includes(value)), 'Synthetic canary found in browser diagnostics');
      }
      report.logCanaryScan = 'Passed (bounded browser logs only)';
    } catch {
      report.outcome = 'Failed'; report.logCanaryScan = 'Failed; raw logs retained only inside the VM';
    }
    // Do not copy profiles or raw logs. They remain in this uniquely owned guest directory.
    await writeFile(config.reportPath, JSON.stringify(report, null, 2));
  }
  return report;
}

if (process.argv[2] === '--self-test') {
  const {runInNewContext} = await import('node:vm');
  const observe = async globals => JSON.parse(JSON.stringify(await runInNewContext(toolbarObservation, globals, {timeout:1000})));
  for (const globals of [{}, {chrome:{}}, {chrome:{runtime:{id:extensionId}}}]) {
    assert.deepEqual(await observe(globals), {ready:false});
  }
  let reads = 0;
  const api = {runtime:{id:extensionId,connectNative(){throw new Error('Observer must not make a native request');}},
    action:{async getBadgeText(){reads++;return 'ON';},async getTitle(){reads++;return 'Librarian is connected and unlocked.';}},
    permissions:{async contains(query){reads++;assert.equal(JSON.stringify(query),'{"origins":["https://*/*"]}');return true;}}};
  assert.deepEqual(await observe({chrome:api}), {ready:true,id:extensionId,badge:'ON',title:'Librarian is connected and unlocked.',permitted:true});
  assert.equal(reads,3);
  api.action.getBadgeText = async () => {throw new Error('API rejection');};
  await assert.rejects(observe({chrome:api}), /API rejection/);
  console.log('PASS toolbar observer waits for APIs, only reads status, and preserves API failures');
  fixtures.set('https://librarian.test/check', documentBody(login, '1'));
  assert.equal(route({ method: 'GET', url: 'https://librarian.test/check' }).body.includes('fixture-id'), true);
  for (const request of [{ method: 'POST', url: 'https://librarian.test/check' },
    { method: 'GET', url: 'https://example.com' }, { method: 'GET', url: 'https://librarian.test/unknown' }]) assert.deepEqual(route(request), { blocked: true });
  assert.equal(documentBody(login, '1').includes('Issue17-Test-Only!2026'), false);
  console.log('PASS fixture routing never forwards requests or embeds credentials');
} else {
  const transportOnly = process.argv[2] === '--transport-self-test';
  const contextOnly = process.argv[2] === '--context-self-test';
  const actionOnly = process.argv[2] === '--action-self-test';
  if (!transportOnly && !contextOnly && !actionOnly) check(hostname().toUpperCase() === 'LIBRARIAN-TEST' && process.platform === 'win32', 'Installed fill probe is restricted to the disposable Home VM');
  const config = JSON.parse((await readFile(resolve(process.argv[transportOnly || contextOnly || actionOnly ? 3 : 2]), 'utf8')).replace(/^\uFEFF/, ''));
  if (config.labPackage) {
    check(/^Librarian\.I17\.R[0-9a-f]{24}$/.test(config.labPackage), 'Invalid isolated lab package identity');
    check(resolve(config.extensionDirectory).startsWith(`C:\\LibrarianTest\\authlab-${config.labPackage}\\`), 'Lab extension must stay inside its isolated staging tree');
    check(resolve(config.outputDirectory).startsWith(`C:\\LibrarianTest\\authlab-${config.labPackage}\\`), 'Lab reports must stay inside their isolated staging tree');
  }
  if (contextOnly) {
    const manifest = JSON.parse(await readFile(join(config.extensionDirectory, 'manifest.json'), 'utf8'));
    check(JSON.stringify(manifest.permissions) === '["webNavigation"]' && manifest.name === 'Librarian context-only test', 'Context self-test must have no native-messaging permission');
  }
  if (actionOnly) {
    const manifest=JSON.parse(await readFile(join(config.extensionDirectory,'manifest.json'),'utf8'));
    check(JSON.stringify(manifest.permissions)==='[]' && manifest.name==='Librarian action-only test', 'Action transport self-test must have no native permission');
  }
  check(['edge', 'chrome'].includes(config.browser) && basename(config.reportPath) === `fill-${config.browser}.json`, 'Unexpected report identity');
  check(resolve(config.reportPath) === join(resolve(config.outputDirectory), `fill-${config.browser}.json`), 'Report must stay within the test output directory');
  validateFixtureAccounts(config.account,config.additionalAccounts,config.batch ?? 'Initial');
  const report = await probe(config, transportOnly, contextOnly, actionOnly);
  console.log(`${report.outcome}: ${report.purpose}`);
  process.exitCode = report.outcome === 'Passed' ? 0 : 1;
}

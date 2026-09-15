// Host-side routing test: no extension, native host, vault, or live websites.
import {mkdtemp,writeFile,readFile,mkdir} from 'node:fs/promises';
import {spawn} from 'node:child_process';
import {resolve,join} from 'node:path';
import assert from 'node:assert/strict';
import {initialAccount,extraAccounts,extendedCases} from './.codex-issue17-extended-cases.mjs';

const root = await mkdtemp(resolve('artifacts/extended-transport-'));
await Promise.all([
  ['edge','C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe'],
  ['chrome','C:/Program Files/Google/Chrome/Application/chrome.exe'],
].map(async ([browser,executable]) => {
  for(const batch of ['Initial','Extended']) {
  const outputDirectory = join(root,browser+'-'+batch); await mkdir(outputDirectory);
  const config = {browser,executable,batch,account:initialAccount,additionalAccounts:batch === 'Extended' ? extraAccounts : [],
    outputDirectory,reportPath:join(outputDirectory,`fill-${browser}.json`)};
  const configPath = join(outputDirectory,'config.json'); await writeFile(configPath,JSON.stringify(config));
  const process = spawn(globalThis.process.execPath,['.codex-issue17-fill-probe.mjs','--transport-self-test',configPath],
    {windowsHide:true,stdio:['ignore','ignore','inherit']});
  const code = await new Promise((res,rej) => {process.on('error',rej);process.on('exit',res);});
  const report = JSON.parse(await readFile(config.reportPath,'utf8'));
  console.log(JSON.stringify({browser:report.browser,outcome:report.outcome,tests:report.tests.length,
    purpose:report.purpose,cleanup:report.cleanup,failure:report.failure,reportPath:config.reportPath}));
  assert.equal(code,0); assert.equal(report.outcome,'Passed'); assert.equal(report.tests.length,batch === 'Extended' ? extendedCases.length : 5);
  assert.equal(report.interceptedDocuments,batch === 'Extended' ? extendedCases.length : 3);
  assert.equal(report.networkForwarded,false); assert.equal(report.unexpectedRequests,0);
  assert.equal(report.logCanaryScan,'Passed (bounded browser logs only)'); assert.equal(report.cleanup,'Passed');
  if(batch === 'Extended') assert.ok(report.tests.every(t => t.name.startsWith('transport only: ')));
  }
}));

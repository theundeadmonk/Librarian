// Disposable browser-API probe. No native messaging permission or vault access.
import {mkdtemp,mkdir,readFile,writeFile} from 'node:fs/promises';
import {spawn} from 'node:child_process';
import {resolve,join} from 'node:path';
import assert from 'node:assert/strict';
import {initialAccount} from './.codex-issue17-extended-cases.mjs';

const root=await mkdtemp(resolve('artifacts/action-transport-'));
const extension=join(root,'extension');
await mkdir(join(extension,'dist'),{recursive:true});
const product=JSON.parse(await readFile('apps/browser-extension/manifest.json','utf8'));
await writeFile(join(extension,'manifest.json'),JSON.stringify({manifest_version:3,
  name:'Librarian action-only test',version:'1.0.0',key:product.key,permissions:[],action:{},
  background:{service_worker:'dist/background.js'}}));
await writeFile(join(extension,'dist/background.js'),
  'globalThis.actionCount=0;chrome.action.onClicked.addListener(()=>{globalThis.actionCount++;});');
for(const [browser,executable] of [
  ['chrome','C:/Program Files/Google/Chrome/Application/chrome.exe'],
  ['edge','C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe']]) {
  const outputDirectory=join(root,browser);await mkdir(outputDirectory);
  const reportPath=join(outputDirectory,`fill-${browser}.json`);
  const configPath=join(outputDirectory,'config.json');
  await writeFile(configPath,JSON.stringify({browser,executable,extensionDirectory:extension,
    outputDirectory,reportPath,account:initialAccount}));
  const child=spawn(process.execPath,['.codex-issue17-fill-probe.mjs','--action-self-test',configPath],
    {windowsHide:true,stdio:['ignore','pipe','pipe']});
  // Child reports are bounded and sanitized; no raw diagnostics are printed.
  let diagnosticBytes=0;
  for(const stream of [child.stdout,child.stderr]) stream.on('data',chunk=>{
    diagnosticBytes+=chunk.length;if(diagnosticBytes>131072)child.kill();
  });
  const code=await new Promise((res,rej)=>{child.on('close',res);child.on('error',rej);});
  const report=JSON.parse(await readFile(reportPath,'utf8'));
  console.log(JSON.stringify({browser:report.browser,outcome:report.outcome,tests:report.tests.length,
    failure:report.failure,stage:report.waitStage,cleanup:report.cleanup,reportPath}));
  assert.equal(code,0);assert.equal(report.outcome,'Passed');
}

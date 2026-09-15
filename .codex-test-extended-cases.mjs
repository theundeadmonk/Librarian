import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {initialAccount,extraAccounts,extendedCases,validateFixtureAccounts,canariesFor,validateCaseObservation} from './.codex-issue17-extended-cases.mjs';

const fixture = JSON.parse(await readFile(new URL('./.codex-issue17-fill-fixtures.json',import.meta.url),'utf8'));
validateFixtureAccounts(fixture.accounts[0],undefined,'Initial');
validateFixtureAccounts(fixture.accounts[0],fixture.extended.accounts,'Extended');
assert.deepEqual(fixture.extended.requiredTests,extendedCases.map(c => c.name));
assert.equal(new Set(extendedCases.map(c => c.name)).size,15);
assert.equal(extendedCases.filter(c => c.expected).length,5);
assert.equal(new URL(extraAccounts[1].origin).origin,'https://xn--bcher-kva.librarian.test');
const accounts = [initialAccount,...extraAccounts];
const compiledFixtureRows = (await readFile(new URL('./tests/fixtures/issue17-accounts.tsv',import.meta.url),'utf8'))
  .split(/\r?\n/).filter(line => line && !line.startsWith('#'))
  .map(line => {
    const fields = line.split('\t');
    assert.equal(fields.length,4,'Compiled fixture must contain exactly four fields');
    const [serviceName,origin,username,password] = fields;
    return {serviceName,origin,username,password};
  });
assert.deepEqual(compiledFixtureRows,accounts,'Automatic and installed test-account fixtures must agree');
for (const entry of extendedCases) {
  const origin = new URL(entry.origin).origin;
  assert.ok(new URL(origin).hostname.endsWith('.librarian.test') || origin === initialAccount.origin);
  const matches = accounts.filter(a => new URL(a.origin).origin === origin && origin.startsWith('https:'));
  assert.equal(matches.length === 1,!!entry.expected,entry.name);
  if (entry.expected) assert.deepEqual(matches[0],entry.expected);
}
for (const additional of [[],extraAccounts.slice(1),[...extraAccounts,extraAccounts[0]],
  extraAccounts.map((a,i) => i === 0 ? {...a,origin:'https://example.com'} : a),
  extraAccounts.map((a,i) => i === 0 ? {...a,password:'not-an-allowed-canary'} : a)]) {
  assert.throws(() => validateFixtureAccounts(initialAccount,additional,'Extended'));
}
assert.throws(() => validateFixtureAccounts(initialAccount,undefined,'typo'));
assert.throws(() => validateFixtureAccounts({...initialAccount,origin:'https://example.com'},undefined,'Initial'));
assert.equal(canariesFor('Extended').length,10);
assert.equal(new Set(canariesFor('Extended')).size,10);
const positive = {inputCount:2,submissions:0,usernameMatches:true,passwordMatches:true,inputs:['user','pass'],changes:['user','pass']};
const negative = {inputCount:2,submissions:0,allEmpty:true,anyCanary:false,inputs:[],changes:[]};
validateCaseObservation(positive,true); validateCaseObservation(negative,false);
for (const [field,value] of [['inputCount',0],['submissions',1],['usernameMatches',false],['passwordMatches',false],['inputs',[]],['changes',[]]]) {
  assert.throws(() => validateCaseObservation({...positive,[field]:value},true));
}
for (const [field,value] of [['inputCount',0],['submissions',1],['allEmpty',false],['anyCanary',true],['inputs',['pass']],['changes',['pass']]]) {
  assert.throws(() => validateCaseObservation({...negative,[field]:value},false));
}
console.log('PASS: all 15 origin cases, exact synthetic fixture allowlist, IDN/port canonicalization, and fail-closed DOM evidence');

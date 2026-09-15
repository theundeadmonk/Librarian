// Local acceptance fixtures only. Never imported by production code.
import assert from 'node:assert/strict';

export const initialAccount = Object.freeze({
  serviceName: 'Issue 17 test', origin: 'https://librarian.test',
  username: 'issue17-test-user', password: 'Issue17-Test-Only!2026',
});
export const extraAccounts = Object.freeze([
  {serviceName:'Issue 17 port', origin:'https://ports.librarian.test:8443', username:'issue17-port-user', password:'Issue17-Port-Only!2026'},
  {serviceName:'Issue 17 IDN', origin:'https://b\u00fccher.librarian.test', username:'issue17-idn-user', password:'Issue17-IDN-Only!2026'},
  {serviceName:'Issue 17 duplicate A', origin:'https://duplicates.librarian.test', username:'issue17-duplicate-a', password:'Issue17-Duplicate-A!2026'},
  {serviceName:'Issue 17 duplicate B', origin:'https://duplicates.librarian.test', username:'issue17-duplicate-b', password:'Issue17-Duplicate-B!2026'},
].map(Object.freeze));
const [port, idn] = extraAccounts;
export const extendedCases = Object.freeze([
  {name:'baseline single account still fills', origin:initialAccount.origin, expected:initialAccount},
  {name:'exact non-default HTTPS port fills its own account', origin:port.origin, expected:port},
  {name:'zero-padded matching port canonicalizes', origin:'https://ports.librarian.test:08443', expected:port},
  {name:'omitted port does not match the saved non-default port', origin:'https://ports.librarian.test'},
  {name:'explicit default port does not match the saved non-default port', origin:'https://ports.librarian.test:443'},
  {name:'different non-default port receives no credential', origin:'https://ports.librarian.test:8444'},
  {name:'HTTP with the saved numeric port receives no credential', origin:'http://ports.librarian.test:8443'},
  {name:'Unicode IDN fills its own account', origin:idn.origin, expected:idn},
  {name:'punycode spelling fills the same IDN account', origin:'https://xn--bcher-kva.librarian.test', expected:idn},
  {name:'ASCII lookalike of the IDN receives no credential', origin:'https://bucher.librarian.test'},
  {name:'IDN subdomain receives no credential', origin:'https://sub.xn--bcher-kva.librarian.test'},
  {name:'IDN at a different port receives no credential', origin:'https://xn--bcher-kva.librarian.test:8443'},
  {name:'two accounts at the exact origin cause no fill', origin:'https://duplicates.librarian.test'},
  {name:'another path cannot select one of two matching accounts', origin:'https://duplicates.librarian.test', path:'/another-login'},
  {name:'duplicate-account origin at a different port receives no credential', origin:'https://duplicates.librarian.test:8443'},
].map(Object.freeze));

export function validateFixtureAccounts(account, additionalAccounts, batch) {
  assert.ok(batch === 'Initial' || batch === 'Extended', 'Unknown fill batch');
  // Exact synthetic allowlist; never accept arbitrary user-supplied vault values.
  for (const field of ['origin','username','password']) assert.equal(account?.[field], initialAccount[field], 'Unexpected initial fixture');
  if (batch === 'Extended') assert.deepEqual(additionalAccounts, extraAccounts, 'Unexpected extended fixtures');
  else assert.ok(additionalAccounts === undefined || additionalAccounts.length === 0, 'Unexpected additional fixtures');
}

export function canariesFor(batch) {
  return [initialAccount, ...(batch === 'Extended' ? extraAccounts : [])].flatMap(a => [a.username,a.password]);
}

// Only booleans and event IDs/counts cross back from the fixture DOM.
export function validateCaseObservation(observation, positive) {
  assert.equal(observation.inputCount, 2, 'Fixture inputs are missing');
  assert.equal(observation.submissions, 0, 'A form was submitted');
  if (positive) {
    assert.equal(observation.usernameMatches, true, 'Wrong username');
    assert.equal(observation.passwordMatches, true, 'Wrong password');
    assert.deepEqual(observation.inputs, ['user','pass'], 'Unexpected input events');
    assert.deepEqual(observation.changes, ['user','pass'], 'Unexpected change events');
  } else {
    assert.equal(observation.allEmpty, true, 'Unexpected field values');
    assert.equal(observation.anyCanary, false, 'Credential disclosed to a negative fixture');
    assert.deepEqual(observation.inputs, [], 'Unexpected input events');
    assert.deepEqual(observation.changes, [], 'Unexpected change events');
  }
}

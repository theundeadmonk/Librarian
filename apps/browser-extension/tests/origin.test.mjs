import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

import {
  MAX_BROWSER_URL_BYTES,
  MAX_ORIGIN_BYTES,
  exactHttpsOriginMatch,
  originFromBrowserUrl,
  parseHttpsOrigin,
} from "../dist/origin.js";

const corpus = readFileSync(
  new URL("../../../tests/fixtures/browser-origin-policy.tsv", import.meta.url),
  "utf8",
);

for (const line of corpus.trimEnd().split(/\r?\n/u)) {
  if (line.startsWith("#")) continue;
  const fields = line.split("\t");
  assert.equal(fields.length, 3, "invalid fixture row");
  const [label, input, expected] = fields;
  test(`shared canonical origin: ${label}`, () => {
    assert.equal(parseHttpsOrigin(input), expected === "-" ? null : expected);
  });
}

test("normalizes browser URLs before comparison, dropping path/query/fragment", () => {
  for (const url of [
    "https://example.com",
    "HTTPS://EXAMPLE.COM:443/login?next=%2Fhome#sign-in",
    "https://example.com/path?origin=https://evil.test",
  ]) {
    assert.equal(originFromBrowserUrl(url), "https://example.com");
  }
  assert.equal(originFromBrowserUrl("https://bücher.example/login"),
    "https://xn--bcher-kva.example");
  assert.equal(originFromBrowserUrl("https://[0:0:0:0:0:0:0:1]/login"),
    "https://[::1]");
});

test("does not repair malformed or credential-bearing browser URL claims", () => {
  for (const url of [
    "https:example.com", "https:/example.com", "https:\\example.com",
    "https://example.com\\@evil.test", " https://example.com",
    "https://exam\nple.com", "https://exam\tple.com", "https://example.com\0",
    "https://example.com/raw space", "https://user:password@example.com",
    "https://@example.com", "https://example.com@evil.test", "https://",
    "http://example.com", "http://localhost", "blob:https://example.com/id",
    "about:blank", "data:text/html,hello", "file:///example.com",
    "//example.com", undefined, null, {}, [], 1,
  ]) {
    assert.equal(originFromBrowserUrl(url), null);
  }
});

test("rejects non-string, control-containing, and oversized origin values", () => {
  for (const value of [undefined, null, {}, [], 1, "https://exam\nple.com",
    "https://exam\tple.com", "https://example.com\0",
    `https://${"a".repeat(MAX_ORIGIN_BYTES)}.example`]) {
    assert.equal(parseHttpsOrigin(value), null);
  }
  assert.equal(originFromBrowserUrl(
    `https://example.com/${"a".repeat(MAX_BROWSER_URL_BYTES)}`), null);
  assert.equal(originFromBrowserUrl(
    `https://example.com/${"é".repeat(MAX_BROWSER_URL_BYTES / 2)}`), null);
});

test("exact matching never widens to subdomains, lookalikes, schemes, or ports", () => {
  const origin = "https://example.com";
  for (const other of [
    "https://login.example.com", "https://example.com.evil.test",
    "https://examp1e.com", "https://example.com.", "http://example.com",
    "https://example.com:8443", "https://example.com:80",
    // Cyrillic a has a different ASCII origin, despite visual resemblance.
    originFromBrowserUrl("https://exаmple.com"),
    null, undefined,
  ]) {
    assert.equal(exactHttpsOriginMatch(origin, other), false);
    assert.equal(exactHttpsOriginMatch(other, origin), false);
  }
  assert.equal(exactHttpsOriginMatch(origin, origin), true);
  assert.equal(exactHttpsOriginMatch(null, null), false);
  assert.equal(exactHttpsOriginMatch("http://example.com", "http://example.com"), false);
  assert.equal(exactHttpsOriginMatch(origin,
    originFromBrowserUrl("HTTPS://EXAMPLE.COM:443/login")), true);
});

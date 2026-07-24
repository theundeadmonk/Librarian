import assert from "node:assert/strict";
import { test } from "node:test";

import {
  compareInventories,
  decodeInventory,
  encodeInventory,
  parseTestList,
} from "./rust-test-parity.mjs";

const emptyPolicy = {
  version: 1,
  platformOnlyTests: [],
};

test("parseTestList qualifies tests and ignores the harness summary", () => {
  assert.deepEqual(
    parseTestList(
      "librarian-example",
      [
        "tests::alpha: test",
        "tests::manual_benchmark: benchmark",
        "",
        "1 test, 1 benchmark",
        "",
      ].join("\n"),
    ),
    [
      "librarian-example::tests::alpha",
      "librarian-example::tests::manual_benchmark",
    ],
  );
});

test("parseTestList rejects output it cannot classify", () => {
  assert.throws(
    () => parseTestList("librarian-example", "unrecognized output"),
    /Unexpected cargo test-list output/u,
  );
});

test("identical inventories pass with no platform exceptions", () => {
  assert.deepEqual(
    compareInventories(
      ["crate::alpha", "crate::beta"],
      ["crate::beta", "crate::alpha"],
      emptyPolicy,
    ),
    {
      linuxOnly: 0,
      shared: 2,
      windowsOnly: 0,
    },
  );
});

test("documented platform-only tests pass", () => {
  const policy = {
    version: 1,
    platformOnlyTests: [
      {
        platform: "windows",
        test: "crate::windows_acl",
        rationale: "Exercises Windows access-control semantics.",
      },
      {
        platform: "linux",
        test: "crate::unix_mode",
        rationale: "Exercises Unix permission-bit semantics.",
      },
    ],
  };

  assert.deepEqual(
    compareInventories(
      ["crate::shared", "crate::windows_acl"],
      ["crate::shared", "crate::unix_mode"],
      policy,
    ),
    {
      linuxOnly: 1,
      shared: 1,
      windowsOnly: 1,
    },
  );
});

test("an undocumented Linux-only test fails as a Windows parity gap", () => {
  assert.throws(
    () =>
      compareInventories(
        ["crate::shared"],
        ["crate::shared", "crate::missing_on_windows"],
        emptyPolicy,
      ),
    /Tests unexpectedly run only on Linux:[\s\S]*crate::missing_on_windows/u,
  );
});

test("an undocumented Windows-only test fails as a Linux parity gap", () => {
  assert.throws(
    () =>
      compareInventories(
        ["crate::shared", "crate::missing_on_linux"],
        ["crate::shared"],
        emptyPolicy,
      ),
    /Tests unexpectedly run only on Windows:[\s\S]*crate::missing_on_linux/u,
  );
});

test("a stale policy entry fails when a platform test disappears", () => {
  const policy = {
    version: 1,
    platformOnlyTests: [
      {
        platform: "windows",
        test: "crate::removed_windows_test",
        rationale: "Protects a required Windows-only behavior.",
      },
    ],
  };

  assert.throws(
    () =>
      compareInventories(["crate::shared"], ["crate::shared"], policy),
    /Windows-only policy entries no longer match/u,
  );
});

test("a stale policy entry fails when a platform test becomes portable", () => {
  const policy = {
    version: 1,
    platformOnlyTests: [
      {
        platform: "windows",
        test: "crate::now_portable",
        rationale: "Previously protected a Windows-only behavior.",
      },
    ],
  };

  assert.throws(
    () =>
      compareInventories(
        ["crate::shared", "crate::now_portable"],
        ["crate::shared", "crate::now_portable"],
        policy,
      ),
    /Windows-only policy entries no longer match/u,
  );
});

test("policy entries require a meaningful rationale", () => {
  const policy = {
    version: 1,
    platformOnlyTests: [
      {
        platform: "windows",
        test: "crate::windows_only",
        rationale: "Windows.",
      },
    ],
  };

  assert.throws(
    () =>
      compareInventories(
        ["crate::shared", "crate::windows_only"],
        ["crate::shared"],
        policy,
      ),
    /rationale must explain the platform difference/u,
  );
});

test("inventory encoding is deterministic and round-trips", () => {
  const encoded = encodeInventory(["crate::beta", "crate::alpha"]);

  assert.equal(
    encoded,
    encodeInventory(["crate::alpha", "crate::beta"]),
  );
  assert.deepEqual(decodeInventory(encoded), [
    "crate::alpha",
    "crate::beta",
  ]);
});

test("inventory decoding rejects malformed base64", () => {
  assert.throws(() => decodeInventory("not base64!"), /canonical base64/u);
});

test("inventory decoding rejects non-canonical padding bits", () => {
  assert.throws(() => decodeInventory("AB=="), /canonical base64/u);
});

import assert from "node:assert/strict";
import path from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";

import {
  buildMetadataArguments,
  buildWorkspaceDoctestArguments,
  buildWorkspaceTestArguments,
  collectInventory,
  compareInventories,
  decodeInventory,
  describeCargoTargets,
  encodeInventory,
  parseCompilerArtifacts,
  parseTestList,
  parseWorkspaceDoctestList,
} from "./rust-test-parity.mjs";

const testDirectory = path.dirname(fileURLToPath(import.meta.url));
const featureWorkspace = path.resolve(
  testDirectory,
  "..",
  "tests",
  "fixtures",
  "rust-test-parity",
  "feature-workspace",
);
const featureWorkspacePolicy = path.join(featureWorkspace, "policy.json");
const inactiveHarnessPolicy = path.join(
  featureWorkspace,
  "inactive-harness-policy.json",
);
const emptyPolicy = {
  version: 1,
  platformOnlyTests: [],
};

test("parseTestList preserves target, type, and ignored status", () => {
  assert.deepEqual(
    parseTestList(
      "librarian-example::lib:librarian_example",
      [
        "tests::alpha: test",
        "tests::manual_benchmark: benchmark",
        "",
        "1 test, 1 benchmark",
        "",
      ].join("\n"),
      "tests::manual_benchmark: benchmark\n",
    ),
    [
      "librarian-example::lib:librarian_example::tests::alpha::test:active",
      "librarian-example::lib:librarian_example::tests::manual_benchmark::benchmark:ignored",
    ],
  );
});

test("parseTestList rejects output it cannot classify", () => {
  assert.throws(
    () => parseTestList("librarian-example", "unrecognized output"),
    /Unexpected librarian-example test-list output/u,
  );
});

test("parseTestList rejects ignored tests absent from the complete list", () => {
  assert.throws(
    () =>
      parseTestList(
        "librarian-example::lib:librarian_example",
        "tests::active: test\n",
        "tests::missing: test\n",
      ),
    /ignored-test-list contains a test absent from the complete list/u,
  );
});

test("the same test name remains distinct across Cargo targets", () => {
  const libraryTests = parseTestList(
    "librarian-example::lib:librarian_example",
    "tests::same_name: test\n",
  );
  const integrationTests = parseTestList(
    "librarian-example::test:lifecycle",
    "tests::same_name: test\n",
  );

  assert.notEqual(libraryTests[0], integrationTests[0]);
  assert.doesNotThrow(() =>
    encodeInventory([...libraryTests, ...integrationTests]),
  );
});

test("a doctest-enabled library produces distinct unit and doc targets", () => {
  assert.deepEqual(
    describeCargoTargets({
      doctest: true,
      kind: ["lib"],
      name: "librarian_example",
    }),
    [
      {
        identity: "lib:librarian_example",
        selection: ["--lib"],
      },
      {
        identity: "doc:librarian_example",
        selection: ["--doc"],
      },
    ],
  );
});

test("rustdoc timing summaries do not enter doctest inventories", () => {
  const allDoctests = [
    "src/lib.rs - add_one (line 3): test",
    "src/lib.rs - add_one (line 7): test",
    "all doctests ran in 0.18s; merged doctests compilation took 0.18s",
    "",
  ].join("\n");
  const ignoredDoctests = [
    "src/lib.rs - add_one (line 7): test",
    "all doctests ran in 0.10s; merged doctests compilation took 0.10s",
    "",
  ].join("\n");

  assert.deepEqual(
    parseTestList(
      "librarian-example::doc:librarian_example",
      allDoctests,
      ignoredDoctests,
    ),
    [
      "librarian-example::doc:librarian_example::src/lib.rs - add_one (line 3)::test:active",
      "librarian-example::doc:librarian_example::src/lib.rs - add_one (line 7)::test:ignored",
    ],
  );
});

test("doctest path separators normalize across Windows and Linux", () => {
  const targets = [
    {
      sourcePath: "crates/example/src/lib.rs",
      targetIdentity: "librarian-example::doc:librarian_example",
    },
  ];
  const windowsDoctests = parseWorkspaceDoctestList(
    targets,
    [
      "crates\\example\\src\\lib.rs - add_one (line 3): test",
      "all doctests ran in 0.18s; merged doctests compilation took 0.18s",
      "",
    ].join("\n"),
  );
  const linuxDoctests = parseWorkspaceDoctestList(
    targets,
    [
      "crates/example/src/lib.rs - add_one (line 3): test",
      "all doctests ran in 0.18s; merged doctests compilation took 0.18s",
      "",
    ].join("\n"),
  );

  assert.deepEqual(windowsDoctests, linuxDoctests);
});

test("compiler artifacts preserve package and target identities", () => {
  const messages = [
    {
      executable: "/workspace/target/example",
      package_id: "workspace-package",
      profile: { test: true },
      reason: "compiler-artifact",
      target: {
        kind: ["test"],
        name: "lifecycle",
        test: false,
      },
    },
    {
      executable: "/workspace/target/ordinary-binary",
      package_id: "workspace-package",
      profile: { test: false },
      reason: "compiler-artifact",
      target: {
        kind: ["bin"],
        name: "helper",
        test: true,
      },
    },
  ]
    .map((message) => JSON.stringify(message))
    .join("\n");

  assert.deepEqual(
    parseCompilerArtifacts(messages, [
      {
        id: "workspace-package",
        manifest_path: "/workspace/Cargo.toml",
        name: "librarian-example",
      },
    ]),
    [
      {
        executable: "/workspace/target/example",
        targetIdentity: "librarian-example::test:lifecycle",
        workingDirectory: "/workspace",
      },
    ],
  );
});

test("workspace compilation preserves the exact tested feature graph", () => {
  assert.deepEqual(
    buildWorkspaceTestArguments("x86_64-pc-windows-msvc"),
    [
      "test",
      "--workspace",
      "--all-targets",
      "--no-run",
      "--locked",
      "--message-format",
      "json-render-diagnostics",
      "--target",
      "x86_64-pc-windows-msvc",
    ],
  );
  assert.deepEqual(
    buildWorkspaceDoctestArguments("x86_64-pc-windows-msvc"),
    [
      "test",
      "--workspace",
      "--doc",
      "--locked",
      "--target",
      "x86_64-pc-windows-msvc",
    ],
  );
});

test("metadata receives the platform target exactly once", () => {
  assert.deepEqual(
    buildMetadataArguments("x86_64-pc-windows-msvc"),
    [
      "metadata",
      "--locked",
      "--no-deps",
      "--format-version",
      "1",
      "--filter-platform",
      "x86_64-pc-windows-msvc",
    ],
  );
});

test(
  "inventory preserves workspace dependency features and active targets",
  { timeout: 120_000 },
  () => {
    const inventory = collectInventory({
      cwd: featureWorkspace,
      policyPath: featureWorkspacePolicy,
    });
    assert.deepEqual(
      inventory.filter((entry) => !entry.includes("::doc:")),
      [
        "feature-observer::lib:feature_observer::tests::workspace_dependency_feature_is_unified::test:active",
        "feature-provider::example:gated::tests::resolved_feature_is_active::test:active",
      ],
    );
    const doctests = inventory.filter((entry) => entry.includes("::doc:"));
    assert.equal(doctests.length, 1);
    assert.match(
      doctests[0],
      /^feature-observer::doc:feature_observer::a\/src\/lib\.rs - workspace_feature_is_enabled \(line \d+\)::test:active$/u,
    );
  },
);

test(
  "inactive harness-free policy targets fail closed",
  { timeout: 120_000 },
  () => {
    assert.throws(
      () =>
        collectInventory({
          cwd: featureWorkspace,
          policyPath: inactiveHarnessPolicy,
        }),
      /Harness-free target policy entries do not match selected Cargo test artifacts/u,
    );
  },
);

test("bench metadata does not claim to expose the harness setting", () => {
  assert.deepEqual(
    describeCargoTargets({
      kind: ["bench"],
      name: "criterion",
      test: false,
    }),
    [
      {
        identity: "bench:criterion",
        selection: ["--bench", "criterion"],
      },
    ],
  );
});

test("harness-free target policy rejects duplicate identities", () => {
  assert.throws(
    () =>
      compareInventories(
        ["crate::shared"],
        ["crate::shared"],
        {
          harnessFreeTargets: [
            "crate::bench:criterion",
            "crate::bench:criterion",
          ],
          platformOnlyTests: [],
          version: 1,
        },
      ),
    /duplicate harness-free targets/u,
  );
});

test("active versus ignored status creates a parity difference", () => {
  const windowsTests = parseTestList(
    "librarian-example::lib:librarian_example",
    "tests::portable: test\n",
    "tests::portable: test\n",
  );
  const linuxTests = parseTestList(
    "librarian-example::lib:librarian_example",
    "tests::portable: test\n",
  );

  assert.throws(
    () => compareInventories(windowsTests, linuxTests, emptyPolicy),
    /unexpectedly run only on Windows[\s\S]*unexpectedly run only on Linux/u,
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

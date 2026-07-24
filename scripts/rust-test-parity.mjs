import { spawnSync } from "node:child_process";
import { appendFileSync, readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const scriptDirectory = path.dirname(fileURLToPath(import.meta.url));
const repositoryRoot = path.resolve(scriptDirectory, "..");
const defaultPolicyPath = path.join(
  repositoryRoot,
  "tests",
  "rust-test-parity.json",
);
const summaryPattern = /^\d+ tests?, \d+ benchmarks?$/;
const rustdocSummaryPattern =
  /^all doctests ran in \S+; merged doctests compilation took \S+$/;
const testPattern = /^(.*): (test|benchmark)$/;

function compareText(left, right) {
  if (left < right) {
    return -1;
  }

  if (left > right) {
    return 1;
  }

  return 0;
}

function requireNonEmptyString(value, label) {
  if (typeof value !== "string" || value.trim().length === 0) {
    throw new Error(`${label} must be a non-empty string.`);
  }

  return value.trim();
}

function normalizeInventory(inventory, label) {
  if (!Array.isArray(inventory)) {
    throw new Error(`${label} must be a JSON array.`);
  }

  const normalized = inventory.map((test, index) =>
    requireNonEmptyString(test, `${label}[${index}]`),
  );
  const unique = new Set(normalized);

  if (unique.size !== normalized.length) {
    throw new Error(`${label} contains duplicate test identifiers.`);
  }

  return [...unique].sort(compareText);
}

function parseHarnessList(output, label) {
  const tests = [];

  for (const rawLine of output.split(/\r?\n/u)) {
    const line = rawLine.trim();
    if (
      line.length === 0 ||
      summaryPattern.test(line) ||
      rustdocSummaryPattern.test(line)
    ) {
      continue;
    }

    const match = line.match(testPattern);
    if (match === null || match[1].length === 0) {
      throw new Error(`Unexpected ${label} output: ${line}`);
    }

    tests.push({
      name: match[1],
      type: match[2],
    });
  }

  const keys = tests.map((test) => `${test.name}\0${test.type}`);
  if (new Set(keys).size !== keys.length) {
    throw new Error(`${label} contains duplicate test identities.`);
  }

  return tests.sort((left, right) =>
    compareText(`${left.name}\0${left.type}`, `${right.name}\0${right.type}`),
  );
}

function normalizeHarnessTests(tests, targetIdentity, label) {
  const isDoctestTarget = targetIdentity.includes("::doc:");
  const normalized = tests.map((test) => ({
    ...test,
    name: isDoctestTarget ? test.name.replaceAll("\\", "/") : test.name,
  }));
  const keys = normalized.map((test) => `${test.name}\0${test.type}`);

  if (new Set(keys).size !== keys.length) {
    throw new Error(`${label} contains duplicate normalized test identities.`);
  }

  return normalized;
}

export function parseTestList(targetIdentity, output, ignoredOutput = "") {
  const qualifiedTarget = requireNonEmptyString(
    targetIdentity,
    "Cargo target identity",
  );
  const listedLabel = `${qualifiedTarget} test-list`;
  const ignoredLabel = `${qualifiedTarget} ignored-test-list`;
  const listedTests = normalizeHarnessTests(
    parseHarnessList(output, listedLabel),
    qualifiedTarget,
    listedLabel,
  );
  const ignoredTests = normalizeHarnessTests(
    parseHarnessList(ignoredOutput, ignoredLabel),
    qualifiedTarget,
    ignoredLabel,
  );
  const listedKeys = new Set(
    listedTests.map((test) => `${test.name}\0${test.type}`),
  );
  const ignoredKeys = new Set(
    ignoredTests.map((test) => `${test.name}\0${test.type}`),
  );

  for (const ignoredKey of ignoredKeys) {
    if (!listedKeys.has(ignoredKey)) {
      throw new Error(
        `${qualifiedTarget} ignored-test-list contains a test absent from the complete list.`,
      );
    }
  }

  return listedTests.map((test) => {
    const key = `${test.name}\0${test.type}`;
    const status = ignoredKeys.has(key) ? "ignored" : "active";
    return `${qualifiedTarget}::${test.name}::${test.type}:${status}`;
  });
}

function runProcess(executable, arguments_, { cwd, label = executable }) {
  const result = spawnSync(executable, arguments_, {
    cwd,
    encoding: "utf8",
    maxBuffer: 16 * 1024 * 1024,
    shell: false,
  });

  if (result.error !== undefined) {
    throw new Error(
      `Unable to run ${label} ${arguments_.join(" ")}: ${result.error.message}`,
    );
  }

  if (result.status !== 0) {
    const details = [result.stdout, result.stderr]
      .map((value) => value.trim())
      .filter((value) => value.length > 0)
      .join("\n");
    throw new Error(
      `${label} ${arguments_.join(" ")} failed with exit code ${result.status}.` +
        (details.length === 0 ? "" : `\n${details}`),
    );
  }

  return result.stdout;
}

function runCargo(arguments_, { cargo, cwd }) {
  return runProcess(cargo, arguments_, { cwd });
}

export function describeCargoTargets(target) {
  const name = requireNonEmptyString(target.name, "Cargo target name");
  if (!Array.isArray(target.kind) || target.kind.length === 0) {
    throw new Error(`Cargo target ${name} has no target kind.`);
  }

  const kinds = new Set(target.kind);
  if (kinds.has("custom-build")) {
    return [];
  }

  const libraryKinds = [
    "cdylib",
    "dylib",
    "lib",
    "proc-macro",
    "rlib",
    "staticlib",
  ];
  const selections = [
    {
      matches: libraryKinds.some((kind) => kinds.has(kind)),
      identity: `lib:${name}`,
      selection: ["--lib"],
    },
    {
      matches: kinds.has("bin"),
      identity: `bin:${name}`,
      selection: ["--bin", name],
    },
    {
      matches: kinds.has("test"),
      identity: `test:${name}`,
      selection: ["--test", name],
    },
    {
      matches: kinds.has("example"),
      identity: `example:${name}`,
      selection: ["--example", name],
    },
    {
      matches: kinds.has("bench"),
      identity: `bench:${name}`,
      selection: ["--bench", name],
    },
  ].filter((selection) => selection.matches);

  if (selections.length !== 1) {
    throw new Error(
      `Cargo target ${name} has unsupported or ambiguous kinds: ${target.kind.join(", ")}`,
    );
  }

  const [{ identity, selection }] = selections;
  const targets = [{ identity, selection }];

  if (identity.startsWith("lib:") && target.doctest === true) {
    targets.push({
      identity: `doc:${name}`,
      selection: ["--doc"],
    });
  }

  return targets;
}

export function buildMetadataArguments(rustTarget) {
  const arguments_ = [
    "metadata",
    "--locked",
    "--no-deps",
    "--format-version",
    "1",
  ];

  if (rustTarget !== undefined) {
    arguments_.push(
      "--filter-platform",
      requireNonEmptyString(rustTarget, "Rust target"),
    );
  }

  return arguments_;
}

export function buildWorkspaceTestArguments(rustTarget) {
  const arguments_ = [
    "test",
    "--workspace",
    "--all-targets",
    "--no-run",
    "--locked",
    "--message-format",
    "json-render-diagnostics",
  ];

  if (rustTarget !== undefined) {
    arguments_.push(
      "--target",
      requireNonEmptyString(rustTarget, "Rust target"),
    );
  }

  return arguments_;
}

export function buildWorkspaceDoctestArguments(rustTarget) {
  const arguments_ = [
    "test",
    "--workspace",
    "--doc",
    "--locked",
  ];

  if (rustTarget !== undefined) {
    arguments_.push(
      "--target",
      requireNonEmptyString(rustTarget, "Rust target"),
    );
  }

  return arguments_;
}

export function parseCompilerArtifacts(output, workspacePackages) {
  if (!Array.isArray(workspacePackages)) {
    throw new Error("Workspace packages must be an array.");
  }

  const packagesById = new Map(
    workspacePackages.map((package_) => [
      requireNonEmptyString(package_.id, "Cargo package ID"),
      {
        name: requireNonEmptyString(package_.name, "Cargo package name"),
        workingDirectory: path.dirname(
          requireNonEmptyString(
            package_.manifest_path,
            "Cargo package manifest path",
          ),
        ),
      },
    ]),
  );
  const artifacts = new Map();

  for (const rawLine of output.split(/\r?\n/u)) {
    const line = rawLine.trim();
    if (line.length === 0) {
      continue;
    }

    let message;
    try {
      message = JSON.parse(line);
    } catch (error) {
      throw new Error(`Cargo emitted invalid JSON: ${error.message}`);
    }

    const package_ = packagesById.get(message.package_id);
    if (
      message.reason !== "compiler-artifact" ||
      package_ === undefined ||
      message.executable === null ||
      message.executable === undefined ||
      message.profile?.test !== true
    ) {
      continue;
    }

    const cargoTarget = describeCargoTargets(message.target).find(
      (target) => !target.identity.startsWith("doc:"),
    );
    if (cargoTarget === undefined) {
      throw new Error(
        `Cargo test artifact for ${package_.name} has no executable target identity.`,
      );
    }

    const targetIdentity = `${package_.name}::${cargoTarget.identity}`;
    const executable = requireNonEmptyString(
      message.executable,
      `${targetIdentity} executable`,
    );
    const existing = artifacts.get(targetIdentity);
    if (existing !== undefined && existing.executable !== executable) {
      throw new Error(
        `Cargo emitted multiple test executables for ${targetIdentity}.`,
      );
    }
    artifacts.set(targetIdentity, {
      executable,
      workingDirectory: package_.workingDirectory,
    });
  }

  return [...artifacts]
    .map(([targetIdentity, artifact]) => ({
      ...artifact,
      targetIdentity,
    }))
    .sort((left, right) =>
      compareText(left.targetIdentity, right.targetIdentity),
    );
}

function parseDoctestHarness(output, label) {
  return normalizeHarnessTests(
    parseHarnessList(output, label),
    "workspace::doc:workspace",
    label,
  );
}

export function parseWorkspaceDoctestList(
  docTargets,
  output,
  ignoredOutput = "",
) {
  if (!Array.isArray(docTargets)) {
    throw new Error("Documentation targets must be an array.");
  }

  const normalizedTargets = docTargets.map((target, index) => ({
    sourcePath: requireNonEmptyString(
      target.sourcePath,
      `Documentation target ${index} source path`,
    ).replaceAll("\\", "/"),
    targetIdentity: requireNonEmptyString(
      target.targetIdentity,
      `Documentation target ${index} identity`,
    ),
  }));
  const sourcePaths = normalizedTargets.map((target) => target.sourcePath);
  if (new Set(sourcePaths).size !== sourcePaths.length) {
    throw new Error("Documentation targets contain duplicate source paths.");
  }

  const listedTests = parseDoctestHarness(
    output,
    "workspace documentation test-list",
  );
  const ignoredTests = parseDoctestHarness(
    ignoredOutput,
    "workspace documentation ignored-test-list",
  );
  const listedKeys = new Set(
    listedTests.map((test) => `${test.name}\0${test.type}`),
  );
  const ignoredKeys = new Set(
    ignoredTests.map((test) => `${test.name}\0${test.type}`),
  );

  for (const ignoredKey of ignoredKeys) {
    if (!listedKeys.has(ignoredKey)) {
      throw new Error(
        "Workspace documentation ignored-test-list contains a test absent from the complete list.",
      );
    }
  }

  return listedTests.map((test) => {
    const matches = normalizedTargets.filter((target) =>
      test.name.startsWith(`${target.sourcePath} - `),
    );
    if (matches.length !== 1) {
      throw new Error(
        `Unable to map documentation test to one Cargo target: ${test.name}`,
      );
    }

    const key = `${test.name}\0${test.type}`;
    const status = ignoredKeys.has(key) ? "ignored" : "active";
    return `${matches[0].targetIdentity}::${test.name}::${test.type}:${status}`;
  });
}

export function collectInventory({
  cargo = process.env.CARGO ?? "cargo",
  cwd = repositoryRoot,
  policyPath = defaultPolicyPath,
  target: rustTarget,
} = {}) {
  const metadata = JSON.parse(
    runCargo(buildMetadataArguments(rustTarget), { cargo, cwd }),
  );
  const policy = normalizePolicy(readPolicy(policyPath));
  const harnessFreeTargets = new Set(policy.harnessFreeTargets);
  const workspaceMembers = new Set(metadata.workspace_members);
  const packages = metadata.packages
    .filter((package_) => workspaceMembers.has(package_.id))
    .sort((left, right) => compareText(left.name, right.name));
  const workspaceRoot = requireNonEmptyString(
    metadata.workspace_root,
    "Cargo workspace root",
  );
  const artifactOutput = runCargo(
    buildWorkspaceTestArguments(rustTarget),
    { cargo, cwd },
  );
  const artifacts = parseCompilerArtifacts(artifactOutput, packages);
  const selectedTargets = new Set(
    artifacts.map((artifact) => artifact.targetIdentity),
  );
  const staleHarnessFreeTargets = policy.harnessFreeTargets.filter(
    (target) => !selectedTargets.has(target),
  );
  if (staleHarnessFreeTargets.length > 0) {
    throw new Error(
      "Harness-free target policy entries do not match selected Cargo test artifacts:\n" +
        formatTests(staleHarnessFreeTargets),
    );
  }

  const inventory = [];

  for (const artifact of artifacts) {
    if (harnessFreeTargets.has(artifact.targetIdentity)) {
      inventory.push(
        `${artifact.targetIdentity}::<harness-free-target>::target:active`,
      );
      continue;
    }

    const output = runProcess(
      artifact.executable,
      ["--list", "--format", "terse"],
      {
        cwd: artifact.workingDirectory,
        label: artifact.targetIdentity,
      },
    );
    const ignoredOutput = runProcess(
      artifact.executable,
      ["--ignored", "--list", "--format", "terse"],
      {
        cwd: artifact.workingDirectory,
        label: artifact.targetIdentity,
      },
    );
    inventory.push(
      ...parseTestList(
        artifact.targetIdentity,
        output,
        ignoredOutput,
      ),
    );
  }

  const docTargets = packages.flatMap((package_) =>
    package_.targets.flatMap((target) => {
      const docTarget = describeCargoTargets(target).find(
        (cargoTarget) => cargoTarget.identity.startsWith("doc:"),
      );
      if (docTarget === undefined) {
        return [];
      }

      const sourcePath = path
        .relative(
          workspaceRoot,
          requireNonEmptyString(target.src_path, "Cargo target source path"),
        )
        .replaceAll("\\", "/");
      return [
        {
          sourcePath,
          targetIdentity: `${package_.name}::${docTarget.identity}`,
        },
      ];
    }),
  );
  if (docTargets.length > 0) {
    const arguments_ = buildWorkspaceDoctestArguments(rustTarget);
    const output = runCargo(
      [...arguments_, "--", "--list", "--format", "terse"],
      { cargo, cwd },
    );
    const ignoredOutput = runCargo(
      [...arguments_, "--", "--ignored", "--list", "--format", "terse"],
      { cargo, cwd },
    );
    inventory.push(
      ...parseWorkspaceDoctestList(
        docTargets,
        output,
        ignoredOutput,
      ),
    );
  }

  return normalizeInventory(inventory, "Rust test inventory");
}

function normalizePolicy(policy) {
  if (policy === null || typeof policy !== "object" || Array.isArray(policy)) {
    throw new Error("Parity policy must be a JSON object.");
  }

  if (policy.version !== 1) {
    throw new Error("Parity policy version must be 1.");
  }

  if (!Array.isArray(policy.platformOnlyTests)) {
    throw new Error("Parity policy platformOnlyTests must be an array.");
  }

  const harnessFreeTargets = policy.harnessFreeTargets ?? [];
  if (!Array.isArray(harnessFreeTargets)) {
    throw new Error("Parity policy harnessFreeTargets must be an array.");
  }

  const normalizedHarnessFreeTargets = harnessFreeTargets.map(
    (target, index) => {
      const normalized = requireNonEmptyString(
        target,
        `Harness-free target ${index}`,
      );
      if (
        !normalized.includes("::") ||
        normalized.includes("::doc:")
      ) {
        throw new Error(
          `Harness-free target ${index} must use package::kind:name identity.`,
        );
      }
      return normalized;
    },
  );
  if (
    new Set(normalizedHarnessFreeTargets).size !==
    normalizedHarnessFreeTargets.length
  ) {
    throw new Error("Parity policy contains duplicate harness-free targets.");
  }

  const entries = policy.platformOnlyTests.map((entry, index) => {
    if (entry === null || typeof entry !== "object" || Array.isArray(entry)) {
      throw new Error(`Policy entry ${index} must be an object.`);
    }

    if (entry.platform !== "windows" && entry.platform !== "linux") {
      throw new Error(
        `Policy entry ${index} platform must be "windows" or "linux".`,
      );
    }

    const test = requireNonEmptyString(entry.test, `Policy entry ${index} test`);
    const rationale = requireNonEmptyString(
      entry.rationale,
      `Policy entry ${index} rationale`,
    );

    if (rationale.length < 12) {
      throw new Error(
        `Policy entry ${index} rationale must explain the platform difference.`,
      );
    }

    return { platform: entry.platform, rationale, test };
  });
  const keys = entries.map((entry) => `${entry.platform}:${entry.test}`);

  if (new Set(keys).size !== keys.length) {
    throw new Error("Parity policy contains duplicate platform/test entries.");
  }

  return {
    harnessFreeTargets: normalizedHarnessFreeTargets.sort(compareText),
    platformOnlyTests: entries,
  };
}

function difference(left, right) {
  return left.filter((test) => !right.has(test));
}

function formatTests(tests) {
  return tests.map((test) => `  - ${test}`).join("\n");
}

export function compareInventories(windowsInventory, linuxInventory, policy) {
  const windows = normalizeInventory(windowsInventory, "Windows inventory");
  const linux = normalizeInventory(linuxInventory, "Linux inventory");

  if (windows.length === 0 || linux.length === 0) {
    throw new Error("Windows and Linux inventories must both contain tests.");
  }

  const windowsSet = new Set(windows);
  const linuxSet = new Set(linux);
  const actualWindowsOnly = difference(windows, linuxSet);
  const actualLinuxOnly = difference(linux, windowsSet);
  const policyEntries = normalizePolicy(policy).platformOnlyTests;
  const expectedWindowsOnly = policyEntries
    .filter((entry) => entry.platform === "windows")
    .map((entry) => entry.test)
    .sort(compareText);
  const expectedLinuxOnly = policyEntries
    .filter((entry) => entry.platform === "linux")
    .map((entry) => entry.test)
    .sort(compareText);
  const actualWindowsOnlySet = new Set(actualWindowsOnly);
  const actualLinuxOnlySet = new Set(actualLinuxOnly);
  const expectedWindowsOnlySet = new Set(expectedWindowsOnly);
  const expectedLinuxOnlySet = new Set(expectedLinuxOnly);
  const errors = [];

  const unexpectedWindowsOnly = difference(
    actualWindowsOnly,
    expectedWindowsOnlySet,
  );
  if (unexpectedWindowsOnly.length > 0) {
    errors.push(
      `Tests unexpectedly run only on Windows:\n${formatTests(unexpectedWindowsOnly)}`,
    );
  }

  const unexpectedLinuxOnly = difference(actualLinuxOnly, expectedLinuxOnlySet);
  if (unexpectedLinuxOnly.length > 0) {
    errors.push(
      `Tests unexpectedly run only on Linux:\n${formatTests(unexpectedLinuxOnly)}`,
    );
  }

  const staleWindowsPolicy = difference(
    expectedWindowsOnly,
    actualWindowsOnlySet,
  );
  if (staleWindowsPolicy.length > 0) {
    const details = formatTests(staleWindowsPolicy);
    errors.push(
      `Windows-only policy entries no longer match the test inventories:\n${details}`,
    );
  }

  const staleLinuxPolicy = difference(expectedLinuxOnly, actualLinuxOnlySet);
  if (staleLinuxPolicy.length > 0) {
    const details = formatTests(staleLinuxPolicy);
    errors.push(
      `Linux-only policy entries no longer match the test inventories:\n${details}`,
    );
  }

  if (errors.length > 0) {
    const guidance =
      "Make the test portable or update tests/rust-test-parity.json " +
      "with a reviewed rationale.";
    throw new Error(
      `${errors.join("\n\n")}\n\n${guidance}`,
    );
  }

  return {
    linuxOnly: actualLinuxOnly.length,
    shared: windows.filter((test) => linuxSet.has(test)).length,
    windowsOnly: actualWindowsOnly.length,
  };
}

export function encodeInventory(inventory) {
  const normalized = normalizeInventory(inventory, "Inventory");
  return Buffer.from(JSON.stringify(normalized), "utf8").toString("base64");
}

export function decodeInventory(encoded, label = "Inventory") {
  const value = requireNonEmptyString(encoded, label);
  const base64Pattern =
    /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/u;
  if (!base64Pattern.test(value)) {
    throw new Error(`${label} must be canonical base64.`);
  }

  const bytes = Buffer.from(value, "base64");
  if (bytes.toString("base64") !== value) {
    throw new Error(`${label} must be canonical base64.`);
  }

  let decoded;
  try {
    decoded = JSON.parse(bytes.toString("utf8"));
  } catch (error) {
    throw new Error(`${label} does not contain valid JSON: ${error.message}`);
  }

  return normalizeInventory(decoded, label);
}

function parseOptions(values) {
  const options = new Map();

  for (let index = 0; index < values.length; index += 2) {
    const key = values[index];
    const value = values[index + 1];
    if (!key?.startsWith("--") || value === undefined) {
      throw new Error(`Expected --name value arguments, received: ${values.join(" ")}`);
    }

    if (options.has(key)) {
      throw new Error(`Duplicate option: ${key}`);
    }

    options.set(key, value);
  }

  return options;
}

function rejectUnknownOptions(options, allowedOptions) {
  for (const option of options.keys()) {
    if (!allowedOptions.has(option)) {
      throw new Error(`Unknown option: ${option}`);
    }
  }
}

function readPolicy(policyPath) {
  return JSON.parse(readFileSync(policyPath, "utf8"));
}

function requireEnvironment(name) {
  return requireNonEmptyString(process.env[name], `Environment variable ${name}`);
}

function runCommand() {
  const [command, ...values] = process.argv.slice(2);
  const options = parseOptions(values);

  if (command === "inventory") {
    rejectUnknownOptions(
      options,
      new Set(["--github-output", "--target"]),
    );
    const target = options.get("--target");
    const inventory = collectInventory({ target });
    const outputName = options.get("--github-output");

    if (outputName === undefined) {
      process.stdout.write(`${JSON.stringify(inventory, null, 2)}\n`);
      return;
    }

    const outputPath = requireEnvironment("GITHUB_OUTPUT");
    const qualifiedOutputName = requireNonEmptyString(
      outputName,
      "GitHub output name",
    );
    if (!/^[A-Za-z_][A-Za-z0-9_-]*$/u.test(qualifiedOutputName)) {
      throw new Error("GitHub output name contains unsupported characters.");
    }

    appendFileSync(
      outputPath,
      `${qualifiedOutputName}=${encodeInventory(inventory)}\n`,
      "utf8",
    );
    process.stdout.write(`Recorded ${inventory.length} Rust tests.\n`);
    return;
  }

  if (command === "compare") {
    rejectUnknownOptions(options, new Set(["--policy"]));
    const policyPath = path.resolve(
      repositoryRoot,
      options.get("--policy") ?? defaultPolicyPath,
    );
    const windows = decodeInventory(
      requireEnvironment("WINDOWS_TEST_INVENTORY"),
      "Windows test inventory",
    );
    const linux = decodeInventory(
      requireEnvironment("LINUX_TEST_INVENTORY"),
      "Linux test inventory",
    );
    const result = compareInventories(windows, linux, readPolicy(policyPath));
    process.stdout.write(
      `Rust test parity verified: ${result.shared} shared, ` +
        `${result.windowsOnly} Windows-only, ${result.linuxOnly} Linux-only.\n`,
    );
    return;
  }

  throw new Error(
    "Usage: rust-test-parity.mjs inventory [--target TARGET] " +
      "[--github-output NAME] | compare [--policy PATH]",
  );
}

const entryPoint =
  process.argv[1] !== undefined &&
  import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href;

if (entryPoint) {
  try {
    runCommand();
  } catch (error) {
    process.stderr.write(`Rust test parity failed: ${error.message}\n`);
    process.exitCode = 1;
  }
}

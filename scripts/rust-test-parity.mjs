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

export function parseTestList(packageName, output) {
  const qualifiedPackage = requireNonEmptyString(packageName, "Package name");
  const tests = [];

  for (const rawLine of output.split(/\r?\n/u)) {
    const line = rawLine.trim();
    if (line.length === 0 || summaryPattern.test(line)) {
      continue;
    }

    const match = line.match(testPattern);
    if (match === null || match[1].length === 0) {
      throw new Error(
        `Unexpected cargo test-list output for ${qualifiedPackage}: ${line}`,
      );
    }

    tests.push(`${qualifiedPackage}::${match[1]}`);
  }

  return normalizeInventory(tests, `Test list for ${qualifiedPackage}`);
}

function runCargo(arguments_, { cargo, cwd }) {
  const result = spawnSync(cargo, arguments_, {
    cwd,
    encoding: "utf8",
    maxBuffer: 16 * 1024 * 1024,
    shell: false,
  });

  if (result.error !== undefined) {
    throw new Error(
      `Unable to run ${cargo} ${arguments_.join(" ")}: ${result.error.message}`,
    );
  }

  if (result.status !== 0) {
    const details = [result.stdout, result.stderr]
      .map((value) => value.trim())
      .filter((value) => value.length > 0)
      .join("\n");
    throw new Error(
      `${cargo} ${arguments_.join(" ")} failed with exit code ${result.status}.` +
        (details.length === 0 ? "" : `\n${details}`),
    );
  }

  return result.stdout;
}

export function collectInventory({
  cargo = process.env.CARGO ?? "cargo",
  cwd = repositoryRoot,
  target,
} = {}) {
  const metadata = JSON.parse(
    runCargo(
      ["metadata", "--locked", "--no-deps", "--format-version", "1"],
      { cargo, cwd },
    ),
  );
  const workspaceMembers = new Set(metadata.workspace_members);
  const packages = metadata.packages
    .filter((package_) => workspaceMembers.has(package_.id))
    .map((package_) => package_.name)
    .sort(compareText);
  const inventory = [];

  for (const packageName of packages) {
    const arguments_ = [
      "test",
      "-p",
      packageName,
      "--all-targets",
      "--locked",
    ];

    if (target !== undefined) {
      arguments_.push("--target", requireNonEmptyString(target, "Rust target"));
    }

    arguments_.push("--", "--list", "--format", "terse");
    const output = runCargo(arguments_, { cargo, cwd });
    inventory.push(...parseTestList(packageName, output));
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

  return entries;
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
  const policyEntries = normalizePolicy(policy);
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

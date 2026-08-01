import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const packageRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const packageJsonPath = join(packageRoot, 'package.json');
const packageJson = JSON.parse(readFileSync(packageJsonPath, 'utf8'));

const requiredFiles = [
  'index.js',
  'index.d.ts',
  'telemetry.js',
  'lib/ap2.js',
  'README.md',
  'LICENSE',
  'SECURITY.md',
  'package.json',
];
const expectedPackedFiles = new Set(requiredFiles);
const forbiddenPathPatterns = [
  /(^|\/)\.env(?:$|[.\/])/i,
  /(^|\/)(?:node_modules|test|tests|coverage|\.git|\.kiro)(?:\/|$)/i,
  /(?:package-lock\.json|npm-debug\.log|\.tgz)$/i,
];
const forbiddenLiterals = [
  ['ag', 'secret', 'demo', 'key', '2026'].join('_'),
  ['default', 'dev', 'secret'].join('-'),
];
const credentialPatterns = [
  /(?:^|[^A-Za-z0-9])(ghp|github_pat|sk_live|sk_test|whsec|pdl_sdbx)_[A-Za-z0-9_-]{16,}/,
  /(?:^|[^A-Za-z0-9])eyJ[A-Za-z0-9_-]{40,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}/,
];

function fail(message) {
  console.error(`Package boundary check failed: ${message}`);
  process.exitCode = 1;
}

if (!Array.isArray(packageJson.files) || !packageJson.files.includes('index.js')) {
  fail('package.json must define an explicit files allowlist containing index.js');
}
if (packageJson.publishConfig?.access !== 'public') {
  fail('package.json must set publishConfig.access to public');
}
if (typeof packageJson.engines?.node !== 'string') {
  fail('package.json must declare a supported Node.js engine');
}
if (!/^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/.test(packageJson.version)) {
  fail(`package version is not valid semver: ${packageJson.version}`);
}
for (const [section, dependencies] of Object.entries({
  dependencies: packageJson.dependencies,
  optionalDependencies: packageJson.optionalDependencies,
  peerDependencies: packageJson.peerDependencies,
})) {
  for (const [name, version] of Object.entries(dependencies || {})) {
    if (String(version).startsWith('file:')) {
      fail(`${section}.${name} must not depend on a sibling workspace path`);
    }
  }
}

const npmInvocation = process.env.npm_execpath
  ? { command: process.execPath, args: [process.env.npm_execpath] }
  : { command: process.platform === 'win32' ? 'npm.cmd' : 'npm', args: [] };
let packMetadata;
try {
  const output = execFileSync(
    npmInvocation.command,
    [...npmInvocation.args, 'pack', '--dry-run', '--ignore-scripts', '--json'],
    { cwd: packageRoot, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }
  );
  const start = output.indexOf('[');
  const end = output.lastIndexOf(']');
  packMetadata = JSON.parse(output.slice(start, end + 1));
} catch (error) {
  fail(`npm pack --dry-run could not be inspected: ${error.message}`);
  process.exit();
}

const packedFiles = packMetadata[0]?.files?.map(({ path }) => path.replaceAll('\\', '/')) || [];
if (packedFiles.length !== expectedPackedFiles.size || packedFiles.some((packedFile) => !expectedPackedFiles.has(packedFile))) {
  fail(`unexpected npm package contents: ${packedFiles.join(', ')}`);
}
for (const requiredFile of requiredFiles) {
  if (!packedFiles.includes(requiredFile)) {
    fail(`${requiredFile} is missing from the npm package contents`);
  }
}
for (const packedFile of packedFiles) {
  if (forbiddenPathPatterns.some((pattern) => pattern.test(packedFile))) {
    fail(`forbidden path is included in the npm package: ${packedFile}`);
    continue;
  }

  try {
    const content = readFileSync(join(packageRoot, packedFile), 'utf8');
    for (const literal of forbiddenLiterals) {
      if (content.includes(literal)) {
        fail(`known insecure credential literal found in ${packedFile}`);
      }
    }
    for (const pattern of credentialPatterns) {
      if (pattern.test(content)) {
        fail(`credential-like value found in ${packedFile}`);
      }
    }
  } catch (error) {
    fail(`could not scan packed file ${packedFile}: ${error.message}`);
  }
}

if (process.exitCode) {
  process.exit();
}

console.log(`Package boundary check passed: ${packedFiles.length} files; no forbidden paths or credential literals found.`);

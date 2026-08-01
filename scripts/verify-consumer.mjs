import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';

const packageRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const npmInvocation = process.env.npm_execpath
  ? { command: process.execPath, args: [process.env.npm_execpath] }
  : { command: process.platform === 'win32' ? 'npm.cmd' : 'npm', args: [] };

function runNpm(args, cwd) {
  return execFileSync(
    npmInvocation.command,
    [...npmInvocation.args, ...args],
    { cwd, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }
  );
}

function parsePackJson(output) {
  const start = output.indexOf('[');
  const end = output.lastIndexOf(']');
  return JSON.parse(output.slice(start, end + 1));
}

const consumerDir = mkdtempSync(join(tmpdir(), 'agentsbloom-sdk-consumer-'));
let tarballPath;

try {
  const packMetadata = parsePackJson(runNpm(['pack', '--ignore-scripts', '--json'], packageRoot));
  tarballPath = resolve(packageRoot, packMetadata[0].filename);

  writeFileSync(
    join(consumerDir, 'package.json'),
    JSON.stringify({
      name: 'agentsbloom-sdk-consumer-smoke',
      version: '1.0.0',
      private: true,
      type: 'module',
    }, null, 2)
  );

  runNpm(
    ['install', '--ignore-scripts', '--omit=optional', '--no-audit', '--no-fund', tarballPath],
    consumerDir
  );

  execFileSync(
    process.execPath,
    [
      '--input-type=module',
      '-e',
      'const sdk = await import("@agentsbloom/sdk"); if (typeof sdk.agentsbloom !== "function" || typeof sdk.createAp2Mandate !== "function" || typeof sdk.shutdown !== "function") process.exit(1); const middleware = sdk.agentsbloom({ apiKey: "consumer-smoke", agentSecret: "consumer-secret", baseUrl: "https://store.test" }); if (typeof middleware !== "function") process.exit(1);',
    ],
    { cwd: consumerDir, stdio: 'pipe' }
  );

  const packageJson = JSON.parse(readFileSync(join(consumerDir, 'node_modules', '@agentsbloom', 'sdk', 'package.json'), 'utf8'));
  console.log(`Clean consumer check passed for @agentsbloom/sdk@${packageJson.version}.`);
} finally {
  if (tarballPath) rmSync(tarballPath, { force: true });
  rmSync(consumerDir, { recursive: true, force: true });
}

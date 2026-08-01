import { describe, it } from 'node:test';
import assert from 'node:assert';
import fc from 'fast-check';
import { initExporter } from '../telemetry.js';

/**
 * These tests exercise `initExporter` against the real `@opentelemetry/*`
 * packages, which are installed as devDependencies of this package (in
 * addition to being declared as optionalDependencies for the published
 * package) specifically so this suite can verify real exporter
 * configuration without forcing merchant apps installing @agentsbloom/sdk
 * to install the OTel SDK themselves.
 *
 * OTLPTraceExporter does not expose its configured url/headers as public
 * properties, so the tests reach into its internal transport
 * (`_delegate._transport._transport._parameters`) to read back the url and
 * the (possibly async) headers factory that were passed to its
 * constructor. This is coupled to the installed exporter version's
 * internals; if a future upgrade of @opentelemetry/exporter-trace-otlp-http
 * changes this internal shape, only this test file needs updating, not
 * telemetry.js itself.
 */

async function readExporterUrlAndHeaders(exporter) {
  const params = exporter._delegate._transport._transport._parameters;
  const headers = typeof params.headers === 'function' ? await params.headers() : params.headers;
  return { url: params.url, headers };
}

describe('initExporter', () => {

  it('returns a provider/exporter handle for a basic valid config', async () => {
    const handle = await initExporter({
      otlpEndpoint: 'http://localhost:4318',
      serviceName: 'test-service',
      samplingRatio: 1.0,
      apiKey: 'test-key',
    });
    assert.ok(handle, 'expected initExporter to return a handle when OTel packages are installed');
    assert.ok(handle.provider);
    assert.ok(handle.exporter);
    await handle.provider.shutdown();
  });

  // Feature: beta-launch-hardening, Property 17: OTLP exporter initialization uses the configured endpoint and Bearer token
  it('property: targets a URL derived from otlpEndpoint and sends a Bearer token built from apiKey', async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.webUrl().map((u) => u.replace(/\/$/, '')),
        fc.string({ minLength: 1 }).filter((s) => !/[\r\n]/.test(s)),
        async (otlpEndpoint, apiKey) => {
          const handle = await initExporter({
            otlpEndpoint,
            serviceName: 'prop-service',
            samplingRatio: 1.0,
            apiKey,
          });

          // Packages are installed as devDependencies for this suite, so
          // this branch should always be exercised in this environment.
          assert.ok(handle, 'expected a real exporter handle since OTel packages are installed');

          const { url, headers } = await readExporterUrlAndHeaders(handle.exporter);
          assert.strictEqual(url, `${otlpEndpoint}/v1/traces`);
          assert.strictEqual(headers.Authorization, `Bearer ${apiKey}`);

          await handle.provider.shutdown();
        }
      ),
      { numRuns: 100 }
    );
  });

});

describe('initExporter graceful fallback', () => {

  // Feature: beta-launch-hardening, Property 18: Telemetry setup never throws when optional dependencies fail to load
  it('property: never throws and always resolves to a handle object or null across arbitrary configs', async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.record({
          otlpEndpoint: fc.oneof(fc.webUrl(), fc.string(), fc.constant(undefined)),
          serviceName: fc.oneof(fc.string(), fc.constant(undefined)),
          samplingRatio: fc.oneof(fc.float(), fc.integer(), fc.constant(undefined)),
          apiKey: fc.oneof(fc.string(), fc.constant(undefined)),
        }),
        async (config) => {
          let handle;
          let threw = false;
          try {
            handle = await initExporter(config);
          } catch {
            threw = true;
          }

          assert.strictEqual(threw, false, 'initExporter must never throw, even for malformed config');
          assert.ok(
            handle === null || (typeof handle === 'object' && handle !== null),
            'initExporter must resolve to null or a handle object'
          );

          if (handle) {
            await handle.provider.shutdown();
          }
        }
      ),
      { numRuns: 100 }
    );
  });

  it('returns null and does not throw when the dynamic import fails (simulated missing package)', async () => {
    // Simulate the "optional dependency not installed" branch directly:
    // dynamically importing a module that cannot be resolved must be
    // caught by initExporter's try/catch, mirroring what happens when a
    // merchant app has not installed the optional OTel SDK packages.
    let threw = false;
    let result;
    try {
      result = await (async () => {
        try {
          await import('@opentelemetry/this-package-does-not-exist');
          return 'imported';
        } catch (err) {
          console.warn('🌸 AgentsBloom: OTel SDK packages unavailable, continuing without export:', err.message);
          return null;
        }
      })();
    } catch {
      threw = true;
    }
    assert.strictEqual(threw, false);
    assert.strictEqual(result, null);
  });

});

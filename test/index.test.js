import { describe, it } from 'node:test';
import assert from 'node:assert';
import crypto from 'node:crypto';
import fc from 'fast-check';
import {
  agentsbloom,
  resolveProtocol,
  verifyAP2Mandates,
  setupTelemetry,
  shutdown,
  createAp2Mandate,
  didKeyFromEd25519PublicKey,
} from '../index.js';

describe('AgentsBloom SDK Core Suite', () => {

  it('should initialize agentsbloom middleware with config', () => {
    const middleware = agentsbloom({
      apiKey: 'ag_test_123456789',
      agentSecret: 'secret_test_key_123',
      name: 'Test Storefront',
      baseUrl: 'http://localhost:3000'
    });
    assert.strictEqual(typeof middleware, 'function');
  });

  it('should correctly resolve protocols', () => {
    assert.strictEqual(resolveProtocol({ headers: { accept: 'application/mcp+json' } }), 'WEBMCP');
    assert.strictEqual(resolveProtocol({ headers: { 'x-protocol': 'ucp' } }), 'UCP');
    assert.strictEqual(resolveProtocol({ headers: { 'x-protocol': 'acp' } }), 'ACP');
    assert.strictEqual(resolveProtocol({ headers: { 'x-ap2-mandate': 'Bearer test' } }), 'AP2');
    assert.strictEqual(resolveProtocol({ headers: {} }), 'AGENTSBLOOM_REST');
  });

  it('should configure setupTelemetry', async () => {
    const telemetryConfig = await setupTelemetry({ otlpEndpoint: 'http://localhost:4318', samplingRatio: 0.5 });
    assert.strictEqual(telemetryConfig.otlpEndpoint, 'http://localhost:4318');
    assert.strictEqual(telemetryConfig.samplingRatio, 0.5);
  });

  it('should execute shutdown without throw', async () => {
    await assert.doesNotReject(() => shutdown());
  });

  // Feature: beta-launch-hardening, Property 19: Shutdown flushes and shuts down an initialized exporter exactly once
  it('property: shutdown invokes an initialized exporter handle exactly once, and never on a missing handle', async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.boolean(), // whether an exporter handle was initialized
        fc.integer({ min: 1, max: 5 }), // number of times shutdown() is called
        async (hasHandle, callCount) => {
          // Reset global telemetry state before each iteration
          globalThis.__agentsbloom_otel_handle = undefined;

          let shutdownCalls = 0;
          if (hasHandle) {
            globalThis.__agentsbloom_otel_handle = {
              provider: {
                shutdown: async () => {
                  shutdownCalls += 1;
                },
              },
            };
          }

          // Call the exported shutdown() the requested number of times.
          for (let i = 0; i < callCount; i++) {
            await assert.doesNotReject(() => shutdown());
          }

          if (hasHandle) {
            // The handle's provider.shutdown() is invoked exactly once for the
            // first shutdown() call; subsequent calls find the handle cleared
            // (set to null) and do not invoke it again.
            assert.strictEqual(shutdownCalls, 1);
          } else {
            // No handle was ever initialized, so shutdown() must never
            // attempt to call .provider.shutdown() on anything.
            assert.strictEqual(shutdownCalls, 0);
          }

          // Handle must be cleared after shutdown regardless of the branch taken.
          assert.strictEqual(globalThis.__agentsbloom_otel_handle, hasHandle ? null : undefined);
        }
      ),
      { numRuns: 100 }
    );

    // Clean up global state so it doesn't leak into other tests.
    globalThis.__agentsbloom_otel_handle = undefined;
  });

  it('should shut down the exporter created by a real setupTelemetry() call exactly once', async () => {
    const config = await setupTelemetry({
      otlpEndpoint: 'http://localhost:4318',
      serviceName: 'shutdown-test-service',
      samplingRatio: 1.0,
      apiKey: 'test-key',
    });
    assert.strictEqual(config.otlpEndpoint, 'http://localhost:4318');

    // A real exporter handle should have been initialized since the OTel
    // SDK packages are installed as devDependencies in this workspace.
    assert.ok(globalThis.__agentsbloom_otel_handle, 'expected a real exporter handle to be initialized');

    // Wrap provider.shutdown to count invocations without depending on OTel internals.
    let shutdownCalls = 0;
    const originalShutdown = globalThis.__agentsbloom_otel_handle.provider.shutdown.bind(
      globalThis.__agentsbloom_otel_handle.provider
    );
    globalThis.__agentsbloom_otel_handle.provider.shutdown = async (...args) => {
      shutdownCalls += 1;
      return originalShutdown(...args);
    };

    await assert.doesNotReject(() => shutdown());
    assert.strictEqual(shutdownCalls, 1);
    assert.strictEqual(globalThis.__agentsbloom_otel_handle, null);

    // Calling shutdown again must not throw and must not find a handle to call.
    await assert.doesNotReject(() => shutdown());
    assert.strictEqual(shutdownCalls, 1);
  });

});

describe('AP2 Mandate Verification Suite', () => {
  // Note: as of the AP2 hardening pass, verifyAP2Mandates (the SDK's public,
  // backward-compatible export) now REJECTS any mandate it cannot
  // cryptographically verify, rather than passing it through as "valid but
  // unverified". A dedicated, more thorough suite for the hardened
  // semantics (did:key derivation, replay protection, audience/scope
  // binding, bounded lifetime, category enforcement) lives in
  // test/ap2.test.js. These tests focus on the properties that were
  // already covered pre-hardening, updated to use real signed mandates
  // with a real did:key issuer where a signature is now required.

  it('should pass when no mandate is attached', () => {
    const result = verifyAP2Mandates({}, {});
    assert.strictEqual(result.valid, true);
    assert.strictEqual(result.verified, false);
    assert.strictEqual(result.protocol, 'AP2');
  });

  it('should reject expired JWT mandates', () => {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
    const did = `did:key:${Buffer.from('placeholder').toString('hex')}`; // deliberately invalid did - exp check runs before signature verification
    const header = Buffer.from(JSON.stringify({ alg: 'EdDSA', typ: 'JWT' })).toString('base64url');
    const payload = Buffer.from(JSON.stringify({
      iss: did,
      aud: 'test-store',
      iat: Math.floor(Date.now() / 1000) - 7200,
      exp: Math.floor(Date.now() / 1000) - 3600, // Expired 1 hour ago
      jti: crypto.randomUUID(),
      intentMandate: { maxBudget: 100 }
    })).toString('base64url');
    const data = `${header}.${payload}`;
    const signature = crypto.sign(null, Buffer.from(data), privateKey).toString('base64url');
    const token = `${data}.${signature}`;

    const result = verifyAP2Mandates({ 'x-ap2-mandate': `Bearer ${token}` }, {});
    assert.strictEqual(result.valid, false);
    assert.strictEqual(result.reason, 'Token expired');
  });

  it('should reject JWT with future iat', () => {
    const { privateKey } = crypto.generateKeyPairSync('ed25519');
    const header = Buffer.from(JSON.stringify({ alg: 'EdDSA', typ: 'JWT' })).toString('base64url');
    const payload = Buffer.from(JSON.stringify({
      iss: 'did:key:zplaceholder',
      aud: 'test-store',
      iat: Math.floor(Date.now() / 1000) + 7200, // 2 hours in the future
      exp: Math.floor(Date.now() / 1000) + 14400,
      jti: crypto.randomUUID(),
      intentMandate: { maxBudget: 100 }
    })).toString('base64url');
    const data = `${header}.${payload}`;
    const signature = crypto.sign(null, Buffer.from(data), privateKey).toString('base64url');
    const token = `${data}.${signature}`;

    const result = verifyAP2Mandates({ 'x-ap2-mandate': `Bearer ${token}` }, {});
    assert.strictEqual(result.valid, false);
    assert.strictEqual(result.reason, 'Token issued in the future');
  });

  it('should reject JWT without issuer', () => {
    const header = Buffer.from(JSON.stringify({ alg: 'EdDSA', typ: 'JWT' })).toString('base64url');
    const payload = Buffer.from(JSON.stringify({
      aud: 'test-store',
      iat: Math.floor(Date.now() / 1000),
      exp: Math.floor(Date.now() / 1000) + 3600,
      jti: crypto.randomUUID(),
      intentMandate: { maxBudget: 100 }
    })).toString('base64url');
    const token = `${header}.${payload}.fake-signature`;

    const result = verifyAP2Mandates({ 'x-ap2-mandate': `Bearer ${token}` }, {});
    assert.strictEqual(result.valid, false);
    assert.strictEqual(result.reason, 'Missing issuer');
  });

  it('should enforce budget limits on order total', () => {
    const { token } = createAp2Mandate({ audience: 'test-store', maxBudget: 50 });

    // Order total exceeds budget
    const result = verifyAP2Mandates(
      { 'x-ap2-mandate': `Bearer ${token}` },
      { orderTotal: 100 }
    );
    assert.strictEqual(result.valid, false);
    assert.ok(result.reason.includes('maxBudget'));
  });

  it('should accept valid mandate with budget under limit', () => {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
    const did = didKeyFromEd25519PublicKey(publicKey);
    const header = Buffer.from(JSON.stringify({ alg: 'EdDSA', typ: 'JWT' })).toString('base64url');
    const payload = Buffer.from(JSON.stringify({
      iss: did,
      aud: 'test-store',
      iat: Math.floor(Date.now() / 1000),
      exp: Math.floor(Date.now() / 1000) + 3600,
      jti: crypto.randomUUID(),
      intentMandate: { maxBudget: 200 }
    })).toString('base64url');
    const data = `${header}.${payload}`;
    const signature = crypto.sign(null, Buffer.from(data), privateKey).toString('base64url');
    const token = `${data}.${signature}`;

    const result = verifyAP2Mandates(
      { 'x-ap2-mandate': `Bearer ${token}` },
      { orderTotal: 50 }
    );
    assert.strictEqual(result.valid, true);
    assert.strictEqual(result.protocol, 'AP2');
    assert.ok(result.mandates);
    assert.strictEqual(result.mandates.intentMandate.maxBudget, 200);
  });

  it('should verify real Ed25519 signed mandate against a merchant-trusted key', () => {
    // Generate Ed25519 keypair
    const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');

    const header = Buffer.from(JSON.stringify({ alg: 'EdDSA', typ: 'JWT' })).toString('base64url');
    const payload = Buffer.from(JSON.stringify({
      iss: 'test-wallet', // not a did:key - relies on the trusted key
      aud: 'test-store',
      iat: Math.floor(Date.now() / 1000),
      exp: Math.floor(Date.now() / 1000) + 3600,
      jti: crypto.randomUUID(),
      intentMandate: { maxBudget: 500 },
      paymentMandate: { currency: 'USD' }
    })).toString('base64url');

    const data = `${header}.${payload}`;
    const signature = crypto.sign(null, Buffer.from(data), privateKey);
    const token = `${data}.${signature.toString('base64url')}`;

    // Legacy call shape: third arg is the raw public key (backward compat).
    const result = verifyAP2Mandates(
      { 'x-ap2-mandate': `Bearer ${token}` },
      { orderTotal: 100 },
      publicKey
    );
    assert.strictEqual(result.valid, true);
    assert.strictEqual(result.verified, true);
    assert.strictEqual(result.protocol, 'AP2');
  });

  it('should reject a mandate that cannot be cryptographically verified (closes the original bypass)', () => {
    // Simulates the pre-hardening exploit: an unsigned mandate with a fake
    // issuer string and no trusted key configured. Previously this was
    // returned as `{ valid: true, verified: false }` - now it must be
    // rejected outright.
    const header = Buffer.from(JSON.stringify({ alg: 'none', typ: 'JWT' })).toString('base64url');
    const payload = Buffer.from(JSON.stringify({
      iss: 'totally-fake-issuer',
      aud: 'test-store',
      iat: Math.floor(Date.now() / 1000),
      exp: Math.floor(Date.now() / 1000) + 3600,
      jti: crypto.randomUUID(),
      intentMandate: { maxBudget: 999999 }
    })).toString('base64url');
    const token = `${header}.${payload}.`;

    const result = verifyAP2Mandates({ 'x-ap2-mandate': `Bearer ${token}` }, { orderTotal: 999999 });
    assert.strictEqual(result.valid, false);
  });

});


describe('AgentsBloom middleware security defaults', () => {
  function createRequest({ path = '/api/agentsbloom/purchase', headers = {}, body = {}, method = 'POST', ip = '127.0.0.1' } = {}) {
    return {
      path,
      method,
      headers,
      body,
      query: {},
      ip,
      protocol: 'https',
      originalUrl: path,
      socket: { remoteAddress: ip },
      get(name) {
        return this.headers[name.toLowerCase()];
      },
    };
  }

  function createResponse() {
    const headers = new Map();
    return {
      statusCode: 200,
      headersSent: false,
      body: undefined,
      setHeader(name, value) {
        headers.set(name.toLowerCase(), value);
        return this;
      },
      getHeader(name) {
        return headers.get(name.toLowerCase());
      },
      removeHeader(name) {
        headers.delete(name.toLowerCase());
      },
      status(code) {
        this.statusCode = code;
        return this;
      },
      json(value) {
        this.body = value;
        this.headersSent = true;
        return this;
      },
      send(value) {
        this.body = value;
        this.headersSent = true;
        return this;
      },
      end(value) {
        this.body = value;
        this.headersSent = true;
        return this;
      },
    };
  }

  function signLegacyRequest(req, { secret, identifier, timestamp, nonce }) {
    const payload = JSON.stringify([
      identifier,
      String(req.method || '').toUpperCase(),
      req.originalUrl || req.path,
      timestamp,
      nonce,
      req.body ?? null,
    ]);
    return crypto.createHmac('sha256', secret).update(payload).digest('hex');
  }

  it('rejects legacy signed writes when no agent secret is configured', async () => {
    const previousSecret = process.env.AGENTSBLOOM_SECRET;
    delete process.env.AGENTSBLOOM_SECRET;

    try {
      let handlerCalled = false;
      const middleware = agentsbloom({
        apiKey: 'ag_test_security_defaults',
        baseUrl: 'https://store.test',
        actions: {
          purchase: {
            handler: async () => {
              handlerCalled = true;
              return { ok: true };
            },
          },
        },
      });
      const identifier = 'agent-with-unconfigured-secret';
      const historicalFallbackCandidate = ['ag', 'secret', 'demo', 'key', '2026'].join('_');
      const signature = crypto.createHmac('sha256', historicalFallbackCandidate)
        .update(identifier)
        .digest('hex');
      const req = createRequest({
        headers: {
          'x-agent-identifier': identifier,
          'x-agent-signature': signature,
        },
      });
      const res = createResponse();

      await middleware(req, res, () => {
        throw new Error('next() should not be called for a rejected action');
      });

      assert.strictEqual(res.statusCode, 403);
      assert.strictEqual(handlerCalled, false);
    } finally {
      if (previousSecret === undefined) delete process.env.AGENTSBLOOM_SECRET;
      else process.env.AGENTSBLOOM_SECRET = previousSecret;
    }
  });

  it('rejects an invalid legacy signature with a configured secret', async () => {
    let handlerCalled = false;
    const middleware = agentsbloom({
      apiKey: 'ag_test_invalid_signature',
      agentSecret: 'configured-test-secret',
      baseUrl: 'https://store.test',
      actions: {
        purchase: {
          handler: async () => {
            handlerCalled = true;
            return { ok: true };
          },
        },
      },
    });
    const timestamp = String(Math.floor(Date.now() / 1000));
    const nonce = crypto.randomUUID();
    const res = createResponse();

    await middleware(
      createRequest({
        ip: '127.0.0.2',
        headers: {
          'x-agent-identifier': 'agent-1',
          'x-agent-timestamp': timestamp,
          'x-agent-nonce': nonce,
          'x-agent-signature': '0'.repeat(64),
        },
      }),
      res,
      () => {
        throw new Error('next() should not be called for an invalid signature');
      }
    );

    assert.strictEqual(res.statusCode, 403);
    assert.strictEqual(handlerCalled, false);
  });

  it('protects versioned action routes and accepts a correctly signed request', async () => {
    let handlerCalled = false;
    const secret = 'configured-versioned-route-secret';
    const identifier = 'agent-2';
    const timestamp = String(Math.floor(Date.now() / 1000));
    const nonce = crypto.randomUUID();
    const middleware = agentsbloom({
      apiKey: 'ag_test_versioned_route',
      agentSecret: secret,
      baseUrl: 'https://store.test',
      actions: {
        search: {
          handler: async () => {
            handlerCalled = true;
            return { items: [] };
          },
        },
      },
    });
    const req = createRequest({
      path: '/v1/agent/actions/search',
      body: { query: 'shoes' },
      ip: '127.0.0.3',
      headers: {
        'x-agent-identifier': identifier,
        'x-agent-timestamp': timestamp,
        'x-agent-nonce': nonce,
      },
    });
    req.headers['x-agent-signature'] = signLegacyRequest(req, { secret, identifier, timestamp, nonce });
    const res = createResponse();

    await middleware(req, res, () => {
      throw new Error('next() should not be called for a handled action');
    });

    assert.strictEqual(res.statusCode, 200);
    assert.deepStrictEqual(res.body, { items: [] });
    assert.strictEqual(handlerCalled, true);

    const replayResponse = createResponse();
    await middleware(req, replayResponse, () => {
      throw new Error('next() should not be called for a replayed action');
    });
    assert.strictEqual(replayResponse.statusCode, 403);
    assert.match(replayResponse.body.message, /nonce.*already been used/i);
  });

  it('rejects a method mismatch before invoking a POST action', async () => {
    let handlerCalled = false;
    const middleware = agentsbloom({
      apiKey: 'ag_test_method_mismatch',
      baseUrl: 'https://store.test',
      actions: {
        purchase: {
          method: 'POST',
          handler: async () => {
            handlerCalled = true;
            return { ok: true };
          },
        },
      },
    });
    const res = createResponse();

    await middleware(
      createRequest({ path: '/api/agentsbloom/purchase', method: 'GET', ip: '127.0.0.5' }),
      res,
      () => {
        throw new Error('next() should not be called for a configured action');
      }
    );

    assert.strictEqual(res.statusCode, 405);
    assert.strictEqual(res.getHeader('allow'), 'POST');
    assert.strictEqual(handlerCalled, false);
  });

  it('rejects incomplete RFC HTTP Message Signature headers', async () => {
    let handlerCalled = false;
    const middleware = agentsbloom({
      apiKey: 'ag_test_partial_rfc',
      agentSecret: 'configured-test-secret',
      baseUrl: 'https://store.test',
      actions: {
        purchase: {
          handler: async () => {
            handlerCalled = true;
            return { ok: true };
          },
        },
      },
    });
    const res = createResponse();

    await middleware(
      createRequest({
        ip: '127.0.0.6',
        headers: { signature: 'sig1=:AA==:' },
      }),
      res,
      () => {
        throw new Error('next() should not be called for incomplete RFC headers');
      }
    );

    assert.strictEqual(res.statusCode, 403);
    assert.strictEqual(handlerCalled, false);
  });

  it('rejects caller-selected remote JWKS URLs without making a network request', async () => {
    let handlerCalled = false;
    const middleware = agentsbloom({
      apiKey: 'ag_test_remote_jwks',
      baseUrl: 'https://store.test',
      actions: {
        purchase: {
          handler: async () => {
            handlerCalled = true;
            return { ok: true };
          },
        },
      },
    });
    const res = createResponse();

    await middleware(
      createRequest({
        ip: '127.0.0.7',
        headers: {
          signature: 'sig1=:AA==:',
          'signature-input': 'sig1=("@method");keyid="http://127.0.0.1:9/jwks";alg="rsa-v1_5-sha256"',
        },
      }),
      res,
      () => {
        throw new Error('next() should not be called for an untrusted JWKS URL');
      }
    );

    assert.strictEqual(res.statusCode, 403);
    assert.strictEqual(handlerCalled, false);
  });

  it('requires an authentication header for protected writes', async () => {
    const middleware = agentsbloom({
      apiKey: 'ag_test_missing_auth',
      agentSecret: 'configured-test-secret',
      baseUrl: 'https://store.test',
      actions: { purchase: { handler: async () => ({ ok: true }) } },
    });
    const res = createResponse();

    await middleware(
      createRequest({ ip: '127.0.0.8' }),
      res,
      () => {
        throw new Error('next() should not be called without authentication');
      }
    );

    assert.strictEqual(res.statusCode, 401);
  });

  it('allows an explicit demoMode bypass for local demonstrations only', async () => {
    let handlerCalled = false;
    const middleware = agentsbloom({
      apiKey: 'ag_test_explicit_demo',
      baseUrl: 'https://store.test',
      demoMode: true,
      actions: {
        purchase: {
          handler: async () => {
            handlerCalled = true;
            return { demo: true };
          },
        },
      },
    });
    const res = createResponse();

    await middleware(
      createRequest({ ip: '127.0.0.4' }),
      res,
      () => {
        throw new Error('next() should not be called for a handled demo action');
      }
    );

    assert.strictEqual(res.statusCode, 200);
    assert.deepStrictEqual(res.body, { demo: true });
    assert.strictEqual(handlerCalled, true);
  });

  it('clears a failing telemetry handle before awaiting provider shutdown', async () => {
    let shutdownCalls = 0;
    globalThis.__agentsbloom_otel_handle = {
      provider: {
        shutdown: async () => {
          shutdownCalls += 1;
          throw new Error('shutdown failure');
        },
      },
    };

    await assert.rejects(() => shutdown(), /shutdown failure/);
    assert.strictEqual(shutdownCalls, 1);
    assert.strictEqual(globalThis.__agentsbloom_otel_handle, null);
    await assert.doesNotReject(() => shutdown());
    assert.strictEqual(shutdownCalls, 1);
    globalThis.__agentsbloom_otel_handle = undefined;
  });
});


describe('AgentsBloom security regression coverage', () => {
  function createRequest({ path = '/api/agentsbloom/purchase', headers = {}, body = {}, method = 'POST' } = {}) {
    return {
      path,
      method,
      headers,
      body,
      query: {},
      ip: '127.0.0.1',
      protocol: 'https',
      originalUrl: path,
      socket: { remoteAddress: '127.0.0.1' },
      get(name) {
        return this.headers[name.toLowerCase()];
      },
    };
  }

  function createResponse({ jsonUsesSend = false } = {}) {
    const headers = new Map();
    return {
      statusCode: 200,
      headersSent: false,
      body: undefined,
      setHeader(name, value) {
        headers.set(name.toLowerCase(), value);
        return this;
      },
      getHeader(name) {
        return headers.get(name.toLowerCase());
      },
      removeHeader(name) {
        headers.delete(name.toLowerCase());
      },
      status(code) {
        this.statusCode = code;
        return this;
      },
      json(value) {
        if (jsonUsesSend) return this.send(value);
        this.body = value;
        this.headersSent = true;
        return this;
      },
      send(value) {
        this.body = value;
        this.headersSent = true;
        return this;
      },
      end(value) {
        this.body = value;
        this.headersSent = true;
        return this;
      },
    };
  }

  function signLegacyRequest(req, { secret, identifier, timestamp, nonce }) {
    const payload = JSON.stringify([
      identifier,
      String(req.method || '').toUpperCase(),
      req.originalUrl || req.path,
      timestamp,
      nonce,
      req.body ?? null,
    ]);
    return crypto.createHmac('sha256', secret).update(payload).digest('hex');
  }

  function addRfcSignature(req, { privateKey, keyid, nonce = crypto.randomUUID(), created = Math.floor(Date.now() / 1000) }) {
    const expires = created + 240;
    const contentDigest = `sha-256=:${crypto.createHash('sha256')
      .update(Buffer.from(JSON.stringify(req.body ?? null)))
      .digest('base64')}:`;
    const signatureInput = `sig1=("@method" "@path" "content-digest");created=${created};expires=${expires};nonce="${nonce}";keyid="${keyid}";alg="rsa-v1_5-sha256"`;
    req.headers['content-digest'] = contentDigest;
    const signatureBase = [
      `"@method": ${req.method.toLowerCase()}`,
      `"@path": ${req.originalUrl || req.path}`,
      `"content-digest": ${contentDigest}`,
      `"@signature-params": ("@method" "@path" "content-digest");created=${created};expires=${expires};nonce="${nonce}";keyid="${keyid}";alg="rsa-v1_5-sha256"`,
    ].join('\n');
    const signature = crypto.sign('sha256', Buffer.from(signatureBase), privateKey).toString('base64');
    req.headers.signature = `sig1=:${signature}:`;
    req.headers['signature-input'] = signatureInput;
  }

  it('authenticates before serving an idempotent cached response', async () => {
    const secret = 'idempotency-auth-order-secret';
    const identifier = 'idempotency-agent';
    const idempotencyHeader = 'same-idempotency-key';
    let handlerCalls = 0;
    const middleware = agentsbloom({
      apiKey: 'ag_test_idempotency_auth_order',
      agentSecret: secret,
      baseUrl: 'https://store.test',
      actions: {
        purchase: {
          handler: async () => {
            handlerCalls += 1;
            return { ok: true };
          },
        },
      },
    });

    const createSignedRequest = ({ body = { item: 'book' } } = {}) => {
      const timestamp = String(Math.floor(Date.now() / 1000));
      const nonce = crypto.randomUUID();
      const req = createRequest({
        body,
        headers: {
          'idempotency-key': idempotencyHeader,
          'x-agent-identifier': identifier,
          'x-agent-timestamp': timestamp,
          'x-agent-nonce': nonce,
        },
      });
      req.headers['x-agent-signature'] = signLegacyRequest(req, {
        secret,
        identifier,
        timestamp,
        nonce,
      });
      return req;
    };

    const firstResponse = createResponse({ jsonUsesSend: true });
    await middleware(createSignedRequest(), firstResponse, () => {
      throw new Error('next() should not be called for a handled action');
    });
    assert.strictEqual(firstResponse.statusCode, 200);
    assert.strictEqual(handlerCalls, 1);

    const unauthenticatedResponse = createResponse();
    await middleware(
      createRequest({
        body: { item: 'book' },
        headers: {
          'idempotency-key': idempotencyHeader,
          'x-agent-identifier': identifier,
        },
      }),
      unauthenticatedResponse,
      () => {
        throw new Error('next() should not be called for an unauthenticated action');
      }
    );
    assert.strictEqual(unauthenticatedResponse.statusCode, 401);
    assert.strictEqual(handlerCalls, 1);

    const authenticatedReplayResponse = createResponse();
    await middleware(createSignedRequest(), authenticatedReplayResponse, () => {
      throw new Error('next() should not be called for a cached action');
    });
    assert.strictEqual(authenticatedReplayResponse.statusCode, 200);
    assert.strictEqual(authenticatedReplayResponse.getHeader('x-cache'), 'Idempotent-Hit');
    assert.strictEqual(handlerCalls, 1);

    const mismatchedRequestResponse = createResponse({ jsonUsesSend: true });
    await middleware(
      createSignedRequest({ body: { item: 'different-book' } }),
      mismatchedRequestResponse,
      () => {
        throw new Error('next() should not be called for a handled action with a different body');
      }
    );
    assert.strictEqual(mismatchedRequestResponse.statusCode, 200);
    assert.strictEqual(mismatchedRequestResponse.getHeader('x-cache'), undefined);
    assert.strictEqual(handlerCalls, 2);
  });

  it('does not reuse inline JWKS keys across middleware instances', async () => {
    const keyPairOne = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
    const keyPairTwo = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
    const keyid = 'shared-key-id';
    const jwkOne = { ...keyPairOne.publicKey.export({ format: 'jwk' }), kid: keyid };
    const jwkTwo = { ...keyPairTwo.publicKey.export({ format: 'jwk' }), kid: keyid };

    const firstMiddleware = agentsbloom({
      apiKey: 'ag_test_jwks_cache_one',
      baseUrl: 'https://store.test',
      agentJwks: { keys: [jwkOne] },
      actions: { purchase: { handler: async () => ({ first: true }) } },
    });
    const firstRequest = createRequest();
    addRfcSignature(firstRequest, { privateKey: keyPairOne.privateKey, keyid });
    const firstResponse = createResponse();
    await firstMiddleware(firstRequest, firstResponse, () => {
      throw new Error('next() should not be called for the first signed action');
    });
    assert.strictEqual(firstResponse.statusCode, 200);

    let secondHandlerCalled = false;
    const secondMiddleware = agentsbloom({
      apiKey: 'ag_test_jwks_cache_two',
      baseUrl: 'https://store.test',
      agentJwks: { keys: [jwkTwo] },
      actions: {
        purchase: {
          handler: async () => {
            secondHandlerCalled = true;
            return { second: true };
          },
        },
      },
    });
    const secondRequest = createRequest();
    addRfcSignature(secondRequest, { privateKey: keyPairOne.privateKey, keyid });
    const secondResponse = createResponse();
    await secondMiddleware(secondRequest, secondResponse, () => {
      throw new Error('next() should not be called for an invalid signed action');
    });

    assert.strictEqual(secondResponse.statusCode, 403);
    assert.strictEqual(secondHandlerCalled, false);
  });

  it('rejects replayed and body-tampered RFC signatures', async () => {
    const keyPair = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
    const keyid = 'rfc-replay-key';
    const jwk = { ...keyPair.publicKey.export({ format: 'jwk' }), kid: keyid };
    let handlerCalls = 0;
    const middleware = agentsbloom({
      apiKey: 'ag_test_rfc_replay',
      baseUrl: 'https://store.test',
      agentJwks: { keys: [jwk] },
      actions: {
        purchase: {
          handler: async () => {
            handlerCalls += 1;
            return { ok: true };
          },
        },
      },
    });

    const signedRequest = createRequest({ body: { item: 'book' } });
    addRfcSignature(signedRequest, { privateKey: keyPair.privateKey, keyid });
    const firstResponse = createResponse();
    await middleware(signedRequest, firstResponse, () => {
      throw new Error('next() should not be called for a valid RFC signature');
    });
    assert.strictEqual(firstResponse.statusCode, 200);
    assert.strictEqual(handlerCalls, 1);

    const replayResponse = createResponse();
    await middleware(signedRequest, replayResponse, () => {
      throw new Error('next() should not be called for an RFC replay');
    });
    assert.strictEqual(replayResponse.statusCode, 403);
    assert.match(replayResponse.body.message, /nonce.*already been used/i);

    const tamperedRequest = createRequest({
      body: { item: 'different-book' },
      headers: { ...signedRequest.headers },
    });
    const tamperedResponse = createResponse();
    await middleware(tamperedRequest, tamperedResponse, () => {
      throw new Error('next() should not be called for a body-tampered RFC signature');
    });
    assert.strictEqual(tamperedResponse.statusCode, 403);
    assert.strictEqual(handlerCalls, 1);
  });

  it('requires authentication for MCP message writes', async () => {
    let handlerCalled = false;
    const middleware = agentsbloom({
      apiKey: 'ag_test_mcp_auth',
      baseUrl: 'https://store.test',
      actions: {
        purchase: {
          handler: async () => {
            handlerCalled = true;
            return { ok: true };
          },
        },
      },
    });
    const response = createResponse();

    await middleware(
      createRequest({
        path: '/mcp/messages',
        body: {
          jsonrpc: '2.0',
          id: 1,
          method: 'tools/call',
          params: { name: 'purchase', arguments: {} },
        },
      }),
      response,
      () => {
        throw new Error('next() should not be called for an unauthenticated MCP message');
      }
    );

    assert.strictEqual(response.statusCode, 401);
    assert.strictEqual(handlerCalled, false);
  });
});

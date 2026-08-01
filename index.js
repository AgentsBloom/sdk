import zlib from 'zlib';
import crypto from 'crypto';
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { SSEServerTransport } from '@modelcontextprotocol/sdk/server/sse.js';
import { trace, metrics, ValueType, context, propagation } from '@opentelemetry/api';
import { initExporter } from './telemetry.js';
import {
  verifyAp2Mandate,
  createAp2Mandate,
  didKeyFromEd25519PublicKey,
  ed25519PublicKeyFromDidKey,
  resetAp2ReplayCache,
  stopAp2ReplayCleanup,
} from './lib/ap2.js';

const tracer = trace.getTracer('agentsbloom-sdk');
const meter = metrics.getMeter('agentsbloom-sdk');

const agentRequestsCounter = meter.createCounter('agent_visits_total', { description: 'Total AI Visits' });
const agentRevenueCounter = meter.createCounter('agent_revenue_usd', { description: 'Total AI Revenue', valueType: ValueType.DOUBLE });

/**
 * Initialize OpenTelemetry with OTLP exporters.
 * Call this BEFORE using the agentsbloom() middleware.
 * 
 * @param {Object} options
 * @param {string} options.otlpEndpoint - OTLP collector URL (default: http://localhost:4318)
 * @param {string} options.serviceName - Service name for traces (default: agentsbloom-merchant)
 * @param {number} options.samplingRatio - Trace sampling ratio 0.0-1.0 (default: 1.0)
 * @param {string} options.apiKey - API key for authenticating with the collector
 */
export async function setupTelemetry(options = {}) {
  const {
    otlpEndpoint = process.env.AGENTSBLOOM_OTEL_ENDPOINT || 'http://localhost:4318',
    serviceName = 'agentsbloom-merchant',
    samplingRatio = parseFloat(process.env.AGENTSBLOOM_SAMPLING_RATIO || '1.0'),
    apiKey = process.env.AGENTSBLOOM_API_KEY || '',
  } = options;

  // Store config for lazy initialization when OTel SDK packages are available
  globalThis.__agentsbloom_otel_config = {
    otlpEndpoint,
    serviceName,
    samplingRatio,
    apiKey,
  };

  const handle = await initExporter({ otlpEndpoint, serviceName, samplingRatio, apiKey });
  globalThis.__agentsbloom_otel_handle = handle;

  console.log(`🌸 AgentsBloom: Telemetry configured (sampling: ${samplingRatio * 100}%)`);
  return { otlpEndpoint, serviceName, samplingRatio };
}
const DEFAULT_RFC_JWKS_URL = 'https://platform.openai.com/.well-known/jwks.json';
const LEGACY_SIGNATURE_MAX_AGE_MS = 5 * 60 * 1000;
const RFC_SIGNATURE_CLOCK_SKEW_MS = 30 * 1000;
const SIGNATURE_REPLAY_CACHE_MAX_SIZE = 50_000;
const jwksCache = new Map();

function verifySignature(signature, payload, secret) {
  try {
    if (typeof signature !== 'string' || !/^[a-f0-9]{64}$/i.test(signature)) return false;
    const computed = crypto.createHmac('sha256', secret).update(payload).digest();
    const provided = Buffer.from(signature, 'hex');
    return crypto.timingSafeEqual(computed, provided);
  } catch {
    return false;
  }
}

function buildLegacySignaturePayload(req, identifier, timestamp, nonce) {
  return JSON.stringify([
    identifier,
    String(req.method || '').toUpperCase(),
    req.originalUrl || req.path,
    timestamp,
    nonce,
    req.body ?? null,
  ]);
}

function buildRequestContentDigest(req) {
  let bodyBytes;
  if (req.rawBody !== undefined) {
    bodyBytes = Buffer.isBuffer(req.rawBody) ? req.rawBody : Buffer.from(String(req.rawBody));
  } else if (Buffer.isBuffer(req.body)) {
    bodyBytes = req.body;
  } else if (req.body !== undefined) {
    bodyBytes = Buffer.from(JSON.stringify(req.body ?? null));
  } else {
    const contentLength = Number(req.headers['content-length'] || 0);
    if (contentLength > 0) {
      throw new Error('Protected HTTP signatures require parsed request bodies or req.rawBody');
    }
    bodyBytes = Buffer.alloc(0);
  }

  const digest = crypto.createHash('sha256').update(bodyBytes).digest('base64');
  return `sha-256=:${digest}:`;
}

// In-memory rate limiting map
const rateLimitMap = new Map();
const rateLimitInterval = setInterval(() => {
  const now = Date.now();
  for (const [key, val] of rateLimitMap.entries()) {
    if (val.resetTime < now) rateLimitMap.delete(key);
  }
}, 60 * 1000);
rateLimitInterval.unref();

// In-memory Idempotency cache
const idempotencyMap = new Map();
const signatureNonceMap = new Map();
const idempotencyInterval = setInterval(() => {
  const now = Date.now();
  for (const [key, val] of idempotencyMap.entries()) {
    if (val.expiry < now) idempotencyMap.delete(key);
  }
  for (const [key, expiresAt] of signatureNonceMap.entries()) {
    if (expiresAt < now) signatureNonceMap.delete(key);
  }
}, 60 * 1000);
idempotencyInterval.unref();

let otelShutdownPromise = null;

export async function shutdown() {
  clearInterval(rateLimitInterval);
  clearInterval(idempotencyInterval);
  rateLimitMap.clear();
  idempotencyMap.clear();
  signatureNonceMap.clear();
  jwksCache.clear();
  stopAp2ReplayCleanup();

  if (otelShutdownPromise) {
    return otelShutdownPromise;
  }

  const otelHandle = globalThis.__agentsbloom_otel_handle;
  if (!otelHandle) return;

  // Clear the handle before awaiting so a repeated/concurrent shutdown cannot
  // start a second provider shutdown, even if the first one rejects.
  globalThis.__agentsbloom_otel_handle = null;
  otelShutdownPromise = Promise.resolve().then(() => otelHandle.provider.shutdown());
  try {
    await otelShutdownPromise;
  } finally {
    otelShutdownPromise = null;
  }
}

export function agentsbloom(config = {}) {
  const {
    apiKey = null,
    name = "My Agent-Ready Store",
    description = "An e-commerce store optimized for human and machine AI agents.",
    actions = {},
    llmsDoc = "",
    baseUrl = ""
  } = config;

  if (!apiKey) {
    console.error("🌸 AgentsBloom SDK Error: Missing `apiKey`. You must provide an API Key to use the SDK. Get one at dashboard.agentsbloom.com");
  }
  if (!baseUrl) {
    console.error("🌸 AgentsBloom SDK Error: Missing `baseUrl` in config. This is required for secure telemetry.");
  }

  let quotaExceededUntil = 0;

  const MAX_REQUESTS = config.rateLimit?.max || 30;
  const RATE_LIMIT_WINDOW = config.rateLimit?.windowMs || 60 * 1000;
  const IDEMPOTENCY_TTL = config.idempotency?.ttlMs || 5 * 60 * 1000;
  const signatureMaxAgeMs = Number.isFinite(config.signature?.maxAgeMs) && config.signature.maxAgeMs > 0
    ? config.signature.maxAgeMs
    : LEGACY_SIGNATURE_MAX_AGE_MS;
  
  const configuredAgentSecret = config.agentSecret ?? process.env.AGENTSBLOOM_SECRET;
  const agentSecret = typeof configuredAgentSecret === 'string' && configuredAgentSecret.length > 0
    ? configuredAgentSecret
    : null;
  const signatureAuthEnabled = config.disableSignatureAuth !== true && config.demoMode !== true;
  const cacheNamespace = crypto.randomUUID();

  if (!agentSecret && signatureAuthEnabled) {
    console.warn("🌸 AgentsBloom Warning: AGENTSBLOOM_SECRET is not set. Legacy signed write requests will be rejected until a secret is configured.");
  }

  return async (req, res, next) => {
    const contentLength = parseInt(req.headers['content-length'] || '0', 10);
    if (contentLength > 1024 * 1024) {
      return res.status(413).json({ error: "Payload Too Large", message: "Request body exceeds 1MB limit." });
    }

    if (req.path === '/health' && req.method === 'GET') {
      return res.json({ status: "ok", version: "0.2.0", uptime: process.uptime() });
    }

    const requestUrl = baseUrl || `${req.protocol}://${req.get('host')}`;
    const ip = req.ip || req.socket.remoteAddress || '127.0.0.1';
    const now = Date.now();

    // --- CORS HEADERS ---
    const allowedOrigin = config.corsOrigin || baseUrl || '*';
    res.setHeader('Access-Control-Allow-Origin', allowedOrigin);
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, PATCH, DELETE, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Content-Digest, X-Agent-Signature, X-Agent-Identifier, X-Agent-Timestamp, X-Agent-Nonce, Idempotency-Key, Signature, Signature-Input, Signature-Agent');
    if (req.method === 'OPTIONS') {
      return res.status(204).end();
    }

    // --- SaaS QUOTA ENFORCEMENT (Zero Latency Cache) ---
    if (now < quotaExceededUntil) {
      res.setHeader('Content-Type', 'application/json');
      return res.status(402).json({
        error: "AgentsBloom Quota Exceeded. Please upgrade your API plan to continue serving AI Agents.",
        code: "api_quota_exceeded"
      });
    }

    // --- 1. DDoS PROTECTION (RATE LIMITING) ---
    let limit = rateLimitMap.get(ip);
    if (!limit || now > limit.resetTime) {
      limit = { count: 1, resetTime: now + RATE_LIMIT_WINDOW };
      rateLimitMap.set(ip, limit);
    } else {
      limit.count++;
    }

    const remaining = Math.max(0, MAX_REQUESTS - limit.count);
    res.setHeader('X-RateLimit-Limit', String(MAX_REQUESTS));
    res.setHeader('X-RateLimit-Remaining', String(remaining));
    res.setHeader('X-RateLimit-Reset', String(Math.ceil((limit.resetTime - now) / 1000)));

    if (limit.count > MAX_REQUESTS) {
      res.setHeader('Content-Type', 'application/json');
      res.setHeader('Retry-After', String(Math.ceil((limit.resetTime - now) / 1000)));
      return res.status(429).json({
        error: "Too Many Requests",
        message: "Rate limit exceeded. Please slow down.",
        retryAfter: Math.ceil((limit.resetTime - now) / 1000)
      });
    }

    // --- 2. SERVE SPEC ENDPOINTS ---
    
    // Serve /.well-known/agent-spec & /v1/agent/spec (API Versioning)
    if (req.path === '/.well-known/agent-spec' || req.path === '/v1/agent/spec') {
      res.setHeader('Content-Type', 'application/json');
      res.setHeader('Cache-Control', 'public, max-age=86400, stale-while-revalidate=3600');
      return res.json({
        name,
        description,
        version: "1.0.0",
        agentsbloomVersion: "0.2.0",
        discoveryUrl: `${requestUrl}/v1/agent/spec`,
        catalogUrl: `${requestUrl}/v1/agent/catalog`,
        llmsUrl: `${requestUrl}/llms.txt`,
        security: {
          rateLimiting: { maxRequestsPerMin: MAX_REQUESTS },
          captchaBypassing: { supported: true, authHeader: "X-Agent-Signature", webBotAuth: true },
          idempotency: { supported: true, header: "Idempotency-Key", ttlSeconds: 300 }
        },
        actions: Object.entries(actions).reduce((acc, [key, val]) => {
          acc[key] = {
            endpoint: `/api/agentsbloom/${key}`,
            method: val.method || 'POST',
            description: val.description,
            params: val.params || {}
          };
          return acc;
        }, {}),
        authentication: { type: "http-message-signatures-or-x-agent-signature", requiredForWrites: true }
      });
    }

    // Serve /.well-known/http-message-signatures-directory
    if (req.path === '/.well-known/http-message-signatures-directory') {
      res.setHeader('Content-Type', 'application/json');
      res.setHeader('Cache-Control', 'public, max-age=86400');
      if (config.merchantJwks) {
        return res.json(config.merchantJwks);
      } else {
        console.warn("🌸 AgentsBloom Warning: Serving placeholder JWKS. Provide `merchantJwks` in config for real keys.");
        return res.json({
          keys: [
            {
              kty: "OKP",
              crv: "Ed25519",
              kid: "placeholder-merchant-key",
              x: "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPPRwX0"
            }
          ]
        });
      }
    }

    // Serve /.well-known/ucp (Universal Commerce Protocol Profile)
    if (req.path === '/.well-known/ucp') {
      res.setHeader('Content-Type', 'application/json');
      res.setHeader('Cache-Control', 'public, max-age=86400');
      return res.json({
        protocol: "ucp",
        version: "1.0.0",
        store: { name, description, baseUrl: requestUrl },
        capabilities: [
          "dev.ucp.shopping",
          "dev.ucp.shopping.checkout",
          "dev.ucp.common.identity_linking"
        ],
        endpoints: {
          catalog: `${requestUrl}/ai-catalog.json`,
          cart: `${requestUrl}/api/agentsbloom/cart`,
          checkout: `${requestUrl}/api/agentsbloom/checkout/acp`
        },
        auth: {
          methods: ["http-message-signatures", "x-agent-signature"]
        }
      });
    }

    // Serve /ai-catalog.json & /v1/agent/catalog (ARD / UCP Compliant)
    if (req.path === '/ai-catalog.json' || req.path === '/.well-known/ai-catalog.json' || req.path === '/v1/agent/catalog') {
      res.setHeader('Content-Type', 'application/json');
      res.setHeader('Cache-Control', 'public, max-age=86400, stale-while-revalidate=3600');
      return res.json({
        $schema: "https://universalcommerce.org/schemas/catalog.json",
        name,
        description,
        version: "1.0.0",
        auth: {
          supported: ["http-message-signatures", "x-agent-signature"]
        },
        items: Object.entries(actions).map(([key, val]) => ({
          id: key,
          type: "action",
          title: key,
          description: val.description,
          actionUrl: `${requestUrl}/api/agentsbloom/${key}`
        }))
      });
    }

    // Serve MCP SSE Endpoint for Tool Calling
    if (req.path === '/mcp') {
      const transport = new SSEServerTransport('/mcp/messages', res);
      const mcpServer = new Server({ name: name, version: "1.0.0" }, { capabilities: { tools: {} } });
      
      // Auto-generate MCP tool declarations from actions
      mcpServer.setRequestHandler("tools/list", async () => ({
        tools: Object.entries(actions).map(([key, val]) => ({
          name: key,
          description: val.description,
          inputSchema: {
            type: "object",
            properties: Object.entries(val.params || {}).reduce((acc, [pkey, pval]) => {
              acc[pkey] = { type: pval };
              return acc;
            }, {})
          }
        }))
      }));

      mcpServer.setRequestHandler("tools/call", async (request) => {
        const action = actions[request.params.name];
        if (!action) throw new Error(`Tool not found: ${request.params.name}`);
        const result = await action.handler(request.params.arguments, req, res);
        return { content: [{ type: "text", text: JSON.stringify(result) }] };
      });

      return mcpServer.connect(transport);
    }

    // Serve /llms.txt
    if (req.path === '/llms.txt') {
      res.setHeader('Content-Type', 'text/plain; charset=utf-8');
      res.setHeader('Cache-Control', 'public, max-age=86400, stale-while-revalidate=3600');
      const defaultLlmDoc = `# ${name}\n\n${description}\n\n## Developer API Reference\n\n- GET /.well-known/agent-spec : Spec sheets\n- GET /ai-catalog.json : Catalog schemas\n`;
      return res.send(llmsDoc || defaultLlmDoc);
    }

    // --- 3. IDEMPOTENCY METADATA FOR WRITES (POST/PUT/PATCH/DELETE) ---
    const method = String(req.method || '').toUpperCase();
    const isWrite = ['POST', 'PUT', 'PATCH', 'DELETE'].includes(method);
    const rawIdempotencyKey = req.headers['idempotency-key'];
    const idempotencyHeader = typeof rawIdempotencyKey === 'string' ? rawIdempotencyKey : null;
    let idempotencyKey = null;
    let authenticatedCacheIdentity = null;

    // --- 4. CRYPTOGRAPHIC CAPTCHA BYPASSING (Web Bot Auth + Legacy HMAC) ---
    const isMcpMessage = req.path === '/mcp/messages' && method === 'POST';
    const isAgentAction = req.path.startsWith('/api/agentsbloom/')
      || req.path.startsWith('/v1/agent/actions/')
      || isMcpMessage;
    if (isAgentAction && isWrite && signatureAuthEnabled) {
      const signature = req.headers['x-agent-signature'];
      const identifier = req.headers['x-agent-identifier'];
      const timestamp = req.headers['x-agent-timestamp'];
      const nonce = req.headers['x-agent-nonce'];
      
      const rfcSignature = req.headers['signature'];
      const rfcSignatureInput = req.headers['signature-input'];
      const hasRfcSignature = typeof rfcSignature === 'string' && rfcSignature.length > 0;
      const hasRfcSignatureInput = typeof rfcSignatureInput === 'string' && rfcSignatureInput.length > 0;

      if (!signature && !hasRfcSignature && !hasRfcSignatureInput) {
        return res.status(401).json({
          error: "Verification Required",
          message: "CAPTCHA check required. Please provide standard RFC 9421 HTTP Message Signatures or the legacy X-Agent-Signature."
        });
      }

      if (hasRfcSignature !== hasRfcSignatureInput) {
        return res.status(403).json({
          error: "Verification Failed",
          message: "Signature and Signature-Input headers must be provided together."
        });
      }
      
      if (hasRfcSignature) {
        try {
          const keyidMatch = rfcSignatureInput.match(/keyid="([^"]+)"/);
          if (!keyidMatch) throw new Error("Missing keyid");
          const keyid = keyidMatch[1];
          const componentsMatch = rfcSignatureInput.match(/\(([^)]+)\)/);
          const components = componentsMatch
            ? componentsMatch[1].split(' ').map(s => s.replace(/"/g, ''))
            : [];
          if (!components.includes('@method') || !components.includes('@path') || !components.includes('content-digest')) {
            throw new Error('HTTP Message Signatures must cover @method, @path, and content-digest');
          }

          const createdMatch = rfcSignatureInput.match(/(?:^|;)created=(\d+)(?:;|$)/);
          const expiresMatch = rfcSignatureInput.match(/(?:^|;)expires=(\d+)(?:;|$)/);
          const nonceMatch = rfcSignatureInput.match(/(?:^|;)nonce="([^"]+)"(?:;|$)/);
          const algMatch = rfcSignatureInput.match(/(?:^|;)alg="([^"]+)"(?:;|$)/);
          if (!createdMatch || !expiresMatch || !nonceMatch || !algMatch) {
            throw new Error('HTTP Message Signatures require created, expires, nonce, and alg parameters');
          }

          const createdSeconds = Number(createdMatch[1]);
          const expiresSeconds = Number(expiresMatch[1]);
          const createdMs = createdSeconds * 1000;
          const expiresMs = expiresSeconds * 1000;
          const nowMs = Date.now();
          if (
            !Number.isSafeInteger(createdSeconds) ||
            !Number.isSafeInteger(expiresSeconds) ||
            expiresSeconds <= createdSeconds ||
            createdMs > nowMs + RFC_SIGNATURE_CLOCK_SKEW_MS ||
            createdMs < nowMs - signatureMaxAgeMs ||
            expiresMs < nowMs - RFC_SIGNATURE_CLOCK_SKEW_MS ||
            expiresMs - createdMs > signatureMaxAgeMs
          ) {
            throw new Error('HTTP Message Signature is expired or outside the allowed lifetime');
          }

          const rfcNonce = nonceMatch[1];
          if (!/^[\x21-\x7e]{16,256}$/.test(rfcNonce)) {
            throw new Error('HTTP Message Signature nonce must be a printable value of 16 to 256 characters');
          }

          const contentDigest = req.headers['content-digest'];
          if (typeof contentDigest !== 'string' || contentDigest !== buildRequestContentDigest(req)) {
            throw new Error('HTTP Message Signature content-digest does not match the request body');
          }

          const alg = algMatch[1];
          const rfcReplayKey = `${cacheNamespace}:rfc:${keyid}:${rfcNonce}`;
          
          if (/^https?:\/\//i.test(keyid)) {
            throw new Error("Remote keyid URLs are not accepted; configure a trusted JWKS and use its exact key id");
          }

          const trustedJwks = config.agentJwks;
          const trustedJwksUrl = config.agentJwksUrl || DEFAULT_RFC_JWKS_URL;
          const cacheKey = `${cacheNamespace}:${trustedJwks ? 'inline' : trustedJwksUrl}:${keyid}`;
          let publicKey = null;
          const cached = jwksCache.get(cacheKey);
          if (cached && cached.expires > Date.now()) {
            publicKey = cached.key;
          } else {
            let jwks;
            if (trustedJwks) {
              jwks = trustedJwks;
            } else {
              const parsedJwksUrl = new URL(trustedJwksUrl);
              if (parsedJwksUrl.protocol !== 'https:') {
                throw new Error("Configured agentJwksUrl must use HTTPS");
              }
              const jwksRes = await fetch(parsedJwksUrl.href, {
                redirect: 'error',
                signal: AbortSignal.timeout(5000),
              });
              if (!jwksRes.ok) throw new Error(`JWKS request failed with HTTP ${jwksRes.status}`);
              jwks = await jwksRes.json();
            }

            if (!Array.isArray(jwks?.keys)) throw new Error("Configured JWKS is invalid");
            const jwk = jwks.keys.find((candidate) => candidate && candidate.kid === keyid);
            if (!jwk) throw new Error("Configured JWKS does not contain the requested key id");
            publicKey = crypto.createPublicKey({ key: jwk, format: 'jwk' });
            jwksCache.set(cacheKey, { key: publicKey, expires: Date.now() + 3600 * 1000 });
          }

          let signatureBase = '';
          for (const comp of components) {
            if (comp === '@method') signatureBase += `"@method": ${req.method.toLowerCase()}\n`;
            else if (comp === '@path') signatureBase += `"@path": ${req.originalUrl || req.path}\n`;
            else if (comp === '@authority') signatureBase += `"@authority": ${req.headers.host}\n`;
            else signatureBase += `"${comp}": ${req.headers[comp] || ''}\n`;
          }
          const sigParams = rfcSignatureInput.replace(/^[a-zA-Z0-9_]+=\s*/, '');
          signatureBase += `"@signature-params": ${sigParams}`;

          const sigMatch = rfcSignature.match(/=:([a-zA-Z0-9+/=]+):/);
          const rawSig = sigMatch ? sigMatch[1] : rfcSignature.replace(/^[a-zA-Z0-9_]+=\s*/, '');
          const signatureBuffer = Buffer.from(rawSig, 'base64');
          
          const hashAlg = alg.includes('sha512') ? 'SHA512' : 'SHA256';

          const isValid = crypto.verify(hashAlg, Buffer.from(signatureBase), publicKey, signatureBuffer);
          
          if (!isValid) return res.status(403).json({ error: "Forbidden", message: "Invalid HTTP Message Signature." });
          for (const [replayKey, expiresAt] of signatureNonceMap.entries()) {
            if (expiresAt < nowMs) signatureNonceMap.delete(replayKey);
          }
          if (signatureNonceMap.has(rfcReplayKey)) {
            return res.status(403).json({
              error: "Forbidden",
              message: "HTTP Message Signature nonce has already been used."
            });
          }
          if (signatureNonceMap.size >= SIGNATURE_REPLAY_CACHE_MAX_SIZE) {
            return res.status(503).json({
              error: "Verification Unavailable",
              message: "Signature replay protection is temporarily at capacity."
            });
          }
          signatureNonceMap.set(rfcReplayKey, expiresMs);
          authenticatedCacheIdentity = `rfc:${keyid}`;
        } catch (err) {
          return res.status(403).json({ error: "Forbidden", message: "Signature verification failed: " + err.message });
        }
      } else {
        const headerValuePattern = /^[\x21-\x7e]+$/;
        if (
          !agentSecret ||
          typeof signature !== 'string' ||
          typeof identifier !== 'string' ||
          typeof timestamp !== 'string' ||
          typeof nonce !== 'string' ||
          identifier.length > 256 ||
          nonce.length < 16 ||
          nonce.length > 256 ||
          !headerValuePattern.test(identifier) ||
          !headerValuePattern.test(timestamp) ||
          !headerValuePattern.test(nonce)
        ) {
          return res.status(403).json({
            error: "Verification Failed",
            message: "X-Agent-Signature requires a configured secret, identifier, timestamp, and nonce."
          });
        }

        const timestampSeconds = Number(timestamp);
        const timestampMs = timestampSeconds * 1000;
        const nowMs = Date.now();
        if (!Number.isSafeInteger(timestampSeconds) || Math.abs(nowMs - timestampMs) > signatureMaxAgeMs) {
          return res.status(403).json({
            error: "Verification Failed",
            message: "X-Agent-Signature is expired or has an invalid timestamp."
          });
        }

        const replayKey = `${cacheNamespace}:legacy:${identifier}:${nonce}`;
        if (signatureNonceMap.has(replayKey)) {
          return res.status(403).json({
            error: "Verification Failed",
            message: "X-Agent-Signature nonce has already been used."
          });
        }

        let signaturePayload;
        try {
          signaturePayload = buildLegacySignaturePayload(req, identifier, timestamp, nonce);
        } catch {
          return res.status(400).json({
            error: "Invalid Request",
            message: "Request body cannot be serialized for signature verification."
          });
        }
        if (!verifySignature(signature, signaturePayload, agentSecret)) {
          return res.status(403).json({
            error: "Verification Failed",
            message: "X-Agent-Signature is invalid. Access denied."
          });
        }

        for (const [key, expiresAt] of signatureNonceMap.entries()) {
          if (expiresAt < nowMs) signatureNonceMap.delete(key);
        }
        if (signatureNonceMap.size >= SIGNATURE_REPLAY_CACHE_MAX_SIZE) {
          return res.status(503).json({
            error: "Verification Unavailable",
            message: "Signature replay protection is temporarily at capacity."
          });
        }
        signatureNonceMap.set(replayKey, timestampMs + signatureMaxAgeMs);
        authenticatedCacheIdentity = `legacy:${identifier}`;
      }
    }

    // --- 3b. IDEMPOTENCY CHECKS FOR WRITES (POST/PUT/PATCH/DELETE) ---
    // Perform this lookup only after the protected-route authentication gate.
    // Cache keys are scoped to this middleware instance and the verified agent
    // identity so one caller cannot replay another caller's cached response.
    if (isWrite && idempotencyHeader) {
      const requestedIdentity = typeof req.headers['x-agent-identifier'] === 'string'
        ? req.headers['x-agent-identifier']
        : 'anonymous';
      const cacheIdentity = authenticatedCacheIdentity || `anonymous:${requestedIdentity}`;
      let serializedRequestBody;
      try {
        serializedRequestBody = JSON.stringify(req.body ?? null);
      } catch {
        return res.status(400).json({
          error: "Invalid Request",
          message: "Request body cannot be serialized for idempotency verification."
        });
      }
      const cacheKeyMaterial = [
        cacheNamespace,
        cacheIdentity,
        method,
        req.originalUrl || req.path,
        serializedRequestBody,
        idempotencyHeader,
      ].join('\u0000');
      idempotencyKey = `${cacheNamespace}:${crypto.createHash('sha256').update(cacheKeyMaterial).digest('hex')}`;

      for (const [key, val] of idempotencyMap.entries()) {
        if (val.expiry < now) {
          idempotencyMap.delete(key);
        }
      }

      const cachedResponse = idempotencyMap.get(idempotencyKey);
      if (cachedResponse) {
        console.log('🌸 AgentsBloom: Found cached response for an Idempotency Key');
        res.setHeader('X-Cache', 'Idempotent-Hit');
        res.setHeader('Content-Type', cachedResponse.headers['content-type'] || 'application/json');
        return res.status(cachedResponse.status).send(cachedResponse.responseBody);
      }
    }

    // --- 4b. AP2 MANDATE VERIFICATION (Wired into middleware) ---
    const ap2MandateHeader = req.headers['x-ap2-mandate'] || req.headers['authorization'];
    const detectedProtocol = resolveProtocol(req);
    let ap2MandateResult = null;

    if (detectedProtocol === 'AP2' || (ap2MandateHeader && ap2MandateHeader.includes('.'))) {
      // Verify the SD-JWT mandate before allowing any write action. Uses
      // either a merchant-configured trusted public key (config.ap2PublicKey)
      // or, when absent, derives a key from the mandate's own did:key issuer
      // (self-certifying - see lib/ap2.js for why an unverifiable mandate is
      // now rejected outright rather than passed through as "valid").
      ap2MandateResult = verifyAP2Mandates(req.headers, req.body || {}, {
        trustedPublicKey: config.ap2PublicKey || null,
        expectedAudience: config.ap2?.expectedAudience || requestUrl,
        maxMandateLifetimeSec: config.ap2?.maxMandateLifetimeSec,
        requireJti: config.ap2?.requireJti,
        requestedCategories: req.body?.requestedCategories || config.ap2?.requestedCategories,
      });

      if (!ap2MandateResult.valid) {
        return res.status(403).json({
          error: "AP2 Mandate Rejected",
          protocol: "AP2",
          reason: ap2MandateResult.reason,
          message: "The Verifiable Intent mandate failed validation. The agent's payment authorization is invalid."
        });
      }

      // Attach mandate info to request for downstream handlers
      req.ap2Mandate = ap2MandateResult;
    }

    // --- AP2 Discovery Endpoint ---
    if (req.path === '/ap2/capabilities' || req.path === '/v1/ap2/capabilities') {
      return res.json({
        protocol: "AP2",
        version: "1.0.0",
        store: { name, description, baseUrl: requestUrl },
        mandateTypes: ["intentMandate", "cartMandate", "paymentMandate"],
        verificationMethods: ["sd-jwt", "jwt"],
        endpoints: {
          capabilities: `${requestUrl}/ap2/capabilities`,
          intent: `${requestUrl}/ap2/intent`,
          checkout: `${requestUrl}/ap2/checkout`,
          actions: Object.keys(actions).map(k => `${requestUrl}/v1/agent/actions/${k}`)
        },
        budgetEnforcement: true,
        signatureAlgorithms: ["ES256", "ES384", "ES512", "RS256", "RS384", "RS512", "EdDSA"]
      });
    }

    // --- AP2 Intent Endpoint (agent announces what it wants to do) ---
    if ((req.path === '/ap2/intent' || req.path === '/v1/ap2/intent') && req.method === 'POST') {
      // Must check `.verified`, not mere truthiness: ap2MandateResult is a
      // truthy object even when no mandate header was ever presented
      // (`{ valid: true, verified: false, note: '...' }`), so a bare
      // `if (!ap2MandateResult)` check would let unauthenticated requests
      // reach this mandate-gated endpoint.
      if (!ap2MandateResult?.verified) {
        return res.status(401).json({
          error: "AP2 Mandate Required",
          message: "Send x-ap2-mandate: Bearer <sd-jwt> header with a valid Intent Mandate."
        });
      }
      return res.json({
        protocol: "AP2",
        intentAccepted: true,
        mandateVerified: ap2MandateResult.verified,
        mandates: ap2MandateResult.mandates || {},
        availableActions: Object.entries(actions).map(([key, val]) => ({
          action: key,
          endpoint: `/v1/agent/actions/${key}`,
          method: val.method || 'POST',
          description: val.description
        })),
        budgetRemaining: ap2MandateResult.mandates?.intentMandate?.maxBudget || "unlimited"
      });
    }

    // --- AP2 Checkout Endpoint (mandate-gated checkout) ---
    if ((req.path === '/ap2/checkout' || req.path === '/v1/ap2/checkout') && req.method === 'POST') {
      // Same fix as /ap2/intent above: this MUST require a genuinely
      // verified mandate, not just a truthy result object. Previously,
      // hitting /ap2/checkout with no x-ap2-mandate header at all still
      // produced a truthy `ap2MandateResult` (valid:true, verified:false),
      // which passed this check, then found no `.mandates.intentMandate`
      // to read a maxBudget from - so checkout proceeded with ZERO budget
      // enforcement. Requiring `.verified` closes that bypass.
      if (!ap2MandateResult?.verified) {
        return res.status(401).json({
          error: "AP2 Payment Mandate Required",
          message: "AP2 checkout requires x-ap2-mandate header with a valid Payment Mandate."
        });
      }

      const checkoutAction = actions['checkout'];
      if (!checkoutAction || typeof checkoutAction.handler !== 'function') {
        return res.status(404).json({ error: 'Checkout action not configured for this store.' });
      }

      // Validate budget before executing checkout
      const orderTotal = req.body?.orderTotal || req.body?.total || 0;
      const maxBudget = ap2MandateResult.mandates?.intentMandate?.maxBudget
                     || ap2MandateResult.mandates?.paymentMandate?.maxBudget;

      if (maxBudget && Number(orderTotal) > Number(maxBudget)) {
        return res.status(403).json({
          error: "AP2 Budget Exceeded",
          protocol: "AP2",
          orderTotal: Number(orderTotal),
          maxBudget: Number(maxBudget),
          message: `Order total $${orderTotal} exceeds mandate budget limit of $${maxBudget}.`
        });
      }

      return Promise.resolve(checkoutAction.handler(req.body, req, res))
        .then(result => {
          if (!res.headersSent) {
            res.json({
              protocol: "AP2",
              verifiableIntent: {
                mandateVerified: ap2MandateResult.verified,
                budgetEnforced: !!maxBudget,
                maxBudget: maxBudget || null,
                orderTotal: result.total || orderTotal
              },
              session_id: result.sessionId || `ap2_sess_${Date.now()}`,
              payment_url: result.paymentUrl,
              status: "authorized",
              expires_at: Math.floor(Date.now() / 1000) + 3600,
              checkout: result
            });
          }
        })
        .catch(err => {
          console.error("AP2 Checkout error:", err);
          if (!res.headersSent) {
            res.status(500).json({ error: 'Internal AP2 checkout error', protocol: 'AP2' });
          }
        });
    }

    // --- 5. HANDLE ACTION ROUTING ---
    // Agentic Commerce Protocol (ACP) Checkout Wrapper
    if (req.path === '/api/agentsbloom/checkout/acp' && req.method === 'POST') {
      const checkoutAction = actions['checkout'];
      if (checkoutAction && typeof checkoutAction.handler === 'function') {
        return Promise.resolve(checkoutAction.handler(req.body, req, res))
          .then(result => {
            if (!res.headersSent) {
              res.json({
                session_id: result.sessionId || `acp_sess_${Date.now()}`,
                payment_url: result.paymentUrl,
                status: "open",
                expires_at: Math.floor(Date.now() / 1000) + 3600
              });
            }
          })
          .catch(err => {
            console.error(`ACP Checkout execution error:`, err);
            if (!res.headersSent) {
              res.status(500).json({ error: 'Internal ACP checkout error' });
            }
          });
      } else {
        return res.status(404).json({ error: 'ACP Checkout not configured for this store.' });
      }
    }

    if (req.path.startsWith('/api/agentsbloom/') || req.path.startsWith('/v1/agent/actions/')) {
      const actionName = req.path.replace('/api/agentsbloom/', '').replace('/v1/agent/actions/', '');
      const action = actions[actionName];

      if (action && typeof action.handler === 'function') {
        const configuredMethod = String(action.method || 'POST').toUpperCase();
        if (method !== configuredMethod) {
          res.setHeader('Allow', configuredMethod);
          return res.status(405).json({
            error: "Method Not Allowed",
            message: `Action ${actionName} only accepts ${configuredMethod} requests.`,
            allowedMethod: configuredMethod,
          });
        }

        const params = method === 'GET' ? req.query : req.body;
        
        if (action.params) {
          for (const [key, type] of Object.entries(action.params)) {
            if (params[key] !== undefined && typeof params[key] !== type && type !== 'any') {
              return res.status(400).json({ error: "Invalid Parameter", message: `Expected ${type} for parameter ${key}` });
            }
          }
        }
        
        // Cache original res.send to support idempotency key caching
        const originalSend = res.send;
        res.send = function (body) {
          if (isWrite && idempotencyKey && res.statusCode >= 200 && res.statusCode < 300) {
            idempotencyMap.set(idempotencyKey, {
              responseBody: body,
              status: res.statusCode,
              headers: { 'content-type': res.getHeader('content-type') },
              timestamp: Date.now(),
              expiry: Date.now() + IDEMPOTENCY_TTL
            });
          }
          return originalSend.apply(this, arguments);
        };

        const startTime = Date.now();
        const agentName = req.headers['x-agent-identifier'] || req.headers['signature-agent'] || 'Unknown Agent';

        // Extract W3C Trace Context from incoming request (HIGH-16)
        const parentContext = propagation.extract(context.active(), req.headers);
        const span = tracer.startSpan(`agent_request:${actionName}`, {}, parentContext);
        
        return Promise.resolve(action.handler(params, req, res))
          .then(result => {
            if (!res.headersSent) {
              res.json(result);
            }
            
            const latencyMs = Date.now() - startTime;
            const revenue = result && result.totalPrice ? result.totalPrice : 0;

            // OpenTelemetry Native Instrumentation
            span.setAttribute('agent.name', agentName);
            span.setAttribute('agent.route', `/api/agentsbloom/${actionName}`);
            span.setAttribute('http.status_code', res.statusCode);
            span.setAttribute('http.latency_ms', latencyMs);
            
            agentRequestsCounter.add(1, { agent: agentName });
            if (revenue) agentRevenueCounter.add(revenue, { agent: agentName });
            span.end();

            // Telemetry is handled by OTLP exporters configured via setupTelemetry().
            // The span.end() call above will auto-export to the OTLP collector.
          })
          .catch(err => {
            span.setAttribute('error', true);
            span.end();
            console.error(`AgentsBloom action execution error (${actionName}):`, err);
            if (!res.headersSent) {
              res.status(500).json({ error: 'Internal agent endpoint error' });
            }
          });
      } else {
        return res.status(404).json({ error: `Unknown AgentsBloom action.` });
      }
    }

    // --- 6. HTML INJECTION WITH COMPRESSION SUPPORT ---
    // Opt-out via config.disableHtmlInjection (MED-12)
    if (config.disableHtmlInjection) {
      return next();
    }

    const originalWrite = res.write;
    const originalEnd = res.end;
    let chunks = [];
    let isHtml = false;

    const originalWriteHead = res.writeHead;
    res.writeHead = function (statusCode, headers) {
      const contentType = res.getHeader('Content-Type') || (headers && headers['content-type']) || '';
      if (typeof contentType === 'string' && contentType.includes('text/html')) {
        isHtml = true;
        res.removeHeader('Content-Length');
        if (headers) delete headers['content-length'];
      }
      return originalWriteHead.apply(this, arguments);
    };

    res.write = function (chunk) {
      const contentType = res.getHeader('Content-Type') || '';
      if (isHtml || (typeof contentType === 'string' && contentType.includes('text/html'))) {
        isHtml = true;
        chunks.push(typeof chunk === 'string' ? Buffer.from(chunk) : chunk);
        return true;
      }
      return originalWrite.apply(res, arguments);
    };

    res.end = function (chunk) {
      const contentType = res.getHeader('Content-Type') || '';
      if (isHtml || (typeof contentType === 'string' && contentType.includes('text/html'))) {
        isHtml = true;
        if (chunk) {
          chunks.push(typeof chunk === 'string' ? Buffer.from(chunk) : chunk);
        }
        
        let bodyBuffer = Buffer.concat(chunks);
        const encoding = res.getHeader('Content-Encoding');
        const isGzipped = typeof encoding === 'string' && encoding.includes('gzip');

        // Decompress if gzipped
        if (isGzipped) {
          try {
            bodyBuffer = zlib.gunzipSync(bodyBuffer);
          } catch (err) {
            console.error("AgentsBloom decompression error:", err);
          }
        }

        let body = bodyBuffer.toString('utf8');

        if (body.toLowerCase().includes('</body>')) {
          const jsonLdData = {
            "@context": "https://schema.org",
            "@type": "WebPage",
            "name": name,
            "description": description,
            "potentialAction": Object.entries(actions).map(([key, val]) => ({
              "@type": "SearchAction",
              "name": key,
              "target": `${requestUrl}/api/agentsbloom/${key}`
            }))
          };

          const jsonLdScript = `\n<script type="application/ld+json">\n${JSON.stringify(jsonLdData, null, 2)}\n</script>`;

          const webMcpScript = `
<meta name="webmcp" content="active">
<script>
// Auto-generated WebMCP Declarative Actions by AgentsBloom
(function() {
  if (typeof navigator !== 'undefined' && navigator.ai && typeof navigator.ai.registerTool === 'function') {
    console.log("🌸 AgentsBloom: Registering WebMCP tools natively in browser.");
    
    ${Object.entries(actions).map(([key, val]) => `
    navigator.ai.registerTool({
      name: "${key}",
      description: "${val.description.replace(/"/g, '\\"')}",
      inputSchema: {
        type: "object",
        properties: {
          ${Object.entries(val.params || {}).map(([pkey, pval]) => `
          "${pkey}": { type: "${pval}" }
          `).join(',')}
        }
      },
      handler: async (args) => {
        try {
          const method = "${val.method || 'POST'}";
          const headers = { 'Content-Type': 'application/json', 'Accept': 'application/json' };
          let fetchOptions = { method, headers };
          
          let url = '/api/agentsbloom/${key}';
          if (method === 'GET') {
            const queryParams = new URLSearchParams(args).toString();
            if (queryParams) url += '?' + queryParams;
          } else {
            fetchOptions.body = JSON.stringify(args);
          }
          
          const response = await fetch(url, fetchOptions);
          return await response.json();
        } catch (e) {
          return { error: e.message };
        }
      }
    });
    `).join('\n')}
  }
})();
</script>
`;

          if (body.toLowerCase().includes('</head>')) {
            body = body.replace(/<\/head>/i, `${jsonLdScript}\n</head>`);
          } else {
            body = body + jsonLdScript;
          }

          body = body.replace(/<\/body>/i, `${webMcpScript}\n</body>`);
        }

        let outputBuffer = Buffer.from(body);

        // Re-compress if gzipped
        if (isGzipped) {
          try {
            outputBuffer = zlib.gzipSync(outputBuffer);
          } catch (err) {
            console.error("AgentsBloom compression error:", err);
          }
        }

        res.setHeader('Content-Length', outputBuffer.length);
        originalWrite.call(res, outputBuffer);
        return originalEnd.call(res);
      }
      return originalEnd.apply(res, arguments);
    };

    next();
  };
}

// --- UNIFIED PROTOCOL ROUTER ---
export function resolveProtocol(req) {
  const accept = (req.headers && req.headers['accept']) || '';
  const xProtocol = (req.headers && req.headers['x-protocol']) || '';
  const path = req.path || req.url || '';

  if (accept.includes('application/mcp+json') || path.startsWith('/mcp')) {
    return 'WEBMCP';
  }
  if (xProtocol.toLowerCase() === 'ucp' || path.startsWith('/.well-known/ucp') || path.startsWith('/ucp')) {
    return 'UCP';
  }
  if (xProtocol.toLowerCase() === 'acp' || path.startsWith('/acp')) {
    return 'ACP';
  }
  if (req.headers && (req.headers['x-ap2-mandate'] || path.startsWith('/ap2'))) {
    return 'AP2';
  }
  return 'AGENTSBLOOM_REST';
}

// --- AP2 (AGENT PAYMENTS PROTOCOL) SD-JWT MANDATE VERIFIER ---
//
// Thin, backward-compatible wrapper over the hardened implementation in
// lib/ap2.js. The original signature `verifyAP2Mandates(headers, body,
// publicKey)` treated an unsigned/unverifiable mandate as "valid but
// unverified" and let downstream code (and, worse, the /ap2/checkout gate
// itself - see the truthiness-check fix above) treat that as authorization
// to check out. lib/ap2.js's verifyAp2Mandate instead REJECTS any mandate
// it cannot cryptographically verify.
//
// Both call shapes are supported for backward compatibility:
//   verifyAP2Mandates(headers, body, publicKey)              // legacy
//   verifyAP2Mandates(headers, body, { trustedPublicKey, expectedAudience, ... })  // current
export function verifyAP2Mandates(headers = {}, body = {}, publicKeyOrOptions = null) {
  let options;
  if (publicKeyOrOptions === null || publicKeyOrOptions === undefined) {
    options = {};
  } else if (
    publicKeyOrOptions instanceof crypto.KeyObject ||
    Buffer.isBuffer(publicKeyOrOptions) ||
    typeof publicKeyOrOptions === 'string'
  ) {
    // Legacy call shape: third argument is a raw public key.
    options = { trustedPublicKey: publicKeyOrOptions };
  } else {
    // Current call shape: third argument is an options object.
    options = publicKeyOrOptions;
  }
  return verifyAp2Mandate(headers, body, options);
}

export { createAp2Mandate, didKeyFromEd25519PublicKey, ed25519PublicKeyFromDidKey, resetAp2ReplayCache };


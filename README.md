# @agentsbloom/sdk

`@agentsbloom/sdk` is a Node.js/Express middleware package for exposing commerce actions to AI agents through AgentsBloom discovery endpoints and supported agent-commerce protocols.

The package includes action discovery, idempotency and in-memory rate-limit helpers, legacy HMAC agent signatures, RFC HTTP Message Signature verification, AP2 mandate verification, optional OpenTelemetry export, and HTML metadata/WebMCP injection.

## Requirements

- Node.js 20 or newer
- An Express 4 application
- A real `AGENTSBLOOM_SECRET` for protected legacy-signed write actions

The SDK does not contain a default or demo signing secret. If a protected write request uses the legacy `X-Agent-Signature` flow without a configured secret, it is rejected. RFC HTTP Message Signatures and AP2 mandates use their own verification paths.

## Install

```sh
npm install @agentsbloom/sdk express
```

`express` is a peer dependency. OpenTelemetry SDK packages are declared as optional dependencies and npm installs them by default; applications that do not need OTLP export can use `npm install --omit=optional`. The SDK also handles the optional packages being absent when `setupTelemetry()` is called.

## Minimal Express setup

```js
import express from "express";
import { agentsbloom, shutdown } from "@agentsbloom/sdk";

const app = express();
const agentSecret = process.env.AGENTSBLOOM_SECRET;

if (!agentSecret) {
  throw new Error("AGENTSBLOOM_SECRET must be configured before starting the server");
}

app.use(express.json({ limit: "1mb" }));
app.use(agentsbloom({
  apiKey: process.env.AGENTSBLOOM_API_KEY,
  agentSecret,
  baseUrl: process.env.PUBLIC_STORE_URL,
  name: "Example Store",
  description: "An example store for agent-driven commerce.",
  actions: {
    search: {
      method: "POST",
      description: "Search the product catalog.",
      params: { query: "string" },
      handler: async ({ query }) => ({ query, items: [] })
    }
  }
}));

const server = app.listen(process.env.PORT || 3000);
const closeServer = () => new Promise((resolve, reject) => {
  if (!server.listening) return resolve();
  server.close((error) => error ? reject(error) : resolve());
});
const stop = async () => {
  try {
    await closeServer(); // stop accepting requests before clearing SDK state
  } finally {
    await shutdown();
  }
};
process.once("SIGTERM", stop);
process.once("SIGINT", stop);
```

`baseUrl` should be the canonical public HTTPS origin of the store. Do not put an API key or signing secret in source control, client-side code, logs, or package metadata.

## Configuration

- `apiKey`: AgentsBloom account key used for attribution and service integrations.
- `agentSecret`: secret used to verify legacy `X-Agent-Identifier`/`X-Agent-Signature` requests. If omitted, `AGENTSBLOOM_SECRET` is read from the environment; if neither is set, legacy signed writes fail closed. Each legacy signature must also include a fresh timestamp and one-time nonce and is bound to the method, path, and parsed request body.
- `baseUrl`: canonical store origin used for discovery and audience binding.
- `actions`: map of agent action names to handlers. Handlers receive `(params, req, res)` and may return a value or a promise. `method` defaults to `POST` and is enforced; declare `method: "GET"` explicitly for a read action.
- `rateLimit`: optional `{ max, windowMs }` in-memory per-IP limits.
- `idempotency`: optional `{ ttlMs }` for successful write responses keyed by `Idempotency-Key`. Protected action requests authenticate before cache lookup, and cache entries are scoped to the middleware instance and verified agent identity.
- `ap2`: optional AP2 settings including `expectedAudience`, `maxMandateLifetimeSec`, `requireJti`, and `requestedCategories`.
- `merchantJwks`: merchant JWKS document served at the HTTP Message Signatures discovery endpoint.
- `agentJwks`: optional inline trusted JWKS used to verify RFC HTTP Message Signatures. Key IDs must match a JWK `kid` exactly.
- `agentJwksUrl`: optional HTTPS URL for the trusted agent JWKS. The URL is configured by the merchant; a request cannot select an arbitrary remote JWKS URL.
- `signature`: optional `{ maxAgeMs }` for legacy HMAC timestamp validation; the default is five minutes.
- `demoMode`: explicit local/demo-only bypass for signature authentication. Never enable it in a production deployment.
- `disableSignatureAuth`: explicit compatibility bypass. It should not be enabled for an internet-facing deployment.

The middleware does not replace an application-level authorization layer, a distributed rate limiter, a durable idempotency store, TLS termination, or payment-provider verification.

## Legacy HMAC request signatures

For a mutating action that uses `X-Agent-Signature`, send these headers:

- `X-Agent-Identifier`: printable agent identifier.
- `X-Agent-Timestamp`: current Unix timestamp in seconds.
- `X-Agent-Nonce`: a unique printable nonce of at least 16 characters.
- `X-Agent-Signature`: lowercase or uppercase hexadecimal HMAC-SHA-256.

The signed payload is the JSON array `[identifier, method, originalUrl, timestamp, nonce, parsedBody]`, using the configured `agentSecret`. Signatures expire after five minutes by default and a nonce cannot be consumed twice by the same identifier within the process. This is an in-memory replay guard; use a durable authentication and replay store when running multiple instances. Identifier-only signatures from older SDK revisions are intentionally rejected; update the signer to include the timestamp and nonce before upgrading.

## RFC HTTP Message Signatures

Protected write requests using the RFC 9421-compatible path must sign `@method`, `@path`, and `content-digest`, and include `created`, `expires`, `nonce`, `keyid`, and `alg` signature parameters. The SDK validates the five-minute default lifetime, rejects reused nonces, and recomputes `content-digest` from `req.rawBody` when present or the parsed request body otherwise. If an application needs byte-exact verification, configure its body parser to preserve the raw body on `req.rawBody`.

## MCP message authentication

The SSE connection at `/mcp` can advertise the configured tools, but mutating MCP messages sent to `/mcp/messages` must pass the same configured RFC HTTP Message Signature or legacy `X-Agent-Signature` verification as other protected writes. This prevents an unauthenticated MCP client from invoking an action handler.

## AP2

The package exports helpers for creating and verifying signed AP2 mandates:

```js
import {
  createAp2Mandate,
  verifyAP2Mandates,
  resetAp2ReplayCache
} from "@agentsbloom/sdk";

const { token } = createAp2Mandate({
  audience: "https://store.example",
  maxBudget: 100
});

const result = verifyAP2Mandates(
  { "x-ap2-mandate": `Bearer ${token}` },
  { orderTotal: 40 },
  { expectedAudience: "https://store.example" }
);

if (!result.valid) {
  throw new Error(result.reason);
}
```

Presented mandates are cryptographically verified. The verifier enforces signature algorithms, issuer/audience binding, bounded lifetime, required `jti` replay protection, optional category restrictions, and budget limits. Reset the replay cache only when the process is being deliberately reinitialized, such as in a test harness.

## Telemetry

`setupTelemetry()` dynamically loads the optional OpenTelemetry packages and continues without an exporter when they are unavailable. `samplingRatio` is accepted and reported for compatibility, but the current initializer does not apply an SDK-level sampler. `shutdown()` closes the configured provider and clears SDK in-memory state. Applications should call it during graceful process shutdown, after stopping the HTTP server from accepting new requests.

```js
import { setupTelemetry } from "@agentsbloom/sdk";

await setupTelemetry({
  otlpEndpoint: process.env.AGENTSBLOOM_OTEL_ENDPOINT,
  serviceName: "example-store",
  samplingRatio: 1,
  apiKey: process.env.AGENTSBLOOM_API_KEY
});
```

## Development and release checks

From this package directory:

```sh
npm ci
npm test
npm run lint
npm run check:package
npm run verify:consumer
npm run release:check
npm pack --dry-run --ignore-scripts
```

The package uses an explicit npm `files` allowlist. Tests and release scripts remain in the repository but are intentionally excluded from the published tarball. These commands do not publish to npm.

## Security

Please report suspected vulnerabilities privately. See [`SECURITY.md`](./SECURITY.md). Never include live credentials in an issue, pull request, test fixture, or support request.

## License

MIT. See [`LICENSE`](./LICENSE).

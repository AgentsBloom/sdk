<p align="center">
  <a href="https://agentsbloom.com">
    <img src="./assets/logo-mark.svg" alt="AgentsBloom lotus mark" width="96" height="96" />
  </a>
</p>

<h1 align="center">@agentsbloom/sdk</h1>

<p align="center">
  <strong>One install makes your Express store agent-ready.</strong><br />
  Expose commerce actions to AI agents through open discovery surfaces and secure agent-commerce protocols.
</p>

<p align="center">
  <a href="https://docs.agentsbloom.com">Docs</a> ·
  <a href="https://agentsbloom.com">Marketing</a> ·
  <a href="https://blog.agentsbloom.com">Blog</a> ·
  <a href="https://github.com/AgentsBloom">AgentsBloom on GitHub</a>
</p>

<p align="center">
  <a href="https://www.npmjs.com/package/@agentsbloom/sdk"><img src="https://img.shields.io/npm/v/@agentsbloom/sdk?logo=npm&logoColor=white&label=npm" alt="npm version" /></a>
  <a href="https://github.com/AgentsBloom/sdk/actions/workflows/ci.yml"><img src="https://github.com/AgentsBloom/sdk/actions/workflows/ci.yml/badge.svg" alt="CI status" /></a>
  <a href="https://github.com/AgentsBloom/sdk/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-MIT-7c3aed.svg" alt="MIT license" /></a>
</p>

## About AgentsBloom

[AgentsBloom](https://agentsbloom.com) builds open infrastructure for commerce on the agentic web. We help teams make existing server-side commerce actions understandable and usable by software agents while keeping the store in control of its catalog, authorization, inventory, checkout, and payment logic.

This SDK is the open-source Node.js/Express core: a small middleware layer that gives an existing Express store a clear path to agent-ready commerce.

## One install to make an Express store agent-ready

```sh
npm install @agentsbloom/sdk express
```

Then add the middleware and describe your store actions:

```js
import express from "express";
import { agentsbloom } from "@agentsbloom/sdk";

const app = express();

app.use(express.json({ limit: "1mb" }));
app.use(agentsbloom({
  baseUrl: process.env.PUBLIC_STORE_URL,
  actions: {
    search: {
      method: "POST",
      description: "Search the product catalog.",
      params: { query: "string" },
      handler: async ({ query }) => ({
        query,
        items: await searchProducts(query)
      })
    }
  }
}));
```

Follow the [Express quickstart in the AgentsBloom documentation](https://docs.agentsbloom.com). You do not need to rewrite your storefront or move your commerce logic into a proprietary platform.

## What the SDK provides

- Action discovery and machine-readable commerce metadata.
- Express middleware for agent-facing store actions.
- UCP, ACP, AP2, WebMCP, and Web Bot Auth building blocks.
- RFC 9421-compatible HTTP Message Signature verification.
- Legacy HMAC signatures with timestamp and nonce replay protection.
- AP2 mandate creation and verification with budget, audience, lifetime, category, and replay checks.
- Per-IP rate limiting and idempotency handling for protected writes.
- Optional OpenTelemetry export with graceful fallback when exporters are unavailable.
- HTML metadata and WebMCP injection for compatible responses.

## Authentication paths

The SDK does not require an AgentsBloom account just to install or self-host the middleware. Choose the authentication model that fits your integration:

- **Legacy HMAC writes:** configure a private merchant-generated `AGENTSBLOOM_SECRET` or `agentSecret`. This is required only for requests using the legacy `X-Agent-Signature` headers.
- **RFC HTTP Message Signatures:** configure trusted agent public keys through `agentJwks` or `agentJwksUrl`; this path does not use `AGENTSBLOOM_SECRET`.
- **AP2:** use the package's signed mandate helpers and verification path.
- **Local demos:** `demoMode` can bypass signature authentication, but it must never be enabled for an internet-facing production deployment.

An `AGENTSBLOOM_API_KEY` is a separate account/service-integration value. It is not the HMAC signing secret. Keep both values server-side and out of source control.

## Requirements

- Node.js 20 or newer.
- An Express 4 application.
- A real `AGENTSBLOOM_SECRET` for protected legacy-signed write actions, or a configured RFC Message Signature trust path.

## Minimal production setup

```js
import express from "express";
import { agentsbloom, shutdown } from "@agentsbloom/sdk";

const app = express();
const agentSecret = process.env.AGENTSBLOOM_SECRET;

if (!agentSecret) {
  throw new Error("AGENTSBLOOM_SECRET must be configured for legacy-signed writes");
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
    await closeServer();
  } finally {
    await shutdown();
  }
};
process.once("SIGTERM", stop);
process.once("SIGINT", stop);
```

`baseUrl` should be the canonical public HTTPS origin of the store. Do not put API keys or signing secrets in source control, client-side code, logs, or package metadata.

## Configuration

- `apiKey`: optional AgentsBloom account key used for attribution and service integrations.
- `agentSecret`: secret used to verify legacy `X-Agent-Identifier`/`X-Agent-Signature` requests. If omitted, `AGENTSBLOOM_SECRET` is read from the environment; if neither is set, legacy signed writes fail closed.
- `baseUrl`: canonical store origin used for discovery and audience binding.
- `actions`: map of agent action names to handlers. Handlers receive `(params, req, res)` and may return a value or a promise. `method` defaults to `POST`; declare `method: "GET"` explicitly for a read action.
- `rateLimit`: optional `{ max, windowMs }` in-memory per-IP limits.
- `idempotency`: optional `{ ttlMs }` for successful write responses keyed by `Idempotency-Key`.
- `ap2`: optional AP2 settings including `expectedAudience`, `maxMandateLifetimeSec`, `requireJti`, and `requestedCategories`.
- `merchantJwks`: merchant JWKS document served at the HTTP Message Signatures discovery endpoint.
- `agentJwks`: optional inline trusted JWKS used to verify RFC HTTP Message Signatures.
- `agentJwksUrl`: optional HTTPS URL for the trusted agent JWKS. A request cannot select an arbitrary remote JWKS URL.
- `signature`: optional `{ maxAgeMs }` for legacy HMAC timestamp validation; the default is five minutes.
- `demoMode`: explicit local/demo-only bypass for signature authentication. Never enable it in production.
- `disableSignatureAuth`: explicit compatibility bypass. Do not enable it for an internet-facing deployment.

The middleware does not replace application-level authorization, a distributed rate limiter, a durable idempotency store, TLS termination, or payment-provider verification.

## Legacy HMAC request signatures

For a mutating action using `X-Agent-Signature`, send:

- `X-Agent-Identifier`: printable agent identifier.
- `X-Agent-Timestamp`: current Unix timestamp in seconds.
- `X-Agent-Nonce`: unique printable nonce of at least 16 characters.
- `X-Agent-Signature`: lowercase or uppercase hexadecimal HMAC-SHA-256.

The signed payload is the JSON array `[identifier, method, originalUrl, timestamp, nonce, parsedBody]`, using the configured `agentSecret`. Signatures expire after five minutes by default and a nonce cannot be consumed twice by the same identifier within the process. Identifier-only signatures from older SDK revisions are intentionally rejected.

## RFC HTTP Message Signatures

Protected writes using the RFC 9421-compatible path must sign `@method`, `@path`, and `content-digest`, and include `created`, `expires`, `nonce`, `keyid`, and `alg` parameters. The SDK validates the lifetime, rejects reused nonces, and recomputes `content-digest` from `req.rawBody` when present or the parsed request body otherwise.

## MCP message authentication

The SSE connection at `/mcp` can advertise configured tools, but mutating MCP messages sent to `/mcp/messages` must pass the same configured RFC HTTP Message Signature or legacy `X-Agent-Signature` verification as other protected writes.

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

Presented mandates are cryptographically verified. The verifier enforces signature algorithms, issuer/audience binding, bounded lifetime, required `jti` replay protection, optional category restrictions, and budget limits.

## Telemetry

`setupTelemetry()` dynamically loads the optional OpenTelemetry packages and continues without an exporter when they are unavailable. `shutdown()` closes the configured provider and clears SDK in-memory state.

```js
import { setupTelemetry } from "@agentsbloom/sdk";

await setupTelemetry({
  otlpEndpoint: process.env.AGENTSBLOOM_OTEL_ENDPOINT,
  serviceName: "example-store",
  samplingRatio: 1,
  apiKey: process.env.AGENTSBLOOM_API_KEY
});
```

## Learn more

- [AgentsBloom documentation](https://docs.agentsbloom.com)
- [AgentsBloom marketing site](https://agentsbloom.com)
- [AgentsBloom blog](https://blog.agentsbloom.com)
- [AgentsBloom organization](https://github.com/AgentsBloom)
- [SDK issues and discussions](https://github.com/AgentsBloom/sdk/issues)

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
